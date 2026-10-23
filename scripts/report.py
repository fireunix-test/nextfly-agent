"""Write local diagnostics directly to one private PR comment, without artifacts."""
import base64
import contextlib
import html
import json
import os
from pathlib import Path
import random
import re
import sys
import time
import urllib.error
import urllib.request
import zlib

from checks import PLATFORMS, required_names
from diagnostics import bounded, redact

SOURCE = 'fireunix-nextfly/agent'
BUILDER = 'fireunix-test/nextfly-agent'
MARKER = '<!-- external-ci-report -->'
STATE = re.compile(r'<!-- external-ci-state:([A-Za-z0-9+/=]+) -->')


def api(repo, path, data=None, method=None):
    token = os.environ['REPORT_TOKEN' if repo == SOURCE else 'BUILDER_TOKEN']
    request = urllib.request.Request('https://api.github.com/repos/'+repo+path,
        data=None if data is None else json.dumps(data).encode(), method=method,
        headers={'Authorization':'Bearer '+token, 'Accept':'application/vnd.github+json',
                 'X-GitHub-Api-Version':'2022-11-28', 'User-Agent':'nextfly-ci-report',
                 'Content-Type':'application/json'})
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read()
        return json.loads(raw) if raw else None


def pages(repo, path):
    for page in range(1, 101):
        batch = api(repo, path+f'?per_page=100&page={page}')
        yield from batch
        if len(batch)<100:
            return
    raise RuntimeError('Pagination limit exceeded')


@contextlib.contextmanager
def write_lock():
    """Use atomic ref creation to prevent concurrent read-modify-write updates.

    The ref points only to the public workflow commit. Each attempt has a fresh
    lock; an interrupted writer cannot prevent a new attempt from reporting.
    """
    ref = 'tags/ci-report-lock-'+os.environ['GITHUB_RUN_ID']+'-'+os.environ['GITHUB_RUN_ATTEMPT']
    deadline = time.monotonic()+180
    while True:
        try:
            api(BUILDER, '/git/refs', {'ref':'refs/'+ref, 'sha':os.environ['GITHUB_SHA']})
            break
        except urllib.error.HTTPError as error:
            if error.code != 422 or time.monotonic()>=deadline:
                raise
            time.sleep(random.uniform(2, 5))
    try:
        yield
    finally:
        api(BUILDER, '/git/refs/'+ref, method='DELETE')


def unpack(body):
    match = STATE.search(body)
    if not match:
        raise ValueError('Report state missing')
    decoder = zlib.decompressobj()
    raw = decoder.decompress(base64.b64decode(match[1], validate=True), 120_000)
    if not decoder.eof or decoder.unconsumed_tail:
        raise ValueError('Report state too large')
    return json.loads(raw)


def render(state):
    """Keep both the readable report and its private update state below 60 KB."""
    entries = state['entries']
    limit = 24_000 // max(1, sum(bool(e['failures']) for e in entries.values()))
    while True:
        for entry in entries.values():
            budget = limit // max(1, len(entry['failures']))
            for failure in entry['failures']:
                failure['summary'] = bounded(failure['summary'], budget)
        complete = set(state['expected']).issubset(entries)
        passed = complete and all(e['passed'] for e in entries.values())
        title = ('✅ 全部通过' if passed else '❌ CI 失败' if any(not e['passed'] for e in entries.values()) else '⏳ CI 运行中')
        body = [MARKER, f"{title} (SHA {state['head']})", '',
                f"Merge SHA: `{state['merge']}`", f"Head SHA: `{state['head']}`",
                f"[Builder 运行](https://github.com/{BUILDER}/actions/runs/{state['run']}/attempts/{state['attempt']})",
                f"已回报 {len(entries)}/{len(state['expected'])} 个 job。"]
        for platform in PLATFORMS:
            group = [(name,e) for name,e in sorted(entries.items()) if e['platform']==platform]
            if not group:
                continue
            body.extend(['', '<details>', '<summary>'+platform+'</summary>', ''])
            for name,entry in group:
                body.append(('✅ ' if entry['passed'] else '❌ ')+html.escape(name))
                for failure in entry['failures']:
                    body.extend(['', '**'+html.escape(failure['stage'])+'**',
                                 '<pre>'+html.escape(failure['summary'])+'</pre>'])
            body.append('</details>')
        encoded = base64.b64encode(zlib.compress(json.dumps(state, ensure_ascii=False).encode())).decode()
        body.append('<!-- external-ci-state:'+encoded+' -->')
        result = '\n'.join(body)
        if len(result.encode())<=60_000:
            return result
        limit //= 2
        if limit<100:
            raise ValueError('Report cannot fit')


def main():
    pr = os.environ['PR_NUMBER']
    if pr == '0':
        return
    if not re.fullmatch(r'[1-9][0-9]*', pr):
        raise ValueError('Invalid PR')
    source = Path(os.environ['RUNNER_TEMP'])/'ci-private'/'summary.json'
    try:
        payload = json.loads(source.read_text(encoding='utf-8')) if source.is_file() else None
        names = json.loads(os.environ['REPORT_EXPECTED'])
        name = os.environ['REPORT_JOB']
        if name not in names:
            raise ValueError('Unknown job')
        run, attempt = int(os.environ['GITHUB_RUN_ID']), int(os.environ['GITHUB_RUN_ATTEMPT'])
        head, merge = os.environ['HEAD_SHA'], os.environ['SOURCE_SHA']
        valid = payload and all(str(payload.get(k))==v for k,v in
             [('job',name),('run_id',str(run)),('attempt',str(attempt)),('head_sha',head),('source_sha',merge)])
        failures = payload['failures'] if valid else [{'stage':'Infrastructure', 'summary':'No diagnostic summary was produced. Check setup, cancellation or timeout.'}]
        if valid:
            missing = required_names(payload.get('targets', [])) - set(names)
            if missing:
                failures.append({'stage':'Missing required checks', 'summary':'No matrix job exists for: '+', '.join(sorted(missing))})
        if not failures and os.environ['BUILD_OUTCOME']!='success':
            failures = [{'stage':'Infrastructure', 'summary':'The build step did not complete successfully.'}]
        for failure in failures:
            failure['summary'] = bounded(redact(failure['summary']))
        with write_lock():
            # Revalidate inside the lock, immediately before reading or writing comments.
            if not api(SOURCE, '')['private']:
                raise ValueError('Report destination must be private')
            pull = api(SOURCE, '/pulls/'+pr)
            if (pull['state']!='open' or pull['head']['sha']!=head or pull['merge_commit_sha']!=merge
                    or pull['head']['repo']['full_name']!=SOURCE):
                return
            comments = [c for c in pages(SOURCE, '/issues/'+pr+'/comments') if c['body'].startswith(MARKER)]
            if len(comments)>1:
                raise ValueError('Multiple report comments require review')
            comment = comments[0] if comments else None
            state = unpack(comment['body']) if comment else None
            if state and (state['run'],state['attempt'])>(run,attempt):
                return
            if not state or (state['run'],state['attempt'])!=(run,attempt):
                state = {'run':run, 'attempt':attempt, 'head':head, 'merge':merge, 'expected':names, 'entries':{}}
            state['entries'][name] = {'platform':os.environ['REPORT_PLATFORM'], 'passed':not failures, 'failures':failures}
            body = render(state)
            if comment:
                api(SOURCE, '/issues/comments/'+str(comment['id']), {'body':body}, method='PATCH')
            else:
                api(SOURCE, '/issues/'+pr+'/comments', {'body':body})
    finally:
        source.unlink(missing_ok=True)


if __name__ == '__main__':
    try:
        main()
        print('Private PR report: passed', flush=True)
    except BaseException as error:
        # API responses and exceptions can contain private comment bodies:
        # only the error type and HTTP status are printed.
        status = f' {error.code}' if isinstance(error, urllib.error.HTTPError) else ''
        print('Private PR report: failed (' + type(error).__name__ + status + ')', flush=True)
        sys.exit(1)
