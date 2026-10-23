"""Bound, redact and encrypt private diagnostic summaries."""
import base64
import os
from pathlib import Path
import re

LIMIT = 60_000
TRUNCATED = '\n[已截断]\n'


def bounded(text, limit=LIMIT):
    raw = text.encode('utf-8')
    if len(raw) <= limit:
        return text
    return raw[:max(0, limit-len(TRUNCATED.encode()))].decode('utf-8', 'ignore') + TRUNCATED


def redact(text, environment=None, root=None):
    """Remove secret values, runner metadata, ANSI escapes and absolute roots."""
    env = os.environ if environment is None else environment
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', text)
    roots = [str(root)] if root else []
    roots += [v for k,v in env.items() if v and (k in ('GITHUB_WORKSPACE','RUNNER_TEMP','HOME','USERPROFILE') or k.endswith('_DIRECTORY'))]
    for value in sorted(set(roots), key=len, reverse=True):
        for variant in (value, value.replace('\\','/')):
            text = text.replace(variant.rstrip('/\\')+'/', '').replace(variant.rstrip('/\\')+'\\', '')
    values = []
    for key, value in env.items():
        if value and (key.startswith(('GITHUB_', 'RUNNER_', 'ACTIONS_')) or any(word in key.upper() for word in ('TOKEN','SECRET','PASSWORD','REPORT_KEY'))):
            values.append(value)
            if any(word in key.upper() for word in ('TOKEN','SECRET','PASSWORD','REPORT_KEY')):
                values.extend([base64.b64encode(value.encode()).decode(), base64.b64encode(('x-access-token:'+value).encode()).decode()])
    for value in sorted(set(values), key=len, reverse=True):
        # Short metadata values need token boundaries to preserve normal words.
        if len(value) < 4:
            text = re.sub(r'(?<!\w)'+re.escape(value)+r'(?!\w)', '[REDACTED]', text)
        else:
            text = text.replace(value, '[REDACTED]')
    text = re.sub(r'(?:github_pat_[A-Za-z0-9_]+|gh[pousr]_[A-Za-z0-9]+)', '[REDACTED]', text)
    text = re.sub(r'(?i)(authorization\s*[:=]\s*(?:bearer|basic)\s+)\S+', r'\1[REDACTED]', text)
    text = re.sub(r'(?i)((?:token|password|secret)\s*[:=]\s*)[^\s,;]+', r'\1[REDACTED]', text)
    # Keep source-relative paths after common hosted-runner prefixes.
    text = re.sub(r'(?:/home/runner|/Users/runner|[A-Za-z]:[/\\](?:a|Users[/\\]runneradmin))[/\\][^\s:]*?(?=(?:crates|src|tests|fuzz)[/\\])', '', text)
    text = re.sub(r'(?:/home/runner|/Users/runner|[A-Za-z]:[/\\](?:a|Users[/\\]runneradmin))[/\\][^\s\)\]\"\']+', '[runner-path]', text)
    return text


def error_summary(lines):
    selected = []
    # Include diagnostics, locations and their source context, bounded to 200 lines.
    active = False
    for line in lines:
        if re.match(r'^\s*(?:error(?:\[.*?\])?:|Diff in |error:)', line):
            active = True
        if active:
            selected.append(line)
            if not line.strip():
                active = False
    if not selected:
        selected = lines[-40:]
    if len(selected) > 200:
        return '\n'.join(selected[:199]) + TRUNCATED
    return '\n'.join(selected)


def extract(stage, output, code=None, timeout=False, target=None, root=None):
    """Extract only the diagnostics relevant to a stage; never log this return value."""
    lines = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', output).splitlines()
    result = [stage, 'timeout' if timeout else (f'signal {-code}' if code is not None and code < 0 else f'exit code {code}')]
    if stage == 'Tests':
        binary = 'Unknown test binary'
        index = 0
        while index < len(lines):
            line = lines[index]
            if re.match(r'\s*(Running |Doc-tests |Unittests )', line):
                binary = line.strip()
            if re.match(r'^test .+ \.\.\. FAILED', line):
                result.extend([binary, line])
            elif re.match(r'^---- .+ stdout ----$', line):
                result.extend([binary, line])
                block = []
                index += 1
                while index < len(lines) and not re.match(r'^(---- .+ stdout ----|failures:|test result:)', lines[index]):
                    block.append(lines[index]); index += 1
                panic = next((i for i,s in enumerate(block) if re.search(r'panicked at|panic:|fatal runtime error|assertion .*failed',s)), None)
                chosen = block[panic:] if panic is not None else block
                result.extend(chosen[:60])
                if len(chosen)>60:
                    result.append('[已截断]')
                continue
            elif re.search(r'process didn.t exit successfully|signal:|exit code:|test result: FAILED|error: test failed|test target failed|fatal runtime error', line):
                result.extend([binary, line])
            index += 1
        if any(re.match(r'^error(?:\[|:)', line) and 'test failed' not in line for line in lines):
            result.append(error_summary(lines))
    elif stage == 'Fuzz':
        result.append('Target: '+str(target))
        crash = next((s for s in lines if re.search(r'panicked at|ERROR: (?:libFuzzer|AddressSanitizer|UndefinedBehaviorSanitizer)|SUMMARY: .*Sanitizer|runtime error:',s)), 'No crash classification available')
        result.append(crash)
        # File contents, literal inputs, hex dumps and base64 reproductions are excluded.
        for line in lines:
            match = re.search(r'Test unit written to (.+)', line)
            if match:
                path = Path(match.group(1).strip())
                if not path.is_absolute() and root:
                    path = Path(root)/path
                size = path.stat().st_size if path.is_file() else 'unknown'
                result.append(f'Crash input: {path.name} ({size} bytes)')
        if crash == 'No crash classification available' and any(s.startswith('error') for s in lines):
            result.append(error_summary(lines))
    elif stage.startswith(('Throughput','Network namespaces')):
        result.extend(lines[-40:])
    elif stage.startswith('Instruction counts') and any('regressed' in line for line in lines):
        # Each benchmark's name, then its metric lines, regressions among them.
        selected = [line for line in lines if line.startswith('iai::') or 'regressed' in line or 'Iai-Callgrind result' in line]
        result.extend(selected[:200])
        if len(selected) > 200:
            result.append('[已截断]')
    else:
        result.append(error_summary(lines))
    return bounded('\n'.join(result))

