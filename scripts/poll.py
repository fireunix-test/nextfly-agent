"""Reconcile private revisions and public CI runs without private runners."""
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request

from checks import manifest_names, successful

SOURCE = "fireunix-nextfly/agent"
BUILDER = "fireunix-test/nextfly-agent"
CONTEXT = "external-ci/remote"


def api(repo, path, data=None):
    token = os.environ["SOURCE_TOKEN" if repo == SOURCE else "BUILDER_TOKEN"]
    # The newer dispatch API returns run IDs; PR merge fields use the stable schema.
    request = urllib.request.Request("https://api.github.com/repos/" + repo + path,
        data=None if data is None else json.dumps(data).encode(),
        headers={"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2026-03-10" if path.endswith("/dispatches") else "2022-11-28", "User-Agent": "nextfly-ci-poller",
                 "Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read()
        return json.loads(raw) if raw else None


def pages(repo, path, key=None):
    page = 1
    while True:
        result = api(repo, path + ("&" if "?" in path else "?") + f"per_page=100&page={page}")
        batch = result[key] if key else result
        yield from batch
        if len(batch) < 100:
            return
        page += 1


def publish(head, sha, state, url):
    api(SOURCE, "/statuses/" + head,
        {"state": state, "context": CONTEXT, "target_url": url,
         "description": "CI " + sha + " " + state})


def reconcile(pr, head, sha):
    if not all(re.fullmatch(r"[0-9a-f]{40}", value or "") for value in (head, sha)):
        raise ValueError("Invalid revision")
    statuses = pages(SOURCE, "/commits/" + head + "/statuses")
    previous = next((s for s in statuses if s["context"] == CONTEXT), None)
    marker = "CI " + sha + " "
    prefix = "https://github.com/" + BUILDER + "/actions/runs/"
    run_id = None
    if previous and (previous.get("description") or "").startswith(marker):
        url = previous.get("target_url") or ""
        if url.startswith(prefix) and url[len(prefix):].isdigit():
            run_id = int(url[len(prefix):])
    retry = os.environ.get("RETRY_PR") == str(pr) and bool(pr)
    if not run_id or retry:
        # A deterministic request ID recovers dispatches whose API response was lost.
        request_id = "poll-" + hashlib.sha256(f"{pr}:{head}:{sha}".encode()).hexdigest()[:32]
        runs = pages(BUILDER, "/actions/workflows/ci.yml/runs?event=workflow_dispatch", "workflow_runs")
        existing = next((r for r in runs if r["display_title"] == "Build " + request_id), None)
        if existing and not retry:
            run_id = existing["id"]
        else:
            result = api(BUILDER, "/actions/workflows/ci.yml/dispatches",
                {"ref": "main", "inputs": {"source_sha": sha, "head_sha": head,
                 "pr_number": str(pr), "request_id": request_id}})
            if not result or not result.get("workflow_run_id"):
                # The next scheduled pass will find the run by request ID.
                return
            run_id = result["workflow_run_id"]
        publish(head, sha, "pending", prefix + str(run_id))
    run = api(BUILDER, "/actions/runs/" + str(run_id))
    if run["status"] != "completed":
        if previous and previous["state"] != "pending":
            publish(head, sha, "pending", prefix + str(run_id))
        return
    jobs = list(pages(BUILDER, f"/actions/runs/{run_id}/jobs", "jobs"))
    required = manifest_names(api(SOURCE, "/contents/fuzz/Cargo.toml?ref=" + sha))
    success = run["conclusion"] == "success" and successful(jobs, required)
    state = "success" if success else "failure"
    if not previous or previous["state"] != state or not (previous.get("description") or "").startswith(marker):
        publish(head, sha, state, prefix + str(run_id))


def main():
    failed = False
    revisions = [(0, api(SOURCE, "/git/ref/heads/main")["object"]["sha"])]
    for pull in pages(SOURCE, "/pulls?state=open"):
        if pull["head"]["repo"] and pull["head"]["repo"]["full_name"] == SOURCE:
            revisions.append((pull["number"], pull["head"]["sha"]))
    for number, head in revisions:
        try:
            if number:
                pull = api(SOURCE, "/pulls/" + str(number))
                if pull["head"]["sha"] != head or pull["state"] != "open":
                    continue
                if pull["mergeable"] is None:
                    continue
                if not pull["mergeable"]:
                    previous = next((s for s in pages(SOURCE, "/commits/" + head + "/statuses")
                                     if s["context"] == CONTEXT), None)
                    if not previous or previous["description"] != "CI " + head + " failure":
                        publish(head, head, "failure", "https://github.com/" + SOURCE + "/pull/" + str(number))
                    continue
                sha = pull["merge_commit_sha"]
            else:
                sha = head
            reconcile(number, head, sha)
        except Exception as error:
            if isinstance(error, urllib.error.HTTPError):
                print("GitHub API status: " + str(error.code), flush=True)
            else:
                print("Polling error type: " + type(error).__name__, flush=True)
            failed = True
            print("A CI request could not be reconciled; check repository permissions.", flush=True)
    return int(failed)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        print("CI polling failed; check repository permissions and availability.", flush=True)
        sys.exit(1)
