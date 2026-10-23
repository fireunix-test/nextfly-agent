"""Run trusted private source checks without publishing raw process output."""
import base64
import json
import os
from pathlib import Path
import re
import shutil
import stat
import signal
import time
import subprocess
import sys
import tempfile
import tomllib
import urllib.request

from diagnostics import bounded, extract, redact

SOURCE = "fireunix-nextfly/agent"
TARGETS = "bencode_decode krpc_decode bt_wire torrent_info metainfo utp_conn client_hello ja3_import http1_response proxy_reply content_range content_disposition ftp_reply m3u8 bt_mse bt_pex bt_peer tracker_http tracker_udp nat_ssdp nat_upnp nat_pcp bt_holepunch bt_lsd thunder_wire thunder_transport".split()


def child_env():
    """Remove credentials and Actions file-command channels from child processes."""
    return {k: v for k, v in os.environ.items()
            if not k.startswith(("GITHUB_", "RUNNER_", "ACTIONS_", "INPUT_", "SOURCE_", "BUILDER_", "REPORT_", "GIT_CONFIG_"))
            and k not in ("GH_TOKEN", "GH_ENTERPRISE_TOKEN", "REQUEST_ID", "PR_NUMBER", "HEAD_SHA")}


class CommandFailure(RuntimeError):
    """Carry private diagnostics without exposing them through exception messages."""
    def __init__(self, output, code=None, timeout=False):
        super().__init__("Command failed")
        self.output, self.code, self.timeout = output, code, timeout


FAILURES = []
ENVIRONMENT = {}
FUZZ_TARGETS = []
DEADLINE = float("inf")


def run(args, cwd, env=None, capture=False, timeout=1200):
    """Capture both streams locally and terminate the process tree on timeout."""
    timeout = min(timeout, DEADLINE-time.monotonic())
    if timeout <= 0:
        raise CommandFailure("Job diagnostic deadline exceeded", timeout=True)
    with tempfile.TemporaryFile() as output:
        process = subprocess.Popen(args, cwd=cwd, env=env or child_env(),
                                   stdout=output, stderr=subprocess.STDOUT,
                                   start_new_session=os.name != "nt")
        timed_out = False
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                               stdout=output, stderr=subprocess.STDOUT, check=False)
            else:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            process.wait()
        output.seek(0)
        if process.returncode or timed_out:
            raw = output.read(16*1024*1024)
            if output.read(1):
                output.seek(-8*1024*1024, os.SEEK_END)
                raw += b"\n[Output truncated]\n" + output.read()
            raise CommandFailure(raw.decode("utf-8", "replace"), process.returncode, timed_out)
        return output.read() if capture else True


def api(path, token):
    request = urllib.request.Request("https://api.github.com/repos/" + SOURCE + path,
        headers={"Authorization": "Bearer " + token,
                 "Accept": "application/vnd.github+json", "User-Agent": "nextfly-builder"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def validate(token):
    sha = os.environ["SOURCE_SHA"]
    head = os.environ["HEAD_SHA"]
    pr = os.environ["PR_NUMBER"]
    if not re.fullmatch(r"[0-9a-f]{40}", sha) or not re.fullmatch(r"[0-9a-f]{40}", head):
        raise ValueError("Invalid revision")
    if not re.fullmatch(r"0|[1-9][0-9]*", pr):
        raise ValueError("Invalid request")
    if pr == "0":
        if api("/git/ref/heads/main", token)["object"]["sha"] != sha or head != sha:
            raise ValueError("Stale push")
    else:
        pull = api("/pulls/" + pr, token)
        if (pull["state"] != "open" or pull["head"]["repo"]["full_name"] != SOURCE
                or pull["base"]["repo"]["full_name"] != SOURCE
                or pull["head"]["sha"] != head or pull["merge_commit_sha"] != sha):
            raise ValueError("Untrusted or stale pull request")
    return sha


def stage(name, args, root, capture=False, target=None):
    print(name + ": running", flush=True)
    try:
        result = run(args, root, capture=capture, timeout=2400 if name == "Tests" else 1200)
    except CommandFailure as failure:
        summary = extract(name, failure.output, failure.code, failure.timeout, target, root)
        FAILURES.append({"stage": name, "summary": bounded(redact(summary, ENVIRONMENT, root))})
        print(name + ": failed", flush=True)
        return None
    print(name + ": passed", flush=True)
    return result


def iai_crates(root):
    """Crates with an iai-callgrind benchmark in the checked-out revision."""
    return sorted(path.parent.parent.name for path in (root / "crates").glob("*/benches/iai.rs"))


def locked_version(root, package):
    with (root / "Cargo.lock").open("rb") as lock:
        packages = tomllib.load(lock).get("package", [])
    version = next((item.get("version") for item in packages if item.get("name") == package), None)
    return version if isinstance(version, str) and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) else None


def instruction_counts(root, sha):
    """Count instructions under Callgrind and fail on a regression over 5% against the first parent."""
    crates = iai_crates(root)
    version = locked_version(root, "iai-callgrind")
    if not crates or not version:
        return
    # The runner must match the library version the source locks.
    if stage("Instruction count runner", ["cargo", "install", "--locked", "--quiet", "iai-callgrind-runner",
                                          "--version", "=" + version], root) is None:
        return
    def bench(selected, *args):
        packages = [arg for crate in selected for arg in ("-p", crate)]
        return ["cargo", "bench", "--locked", *packages, "--bench", "iai", "--", *args]
    # The baseline is best effort: a parent that cannot be measured leaves
    # the counts unchecked rather than failing this revision.
    measured = False
    try:
        run(["git", "checkout", "--quiet", "--detach", "HEAD^1"], root)
        base = [crate for crate in crates if crate in iai_crates(root)]
        if base and locked_version(root, "iai-callgrind") == version:
            print("Instruction counts (baseline): running", flush=True)
            run(bench(base, "--save-baseline=base"), root)
            measured = True
    except CommandFailure:
        print("Instruction counts (baseline): unavailable", flush=True)
    run(["git", "checkout", "--quiet", "--detach", sha], root)
    limits = ("--baseline=base", "--callgrind-limits=ir=5.0%") if measured else ()
    stage("Instruction counts", bench(crates, *limits), root)


def save_summary():
    """Write only private, redacted diagnostics; a later isolated step encrypts them."""
    directory = Path(os.environ["RUNNER_TEMP"])/"ci-private"
    directory.mkdir(mode=0o700, exist_ok=True)
    remaining = 56_000
    failures = []
    for failure in FAILURES:
        if remaining < 100:
            failures.append({"stage":"Summary", "summary":"[已截断]"})
            break
        summary = bounded(failure["summary"], remaining)
        failures.append({"stage":failure["stage"], "summary":summary})
        remaining -= len(summary.encode())
    payload = {"job": os.environ["REPORT_JOB"], "platform":os.environ["REPORT_PLATFORM"],
               "source_sha":os.environ["SOURCE_SHA"], "head_sha":os.environ["HEAD_SHA"],
               "run_id":os.environ["GITHUB_RUN_ID"], "attempt":os.environ["GITHUB_RUN_ATTEMPT"],
               "failures":failures, "targets":FUZZ_TARGETS}
    serialized = json.dumps(payload,ensure_ascii=False)
    while len(serialized.encode()) > 60_000:
        for failure in payload["failures"]:
            failure["summary"] = bounded(failure["summary"], max(100, len(failure["summary"].encode())//2))
        serialized = json.dumps(payload,ensure_ascii=False)
    path = directory/"summary.json"
    path.write_text(serialized, encoding="utf-8")
    path.chmod(0o600)


def main():
    global FUZZ_TARGETS
    token = os.environ.pop("SOURCE_TOKEN")
    sha = validate(token)
    mode = sys.argv[1]
    if mode not in ("check", "fuzz"):
        raise ValueError("Invalid mode")
    if mode == "fuzz" and sys.argv[2] not in TARGETS:
        raise ValueError("Invalid target")
    root = Path(tempfile.mkdtemp(prefix="private-ci-", dir=os.environ.get("RUNNER_TEMP")))
    try:
        run(["git", "init", "--quiet", str(root)], root)
        env = child_env()
        # Pass credentials only to fetch, without persisting them in Git config.
        auth = base64.b64encode(("x-access-token:" + token).encode()).decode()
        env.update(GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="http.https://github.com/.extraheader",
                   GIT_CONFIG_VALUE_0="AUTHORIZATION: basic " + auth, GIT_TERMINAL_PROMPT="0")
        # Two commits deep: the first parent is the baseline for instruction counts.
        run(["git", "fetch", "--quiet", "--depth=2", "https://github.com/" + SOURCE + ".git", sha], root, env)
        del token, auth, env
        run(["git", "checkout", "--quiet", "--detach", "FETCH_HEAD"], root)
        print("Source preparation: passed", flush=True)
        with (root / "fuzz/Cargo.toml").open("rb") as manifest:
            FUZZ_TARGETS = sorted({item["name"] for item in tomllib.load(manifest).get("bin", [])})
        if mode == "fuzz":
            targets = set(FUZZ_TARGETS)
            if sys.argv[2] not in targets:
                # Older revisions do not contain targets introduced by later PRs.
                print("Fuzz: not applicable to this revision", flush=True)
                return
            stage("Fuzz", ["cargo", "+nightly", "fuzz", "run", "--target", "x86_64-unknown-linux-gnu",
                           sys.argv[2], "--", "-max_total_time=60"], root, target=sys.argv[2])
        else:
            if sys.platform.startswith("linux"):
                stage("Formatting", ["cargo", "fmt", "--all", "--check"], root)
            stage("Clippy", ["cargo", "clippy", "--workspace", "--all-targets", "--locked", "--", "-D", "warnings"], root)
            stage("Tests", ["cargo", "test", "--workspace", "--locked", "--no-fail-fast"], root)
            if sys.platform.startswith("linux"):
                for crate, test in (("na-net", "udp"), ("na-dht", "load"), ("na-http", "throughput"), ("na-bt", "load")):
                    if not (root / "crates" / crate / "tests" / (test + ".rs")).is_file():
                        # Older revisions do not contain tests introduced by later PRs.
                        continue
                    stage("Throughput " + crate + "/" + test, ["cargo", "test", "-p", crate, "--release", "--locked", "--test", test,
                                         "--", "--ignored", "--nocapture"], root)
                instruction_counts(root, sha)
                stage("Load server build", ["cargo", "build", "--release", "--locked", "-p", "na-dht", "--example", "dht_server"], root)
                output = stage("Load test build", ["cargo", "test", "--release", "--locked", "-p", "na-dht", "--test", "load", "--no-run", "--message-format=json"], root, capture=True)
                executable = None
                for line in (output or b"").splitlines():
                    try:
                        item = json.loads(line)
                    except ValueError:
                        continue
                    if item.get("target", {}).get("name") == "load" and item.get("executable"):
                        executable = item["executable"]
                if not executable:
                    FAILURES.append({"stage":"Network namespaces", "summary":"Load test executable unavailable; preceding build failed."})
                    return
                stage("Network namespaces", ["sudo", "bash", "scripts/netns-load.sh", str(root / "target/release/examples/dht_server"), executable, "2"], root)
    finally:
        def remove_readonly(function, path, _error):
            # Git pack files can be read-only on Windows.
            os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
            function(path)
        shutil.rmtree(root, onerror=remove_readonly)


if __name__ == "__main__":
    ENVIRONMENT = dict(os.environ)
    DEADLINE = time.monotonic()+90*60
    try:
        main()
    except BaseException as error:
        # Never send tracebacks or process output to the public runner log.
        FAILURES.append({"stage":"Preparation or infrastructure", "summary":"CI could not finish this job ("+type(error).__name__+")."})
        print("CI: failed", flush=True)
    finally:
        if os.environ.get("REPORT_JOB"):
            try:
                save_summary()
            except BaseException:
                print("Private summary: failed", flush=True)
                FAILURES.append({"stage":"Summary", "summary":"Summary unavailable"})
    sys.exit(1 if FAILURES else 0)
