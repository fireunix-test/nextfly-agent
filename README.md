# Nextfly Agent CI

This public repository contains CI orchestration only. Private source is fetched at
an exact validated merge revision onto ephemeral GitHub-hosted runners. Source,
raw logs, diagnostics and build artifacts are never uploaded here, and build
caches only encrypted (below). Only trusted same-repository pull requests and
current main are accepted.

## Encrypted build caches

Any workflow running in a public repository can restore its Actions caches,
including one that a pull request from a fork brings along, and compiled output
can be reverse engineered. A cache therefore holds only third-party build output
(registry and Git dependencies, BoringSSL above all) and Cargo's download cache:
`scripts/cache.py` deletes everything built from path packages, the private
crates, then seals the rest with AES-256-GCM under the `CACHE_KEY` secret (32
random bytes, base64), which such workflows never receive. Chunks are
authenticated in order, so a tampered or truncated blob is rejected and the job
builds from scratch.

Keys combine the platform, the job kind (`check`, `fuzz`), the exact compiler and
the revision's lockfile; a lockfile change restores the newest cache of the same
compiler, and the job saves a new one. Only fuzz shard 1 saves. Builds use a fixed
target directory outside the checkout and no incremental compilation.

## Credentials and reports

Access to the private source goes through a GitHub App, so no credential here
expires. Create an App owned by `fireunix-nextfly` with no webhook and these
repository permissions, and install it on `fireunix-nextfly/agent` only:

- Contents: read
- Pull requests: read and write
- Commit statuses: read and write
- Metadata: read (always granted)

In this repository, set the variable `APP_CLIENT_ID` to the App's client ID and
the secret `APP_PRIVATE_KEY` to a private key generated for it. The private key
does not expire; rotate it by generating a new one and deleting the old.

Every job mints short-lived installation tokens (one hour, revoked when the job
ends) with only the permissions its step needs:

- builds: Contents and Pull requests read, to validate and fetch the revision;
- the poller: the same plus Commit statuses write, to publish `external-ci/remote`;
- the report step: Pull requests write, to update the private PR comment.

The App key is passed only to the minting steps, never to a step that runs
source code. Until `APP_CLIENT_ID` is set, the poller does nothing.

Each matrix job captures process output locally, extracts redacted diagnostics,
and writes a private temporary summary. Its final `if: always()` step receives
the report token, updates the single private PR comment identified by
`<!-- external-ci-report -->`, then deletes that temporary summary. The test step
never receives the report token. There is no report artifact or encryption key.
Main builds do not post comments.

The private comment records merge/head SHAs, the run link and per-platform results.
Tests use `--no-fail-fast`, preserving failed names, binary names and up to 60 panic
lines per test. Compiler diagnostics are limited to 200 lines, throughput/network
namespace diagnostics to the last 40 lines. Fuzz reports contain the target, crash
type and input filename/size, never input contents. Secrets and runner paths are
filtered. Each local summary and the entire comment are bounded to 60 KB with an
explicit truncation marker. The hidden compressed state inside the **private**
comment preserves results when later jobs update it; it is not encryption.

Matrix jobs run in parallel. A short-lived Git ref
`refs/tags/ci-report-lock-<public-run-id>-<attempt>` serializes comment updates.
It points only to the public workflow commit and contains no source or diagnostics.
The builder's `GITHUB_TOKEN` therefore needs Contents write; it is explicitly
injected only in the report step, with checkout credential persistence disabled.
The private report token still has only PR write access. Runs for one PR are also
serialized; stale revisions and older run/attempt reports cannot replace newer ones.

If a runner is forcibly stopped, GitHub may not execute its final step. The comment
can then remain incomplete; the commit status will not pass. A killed lock holder
may leave its public ref behind and cause other report steps in that attempt to
fail closed after three minutes. A fresh run/attempt uses a different lock.

Output capture prevents accidental disclosure; it is not a sandbox for hostile
code. Only trusted contributors may submit builds, and only trusted maintainers may
change or dispatch these workflows. Do not enable debug logging, unencrypted
caches, artifact uploads or raw diagnostic output. Actions are pinned to reviewed commits.

## Triggering and retrying

`poll.yml` checks open same-repository PRs and main approximately every five minutes
(GitHub scheduling delays apply), deduplicates by head/merge SHA and publishes
`external-ci/remote`. Require that status for merging. No private runner is needed.
The private source retains an optional manual dispatcher, requiring working private
Actions billing.

Failures are not retried automatically. To retry a PR with **current builder code**,
run the public **Poll private PRs** workflow manually and set `retry_pr` to its number:

```sh
gh workflow run poll.yml -R fireunix-test/nextfly-agent -f retry_pr=8
```

This resolves the current PR head and merge SHA, starts a fresh build and changes
the status to pending. The scheduled poller publishes its final result. For the
same workflow revision, GitHub's **Re-run all jobs** also works; run the poller
without `retry_pr` afterward for immediate status reconciliation. Prefer all jobs,
not failed jobs only, so the new report attempt includes every platform. New
commits or changes to the merge revision trigger fresh CI automatically.

Completion verifies three named platform checks and four fuzz shards. Each shard
builds the fuzz crate once and runs every fourth target of the **tested
revision's** `fuzz/Cargo.toml` for 60 seconds, so new targets need no workflow
change; the private report names each failing target. Missing checks and skipped
required checks fail closed; extra orchestration jobs do not alter the required
set.

## Local validation

```sh
python3 -m unittest discover -s scripts -p 'test_*.py'
actionlint .github/workflows/ci.yml .github/workflows/poll.yml
```

Tests cover extraction, UTF-8 truncation, credential/path filtering, timeout handling,
private report state round trips, concurrent-writer locking, single-comment updates
and revision-specific required checks. No private source or live tokens are needed.
