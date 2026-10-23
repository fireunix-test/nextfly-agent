"""Verify named checks against the exact private revision's fuzz manifest."""
import base64
import re
import tomllib

PLATFORMS = ('ubuntu-latest', 'macos-latest', 'windows-latest')
# Fuzz jobs; each builds the fuzz crate once and runs every FUZZ_SHARDS-th
# target of the tested revision's manifest, so all targets are always covered.
FUZZ_SHARDS = 7


def required_names(targets):
    if not all(isinstance(t, str) and re.fullmatch(r'[a-zA-Z0-9_-]+', t) for t in targets):
        raise ValueError('Invalid fuzz manifest')
    return ({f'check ({p})' for p in PLATFORMS}
            | {f'fuzz ({i}/{FUZZ_SHARDS})' for i in range(1, FUZZ_SHARDS + 1)})


def manifest_names(response):
    manifest = tomllib.loads(base64.b64decode(response['content'], validate=False).decode())
    return required_names([target['name'] for target in manifest.get('bin', [])])


def successful(jobs, required):
    return all(sum(j.get('name') == name and j.get('conclusion') == 'success' for j in jobs) == 1
               and sum(j.get('name') == name for j in jobs) == 1 for name in required)
