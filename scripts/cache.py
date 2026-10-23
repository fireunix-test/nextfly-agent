"""Encrypted build caches that never expose private build output.

Actions caches of a public repository can be restored by any workflow that
runs in it, including workflows that pull requests from forks bring along.
Compiled output can be reverse engineered, so a cache holds only third-party
build output and Cargo's download cache, and is sealed with AES-256-GCM under
a key that exists only as this repository's secret, which such workflows never
receive. Output of the private crates is removed before packing.

A blob is the magic bytes, an 8-byte random nonce prefix, then chunks of
`flag (1) | length (4) | ciphertext`. Each chunk's nonce is the prefix and its
index; its flag and index are authenticated, so reordered, truncated or
extended blobs fail to open. The payload is a Zstandard compressed tar stream
with `cargo/` (registry and Git database) and `target/` members.
"""
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import urllib.request

MAGIC = b'NXC1'
CHUNK = 8 << 20
# Profile subdirectories that hold per-package output, filtered by package.
PACKAGE_DIRS = ('deps', '.fingerprint', 'build')
# `<name>-<16 hex>` with any extension; library files add a `lib` prefix.
ARTIFACT = re.compile(r'^(?P<name>[A-Za-z0-9_\-]+?)-[0-9a-f]{16}(?:\..*)?$')


def _aead(key):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if len(key) != 32:
        raise ValueError('Cache key must be 32 bytes')
    return AESGCM(key)


def _aad(flag, index):
    return bytes([flag]) + struct.pack('>Q', index)


class Sealer(io.RawIOBase):
    """Encrypts everything written to it into `out` in authenticated chunks."""

    def __init__(self, out, key):
        self.out, self.aead = out, _aead(key)
        self.prefix = os.urandom(8)
        self.index, self.buffer = 0, bytearray()
        out.write(MAGIC + self.prefix)

    def writable(self):
        return True

    def write(self, data):
        self.buffer += data
        while len(self.buffer) > CHUNK:
            self._chunk(0, bytes(self.buffer[:CHUNK]))
            del self.buffer[:CHUNK]
        return len(data)

    def _chunk(self, flag, plain):
        nonce = self.prefix + struct.pack('>I', self.index)
        sealed = self.aead.encrypt(nonce, plain, _aad(flag, self.index))
        self.out.write(bytes([flag]) + struct.pack('>I', len(sealed)) + sealed)
        self.index += 1

    def close(self):
        if not self.closed:
            self._chunk(1, bytes(self.buffer))
            self.buffer.clear()
        super().close()


class Opener(io.RawIOBase):
    """Decrypts a sealed blob, failing on any tampering or truncation."""

    def __init__(self, source, key):
        self.source, self.aead = source, _aead(key)
        head = source.read(len(MAGIC) + 8)
        if len(head) != len(MAGIC) + 8 or head[:len(MAGIC)] != MAGIC:
            raise ValueError('Not a cache blob')
        self.prefix = head[len(MAGIC):]
        self.index, self.plain, self.done = 0, b'', False

    def readable(self):
        return True

    def _exact(self, size):
        data = self.source.read(size)
        if len(data) != size:
            raise ValueError('Truncated cache blob')
        return data

    def readinto(self, target):
        while not self.plain and not self.done:
            flag, length = struct.unpack('>BI', self._exact(5))
            if flag not in (0, 1) or length > CHUNK + 16:
                raise ValueError('Corrupt cache blob')
            nonce = self.prefix + struct.pack('>I', self.index)
            self.plain = self.aead.decrypt(nonce, self._exact(length), _aad(flag, self.index))
            self.index += 1
            if flag == 1:
                self.done = True
                if self.source.read(1):
                    raise ValueError('Data after the last chunk')
        size = min(len(target), len(self.plain))
        target[:size] = self.plain[:size]
        self.plain = self.plain[size:]
        return size


def third_party(metadata):
    """Package and crate names of registry and Git dependencies.

    Path packages, the private crates among them, are left out.
    """
    names = set()
    for package in metadata['packages']:
        if package.get('source') is None:
            continue
        names.add(package['name'])
        names.add(package['name'].replace('-', '_'))
        for target in package.get('targets', []):
            names.add(target['name'].replace('-', '_'))
    return names


def profile_dirs(target):
    """Directories with a `.fingerprint`: `<profile>` and `<triple>/<profile>`."""
    found = []
    for first in target.iterdir() if target.is_dir() else ():
        if not first.is_dir():
            continue
        if (first / '.fingerprint').is_dir():
            found.append(first)
            continue
        found.extend(second for second in first.iterdir()
                     if second.is_dir() and (second / '.fingerprint').is_dir())
    return found


def _remove(path):
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path, ignore_errors=True)
    else:
        path.unlink(missing_ok=True)


def third_party_artifact(name, keep):
    match = ARTIFACT.match(name)
    if not match:
        return False
    crate = match.group('name')
    return crate in keep or (crate.startswith('lib') and crate[3:] in keep)


def prune(target, keep):
    """Removes everything in `target` but third-party output named in `keep`."""
    profiles = profile_dirs(target)
    for profile in profiles:
        for entry in profile.iterdir():
            if entry.name not in PACKAGE_DIRS:
                _remove(entry)
                continue
            for item in entry.iterdir():
                if not third_party_artifact(item.name, keep):
                    _remove(item)
    # Anything else is private output: binaries, docs, benchmarks, tmp.
    kept = set(profiles) | {profile.parent for profile in profiles}
    for entry in list(target.iterdir()) if target.is_dir() else ():
        if entry not in kept:
            _remove(entry)
        elif entry not in profiles:
            for inner in entry.iterdir():
                if inner not in kept:
                    _remove(inner)


def cargo_parts(cargo_home):
    return [cargo_home / 'registry', cargo_home / 'git' / 'db']


def pack(blob, key, cargo_home, target):
    """Seals the Cargo download cache and `target` (already pruned) into `blob`."""
    blob.parent.mkdir(parents=True, exist_ok=True)
    with open(blob, 'wb') as out:
        sealer = Sealer(out, key)
        with tarfile.open(fileobj=sealer, mode='w|zst') as tar:
            for part in cargo_parts(cargo_home):
                if part.is_dir():
                    tar.add(part, arcname='cargo/' + part.relative_to(cargo_home).as_posix())
            if target.is_dir():
                tar.add(target, arcname='target')
        sealer.close()


def unpack(blob, key, cargo_home, target):
    """Restores a sealed cache. Returns `None`, or on failure the error's type
    name after removing what it restored."""
    try:
        with open(blob, 'rb') as source, io.BufferedReader(Opener(source, key), CHUNK) as plain:
            with tarfile.open(fileobj=plain, mode='r|zst') as tar:
                for member in tar:
                    head, _, rest = member.name.partition('/')
                    if head == 'cargo' and rest:
                        dest = cargo_home
                    elif head == 'target':
                        dest = target
                        if not rest:
                            target.mkdir(parents=True, exist_ok=True)
                            continue
                    else:
                        raise ValueError('Unexpected cache member')
                    member.name = rest
                    tar.extract(member, dest, filter='data')
        return None
    except Exception as error:
        for part in cargo_parts(cargo_home) + [target]:
            _remove(part)
        return type(error).__name__


def key_from_env():
    raw = os.environ.get('CACHE_KEY', '')
    return base64.b64decode(raw) if raw else None


def lock_digest(token, sha, kind):
    """Digest of the revision's lockfile, fetched without fetching the source."""
    path = 'fuzz/Cargo.lock' if kind == 'fuzz' else 'Cargo.lock'
    request = urllib.request.Request(
        f'https://api.github.com/repos/fireunix-nextfly/agent/contents/{path}?ref={sha}',
        headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github.raw+json',
                 'User-Agent': 'nextfly-ci-cache'})
    with urllib.request.urlopen(request, timeout=30) as response:
        return hashlib.sha256(response.read()).hexdigest()[:16]


def toolchain_digest(kind):
    args = ['rustc', '+nightly', '-Vv'] if kind == 'fuzz' else ['rustc', '-Vv']
    output = subprocess.run(args, capture_output=True, check=True).stdout
    return hashlib.sha256(output).hexdigest()[:12]


def main():
    """Prints the cache key for this job to the step outputs."""
    kind = os.environ['CACHE_KIND']
    if kind not in ('check', 'fuzz') or not re.fullmatch(r'[0-9a-f]{40}', os.environ['SOURCE_SHA']):
        raise ValueError('Invalid request')
    # Output from another compiler is useless, so only its own toolchain's
    # caches are candidates; a different lockfile still restores most crates.
    prefix = f"v1-{os.environ['RUNNER_OS']}-{kind}-{toolchain_digest(kind)}-"
    key = prefix + lock_digest(os.environ.pop('SOURCE_TOKEN'), os.environ['SOURCE_SHA'], kind)
    with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as output:
        output.write(f'key={key}\nprefix={prefix}\n')
    print('Cache key: ' + key, flush=True)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('Cache key unavailable (' + type(error).__name__ + ')', flush=True)
        sys.exit(1)
