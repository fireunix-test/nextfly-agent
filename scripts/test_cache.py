"""Verify sealed caches: confidentiality, integrity and pruning of private output."""
import io
import os
from pathlib import Path
import tempfile
import unittest

import cache

KEY = bytes(range(32))


def seal(data, key=KEY):
    out = io.BytesIO()
    sealer = cache.Sealer(out, key)
    sealer.write(data)
    sealer.close()
    return out.getvalue()


def open_sealed(blob, key=KEY):
    with io.BufferedReader(cache.Opener(io.BytesIO(blob), key)) as plain:
        return plain.read()


class SealTests(unittest.TestCase):
    def test_roundtrip_across_chunks(self):
        data = os.urandom(cache.CHUNK * 2 + 123)
        blob = seal(data)
        self.assertNotIn(data[:64], blob)
        self.assertEqual(open_sealed(blob), data)
        self.assertEqual(open_sealed(seal(b'')), b'')

    def test_tampering_truncation_and_wrong_key_fail(self):
        data = os.urandom(cache.CHUNK + 10)
        blob = seal(data)
        flipped = bytearray(blob)
        flipped[100] ^= 1
        for bad in (bytes(flipped), blob[:-1], blob[:len(blob) // 2], blob + b'x'):
            with self.assertRaises(Exception):
                open_sealed(bad)
        with self.assertRaises(Exception):
            open_sealed(blob, bytes(32))
        # Dropping the last chunk must not look like a shorter, valid blob.
        first = 12 + 5 + cache.CHUNK + 16
        with self.assertRaises(Exception):
            open_sealed(blob[:first])


class PruneTests(unittest.TestCase):
    def tree(self, root, files):
        for name in files:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'x')

    def test_only_third_party_output_survives(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            h = '0123456789abcdef'
            self.tree(target, [
                f'debug/.fingerprint/boring-sys-{h}/lib', f'debug/build/boring-sys-{h}/out/libcrypto.a',
                f'debug/deps/libboring_sys-{h}.rlib', f'debug/deps/libc-{h}.d', f'debug/deps/liblibc-{h}.rlib',
                f'debug/deps/serde_derive-{h}.so',
                f'debug/.fingerprint/na-bt-{h}/lib', f'debug/deps/libna_bt-{h}.rlib', f'debug/deps/thunder-{h}',
                f'debug/build/na-tls-{h}/out/x', 'debug/nextagent', 'debug/examples/fetch', 'debug/incremental/a',
                f'x86_64-unknown-linux-gnu/release/deps/libboring_sys-{h}.rlib',
                f'x86_64-unknown-linux-gnu/release/deps/bencode_decode-{h}',
                f'x86_64-unknown-linux-gnu/release/.fingerprint/na-bencode-{h}/lib',
                'x86_64-unknown-linux-gnu/release/bencode_decode', 'doc/index.html', 'iai/x', 'tmp/y'])
            cache.prune(target, cache.third_party({'packages': [
                {'name': 'boring-sys', 'source': 'registry+x', 'targets': [{'name': 'boring-sys'}]},
                {'name': 'libc', 'source': 'registry+x', 'targets': [{'name': 'libc'}]},
                {'name': 'serde_derive', 'source': 'registry+x', 'targets': [{'name': 'serde_derive'}]},
                {'name': 'na-bt', 'source': None, 'targets': [{'name': 'na_bt'}, {'name': 'thunder'}]},
                {'name': 'na-bencode', 'source': None, 'targets': [{'name': 'na_bencode'}]}]}))
            left = sorted(p.relative_to(target).as_posix() for p in target.rglob('*') if p.is_file())
            self.assertEqual(left, sorted([
                f'debug/.fingerprint/boring-sys-{h}/lib', f'debug/build/boring-sys-{h}/out/libcrypto.a',
                f'debug/deps/libboring_sys-{h}.rlib', f'debug/deps/libc-{h}.d', f'debug/deps/liblibc-{h}.rlib',
                f'debug/deps/serde_derive-{h}.so',
                f'x86_64-unknown-linux-gnu/release/deps/libboring_sys-{h}.rlib']))


class PackTests(unittest.TestCase):
    def test_pack_and_unpack_restore_both_roots(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home, target, blob = root / 'home', root / 'target', root / 'c' / 'blob.bin'
            (home / 'registry' / 'cache').mkdir(parents=True)
            (home / 'registry' / 'cache' / 'a.crate').write_bytes(b'crate')
            (home / 'bin').mkdir()
            (home / 'bin' / 'tool').write_bytes(b'not cached')
            (target / 'debug' / 'deps').mkdir(parents=True)
            (target / 'debug' / 'deps' / 'x.rlib').write_bytes(b'rlib' * 1000)
            cache.pack(blob, KEY, home, target)
            self.assertNotIn(b'rlibrlib', blob.read_bytes())
            new_home, new_target = root / 'h2', root / 't2'
            self.assertIsNone(cache.unpack(blob, KEY, new_home, new_target))
            self.assertEqual((new_home / 'registry' / 'cache' / 'a.crate').read_bytes(), b'crate')
            self.assertEqual((new_target / 'debug' / 'deps' / 'x.rlib').read_bytes(), b'rlib' * 1000)
            self.assertFalse((new_home / 'bin').exists())
            # A wrong key restores nothing and leaves no partial state.
            other_home, other_target = root / 'h3', root / 't3'
            self.assertEqual(cache.unpack(blob, bytes(32), other_home, other_target), 'InvalidTag')
            self.assertFalse((other_home / 'registry').exists() or other_target.exists())


if __name__ == '__main__':
    unittest.main()
