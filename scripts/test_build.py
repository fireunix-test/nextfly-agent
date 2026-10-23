"""Exercise confidential output handling without loading private source."""
import contextlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import build


class ConfidentialOutputTests(unittest.TestCase):
    def test_failed_process_does_not_publish_output(self):
        with tempfile.TemporaryDirectory() as cwd, io.StringIO() as capture:
            with contextlib.redirect_stdout(capture), contextlib.redirect_stderr(capture):
                with self.assertRaisesRegex(RuntimeError, "^Command failed$"):
                    build.run([sys.executable, "-c", "import sys; print('PRIVATE_SENTINEL'); print('::error::PRIVATE_SENTINEL', file=sys.stderr); sys.exit(1)"], cwd)
            self.assertNotIn("PRIVATE_SENTINEL", capture.getvalue())

    def test_credentials_and_file_commands_are_removed(self):
        with patch.dict(os.environ, {"SOURCE_TOKEN": "secret", "GITHUB_STEP_SUMMARY": "private",
                                   "GITHUB_OUTPUT": "private", "GITHUB_ENV": "private",
                                   "ACTIONS_RUNTIME_TOKEN": "secret", "GH_TOKEN": "secret"}):
            env = build.child_env()
            self.assertNotIn("SOURCE_TOKEN", env)
            self.assertNotIn("GITHUB_STEP_SUMMARY", env)
            self.assertNotIn("GITHUB_OUTPUT", env)
            self.assertNotIn("GITHUB_ENV", env)
            self.assertNotIn("ACTIONS_RUNTIME_TOKEN", env)
            self.assertNotIn("GH_TOKEN", env)

    def test_top_level_failure_is_generic(self):
        env = build.child_env()
        env["SOURCE_TOKEN"] = "PRIVATE_SENTINEL"
        env["SOURCE_SHA"] = "PRIVATE_SENTINEL"
        result = subprocess.run([sys.executable, str(Path(build.__file__).resolve()), "check"],
                                env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("PRIVATE_SENTINEL", result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stdout + result.stderr)

    def test_untrusted_and_stale_pr_are_rejected(self):
        head, merge = "a" * 40, "b" * 40
        pull = {"state": "open", "head": {"repo": {"full_name": "outside/fork"}, "sha": head},
                "base": {"repo": {"full_name": build.SOURCE}}, "merge_commit_sha": merge}
        with patch.dict(os.environ, SOURCE_SHA=merge, HEAD_SHA=head, PR_NUMBER="1"):
            with patch.object(build, "api", return_value=pull):
                with self.assertRaises(ValueError):
                    build.validate("unused")
                pull["head"]["repo"]["full_name"] = build.SOURCE
                self.assertEqual(build.validate("unused"), merge)
                pull["head"]["sha"] = "c" * 40
                with self.assertRaises(ValueError):
                    build.validate("unused")


if __name__ == "__main__":
    unittest.main()

class DiagnosticTests(unittest.TestCase):
    def test_tests_include_all_binaries_and_bounded_panics(self):
        from diagnostics import extract
        output = '\n'.join(['Running unittests src/lib.rs (target/debug/deps/alpha)', 'test a::broken ... FAILED',
            '---- a::broken stdout ----', "thread 'a::broken' panicked at crates/a.rs:10:2:", *['panic detail']*80,
            'failures:', 'test result: FAILED', 'Running tests/integration.rs (target/debug/deps/beta)',
            'test b::broken ... FAILED', '---- b::broken stdout ----', "thread 'b::broken' panicked at tests/b.rs:4:1:", 'assertion failed', 'failures:'])
        summary = extract('Tests', output, 101)
        for text in ['alpha', 'beta', 'a::broken', 'b::broken', 'crates/a.rs:10:2', 'tests/b.rs:4:1', 'exit code 101', '已截断']:
            self.assertIn(text, summary)
        self.assertEqual(summary.count('panic detail'),59)

    def test_error_locations_and_line_cap(self):
        from diagnostics import extract
        summary = extract('Clippy', '\n\n'.join('error[E0308]: mismatched types\n --> crates/a.rs:3:2\n | context' for _ in range(100)), 101)
        self.assertIn('--> crates/a.rs:3:2', summary)
        self.assertLessEqual(len(summary.splitlines()),203)
        self.assertIn('已截断', summary)

    def test_fuzz_does_not_include_crash_input(self):
        from diagnostics import extract
        with tempfile.TemporaryDirectory() as directory:
            Path(directory,'crash-deadbeef').write_text('PRIVATE_INPUT')
            summary = extract('Fuzz', "thread 'main' panicked at fuzz.rs:1\nPRIVATE_INPUT\nBase64: UFJJVkFURV9JTlBVVA==\nTest unit written to crash-deadbeef", 77, target='tracker_http', root=directory)
            self.assertIn('tracker_http',summary)
            self.assertIn('crash-deadbeef (13 bytes)',summary)
            self.assertNotIn('PRIVATE_INPUT',summary)
            self.assertNotIn('Base64',summary)

    def test_utf8_bound_and_secret_filter(self):
        import base64
        from diagnostics import bounded, redact
        self.assertLessEqual(len(bounded('中'*30000).encode()),60000)
        env = {'SOURCE_TOKEN':'secret123','GITHUB_SHA':'ab'*20,'RUNNER_NAME':'host-123','REPORT_TOKEN':'report-secret'}
        text = ' '.join(env.values())+' '+base64.b64encode(b'x-access-token:secret123').decode()+' /home/runner/work/private/crates/a.rs:1:2 github_pat_unknown_secret Authorization: Bearer abc'
        result = redact(text,env)
        for value in env.values(): self.assertNotIn(value,result)
        self.assertNotIn('/home/runner',result)
        self.assertNotIn('github_pat_',result)
        self.assertNotIn('Bearer abc',result)
        self.assertIn('crates/a.rs:1:2',result)

    def test_timeout_and_signal(self):
        from diagnostics import extract
        self.assertIn('signal 11',extract('Tests','',-11))
        self.assertIn('timeout',extract('Tests','',None,True))
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(build.CommandFailure) as failure:
                build.run([sys.executable,'-c','import time; time.sleep(10)'],directory,timeout=0.05)
            self.assertTrue(failure.exception.timeout)

    def test_instruction_count_regressions_are_summarized(self):
        from diagnostics import extract
        output = '\n'.join(['Compiling na-bt', 'iai::picker::pick_blocks half', '  Instructions: 120|100 (+20.0%)',
                             'Performance has regressed: Instructions (100 -> 120) regressed by +20.0% (>+5.00)',
                             'iai::picker::received busy', '  Instructions: 50|50 (No change)',
                             'Iai-Callgrind result: Regressed. 1 without regressions; 1 regressed'])
        summary = extract('Instruction counts', output, 3)
        self.assertIn('iai::picker::pick_blocks', summary)
        self.assertIn('regressed by +20.0%', summary)
        self.assertNotIn('Compiling', summary)

    def test_iai_crates_and_locked_version(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'crates/na-bt/benches').mkdir(parents=True)
            (root / 'crates/na-bt/benches/iai.rs').write_text('')
            (root / 'crates/na-net/benches').mkdir(parents=True)
            (root / 'Cargo.lock').write_text('[[package]]\nname = "iai-callgrind"\nversion = "0.16.1"\n')
            self.assertEqual(build.iai_crates(root), ['na-bt'])
            self.assertEqual(build.locked_version(root, 'iai-callgrind'), '0.16.1')
            self.assertIsNone(build.locked_version(root, 'criterion'))
            (root / 'Cargo.lock').write_text('[[package]]\nname = "iai-callgrind"\nversion = "1.0; rm -rf /"\n')
            self.assertIsNone(build.locked_version(root, 'iai-callgrind'))

    def test_throughput_keeps_last_40_lines(self):
        from diagnostics import extract
        result=extract('Throughput na-net/udp','\n'.join(f'line {i}' for i in range(100)),1)
        self.assertNotIn('line 59',result)
        self.assertIn('line 60',result)
        self.assertIn('line 99',result)
