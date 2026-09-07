#!/usr/bin/env python3
"""Mock regressions for HTML acceptance inventory and execution checks."""
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

spec = importlib.util.spec_from_file_location(
    'html_runner', Path(__file__).with_name('html-relay-test-local.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def success(name):
    return (f'\nrunning 1 test\ntest {name} ... ok\n\n'
            'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; '
            '22 filtered out; finished in 0.03s\n\n')


class AcceptanceTests(unittest.TestCase):
    def run_fixture(self, inventory, execution=None, inventory_exit=0):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tools = root / 'tools'
            (tools / 'usr/bin').mkdir(parents=True)
            for name in ('relay', 'test', 'minio', 'mc', 'usr/bin/valkey-server',
                         'initdb', 'pg_ctl', 'createdb', 'psql'):
                (tools / name).touch()
            argv = ['runner', '--task-root', str(root), '--tools-dir', str(tools),
                    '--pg-bin-dir', str(tools), '--relay-binary', str(tools / 'relay'),
                    '--test-binary', str(tools / 'test'), '--host-netns', 'original']

            def command(argv, **kwargs):
                output, code = '', 0
                if Path(argv[0]).name == 'test':
                    if '--list' in argv:
                        self.assertIn('--ignored', argv)
                        output, code = inventory, inventory_exit
                    else:
                        self.assertIn('--ignored', argv)
                        name = argv[argv.index('--exact') + 1]
                        output = (execution or {}).get(name, success(name))
                elif Path(argv[0]).name == 'initdb':
                    Path(argv[argv.index('-D') + 1]).mkdir()
                return subprocess.CompletedProcess(argv, code, stdout=output)

            process = MagicMock()
            process.poll.return_value = None
            response = MagicMock()
            response.__enter__.return_value.status = 200
            previous_umask = os.umask(0o077)
            try:
                with patch.object(sys, 'argv', argv), \
                     patch.object(runner.os, 'geteuid', return_value=1000), \
                     patch.object(runner.os, 'readlink', return_value='private'), \
                     patch.object(runner.signal, 'signal'), \
                     patch.object(runner.subprocess, 'check_output', return_value=b'[{"ifname":"lo"}]'), \
                     patch.object(runner.subprocess, 'run', side_effect=command) as run, \
                     patch.object(runner.subprocess, 'Popen', return_value=process) as start, \
                     patch.object(runner, 'urlopen', return_value=response), \
                     patch('builtins.print'):
                    failure = None
                    try:
                        runner.main()
                    except (RuntimeError, subprocess.CalledProcessError) as error:
                        failure = error
                logs, = root.glob('html-acceptance-evidence-*')
                result = (logs / 'result.txt').exists()
                self.assertFalse(list(root.glob('html-live-*')))
                self.assertTrue((logs / 'cleanup.txt').exists())
                return failure, result, run.call_args_list, start.call_count
            finally:
                os.umask(previous_umask)

    def test_missing_either_or_both_tests_never_starts_services(self):
        first, second = runner.REQUIRED_TESTS
        for names in ((), (first,), (second,), (first + '_suffix', second),
                      ('module::' + first, second)):
            with self.subTest(names=names):
                inventory = ''.join(f'{name}: test\n' for name in names)
                error, passed, calls, starts = self.run_fixture(inventory)
                self.assertIsInstance(error, RuntimeError)
                self.assertIn('missing required ignored tests', str(error))
                self.assertFalse(passed)
                self.assertEqual(starts, 0)
                self.assertEqual(len(calls), 1)
                self.assertIn('--list', calls[0].args[0])

    def test_inventory_failure_never_starts_services(self):
        error, passed, calls, starts = self.run_fixture(self.inventory(), inventory_exit=1)
        self.assertIsInstance(error, subprocess.CalledProcessError)
        self.assertFalse(passed)
        self.assertEqual((len(calls), starts), (1, 0))

    @staticmethod
    def inventory():
        return ''.join(f'{name}: test\n' for name in runner.REQUIRED_TESTS) + '2 tests, 0 benchmarks\n'

    def test_valid_inventory_runs_both_exact_tests_before_pass(self):
        error, passed, calls, starts = self.run_fixture(self.inventory())
        self.assertIsNone(error)
        self.assertTrue(passed)
        self.assertEqual(starts, 4)
        self.assertIn('--list', calls[0].args[0])
        commands = [call.args[0] for call in calls if '--exact' in call.args[0]]
        self.assertEqual([cmd[cmd.index('--exact') + 1] for cmd in commands],
                         list(runner.REQUIRED_TESTS))

    def test_zero_tests_after_valid_inventory_cannot_write_pass(self):
        output = ('running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored; '
                  '0 measured; 23 filtered out; finished in 0.00s\n')
        for name in runner.REQUIRED_TESTS:
            with self.subTest(name=name):
                error, passed, _, _ = self.run_fixture(self.inventory(), execution={name: output})
                self.assertIsInstance(error, RuntimeError)
                self.assertFalse(passed)

    def test_execution_requires_one_success_and_preserves_output(self):
        name = runner.REQUIRED_TESTS[0]
        valid = success(name)
        cases = [(valid, 0, None), (valid, 1, subprocess.CalledProcessError),
                 (valid.replace('1 passed', '0 passed'), 0, RuntimeError),
                 (valid.replace('0 ignored', '1 ignored'), 0, RuntimeError),
                 (valid.replace('running 1 test', 'running 2 tests'), 0, RuntimeError),
                 (valid + valid, 0, RuntimeError), ('', 0, RuntimeError)]
        for output, code, expected in cases:
            with self.subTest(output=output, code=code):
                transcript = io.StringIO()
                result = subprocess.CompletedProcess([], code, stdout=output)
                with patch.object(runner.subprocess, 'run', return_value=result):
                    if expected:
                        with self.assertRaises(expected):
                            runner.run_test('/test', name, {}, Path('/fixture'), transcript)
                    else:
                        runner.run_test('/test', name, {}, Path('/fixture'), transcript)
                self.assertEqual(transcript.getvalue(), output)


if __name__ == '__main__':
    unittest.main()
