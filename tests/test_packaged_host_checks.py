#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Result collection uses owned Python fixtures; no Wine, sockets or fixed maps."""
import importlib.util
import os
import signal
import time
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import types

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('host_checks', ROOT / 'tools/check_packaged_host_wine.py')
checks = importlib.util.module_from_spec(spec); spec.loader.exec_module(checks)


class HostResultTests(unittest.TestCase):
    def test_exact_existing_suite_membership_excludes_deferred_operation(self):
        expected = {'test_wine_protect_writecopy.py', 'test_wine_decommit_zero.py',
                    'test_wine_seh_fp_state.py', 'test_wine_narrow_syscall_args.py',
                    'test_wine_sched_probe.py', 'test_wine_process_counters.py',
                    'test_wine_processor_times.py', 'test_wine_directory_changes.py',
                    'test_wine_dib_section.py', 'test_wowprospero_contract.py',
                    'test_wine_lookup_misses.py'}
        self.assertEqual({name for name,_ in checks.SUITES}, expected)
        self.assertEqual(len(checks.SUITES), 11)

    def test_zero_exit_is_insufficient_without_complete_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for text, code, expected in [('fixture passed', 0, 'passed'),
                                         ('fixture passed; skipped the lookup', 0, 'failed'),
                                         ('SKIP unavailable', 0, 'failed'),
                                         ('partial', 0, 'failed'), ('fixture passed', 7, 'failed')]:
                with self.subTest(text=text, code=code):
                    result = checks.run_one([sys.executable, '-c', f'print({text!r});raise SystemExit({code})'],
                                            root, dict(os.environ), root/'check.log', 'fixture passed')
                    self.assertEqual(result['status'], expected)
                    self.assertEqual(result['exit'], code)

    def test_owned_python_timeout_is_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = checks.run_one([sys.executable, '-c', 'import time;time.sleep(5)'], root,
                                    dict(os.environ), root/'timeout.log', 'fixture passed', timeout=0.05)
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['exit'], 124)
            self.assertTrue(result['timed_out'])


    def test_timeout_records_all_unattempted_suites_and_stop_reason(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root/'logs').mkdir(); (root/'INPUTS-VERIFIED.json').write_text('{}')
            helper = types.ModuleType('export_notepad_seed')
            helper.INPUTS = {'kit': (1, 'digest', 'member', 'scope')}
            helper.require = lambda ok, message: None if ok else self.fail(message)
            helper.verify_tree = lambda *args: None
            timed_out = {'status': 'failed', 'timed_out': True, 'exit': 124,
                         'cleanup': {'owned_group_absent': None, 'escaped_wine_daemons_verified': False}}
            with mock.patch.dict(sys.modules, {'export_notepad_seed': helper}), \
                 mock.patch.dict(os.environ, {'GITHUB_ACTIONS': 'true'}), \
                 mock.patch.object(checks.shutil, 'which', return_value='/fixture/tool'), \
                 mock.patch.object(checks, 'run_one', return_value=timed_out) as call:
                self.assertEqual(checks.run(types.SimpleNamespace(work=root)), 1)
                self.assertEqual(call.call_count, 1)
            result = __import__('json').loads((root/'logs/RESULTS.json').read_text())
            self.assertEqual(len(result['results']), len(checks.SUITES))
            self.assertTrue(all(x['status'] == 'not_run_after_timeout' for x in result['results'][1:]))
            self.assertEqual(result['stop_reason']['suite'], checks.SUITES[0][0])
            self.assertIsNone(result['stop_reason']['cleanup']['owned_group_absent'])
            self.assertFalse(result['wine_daemon_cleanup_verified'])

    def test_exited_leader_does_not_leave_term_ignoring_descendant_running(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code = """import os, signal, sys, time
from pathlib import Path
root=Path(sys.argv[1])
child=os.fork()
if child == 0:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    (root/'child-pid').write_text(str(os.getpid()))
    while True:
        with (root/'heartbeat').open('a') as out: out.write('alive\\n')
        time.sleep(0.01)
signal.signal(signal.SIGTERM, lambda *args: sys.exit(0))
while True: time.sleep(0.01)
"""
            try:
                result = checks.run_one([sys.executable, '-c', code, str(root)], root,
                                        dict(os.environ), root/'descendant.log', 'fixture passed', timeout=0.3)
                pid = int((root/'child-pid').read_text())
                status = Path('/proc') / str(pid) / 'stat'
                if status.exists():
                    state = status.read_text().rsplit(')', 1)[1].split()[0]
                    self.assertIn(state, {'Z', 'X'})
                size = (root/'heartbeat').stat().st_size
                time.sleep(0.05)
                self.assertEqual((root/'heartbeat').stat().st_size, size)
                self.assertTrue(result['timed_out'])
                self.assertTrue(result['cleanup']['leader_reaped'])
                self.assertFalse(result['cleanup']['escaped_wine_daemons_verified'])
            finally:
                # Test-only cleanup if the implementation regresses; this PID is
                # the original owned fixture child, never a Wine/system process.
                if (root/'child-pid').exists():
                    try:
                        os.kill(int((root/'child-pid').read_text()), signal.SIGKILL)
                    except ProcessLookupError:
                        pass


if __name__ == '__main__':
    unittest.main()
