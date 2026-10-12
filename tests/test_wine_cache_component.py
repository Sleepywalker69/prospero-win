# SPDX-License-Identifier: LGPL-2.1-or-later
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
import yaml
from unittest.mock import Mock, patch
sys.path.insert(0, str(Path(__file__).parents[1] / 'tools'))
import benchmark_wine_cache_component as m

class ComponentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def tree(self):
        work = self.root / 'work'
        source = work / 'source/server/process.c'
        source.parent.mkdir(parents=True)
        source.write_bytes(b'int original;\n')
        build = work / 'build'; build.mkdir()
        (build / 'server').mkdir()
        (build / 'Makefile').write_text('server/process.o: ' + str(source) + '\n')
        state = self.root / 'state'; state.mkdir()
        (state / 'state.json').write_text(json.dumps({'launchers': {
            'cc': 'bound-cc', 'cxx': 'bound-cxx', 'i386': 'bound-32', 'x86_64': 'bound-64'},
            'compilers': {'cc': ['bound-real', 'clang']}}))
        out = self.root / 'out'; out.mkdir()
        return work, source, build, state, out

    def test_generated_target_exact_and_preexisting_rejected(self):
        work, source, build, state, out = self.tree()
        m.generated_target(build, source)
        (build / m.TARGET).write_bytes(b'prior')
        with self.assertRaises(ValueError): m.generated_target(build, source)
        (build / m.TARGET).unlink()
        (build / 'Makefile').write_text('server/other.o: ' + str(source) + '\n')
        with self.assertRaises(ValueError): m.generated_target(build, source)

    def measure(self, bad_control=False, no_hit=False, noop_work=False):
        work, source, build, state, out = self.tree()
        original = source.read_bytes()
        calls = []
        def stage(budget, repo, state_dir, build_dir, label, output):
            if label == 'component-donor-hit':
                data, hits, misses = b'baseline', (0 if no_hit else 1), (1 if no_hit else 0)
            elif label == 'component-noop':
                data, hits, misses = b'baseline', 0, 0
            else:
                self.assertIn(m.MARKER, source.read_bytes())
                data, hits, misses = b'changed', 0, 1
            target = build_dir / m.TARGET
            if label != 'component-noop':
                target.write_bytes(data)
                os.utime(target, ns=(1, 1))
            counters = {'preprocessed_cache_hit': hits, 'cache_miss': misses,
                        'unsupported_compiler_option': int(noop_work and label == 'component-noop')}
            return {'hits': hits, 'misses': misses, 'object_sha256': m.cache.sha(target),
                    'counters': counters, 'seconds': 0.01,
                    'invocations': [{'command': 'ccache bound-real -c -o server/process.o ' + str(source)}]}
        budget = Mock()
        def command(argv, log, env=None):
            calls.append((argv, env))
            if '-q' not in argv:
                self.assertEqual(env['CCACHE_DISABLE'], '1')
                self.assertEqual(env['CC'], 'bound-cc')
                (build / m.TARGET).write_bytes(b'bad' if bad_control else b'changed')
                Path(env['CCACHE_LOGFILE']).write_text(
                    '[2026-10-12T13:00:00.000000 123  ] Command line: ccache bound-real -c -o server/process.o ' +
                    str(source) + '\n[2026-10-12T13:00:00.000001 123  ] Working directory: ' +
                    str(build) + '\n[2026-10-12T13:00:00.000002 123  ] Compiler: bound-real\n[2026-10-12T13:00:00.000003 123  ] Result: disabled\n')
            return 0.02
        budget.run.side_effect = command
        try:
            with patch.object(m, 'stage', side_effect=stage), \
                 patch.object(m.cache, 'checked_identity'), \
                 patch.object(m.cache, 'cache_env', return_value={}):
                result = m.measure(budget, self.root, state, work, out)
            self.assertEqual(result['changed_c']['object_sha256'],
                             result['uncached_same_path_control']['object_sha256'])
            self.assertTrue(result['unchanged_make_noop']['make_query_up_to_date'])
            self.assertFalse(result['target_code_executed'])
            self.assertFalse(result['full_runtime_built'])
            self.assertEqual(calls[0][0][-2:], ['-q', m.TARGET])
            return result
        finally:
            self.assertEqual(source.read_bytes(), original)

    def test_hit_noop_edit_and_same_path_uncached_control(self):
        self.measure()

    def test_no_hit_noop_work_and_byte_mismatch_fail(self):
        for kwargs in ({'no_hit': True}, {'noop_work': True}, {'bad_control': True}):
            with self.subTest(kwargs=kwargs):
                # Each case needs independent staged source/build paths.
                with tempfile.TemporaryDirectory() as directory:
                    old, self.root = self.root, Path(directory)
                    try:
                        with self.assertRaises(ValueError): self.measure(**kwargs)
                    finally:
                        self.root = old

    def test_budget_timeout_terminates_kills_and_reaps(self):
        child = Mock(pid=1234)
        child.wait.side_effect = [subprocess.TimeoutExpired('owned', 1), 0, 0]
        with patch.object(m.subprocess, 'Popen', return_value=child) as create, \
             patch.object(m.os, 'killpg') as kill, self.assertRaises(subprocess.TimeoutExpired):
            m.Budget(1).run(['owned-fixture'], self.root / 'timeout.log')
        self.assertTrue(create.call_args.kwargs['start_new_session'])
        self.assertEqual([call.args for call in kill.call_args_list],
                         [(1234, signal.SIGTERM), (1234, signal.SIGKILL)])
        self.assertEqual(child.wait.call_count, 3)
        self.assertTrue(all(call.kwargs.get('timeout', 0) > 0 for call in child.wait.call_args_list))

    def test_budget_failure_and_cancellation_drain(self):
        for outcome in (1, m.Cancelled('cancel')):
            child = Mock(pid=1234)
            child.wait.side_effect = [outcome, 0, 0]
            with patch.object(m.subprocess, 'Popen', return_value=child), \
                 patch.object(m.os, 'killpg') as kill, \
                 self.assertRaises((ValueError, m.Cancelled)):
                m.Budget(1).run(['owned-fixture'], self.root / str(type(outcome).__name__))
            self.assertEqual(kill.call_count, 2)

    def test_exhausted_budget_does_not_start_process(self):
        budget = m.Budget(1)
        budget.deadline = 0
        with patch.object(m.subprocess, 'Popen') as create, self.assertRaises(ValueError):
            budget.run(['not-started'], self.root / 'absent.log')
        create.assert_not_called()

    def test_workflow_is_opt_in_and_bounded(self):
        path = Path(__file__).parents[1] / '.github/workflows/wine-cache-component.yml'
        workflow = yaml.safe_load(path.read_text())
        job = workflow['jobs']['component']
        self.assertEqual(job['needs'], 'contracts')
        self.assertEqual(job['timeout-minutes'], 20)
        self.assertIn("'measure-wine-cache-component'", job['if'])
        self.assertIn("!contains(github.event.pull_request.labels.*.name, 'build-windows-child-fixture')", job['if'])
        runs = [s.get('run', '') for s in job['steps']]
        self.assertIn('python3 tools/benchmark_wine_cache_component.py --seconds 900', runs)
        self.assertFalse(any('make all' in value or 'make install' in value for value in runs))
        self.assertNotIn('GH_TOKEN', workflow['jobs']['contracts'].get('env', {}))

    def test_pid_bound_target_results_reject_dependency_only_hit(self):
        work, source, build, state_dir, out = self.tree()
        state = json.loads((state_dir / 'state.json').read_text())
        record = {'command': 'ccache bound-real -c -o server/process.o ' + str(source),
                  'source': str(source), 'object': 'server/process.o', 'cwd': str(build), 'compiler': 'bound-real',
                  'results': ['local_storage_read_hit', 'preprocessed_cache_hit']}
        self.assertEqual(m.target_result([record], state, build, 'hit'), record)
        unrelated = record | {'source': str(work / 'source/server/thread.c'),
                              'object': 'server/thread.o'}
        uncacheable = record | {'results': ['unsupported_compiler_option']}
        for records in ([unrelated, uncacheable], [uncacheable], [unrelated],
                        [record, record], [record | {'results': ['cache_miss']}],
                        [record | {'compiler': 'wrong-compiler',
                                   'command': 'ccache wrong-compiler bound-real -c -o server/process.o ' + str(source)}],
                        [record | {'compiler': ''}]):
            with self.subTest(records=records), self.assertRaises(ValueError):
                m.target_result(records, state, build, 'hit')
        self.assertEqual(m.target_result([record | {'results': ['cache_miss', 'local_storage_write']}],
                                        state, build, 'miss')['results'][0], 'cache_miss')

    def test_bounded_log_parser_and_duplicate_pid_metadata(self):
        path = self.root / 'cache.log'
        prefix = '[2026-10-12T13:00:00.000000 42   ] '
        path.write_text(prefix + 'Command line: ccache cc -c source.c\n' +
                        prefix + 'Source file: source.c\n' +
                        prefix + 'Object file: source.o\n' +
                        prefix + 'Result: preprocessed_cache_hit\n')
        records = m.invocation_records(path)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]['results'], ['preprocessed_cache_hit'])
        path.write_text(path.read_text() + prefix + 'Command line: another\n')
        with self.assertRaises(ValueError): m.invocation_records(path)
        path.write_text('unframed input')
        with self.assertRaises(ValueError): m.invocation_records(path)

    @unittest.skipUnless(os.name == 'posix', 'owned process-group cleanup requires POSIX')
    def test_real_owned_subprocess_timeout_is_reaped(self):
        real = subprocess.Popen
        captured = []
        def launch(*args, **kwargs):
            process = real(*args, **kwargs)
            captured.append(process)
            return process
        with patch.object(m.subprocess, 'Popen', side_effect=launch), self.assertRaises(subprocess.TimeoutExpired):
            m.Budget(0.05).run([sys.executable, '-c', 'import time; time.sleep(30)'], self.root / 'real-timeout.log')
        self.assertEqual(len(captured), 1)
        self.assertIsNotNone(captured[0].poll())
        with self.assertRaises(ProcessLookupError): os.kill(captured[0].pid, 0)

    @unittest.skipUnless(os.name == 'posix', 'owned process-group cleanup requires POSIX')
    def test_real_owned_subprocess_cancel_is_reaped(self):
        real = subprocess.Popen
        captured = []
        def launch(*args, **kwargs):
            process = real(*args, **kwargs)
            captured.append(process)
            original_wait = process.wait
            first = [True]
            def wait(*args, **kwargs):
                if first[0]:
                    first[0] = False
                    raise m.Cancelled('owned cancellation test')
                return original_wait(*args, **kwargs)
            process.wait = wait
            return process
        with patch.object(m.subprocess, 'Popen', side_effect=launch), self.assertRaises(m.Cancelled):
            m.Budget(1).run([sys.executable, '-c', 'import time; time.sleep(30)'], self.root / 'real-cancel.log')
        self.assertIsNotNone(captured[0].poll())
        with self.assertRaises(ProcessLookupError): os.kill(captured[0].pid, 0)

    def test_ccache_argument_formatter_is_not_shell_syntax(self):
        argv = ['ccache', "literal'quote", 'two words', 'slash\\path', 'double"quote', '']
        self.assertEqual(m.logged_argv(m.format_logged_argv(argv)), argv)
        for text in ('unclosed "value', 'two  spaces', 'bad\\escape'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                m.logged_argv(text)

if __name__ == '__main__':
    unittest.main()
