#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Actual workflow/helper controls with inert fixture bytes and mocked tools.

No Wine, PE, SDK payload, or native i386 program is executed by this suite.
An Actions cache restore is not compiler-cache hit evidence.
"""
import ast
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
import unittest

import yaml

sys.dont_write_bytecode = True
ROOT = Path(os.environ.get('PW_PERF_SOURCE', Path(__file__).resolve().parents[1])).resolve()


def workflow():
    path = Path(os.environ.get('PW_PERF_WORKFLOW', ROOT / '.github/workflows/windows-child-fixture.yml'))
    return yaml.load(path.read_text(), Loader=yaml.BaseLoader)


def step_by_id(name):
    matches = [(job, step) for job, value in workflow()['jobs'].items()
               for step in value['steps'] if step.get('id') == name]
    if len(matches) != 1:
        raise AssertionError('expected one actual workflow step: ' + name)
    return matches[0]


def actual_job_gate(expression, context):
    """Evaluate only the gate's bounded boolean grammar over original case data.

    This consumes the actual YAML expression, not a second admission function.
    It does not claim to emulate the complete GitHub expression language.
    """
    if not expression.strip().startswith('${{') or not expression.strip().endswith('}}'):
        raise AssertionError('job gate is not an Actions expression')
    value = expression.strip()[3:-2]
    label_call = "contains(github.event.pull_request.labels.*.name, 'build-windows-child-fixture')"
    value = value.replace(label_call, repr('build-windows-child-fixture' in context['labels']))
    for name in sorted((key for key in context if key != 'labels'), key=len, reverse=True):
        value = value.replace(name, repr(context[name]))
    value = value.replace('&&', ' and ').replace('||', ' or ')
    value = re.sub(r'\bfalse\b', 'False', value)
    value = re.sub(r'\btrue\b', 'True', value)

    def visit(node):
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bool)):
            return node.value
        if isinstance(node, ast.BoolOp) and isinstance(node.op, (ast.And, ast.Or)):
            values = [visit(item) for item in node.values]
            return all(values) if isinstance(node.op, ast.And) else any(values)
        if isinstance(node, ast.Compare) and len(node.ops) == len(node.comparators) == 1:
            left, right = visit(node.left), visit(node.comparators[0])
            if isinstance(node.ops[0], ast.Eq):
                return left == right
            if isinstance(node.ops[0], ast.NotEq):
                return left != right
        raise AssertionError('unsupported job-gate grammar: ' + ast.dump(node))

    return visit(ast.parse('(' + value.strip() + ')', mode='eval').body)


class FixturePreflightControls(unittest.TestCase):
    """Run the actual workflow body against owned inert files, not a validator mock."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='fixture perf preflight ')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.pair = self.base / 'fixture-x64'
        self.pair.mkdir()
        self.project = {name: subprocess.check_output(['git', 'rev-parse', value],
                        cwd=ROOT, text=True).strip()
                        for name, value in [('commit', 'HEAD'), ('tree', 'HEAD^{tree}')]}
        image = bytearray(512)
        image[:2] = b'MZ'
        struct.pack_into('<I', image, 60, 128)
        image[128:132] = b'PE\0\0'
        struct.pack_into('<H', image, 132, 0x8664)
        struct.pack_into('<H', image, 152, 0x20b)
        struct.pack_into('<II', image, 152 + 152, 0x1000, 16)
        for name in ('parent.exe', 'child.exe'):
            (self.pair / name).write_bytes(image)
        sha = lambda content: hashlib.sha256(content).hexdigest()
        self.metadata = {
            'schema': 'pw-original-windows-child-msvc/1', 'project': self.project,
            'architecture': 'x64',
            'compiler': {'name': 'MSVC cl.exe', 'file_version': 'inert-test-only', 'sha256': 'a' * 64},
            'reference': {'exit': 0, 'deadline_seconds': 45},
            'files': {name: {'bytes': len(image), 'sha256': sha(image)}
                      for name in ('parent.exe', 'child.exe')},
            'source_sha256': sha((ROOT / 'tests/fixtures/windows_child_process.c').read_bytes()),
            'recipe_sha256': sha((ROOT / 'tools/build_windows_child_fixture.ps1').read_bytes()),
            'run_id': '123456', 'run_attempt': '2'}

    def run_preflight(self, metadata):
        (self.pair / 'fixture-source.json').write_text(json.dumps(metadata))
        _, step = step_by_id('fixture-preflight')
        result = subprocess.run(['bash', '--noprofile', '--norc', '-e', '-o', 'pipefail',
                                 '-c', step['run']], cwd=ROOT, capture_output=True,
                                text=True, timeout=15,
                                env=dict(os.environ, RUNNER_TEMP=str(self.base),
                                         PYTHONDONTWRITEBYTECODE='1',
                                         GITHUB_RUN_ID='123456', GITHUB_RUN_ATTEMPT='2'))
        return result

    def test_exact_current_fixture_passes(self):
        result = self.run_preflight(self.metadata)
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads((self.base / 'fixture-evidence/fixture-preflight.json').read_text())
        self.assertEqual(evidence, self.metadata)

    def test_stale_run_is_rejected_without_success_receipt(self):
        self.metadata['run_id'] = '123455'
        result = self.run_preflight(self.metadata)
        self.assertNotEqual(result.returncode, 0, 'stale run incorrectly passed preflight')
        self.assertFalse((self.base / 'fixture-evidence/fixture-preflight.json').exists())

    def test_stale_attempt_is_rejected_without_success_receipt(self):
        self.metadata['run_attempt'] = '1'
        result = self.run_preflight(self.metadata)
        self.assertNotEqual(result.returncode, 0, 'stale attempt incorrectly passed preflight')
        self.assertFalse((self.base / 'fixture-evidence/fixture-preflight.json').exists())

    def test_source_recipe_commit_tree_and_reference_fail_closed(self):
        for field in ('source_sha256', 'recipe_sha256', 'commit', 'tree', 'reference'):
            with self.subTest(field=field):
                value = copy.deepcopy(self.metadata)
                if field in ('commit', 'tree'):
                    value['project'][field] = '0' * 40
                elif field == 'reference':
                    value['reference']['exit'] = 77
                else:
                    value[field] = '0' * 64
                result = self.run_preflight(value)
                self.assertNotEqual(result.returncode, 0, field + ' incorrectly passed')
                self.assertFalse((self.base / 'fixture-evidence/fixture-preflight.json').exists())

    def test_changed_image_is_rejected_without_success_receipt(self):
        (self.pair / 'child.exe').write_bytes(b'inert changed bytes')
        result = self.run_preflight(self.metadata)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.base / 'fixture-evidence/fixture-preflight.json').exists())


class WorkflowPerformanceContracts(unittest.TestCase):
    """Static Actions wiring checks; these do not execute hosted jobs."""

    def test_exact_branch_seed_trigger_structure_and_permissions(self):
        actual = workflow()
        self.assertEqual(set(actual['on']), {'workflow_dispatch', 'push', 'pull_request'})
        self.assertEqual(actual['on']['push'], {'branches': ['perf/windows-child-incremental-cache']})
        self.assertEqual(actual['on']['pull_request'], {'types': ['opened', 'synchronize', 'reopened', 'labeled']})
        self.assertEqual(actual['permissions'], {'contents': 'read'})
        self.assertEqual(actual['jobs']['matched-runtime']['permissions'],
                         {'contents': 'read', 'actions': 'read'})
        self.assertNotIn('permissions', actual['jobs']['original-x64-reference'])
        self.assertEqual(actual['concurrency'],
                         {'group': 'windows-child-fixture-${{ github.ref }}', 'cancel-in-progress': 'false'})
        expected = """${{ github.event_name == 'workflow_dispatch' ||
            (github.event_name == 'push' &&
             github.ref == 'refs/heads/perf/windows-child-incremental-cache' &&
             github.event.deleted == false) ||
            (github.event_name == 'pull_request' &&
             github.event.pull_request.head.repo.full_name == github.repository &&
             github.event.pull_request.head.ref != 'perf/windows-child-incremental-cache' &&
             contains(github.event.pull_request.labels.*.name, 'build-windows-child-fixture')) }}"""
        for name in ('original-x64-reference', 'matched-runtime'):
            self.assertEqual(''.join(actual['jobs'][name]['if'].split()), ''.join(expected.split()))

    def test_actual_seed_job_gates_truth_table(self):
        seed = 'perf/windows-child-incremental-cache'
        base = {'github.event_name': 'pull_request', 'github.repository': 'Sleepywalker69/prospero-win',
                'github.ref': 'refs/pull/123/merge', 'github.event.deleted': False,
                'github.event.pull_request.head.repo.full_name': 'Sleepywalker69/prospero-win',
                'github.event.pull_request.head.ref': 'reviewed-change',
                'github.event.pull_request.base.ref': 'main', 'labels': ['build-windows-child-fixture']}
        cases = [
            ('dispatch unchanged', {'github.event_name': 'workflow_dispatch', 'labels': []}, True),
            ('seed push', {'github.event_name': 'push', 'github.ref': 'refs/heads/' + seed, 'labels': []}, True),
            ('seed deletion', {'github.event_name': 'push', 'github.ref': 'refs/heads/' + seed,
                               'github.event.deleted': True}, False),
            ('unrelated push even with PR metadata', {'github.event_name': 'push', 'github.ref': 'refs/heads/other'}, False),
            ('tag with matching name', {'github.event_name': 'push', 'github.ref': 'refs/tags/' + seed}, False),
            ('duplicate seed head PR', {'github.event.pull_request.head.ref': seed}, False),
            ('dependent PR into seed', {'github.event.pull_request.base.ref': seed}, True),
            ('ordinary labeled PR', {}, True),
            ('similar head is not excluded', {'github.event.pull_request.head.ref': seed + '-followup'}, True),
            ('unlabeled PR', {'labels': []}, False),
            ('external fork PR', {'github.event.pull_request.head.repo.full_name': 'external/prospero-win'}, False),
            ('other event with copied PR metadata', {'github.event_name': 'issues'}, False),
        ]
        jobs = workflow()['jobs']
        for label, changes, expected in cases:
            context = dict(base, **changes)
            for name in ('original-x64-reference', 'matched-runtime'):
                with self.subTest(case=label, job=name):
                    self.assertIs(actual_job_gate(jobs[name]['if'], context), expected)

    def test_parallel_runtime_retains_trusted_trigger_and_real_reference_join(self):
        jobs = workflow()['jobs']
        runtime, reference = jobs['matched-runtime'], jobs['original-x64-reference']
        self.assertNotIn('original-x64-reference', runtime.get('needs', []))
        self.assertEqual(''.join(runtime['if'].split()), ''.join(reference['if'].split()))
        steps = runtime['steps']
        joins = [i for i, step in enumerate(steps)
                 if 'tools/wine_workflow_join.py' in step.get('run', '')]
        self.assertEqual([steps[i].get('id') for i in joins],
                         ['early-reference-join', 'reference-join'])
        early_index, join_index = joins
        for i in joins:
            join = steps[i]
            self.assertNotIn('if', join)
            self.assertNotIn('continue-on-error', join)
            self.assertEqual(join['env'], {'GH_TOKEN': '${{ github.token }}'})
            self.assertEqual(join['run'].strip(),
                             'python3 tools/wine_workflow_join.py --output '
                             '"$RUNNER_TEMP/fixture-evidence/' + join['id'] + '.json"')
        target_index = next(i for i, step in enumerate(steps)
                            if '--stage target-units --' in step.get('run', ''))
        host_index = next(i for i, step in enumerate(steps)
                          if '--stage host-runtime --' in step.get('run', ''))
        self.assertLess(target_index, early_index)
        self.assertEqual(early_index + 1, host_index)
        join_source = (ROOT / 'tools/wine_workflow_join.py').read_text()
        for variable in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_REPOSITORY'):
            self.assertIn(variable, join_source)
        downloads = [i for i, step in enumerate(steps)
                     if step.get('uses', '').startswith('actions/download-artifact@')]
        self.assertEqual(len(downloads), 1)
        download_index = downloads[0]
        self.assertEqual(join_index + 1, download_index)
        download = steps[download_index]
        self.assertNotIn('if', download)
        self.assertNotIn('continue-on-error', download)
        self.assertEqual(download['with']['name'],
                         'original-fixture-x64-${{ github.sha }}-${{ github.run_attempt }}')
        self.assertNotIn('run-id', download['with'], 'default download must remain within this run')
        preflight_index = next(i for i, step in enumerate(steps) if step.get('id') == 'fixture-preflight')
        self.assertEqual(download_index + 1, preflight_index)
        self.assertNotIn('if', steps[preflight_index])
        self.assertNotIn('continue-on-error', steps[preflight_index])
        consumers = [i for i, step in enumerate(steps)
                     if '--fixture ' in step.get('run', '') or
                     'PW_WINDOWS_CHILD_FIXTURE_DIR' in step.get('env', {}) or
                     'package_windows_child_fixture.py assemble' in step.get('run', '')]
        self.assertTrue(consumers)
        self.assertEqual(preflight_index + 1, min(consumers))
        self.assertTrue(all(preflight_index < i for i in consumers))

    def test_original_msvc_reference_is_always_fresh(self):
        steps = workflow()['jobs']['original-x64-reference']['steps']
        self.assertFalse(any('actions/cache' in step.get('uses', '') or
                             'download-artifact' in step.get('uses', '') for step in steps))
        build = next(step for step in steps if 'build_windows_child_fixture.ps1' in step.get('run', ''))
        reference = next(step for step in steps if 'Start-Process' in step.get('run', ''))
        for step in (build, reference):
            self.assertNotIn('if', step)
            self.assertNotIn('continue-on-error', step)
        for identity in ('tests/fixtures/windows_child_process.c', 'tools/build_windows_child_fixture.ps1',
                         "git rev-parse HEAD", "git rev-parse 'HEAD^{tree}'", 'GITHUB_RUN_ID',
                         'GITHUB_RUN_ATTEMPT', 'Get-FileHash', 'ExitCode -ne 0'):
            self.assertIn(identity, reference['run'])

    def test_native_i386_host_aggregates_remain_mandatory_and_unchanged(self):
        steps = workflow()['jobs']['matched-runtime']['steps']
        expected = {'Run unchanged host aggregate':
                    'make -j2 all 2>&1 | tee "$RUNNER_TEMP/fixture-evidence/host-all.log"',
                    'Run unchanged sanitizer aggregate':
                    'make sanitize 2>&1 | tee "$RUNNER_TEMP/fixture-evidence/host-sanitize.log"'}
        for name, command in expected.items():
            with self.subTest(step=name):
                step = next(item for item in steps if item.get('name') == name)
                self.assertEqual(step['run'].strip(), command)
                self.assertNotIn('continue-on-error', step)
                self.assertEqual(step['env']['PROSPERO_WINE_SOURCE'], '${{ runner.temp }}/wine-source')
                self.assertEqual(step['env']['PW_DISPATCH_CLANG'], '/usr/bin/clang-18')
        # Keep actual native i386 oracle invocation in the aggregate recipe.
        makefile = (ROOT / 'Makefile').read_text()
        self.assertIn('tests/test_x86_differential.py', makefile)
        self.assertIn('tests/test_pw_sse_matrix.py', makefile)
        self.assertIn('tests/test_dynarec_bench.py', makefile)

    def test_actions_cache_contains_only_exact_compiler_directories(self):
        steps = workflow()['jobs']['matched-runtime']['steps']
        cached = [step for step in steps if step.get('uses', '').startswith('actions/cache/')]
        self.assertEqual(len(cached), 4)
        for phase in ('host', 'ps5'):
            expected_path = '${{ runner.temp }}/ccache-' + phase
            selected = [step for step in cached if step['with'].get('path') == expected_path]
            self.assertEqual(len(selected), 2)
            self.assertEqual({step['uses'].split('@')[0] for step in selected},
                             {'actions/cache/restore', 'actions/cache/save'})
            for step in selected:
                self.assertEqual(step['with']['key'], '${{ steps.' + phase + '-cache-key.outputs.key }}')
                expected_fields = {'path', 'key'}
                if step['uses'].startswith('actions/cache/restore@'):
                    expected_fields.add('restore-keys')
                    self.assertEqual(step['with']['restore-keys'],
                                     '${{ steps.' + phase + '-cache-key.outputs.restore-prefix }}')
                self.assertNotIn('continue-on-error', step)
                self.assertEqual(set(step['with']), expected_fields)
        # Evidence, installed runtimes, initialized prefixes and fresh MSVC bytes
        # must not become alternate entries in a cache path list.
        self.assertEqual({step['with']['path'] for step in cached},
                         {'${{ runner.temp }}/ccache-host', '${{ runner.temp }}/ccache-ps5'})

    def test_cache_restore_never_skips_actual_builder_stages(self):
        steps = workflow()['jobs']['matched-runtime']['steps']
        expected = [('host-tools', 'host', 'build_host_wine.sh'),
                    ('host-runtime', 'host', 'build_host_wine.sh'),
                    ('target-units', 'ps5', 'build_wine_ps5.sh'),
                    ('target-runtime', 'ps5', 'build_wine_ps5.sh')]
        for stage, phase, builder in expected:
            with self.subTest(stage=stage):
                found = [step for step in steps if '--stage ' + stage + ' --' in step.get('run', '')]
                self.assertEqual(len(found), 1)
                step = found[0]
                self.assertNotIn('if', step)
                self.assertNotIn('continue-on-error', step)
                self.assertNotIn('|| true', step['run'])
                self.assertIn('tools/wine_compile_cache.py run', step['run'])
                self.assertIn('sh tools/' + builder, step['run'])
                self.assertIn('--state "$RUNNER_TEMP/fixture-evidence/ccache-' + phase + '"', step['run'])
                self.assertEqual(step['env']['PW_CACHE_RESTORE_HIT'],
                                 '${{ steps.' + phase + '-cache.outputs.cache-hit }}')
                self.assertEqual(step['env']['PW_CACHE_MATCHED_KEY'],
                                 '${{ steps.' + phase + '-cache.outputs.cache-matched-key }}')


class ReferenceJoinControls(unittest.TestCase):
    """Actual join function; GitHub responses and time are explicitly mocked."""

    def setUp(self):
        path = Path(os.environ.get('PW_PERF_JOIN', ROOT / 'tools/wine_workflow_join.py'))
        spec = importlib.util.spec_from_file_location('join_under_test', path)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.temp = tempfile.TemporaryDirectory(prefix='reference join ')
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name) / 'evidence/join.json'
        self.clock = 0.0
        self.requests = []
        self.sleeps = []
        self.job = {'id': 123, 'name': 'original-x64-reference', 'run_id': 123456,
                    'run_attempt': 2, 'status': 'completed', 'conclusion': 'success',
                    'started_at': '2026-10-10T00:00:00Z', 'completed_at': '2026-10-10T00:00:01Z'}

    def reply(self, jobs=None):
        jobs = [copy.deepcopy(self.job)] if jobs is None else jobs
        return {'total_count': len(jobs), 'jobs': jobs}

    def invoke(self, responses, *, clock=None, consume=0.0):
        queue = iter(responses)
        def request(endpoint):
            self.requests.append(endpoint)
            self.clock += consume
            value = next(queue)
            if isinstance(value, Exception):
                raise value
            return value
        def sleep(seconds):
            self.assertGreaterEqual(seconds, 0)
            self.assertLessEqual(seconds, 5)
            self.sleeps.append(seconds)
            self.clock += seconds
        return self.module.wait_for_reference('owner/repo', '123456', '2', self.output,
            request_json=request, monotonic=clock or (lambda: self.clock), sleep=sleep, timeout=10)

    def failed(self, responses, **kwargs):
        with self.assertRaises(Exception):
            self.invoke(responses, **kwargs)
        result = json.loads(self.output.read_text())
        self.assertIs(result['success'], False)
        self.assertIn('error', result)
        return result

    def test_completed_reference_is_bound_to_exact_attempt_endpoint(self):
        result = self.invoke([self.reply()])
        self.assertTrue(result['success'])
        self.assertEqual(self.requests, [
            'https://api.github.com/repos/owner/repo/actions/runs/123456/attempts/2/jobs?per_page=100'])
        self.assertEqual(result['run_id'], '123456')
        self.assertEqual(result['run_attempt'], '2')
        self.assertEqual(result['repository'], 'owner/repo')
        self.assertEqual(result['observations'][0]['id'], 123)
        self.assertEqual(json.loads(self.output.read_text()), result)

    def test_pending_then_success_reuses_original_budget(self):
        pending = copy.deepcopy(self.job)
        pending.update(status='in_progress', conclusion=None)
        result = self.invoke([self.reply([pending]), self.reply()])
        self.assertEqual(len(self.requests), 2)
        self.assertEqual(self.sleeps, [5])
        self.assertEqual(result['elapsed_seconds'], 5)

    def test_terminal_failure_never_produces_success_receipt(self):
        for conclusion in ('failure', 'cancelled', 'skipped', 'timed_out', 'action_required', None):
            with self.subTest(conclusion=conclusion):
                self.job['conclusion'] = conclusion
                self.failed([self.reply()])
        self.assertFalse(self.sleeps)

    def test_wrong_run_or_attempt_refused_even_with_success(self):
        for field in ('run_id', 'run_attempt'):
            with self.subTest(field=field):
                value = copy.deepcopy(self.job)
                value[field] = 99
                self.failed([self.reply([value])])

    def test_incomplete_ambiguous_and_malformed_responses_refused(self):
        replies = [None, {}, {'jobs': []}, {'jobs': [], 'total_count': 1},
                   {'jobs': [None], 'total_count': 1}, self.reply([self.job, self.job]),
                   self.reply([dict(self.job, name='other')] * 101),
                   self.reply([dict(self.job, status='unknown')])]
        for value in replies:
            with self.subTest(reply=value):
                self.failed([value])

    def test_missing_reference_waits_only_until_absolute_deadline(self):
        self.failed([self.reply([]), self.reply([])])
        self.assertEqual(self.sleeps, [5, 5])
        self.assertEqual(len(self.requests), 2)
        self.assertEqual(self.clock, 10)

    def test_exact_deadline_response_cannot_authorize_success(self):
        self.failed([self.reply()], consume=10)
        self.assertEqual(len(self.requests), 1)

    def test_clock_rollback_during_request_is_refused(self):
        samples = iter([2, 2, 1, 1])
        self.failed([self.reply()], clock=lambda: next(samples))

    def test_clock_rollback_after_sleep_budget_sample_is_refused(self):
        pending = dict(self.job, status='queued', conclusion=None)
        samples = iter([0, 0, 7, 5, 5, 5])
        self.failed([self.reply([pending]), self.reply()], clock=lambda: next(samples))

    def test_transport_failure_overwrites_no_success_evidence(self):
        self.output.parent.mkdir()
        self.output.write_text('{"success": true, "stale": true}')
        value = self.failed([OSError('synthetic API read failure')])
        self.assertNotIn('stale', value)
        self.assertEqual(len(self.requests), 1)

    def test_repository_and_numeric_inputs_are_validated_before_request(self):
        for repository, run, attempt in [('owner/repo/extra', '123456', '2'),
                                          ('owner/repo', '0', '2'),
                                          ('owner/repo', '123456', '../2')]:
            with self.subTest(repository=repository, run=run, attempt=attempt):
                def forbidden(endpoint):
                    self.fail('invalid identity reached API')
                with self.assertRaises(ValueError):
                    self.module.wait_for_reference(repository, run, attempt, self.output,
                                                   request_json=forbidden)
                self.assertFalse(self.output.exists())


if __name__ == '__main__':
    unittest.main()
