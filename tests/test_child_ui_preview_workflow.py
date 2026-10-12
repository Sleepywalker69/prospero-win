#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Opt-in recipe mutations and static collector controls; no target code runs."""
import argparse
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import yaml

sys.dont_write_bytecode = True
from test_wine_build_performance import actual_job_gate
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import collect_child_ui_preview_validation as collector

WORKFLOW = ROOT / '.github/workflows/windows-child-fixture.yml'
GATE = """${{ (github.event_name == 'workflow_dispatch' && inputs.child_ui_preview == true) ||
    (github.event_name == 'pull_request' &&
     github.event.pull_request.head.repo.full_name == github.repository &&
     github.event.pull_request.head.ref != 'perf/windows-child-incremental-cache' &&
     contains(github.event.pull_request.labels.*.name, 'build-child-ui-preview-static') &&
     (github.event.action == 'opened' || github.event.action == 'synchronize' ||
      github.event.action == 'reopened' ||
      (github.event.action == 'labeled' && github.event.label.name == 'build-child-ui-preview-static'))) }}"""
BUILD = 'Build the opt-in enabled preview in fresh isolated outputs'
COLLECT = 'Recheck both modes and collect static-only preview evidence with exact sources'
UPLOAD = 'Upload the isolated preview static-validation artifact'
INSPECTION = 'Retain bounded isolated preview compiler diagnostics'
EVIDENCE = 'Keep bounded preview logs even when its validation fails'


def workflow():
    return yaml.load(WORKFLOW.read_text(), Loader=yaml.BaseLoader)


def steps(flow):
    return {s.get('name', str(i)): s for i, s in enumerate(flow['jobs']['matched-runtime']['steps'])}


def recipe_contract(flow, native):
    require = collector.require
    option = flow['on']['workflow_dispatch']['inputs']['child_ui_preview']
    require(option['type'] == 'boolean' and option['default'] == 'false' and option['required'] == 'false',
            'preview dispatch must be explicit default-false boolean')
    job = flow['jobs']['matched-runtime']
    require('strategy' not in job and 'PW_WINE_CHILD_UI_ENABLED' not in flow['env'] and
            'PW_WINE_CHILD_UI_ENABLED' not in job['env'], 'preview cannot replace shared/default control')
    selected = steps(flow)
    build, collect, upload = (selected[name] for name in (BUILD, COLLECT, UPLOAD))
    require(all(''.join(s.get('if', '').split()) == ''.join(GATE.split()) and
                'continue-on-error' not in s for s in (build, collect, upload)),
            'preview success stages must retain opt-in and failure gates')
    require(build['env']['PW_WINE_CHILD_UI_ENABLED'] == '1' and
            build['env']['PW_WINE_CHILD_FIXTURE_MODE'] == '1' and
            build['env']['PW_OUTPUT_SUFFIX'] == '-windows-child-fixture' and
            build['env']['PW_WINE_CHILD_RUNTIME'] == '${{ runner.temp }}/wine-ps5', 'preview build flags differ')
    for text in ('git worktree add --detach "$RUNNER_TEMP/preview-source" HEAD',
                 '[[ ! -e "$RUNNER_TEMP/preview-source" && ! -L "$RUNNER_TEMP/preview-source" ]]',
                 'rev-parse HEAD', "rev-parse 'HEAD^{tree}'",
                 'timeout 30m bash "$RUNNER_TEMP/preview-source/tools/build_native.sh"',
                 '--check-title --child-ui --work "$RUNNER_TEMP/preview-source"',
                 '--build "$RUNNER_TEMP/preview-source/build/native-windows-child-fixture"',
                 '--app "$RUNNER_TEMP/preview-source/dist/PPSA99995-windows-child-fixture"',
                 '--run-id "$GITHUB_RUN_ID" --run-attempt "$GITHUB_RUN_ATTEMPT"'):
        require(text in build['run'], 'preview source/build recipe omission: ' + text)
    for text in ('child_ui_args+=(--child-ui)',
                 '--out "$build/wine-child" --llvm-bindir "$llvm_bindir" "${child_ui_args[@]}"',
                 '--out "$build-wine-child-title-inspection" "${child_ui_args[@]}"'):
        require(text in native, 'worker/internal title flag route omission')
    for text in ("source['paths']['repo'] = str(temp / 'preview-source')",
                 "source['paths']['title_build'] = str(temp / 'preview-source/build/native-windows-child-fixture')",
                 'package_windows_child_fixture.py retain-sources',
                 'collect_child_ui_preview_validation.py --inputs "$RUNNER_TEMP/package-inputs.json"',
                 '--repo "$RUNNER_TEMP/preview-source"',
                 '--sources "$RUNNER_TEMP/preview-retained-sources"',
                 '--report "$RUNNER_TEMP/preview-title-inspection/native-wine-child-title.json"',
                 '--out "$RUNNER_TEMP/child-ui-preview-static-validation"'):
        require(text in collect['run'], 'preview collection recipe omission: ' + text)
    require('package_windows_child_fixture.py assemble' not in collect['run'], 'preview deployment admission expanded')
    require(upload['with'] == {'name': 'child-ui-preview-static-validation-${{ github.sha }}-${{ github.run_attempt }}',
                              'path': '${{ runner.temp }}/child-ui-preview-static-validation/',
                              'retention-days': '7', 'if-no-files-found': 'error'}, 'preview artifact identity differs')
    inspection, evidence = selected[INSPECTION], selected[EVIDENCE]
    require(inspection['if'] == evidence['if'] and 'always()' in inspection['if'] and
            'continue-on-error' not in inspection, 'preview diagnostics must run even after failure')
    for text in ('from retain_windows_child_failure import collect_preview_inspection',
                 "temp / 'preview-source/build/native-windows-child-fixture'",
                 "temp / 'preview-title-inspection'", "temp / 'preview-evidence/compiler-inspection'"):
        require(text in inspection['run'], 'isolated preview diagnostic route omission: ' + text)
    ordered = job['steps']
    control = next(s for s in ordered if s.get('name') == 'Build the full-CRT child once and the matched title')
    require('PW_WINE_CHILD_UI_ENABLED' not in control['env'] and '--child-ui' not in control['run'] and
            'if' not in control, 'default-off title control changed')
    normal_upload = next(s for s in ordered if s.get('name') == 'Upload the complete checked original-fixture archive')
    require(ordered.index(normal_upload) < ordered.index(build) < ordered.index(collect) < ordered.index(upload),
            'preview must follow successful default-off package')
    require(ordered.index(upload) < ordered.index(inspection) < ordered.index(evidence),
            'compiler diagnostics must be collected before the preview evidence upload')
    require(evidence['with']['path'] == '${{ runner.temp }}/preview-evidence/',
            'preview compiler diagnostics must share the existing evidence artifact')
    names = [s['with']['name'] for j in flow['jobs'].values() for s in j['steps']
             if s.get('uses', '').startswith('actions/upload-artifact@')]
    require(len(names) == len(set(names)), 'workflow artifact collision')
    require(len([s for s in ordered if '--stage target-runtime --' in s.get('run', '')]) == 1,
            'target runtime must build once')
    require(all('actions/cache' not in s.get('uses', '') for s in (build, collect, upload)),
            'preview title/worker reuse forbidden')


def event_contract(flow):
    """Evaluate actual YAML expressions against bounded event truth tables."""
    selected = steps(flow)
    label = 'build-child-ui-preview-static'
    regular = 'build-windows-child-fixture'
    base = {'github.event_name': 'pull_request', 'github.repository': 'Sleepywalker69/prospero-win',
            'github.ref': 'refs/pull/123/merge', 'github.run_id': '987654', 'github.event.deleted': False,
            'github.event.action': 'labeled', 'github.event.label.name': label,
            'github.event.pull_request.head.repo.full_name': 'Sleepywalker69/prospero-win',
            'github.event.pull_request.head.ref': 'reviewed-change',
            'inputs.child_ui_preview': False, 'labels': [label]}
    cases = [
        ('explicit preview label', {}, True, True),
        ('preview and ordinary labels together', {'labels': [label, regular]}, True, True),
        ('dispatch true', {'github.event_name': 'workflow_dispatch', 'inputs.child_ui_preview': True,
                           'labels': []}, True, True),
        ('dispatch false', {'github.event_name': 'workflow_dispatch'}, True, False),
        ('dispatch missing input', {'github.event_name': 'workflow_dispatch',
                                    'inputs.child_ui_preview': ''}, True, False),
        ('ordinary PR label only', {'github.event.label.name': regular, 'labels': [regular]}, True, False),
        ('ordinary label added to preview PR', {'github.event.label.name': regular,
                                               'labels': [label, regular]}, True, False),
        ('unrelated label on preview PR', {'github.event.label.name': 'documentation'}, False, False),
        ('unrelated label on ordinary PR', {'github.event.label.name': 'documentation',
                                            'labels': [regular, 'documentation']}, False, False),
        ('wrong similar label', {'github.event.label.name': label + '-other'}, False, False),
        ('trigger label missing from current list', {'labels': []}, False, False),
        ('preview trigger with only ordinary current label', {'labels': [regular]}, False, False),
        ('ordinary trigger with only preview current label', {'github.event.label.name': regular}, False, False),
        ('missing event label', {'github.event.label.name': ''}, False, False),
        ('removed preview label', {'github.event.action': 'unlabeled', 'labels': [regular]}, False, False),
        ('unlabeled event with preview still present', {'github.event.action': 'unlabeled'}, False, False),
        ('closed PR', {'github.event.action': 'closed'}, False, False),
        ('external fork preview', {'github.event.pull_request.head.repo.full_name': 'fork/prospero-win'}, False, False),
        ('duplicate seed-head PR', {'github.event.pull_request.head.ref': 'perf/windows-child-incremental-cache'}, False, False),
        ('untrusted event with copied fields', {'github.event_name': 'pull_request_target'}, False, False),
        ('seed branch push', {'github.event_name': 'push',
                              'github.ref': 'refs/heads/perf/windows-child-incremental-cache'}, True, False),
        ('unrelated branch push', {'github.event_name': 'push', 'github.ref': 'refs/heads/unrelated'}, False, False),
    ]
    for action in ('opened', 'synchronize', 'reopened'):
        cases.extend([(action + ' opted-in PR', {'github.event.action': action}, True, True),
                      (action + ' ordinary PR', {'github.event.action': action, 'labels': [regular]}, True, False),
                      (action + ' no opt-in label', {'github.event.action': action, 'labels': []}, False, False)])
    for name, changes, heavy, preview in cases:
        context = dict(base, **changes)
        for job in ('original-x64-reference', 'original-user-x64-reference',
                    'original-network-x64-reference', 'matched-runtime'):
            collector.require(actual_job_gate(flow['jobs'][job]['if'], context) is heavy,
                              name + ': heavy job admission differs: ' + job)
        for step in (BUILD, COLLECT, UPLOAD):
            collector.require(actual_job_gate(selected[step]['if'], context) is preview,
                              name + ': preview step admission differs: ' + step)
        for step in (INSPECTION, EVIDENCE):
            evidence = selected[step]['if'].replace('always()', 'true')
            collector.require(actual_job_gate(evidence, context) is preview,
                              name + ': preview evidence selection differs: ' + step)
        prefix = 'windows-child-fixture-'
        group = flow['concurrency']['group']
        collector.require(group.startswith(prefix), 'concurrency prefix differs')
        selected_group = prefix + actual_job_gate(group[len(prefix):], context)
        expected_group = prefix + (context['github.ref'] if heavy else context['github.run_id'])
        collector.require(selected_group == expected_group,
                          name + ': ignored event must not displace pending admitted build')
    collector.require(flow['concurrency']['cancel-in-progress'] == 'false',
                      'preview must keep non-cancelling build concurrency')
    collector.require(flow['on']['pull_request']['types'] == ['opened', 'synchronize', 'reopened', 'labeled'],
                      'removal/other events must not subscribe new heavy jobs')


class WorkflowRecipe(unittest.TestCase):
    def setUp(self):
        self.flow = workflow()
        self.native = (ROOT / 'tools/build_native.sh').read_text()

    def test_actual_workflow_contract_and_shell_syntax(self):
        recipe_contract(self.flow, self.native)
        for step in self.flow['jobs']['matched-runtime']['steps']:
            if 'run' in step:
                result = subprocess.run(['bash', '-n'], input=step['run'], text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_actual_dispatch_and_label_event_truth_table(self):
        event_contract(self.flow)

    def test_broad_label_or_removed_current_label_guards_are_rejected(self):
        label = 'build-child-ui-preview-static'
        mutations = [
            lambda f: steps(f)[BUILD].update(**{'if': steps(f)[BUILD]['if'].replace(
                "github.event.label.name == '" + label + "'", 'true')}),
            lambda f: steps(f)[BUILD].update(**{'if': steps(f)[BUILD]['if'].replace(
                "contains(github.event.pull_request.labels.*.name, '" + label + "')", 'true')}),
            lambda f: f['jobs']['matched-runtime'].update(**{'if': f['jobs']['matched-runtime']['if'].replace(
                "github.event.label.name == 'build-windows-child-fixture'", 'true')}),
            lambda f: steps(f)[BUILD].update(**{'if': steps(f)[BUILD]['if'].replace(
                "github.event.pull_request.head.repo.full_name == github.repository", 'true')}),
            lambda f: f['concurrency'].update(**{'cancel-in-progress': 'true'}),
            lambda f: f['concurrency'].update(group='windows-child-fixture-${{ github.ref }}'),
            lambda f: f['concurrency'].update(group='windows-child-fixture-${{ github.run_id }}'),
        ]
        for index, change in enumerate(mutations):
            with self.subTest(index=index):
                mutant = copy.deepcopy(self.flow); change(mutant)
                with self.assertRaises(ValueError): event_contract(mutant)

    def test_omitted_recipe_controls_are_rejected(self):
        for name, text in ((BUILD, '--check-title --child-ui'), (BUILD, 'git worktree add --detach'),
                           (BUILD, "rev-parse 'HEAD^{tree}'"),
                           (COLLECT, 'package_windows_child_fixture.py retain-sources'),
                           (COLLECT, 'collect_child_ui_preview_validation.py'),
                           (COLLECT, '--sources "$RUNNER_TEMP/preview-retained-sources"'),
                           (INSPECTION, 'import collect_preview_inspection'),
                           (INSPECTION, 'preview-source/build/native-windows-child-fixture'),
                           (INSPECTION, 'preview-title-inspection'),
                           (INSPECTION, 'preview-evidence/compiler-inspection')):
            with self.subTest(name=name, omission=text):
                mutant = copy.deepcopy(self.flow)
                steps(mutant)[name]['run'] = steps(mutant)[name]['run'].replace(text, 'omitted')
                with self.assertRaises(ValueError): recipe_contract(mutant, self.native)

    def test_flags_default_and_artifact_collision_mutations_rejected(self):
        mutations = [lambda f: f['on']['workflow_dispatch']['inputs']['child_ui_preview'].update(default='true'),
                     lambda f: steps(f)[BUILD]['env'].update(PW_WINE_CHILD_UI_ENABLED='0'),
                     lambda f: steps(f)[BUILD]['env'].update(PW_OUTPUT_SUFFIX='-unadmitted'),
                     lambda f: steps(f)[BUILD]['env'].update(PW_WINE_CHILD_RUNTIME='other-runtime'),
                     lambda f: steps(f)[BUILD].pop('if'),
                     lambda f: steps(f)[INSPECTION].update(**{'if': GATE}),
                     lambda f: steps(f)[EVIDENCE]['with'].update(path='${{ runner.temp }}/wrong/'),
                     lambda f: steps(f)[UPLOAD].update(**{'if': '${{ always() }}'}),
                     lambda f: steps(f)[COLLECT].update(**{'continue-on-error': 'true'}),
                     lambda f: steps(f)[UPLOAD]['with'].update(name='windows-child-fixture-${{ github.sha }}-${{ github.run_attempt }}'),
                     lambda f: f['jobs']['matched-runtime']['env'].update(PW_WINE_CHILD_UI_ENABLED='1')]
        for index, change in enumerate(mutations):
            with self.subTest(index=index):
                mutant = copy.deepcopy(self.flow); change(mutant)
                with self.assertRaises(ValueError): recipe_contract(mutant, self.native)

    def test_both_worker_and_internal_title_routes_required(self):
        for text in ('child_ui_args+=(--child-ui)',
                     '--out "$build/wine-child" --llvm-bindir "$llvm_bindir" "${child_ui_args[@]}"',
                     '--out "$build-wine-child-title-inspection" "${child_ui_args[@]}"'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                recipe_contract(self.flow, self.native.replace(text, 'omitted'))

    def run_build(self, root, script=None, enabled='1'):
        selected = steps(self.flow)[BUILD]
        env = dict(os.environ, RUNNER_TEMP=str(root / 'temp'), GITHUB_WORKSPACE=str(root / 'repo'),
                   GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='2', PS5_PAYLOAD_SDK='/inert/sdk',
                   FOUNDATION='/inert/foundation', WINE_WORK='/inert/runtime', LLVM_CONFIG=str(root / 'llvm-config'))
        env.update({k: v.replace('${{ runner.temp }}', str(root / 'temp')) for k, v in selected['env'].items()})
        env['PW_WINE_CHILD_UI_ENABLED'] = enabled
        return subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', script or selected['run']],
                              cwd=root / 'repo', env=env, capture_output=True, text=True, timeout=20)

    def fixture(self, root):
        (root / 'temp').mkdir(); (root / 'repo/tools').mkdir(parents=True)
        (root / 'repo/control-sentinel').write_text('unchanged default-off control')
        (root / 'llvm-config').write_text('#!/bin/sh\necho /inert/llvm\n'); (root / 'llvm-config').chmod(0o755)
        (root / 'repo/tools/build_native.sh').write_text('''#!/bin/bash
set -eu
[[ $PW_WINE_CHILD_UI_ENABLED == 1 && $PW_WINE_CHILD_FIXTURE_MODE == 1 ]]
[[ $PW_OUTPUT_SUFFIX == -windows-child-fixture && $PW_WINE64_SCRIPT == 0 ]]
[[ $PW_WINE_CHILD_RUNTIME == "$RUNNER_TEMP/wine-ps5" ]]
root=$(cd "$(dirname "$0")/.." && pwd)
[[ $root == "$RUNNER_TEMP/preview-source" ]]
mkdir -p "$root/build/native-windows-child-fixture/wine-child" "$root/dist/PPSA99995-windows-child-fixture"
echo INERT_ENABLED_BUILD
''')
        (root / 'repo/tools/build_wine_service_child.py').write_text('''import os, pathlib, sys
a=sys.argv[1:]
assert '--check-title' in a and '--child-ui' in a
assert a[a.index('--work')+1] == os.environ['RUNNER_TEMP']+'/preview-source'
assert a[a.index('--run-id')+1]=='123' and a[a.index('--run-attempt')+1]=='2'
assert a[a.index('--runtime')+1]=='/inert/runtime'
p=pathlib.Path(a[a.index('--out')+1]); p.mkdir(); (p/'inert.json').write_text('{}')
print('INERT_ENABLED_CHECK')
''')
        subprocess.run(['git', 'init', '-q', str(root / 'repo')], check=True)
        subprocess.run(['git', '-C', str(root / 'repo'), 'add', '.'], check=True)
        subprocess.run(['git', '-C', str(root / 'repo'), '-c', 'user.name=Test', '-c',
                        'user.email=test@example.invalid', 'commit', '-qm', 'Inert recipe inputs'], check=True)

    def test_real_opt_in_shell_builds_fresh_same_source_and_refuses_reuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); self.fixture(root)
            result = self.run_build(root)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('INERT_ENABLED_CHECK', result.stdout)
            self.assertEqual((root / 'repo/control-sentinel').read_text(), 'unchanged default-off control')
            self.assertNotEqual(self.run_build(root).returncode, 0)

    def test_real_opt_in_shell_refuses_flag_mismatches(self):
        for enabled, omit in [('0', False), ('1', True)]:
            with self.subTest(enabled=enabled, omit=omit), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); self.fixture(root)
                script = steps(self.flow)[BUILD]['run']
                if omit: script = script.replace('--check-title --child-ui', '--check-title')
                result = self.run_build(root, script, enabled)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((root / 'temp/preview-title-inspection/inert.json').exists())


    def test_failed_preview_build_retains_real_compiler_stderr_before_upload(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); self.fixture(root)
            build = root / 'repo/tools/build_native.sh'
            build.write_text(build.read_text() + """
mkdir -p "$root/build/native-windows-child-fixture/wine-child/inspection"
printf 'argv: compiler\\nstdout: partial output\\nstderr: inert compiler failure\\n' > "$root/build/native-windows-child-fixture/wine-child/inspection/007-tool.log"
echo 'compiler failed; details are in the numbered inspection log'
exit 42
""")
            subprocess.run(['git', '-C', str(root / 'repo'), 'add', '.'], check=True)
            subprocess.run(['git', '-C', str(root / 'repo'), '-c', 'user.name=Test', '-c',
                            'user.email=test@example.invalid', 'commit', '-qm', 'Inert compiler failure'], check=True)
            result = self.run_build(root)
            self.assertEqual(result.returncode, 42, result.stderr)
            evidence = root / 'temp/preview-evidence'
            self.assertNotIn('stderr: inert compiler failure', (evidence / 'title-build.log').read_text())
            self.assertFalse((root / 'temp/preview-title-inspection').exists())
            # Run the actual workflow collector after failure, from the original
            # workspace, where the default-off logs must remain out of scope.
            (root / 'repo/tools/retain_windows_child_failure.py').write_bytes(
                (ROOT / 'tools/retain_windows_child_failure.py').read_bytes())
            control = root / 'repo/build/native-windows-child-fixture/wine-child/inspection'
            control.mkdir(parents=True); (control / '001-tool.log').write_text('default-off only')
            result = subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', steps(self.flow)[INSPECTION]['run']],
                                    cwd=root / 'repo', env=dict(os.environ, RUNNER_TEMP=str(root / 'temp')),
                                    capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            kept = evidence / 'compiler-inspection/target/child/inspection/007-tool.log'
            self.assertIn('stderr: inert compiler failure', kept.read_text())
            manifest = json.loads((evidence / 'compiler-inspection/UNACCEPTED-BUILD.json').read_text())
            self.assertEqual(set(manifest['files']), {'target/child/inspection/007-tool.log'})
            self.assertFalse(manifest['accepted'])


class CollectorControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.project = {'commit': 'a' * 40, 'tree': 'b' * 40}
        self.paths = {}
        for name in ('repo', 'sdk', 'foundation', 'wine_work', 'llvm_bindir', 'service_work', 'title',
                     'title_build', 'fixture', 'user_fixture', 'network_fixture'):
            p = self.root / ('control-' + name); p.mkdir(); self.paths[name] = str(p)
        for name in ('title_report', 'sdk_source_archive', 'wine_archive'):
            p = self.root / ('control-' + name); p.write_text('{}'); self.paths[name] = str(p)
        self.args = argparse.Namespace(**{name: self.root / name for name in
            ('repo', 'build', 'app', 'report', 'sources', 'sources_report', 'out')})
        for name in ('repo', 'build', 'app', 'sources'): getattr(self.args, name).mkdir()
        (self.args.build / 'wine-child').mkdir()
        (self.args.build / 'wine-child-title-compile.json').write_text('{}')
        (Path(self.paths['title_build']) / 'wine-child-title-compile.json').write_text('{}')
        (self.args.sources / 'source.txt').write_text('inert complete-source validator fixture')
        self.args.sources_report.write_text('{}')
        self.control, self.control_title = self.records(False)
        self.preview, self.preview_title = self.records(True)
        self.config = {'schema': 'pw-windows-child-package-inputs/1', 'paths': self.paths,
                       'run_url': 'https://github.com/Sleepywalker69/prospero-win/actions/runs/123', 'run_attempt': '2'}
        self.sync()

    def records(self, enabled):
        contract = collector.child.child_ui_contract(enabled)
        data = b'preview image' if enabled else b'control image'
        app = self.args.app if enabled else Path(self.paths['title'])
        (app / 'eboot.bin').write_bytes(data)
        files = {'eboot.bin': {**collector.package.record(app / 'eboot.bin'), 'mode': 0o644}}
        runtime = {'report_sha256': 'r' * 64, 'ntdll_sha256': 'n' * 64}
        worker = {'schema': 'pw-wine-service-child/2', 'project': self.project, 'child_ui': contract,
                  'runtime': runtime, 'sources': {'reviewed.c': 's' * 64}, 'console_execution_verified': False,
                  'worker': {'build_id': ('c' if enabled else 'd') * 40,
                             'sha256': ('e' if enabled else 'f') * 64}}
        title = {'schema': 'pw-windows-child-title/2', 'project': self.project, 'runtime': runtime,
                 'console_execution_verified': False, 'build_inputs': {'child_ui': contract},
                 'title_compile_inputs': {'child_ui': contract}, 'files': files}
        return worker, title

    def sync(self):
        for path, value in ((Path(self.paths['service_work']) / 'native-wine-child-build.json', self.control),
                            (self.args.build / 'wine-child/native-wine-child-build.json', self.preview),
                            (Path(self.paths['title_report']), self.control_title), (self.args.report, self.preview_title)):
            path.write_text(json.dumps(value))

    def collect(self, *, mutate_replay=None, retained_error=False, preview_error=None):
        self.sync(); calls = []
        def replay(args):
            calls.append(getattr(args, 'child_ui', False))
            if getattr(args, 'child_ui', False) and preview_error is not None:
                raise preview_error
            args.out.mkdir()
            value = copy.deepcopy(self.preview_title if getattr(args, 'child_ui', False) else self.control_title)
            if mutate_replay: mutate_replay(value, bool(getattr(args, 'child_ui', False)))
            (args.out / 'native-wine-child-title.json').write_text(json.dumps(value))
            self.assertEqual(args.run_id, '123'); self.assertEqual(args.run_attempt, '2')
            self.assertEqual(args.work, self.args.repo if getattr(args, 'child_ui', False) else Path(self.paths['repo']))
            return value
        def control_replay(args):
            self.assertFalse(getattr(args, 'child_ui', False), 'preview must not reuse control interpreter')
            return replay(args)
        def preview_replay(args):
            self.assertIs(args.child_ui, True)
            return replay(args)
        def sources(*args):
            self.assertEqual(args[0], self.args.repo)
            self.assertEqual(args[5], self.preview)
            if retained_error: raise ValueError('source drift')
            return {'inventory': collector.prefix.inventory(self.args.sources)}
        with mock.patch.object(collector.prefix, 'project', return_value=self.project), \
             mock.patch.object(collector.child, 'check_title', side_effect=control_replay), \
             mock.patch.object(collector, 'replay_preview_title', side_effect=preview_replay), \
             mock.patch.object(collector.prefix, 'load_tool', return_value=collector.child), \
             mock.patch.object(collector.package, 'retained_sources', side_effect=sources):
            result = collector.collect(self.config, self.args)
        self.assertEqual(calls, [False, True])
        return result

    def test_collect_replays_off_and_explicit_on_without_deployment_admission(self):
        result = self.collect()
        self.assertIs(result['deployment_package'], False)
        self.assertIs(result['runtime_validated'], False)
        self.assertIs(result['child_input_enabled'], False)
        self.assertEqual(result['same_runtime'], self.preview['runtime'])
        self.assertTrue((self.args.out / 'STATIC-VALIDATION.json').is_file())
        self.assertTrue((self.args.out / 'SHA256SUMS').is_file())
        self.assertFalse((self.args.out / 'console').exists())
        self.assertFalse((self.args.out / 'PPSA99995').exists())
        self.assertEqual((self.args.out / 'target-images/eboot.bin').read_bytes(), b'preview image')

    def test_contract_field_type_and_omission_mutations_rejected(self):
        expected = collector.child.child_ui_contract(True)
        mutants = [{k: v for k, v in expected.items() if k != field} for field in expected]
        mutants += [{**expected, field: value} for field, value in
                    [('enabled', 1), ('enabled', False), ('bootstrap_version', 2), ('bootstrap_version', 3.0),
                     ('bootstrap_rights', 1), ('input_enabled', True), ('runtime_validated', True),
                     ('preview_only', False), ('socket_identity', None)]]
        for value in mutants:
            with self.subTest(value=value), self.assertRaises(ValueError):
                collector.exact_contract(value, True)

    def test_all_manifest_and_title_mode_paths_reject_crossed_modes(self):
        values = [self.control, self.preview, self.control_title['build_inputs'],
                  self.preview_title['build_inputs'], self.control_title['title_compile_inputs'],
                  self.preview_title['title_compile_inputs']]
        for value in values:
            old = value['child_ui']; value['child_ui'] = collector.child.child_ui_contract(not old['enabled'])
            with self.subTest(value=value), self.assertRaises(ValueError):
                collector.paired_contract(self.control, self.preview, self.control_title, self.preview_title, self.project)
            value['child_ui'] = old

    def test_source_runtime_project_and_artifact_drift_rejected(self):
        mutations = [('sources', {'reviewed.c': 'changed'}), ('runtime', {'report_sha256': 'changed'}),
                     ('project', {'commit': 'changed'}), ('worker', copy.deepcopy(self.control['worker']))]
        for name, value in mutations:
            saved = self.preview[name]; self.preview[name] = value
            with self.subTest(name=name), self.assertRaises(ValueError):
                collector.paired_contract(self.control, self.preview, self.control_title, self.preview_title, self.project)
            self.preview[name] = saved
        self.preview_title['files'] = self.control_title['files']
        with self.assertRaises(ValueError):
            collector.paired_contract(self.control, self.preview, self.control_title, self.preview_title, self.project)

    def test_replayed_receipt_drift_never_creates_bundle(self):
        with self.assertRaisesRegex(ValueError, 'replayed preview title receipt'):
            self.collect(mutate_replay=lambda value, enabled: value.update(changed=True) if enabled else None)
        self.assertFalse(self.args.out.exists())

    def test_preview_process_failure_or_timeout_never_creates_bundle(self):
        for index, error in enumerate((subprocess.CalledProcessError(7, ['preview-validator']),
                                      subprocess.TimeoutExpired(['preview-validator'], 1800))):
            self.args.out = self.root / ('failed-preview-' + str(index))
            with self.subTest(error=type(error).__name__), self.assertRaises(type(error)):
                self.collect(preview_error=error)
            self.assertFalse(self.args.out.exists())

    def test_crossed_mode_refusal_never_creates_bundle(self):
        self.preview['child_ui'] = collector.child.child_ui_contract(False)
        with self.assertRaisesRegex(ValueError, 'mode contract differs'): self.collect()
        self.assertFalse(self.args.out.exists())

    def test_separate_checkout_source_drift_refused_before_replay(self):
        with mock.patch.object(collector.prefix, 'project', side_effect=[self.project, {'commit': 'changed'}]), \
             mock.patch.object(collector.child, 'check_title') as inspect:
            with self.assertRaisesRegex(ValueError, 'same-source HEAD'):
                collector.collect(self.config, self.args)
        inspect.assert_not_called()
        self.assertFalse(self.args.out.exists())

    def test_input_receipt_mutation_during_replay_never_creates_bundle(self):
        def mutate(value, enabled):
            if enabled: self.args.report.write_text('{"changed_during_replay": true}')
        with self.assertRaisesRegex(ValueError, 'receipt changed during replay'):
            self.collect(mutate_replay=mutate)
        self.assertFalse(self.args.out.exists())

    def test_compile_receipt_mutation_during_replay_never_creates_bundle(self):
        def mutate(value, enabled):
            if enabled: (self.args.build / 'wine-child-title-compile.json').write_text('{"changed": true}')
        with self.assertRaisesRegex(ValueError, 'receipt changed during replay'):
            self.collect(mutate_replay=mutate)
        self.assertFalse(self.args.out.exists())

    def test_retained_source_refusal_never_creates_bundle(self):
        with self.assertRaisesRegex(ValueError, 'source drift'): self.collect(retained_error=True)
        self.assertFalse(self.args.out.exists())

    def test_post_inspection_image_drift_never_creates_bundle(self):
        (self.args.app / 'eboot.bin').write_bytes(b'changed after synthetic inspection')
        with self.assertRaisesRegex(ValueError, 'title changed after replay'): self.collect()
        self.assertFalse(self.args.out.exists())

    def test_output_collision_and_input_symlink_refused(self):
        self.args.out.mkdir(); (self.args.out / 'sentinel').write_text('preserve')
        with self.assertRaisesRegex(ValueError, 'output already exists'): self.collect()
        self.assertEqual((self.args.out / 'sentinel').read_text(), 'preserve')
        self.args.out = self.root / 'new-output'
        linked = self.root / 'linked-app'; linked.symlink_to(self.args.app, target_is_directory=True)
        self.args.app = linked
        with self.assertRaisesRegex(ValueError, 'symlink'): self.collect()
        self.assertFalse(self.args.out.exists())


class PreviewSubprocessControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='preview replay with spaces ')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.args = argparse.Namespace(child_ui=True, run_id='123', run_attempt='2')
        for name in ('work', 'sdk', 'foundation', 'runtime', 'llvm_bindir', 'service_work',
                     'app', 'build', 'sdk_source_archive', 'fixture', 'user_fixture',
                     'network_fixture', 'out'):
            setattr(self.args, name, self.root / name)
        (self.args.work / 'tools').mkdir(parents=True)
        self.script = self.args.work / 'tools/build_wine_service_child.py'
        self.expected = ['--check-title', '--child-ui']
        for name in ('work', 'sdk', 'foundation', 'runtime', 'llvm_bindir', 'service_work',
                     'app', 'build', 'sdk_source_archive', 'fixture', 'user_fixture',
                     'network_fixture', 'run_id', 'run_attempt', 'out'):
            self.expected += ['--' + name.replace('_', '-'), str(getattr(self.args, name))]
        self.script.write_text('''import json, os, pathlib, sys
assert sys.flags.dont_write_bytecode
assert sys.argv[1:] == ''' + repr(self.expected) + '''
assert pathlib.Path.cwd() == pathlib.Path(''' + repr(str(self.args.work)) + ''')
out = pathlib.Path(sys.argv[sys.argv.index('--out') + 1]); out.mkdir()
(out / 'native-wine-child-title.json').write_text('{"fresh": true}')
print('stdout is not a title receipt')
''')

    def test_real_child_receives_every_exact_argument_and_fresh_report(self):
        self.assertEqual(collector.replay_preview_title(self.args), {'fresh': True})
        self.assertFalse((self.args.work / 'tools/__pycache__').exists())

    def test_process_is_checked_bounded_and_never_uses_a_shell(self):
        self.args.out.mkdir()
        report = self.args.out / 'native-wine-child-title.json'
        report.write_text('{"inert": true}')
        with mock.patch.object(collector.subprocess, 'run') as run:
            self.assertEqual(collector.replay_preview_title(self.args), {'inert': True})
        run.assert_called_once_with([sys.executable, '-B', str(self.script), *self.expected],
                                    cwd=self.args.work, check=True, shell=False, timeout=1800)

    def test_nonzero_process_refused_even_if_it_writes_a_valid_report(self):
        self.script.write_text(self.script.read_text() + '\nsys.exit(7)\n')
        with self.assertRaises(subprocess.CalledProcessError) as raised:
            collector.replay_preview_title(self.args)
        self.assertEqual(raised.exception.returncode, 7)
        self.assertTrue((self.args.out / 'native-wine-child-title.json').is_file())

    def test_missing_duplicate_or_symlink_report_refused(self):
        for index, body in enumerate(('',
                "(out / 'native-wine-child-title.json').write_text('{\"a\": 1, \"a\": 2}')",
                "(out / 'elsewhere.json').write_text('{}'); "
                "(out / 'native-wine-child-title.json').symlink_to(out / 'elsewhere.json')")):
            self.args.out = self.root / ('bad-report-' + str(index))
            prefix = 'import pathlib\nout = pathlib.Path(' + repr(str(self.args.out)) + '); out.mkdir()\n'
            self.script.write_text(prefix + body + '\n')
            with self.subTest(index=index), self.assertRaises((ValueError, FileNotFoundError)):
                collector.replay_preview_title(self.args)

    def test_missing_or_linked_entry_point_and_implicit_mode_refused(self):
        self.args.child_ui = False
        with self.assertRaisesRegex(ValueError, 'explicit child UI'):
            collector.replay_preview_title(self.args)
        self.args.child_ui = True
        self.script.unlink()
        with self.assertRaises((ValueError, FileNotFoundError)):
            collector.replay_preview_title(self.args)
        actual = self.script.with_name('other.py'); actual.write_text('raise AssertionError("must not run")')
        self.script.symlink_to(actual)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            collector.replay_preview_title(self.args)


class PreviewValidatorOriginTests(unittest.TestCase):
    """Real admission contracts with inert receipts, isolated from suite imports.

    These controls execute no PE code, compiler, Wine, console, or network. Every
    validator import and fixture-helper import occurs in a child interpreter.
    """

    _FIXTURES = r'''
import hashlib
import json
import sys
from pathlib import Path
original, preview, data = map(Path, sys.argv[1:4])
sys.path[:0] = [str(original / 'tools'), str(original / 'tests')]
import test_windows_child_user_contract as user_fixture
import test_windows_child_network_contract as network_fixture

def digest(value):
    return hashlib.sha256(value).hexdigest()

def record(value):
    return {'bytes': len(value), 'sha256': digest(value)}

project = {'commit': 'a' * 40, 'tree': 'b' * 40}
(data / 'service/native-wine-child-build.json').write_text(json.dumps({'project': project}))
leaf = user_fixture.make_pe('parent')
for name in ('parent.exe', 'child.exe'):
    (data / 'leaf' / name).write_bytes(leaf)
leaf_receipt = {
    'schema': 'pw-original-windows-child-msvc/1',
    'project': project, 'architecture': 'x64', 'run_id': '123', 'run_attempt': '1',
    'compiler': {'name': 'MSVC cl.exe', 'file_version': 'inert-synthetic-test',
                 'sha256': 'c' * 64},
    'reference': {'exit': 0, 'deadline_seconds': 45},
    'source_sha256': digest((original / 'tests/fixtures/windows_child_process.c').read_bytes()),
    'recipe_sha256': digest((original / 'tools/build_windows_child_fixture.ps1').read_bytes()),
    'files': {name: record(leaf) for name in ('parent.exe', 'child.exe')},
}
(data / 'leaf/fixture-source.json').write_text(json.dumps(leaf_receipt))
for role, fixture in (('user', user_fixture), ('network', network_fixture)):
    files, receipt, _, _, _ = fixture.make_bundle()
    sources = [('source_sha256', fixture.contract.SOURCE),
               ('recipe_sha256', fixture.contract.RECIPE),
               ('validator_sha256', fixture.contract.VALIDATOR)]
    if role == 'network':
        sources.append(('header_sha256', fixture.contract.HEADER))
    for key, relative in sources:
        source = (original / relative).read_bytes()
        receipt[key] = digest(source)
        if Path(relative).name in files:
            files[Path(relative).name] = source
    if role == 'network':
        receipt['headers'][r'D:\a\repo\tests\fixtures\windows_child_network_contract.h'] = record(
            (original / fixture.contract.HEADER).read_bytes())
    files[fixture.contract.RECEIPT] = json.dumps(receipt).encode()
    for name, value in files.items():
        (data / role / name).write_bytes(value)
print(json.dumps({'fixture_kind': 'inert', 'roles': ['user', 'network']}))
'''

    _PROBE = r'''
import json
import sys
from pathlib import Path
original, preview, data, import_root, work_root = map(Path, sys.argv[1:6])
user_enabled, network_enabled = [value == '1' for value in sys.argv[6:8]]
attempt, mode = sys.argv[8:10]
sys.path.insert(0, str(import_root / 'tools'))
import collect_child_ui_preview_validation as collector
builder = collector.child

def contract(root, user=True, network=True, expected_attempt='1'):
    return builder.title_profiles_input_contract(
        root, data / 'service', data / 'leaf', data / 'user' if user else None,
        '123', expected_attempt, data / 'network' if network else None)

outcome = {}
if mode != 'fresh':
    control = contract(original)
    outcome['original_control'] = {
        'user_enabled': control[0]['user_enabled'],
        'network_enabled': control[0]['network_enabled'],
    }
if mode in ('prepend', 'load_tool'):
    sys.path.insert(0, str(preview / 'tools'))
if mode == 'load_tool':
    builder = collector.prefix.load_tool(preview, 'build_wine_service_child')
try:
    result = contract(work_root, user_enabled, network_enabled, attempt)
    outcome.update(status='pass', result=result[0])
except ValueError as error:
    outcome.update(status='refused', error=str(error))
outcome['builder_origin'] = str(Path(builder.__file__).resolve())
outcome['validator_origins'] = {
    role: str(Path(sys.modules['windows_child_' + role + '_contract'].__file__).resolve())
    for role in ('user', 'network')
    if 'windows_child_' + role + '_contract' in sys.modules
}
print(json.dumps(outcome))
'''

    def setUp(self):
        import shutil

        self._temp = tempfile.TemporaryDirectory(prefix='child-ui-origin-')
        self.addCleanup(self._temp.cleanup)
        self.base = Path(self._temp.name)
        self.original, self.preview, self.data = (
            self.base / name for name in ('original', 'preview', 'inert-fixtures'))
        for root in (self.original, self.preview):
            shutil.copytree(ROOT / 'tools', root / 'tools',
                            ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
            for name in ('windows_child_process.c', 'windows_child_user.c',
                         'windows_child_network.c', 'windows_child_network_contract.h'):
                target = root / 'tests/fixtures' / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / 'tests/fixtures' / name, target)
            for name in ('test_windows_child_user_contract.py',
                         'test_windows_child_network_contract.py'):
                shutil.copyfile(ROOT / 'tests' / name, root / 'tests' / name)
        for source in (ROOT / 'tools').rglob('*'):
            if not source.is_file() or '__pycache__' in source.parts or source.suffix == '.pyc':
                continue
            relative = source.relative_to(ROOT)
            self.assertEqual(source.read_bytes(), (self.original / relative).read_bytes())
            self.assertEqual(source.read_bytes(), (self.preview / relative).read_bytes())
        for role in ('leaf', 'user', 'network', 'service'):
            (self.data / role).mkdir(parents=True)
        self.assertEqual(self._run_isolated(self._FIXTURES)['fixture_kind'], 'inert')

    def _run_isolated(self, script, *args):
        env = os.environ.copy()
        # Existing fixture helper overrides must not select another checkout.
        env.update(PW_USER_BASE_REPO=str(self.original),
                   PW_NETWORK_BASE_REPO=str(self.original))
        completed = subprocess.run(
            [sys.executable, '-I', '-B', '-c', script,
             str(self.original), str(self.preview), str(self.data), *map(str, args)],
            cwd=self.original, env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(completed.returncode, 0,
                         'isolated contract probe failed:\n' + completed.stdout + completed.stderr)
        return json.loads(completed.stdout)

    def _probe(self, *, import_root=None, work_root=None, user=True, network=True,
               attempt='1', mode='fresh'):
        return self._run_isolated(
            self._PROBE, import_root or self.preview, work_root or self.preview,
            int(user), int(network), attempt, mode)

    def _assert_original_control(self, outcome):
        self.assertEqual(outcome['original_control'],
                         {'user_enabled': True, 'network_enabled': True})

    def _assert_origin_refusal(self, outcome, role, origin):
        self.assertEqual(outcome['status'], 'refused')
        label = 'USER' if role == 'user' else 'network'
        self.assertEqual(outcome['error'], label + ' validator loaded from another project')
        self.assertEqual(outcome['validator_origins'][role],
                         str((origin / 'tools' / ('windows_child_' + role + '_contract.py')).resolve()))

    def test_unchanged_same_process_original_control_passes(self):
        outcome = self._probe(import_root=self.original, work_root=self.original, mode='warm')
        self._assert_original_control(outcome)
        self.assertEqual(outcome['status'], 'pass')
        self.assertIs(outcome['result']['user_enabled'], True)
        self.assertIs(outcome['result']['network_enabled'], True)

    def test_cached_original_user_validator_rejects_preview_root(self):
        outcome = self._probe(import_root=self.original, network=False, mode='warm')
        self._assert_original_control(outcome)
        self._assert_origin_refusal(outcome, 'user', self.original)

    def test_cached_original_network_validator_rejects_preview_root(self):
        outcome = self._probe(import_root=self.original, user=False, mode='warm')
        self._assert_original_control(outcome)
        self._assert_origin_refusal(outcome, 'network', self.original)

    def test_prepending_preview_tools_does_not_replace_cached_validators(self):
        for role in ('user', 'network'):
            with self.subTest(role=role):
                outcome = self._probe(import_root=self.original, user=role == 'user',
                                      network=role == 'network', mode='prepend')
                self._assert_original_control(outcome)
                self._assert_origin_refusal(outcome, role, self.original)

    def test_loading_preview_builder_does_not_replace_cached_validators(self):
        for role in ('user', 'network'):
            with self.subTest(role=role):
                outcome = self._probe(import_root=self.original, user=role == 'user',
                                      network=role == 'network', mode='load_tool')
                self._assert_original_control(outcome)
                self.assertEqual(outcome['builder_origin'],
                                 str((self.preview / 'tools/build_wine_service_child.py').resolve()))
                self._assert_origin_refusal(outcome, role, self.original)

    def test_fresh_preview_interpreter_passes_from_original_cwd(self):
        outcome = self._probe()
        self.assertEqual(outcome['status'], 'pass')
        self.assertIs(outcome['result']['user_enabled'], True)
        self.assertIs(outcome['result']['network_enabled'], True)
        for role in ('user', 'network'):
            self.assertEqual(outcome['validator_origins'][role],
                             str((self.preview / 'tools' / ('windows_child_' + role + '_contract.py')).resolve()))

    def test_fresh_interpreter_still_rejects_wrong_validator_origin(self):
        for role in ('user', 'network'):
            with self.subTest(role=role):
                outcome = self._probe(import_root=self.original, user=role == 'user',
                                      network=role == 'network')
                self._assert_origin_refusal(outcome, role, self.original)

    def test_fresh_preview_interpreter_rejects_stale_run_attempt(self):
        for role in ('user', 'network'):
            with self.subTest(role=role):
                outcome = self._probe(user=role == 'user', network=role == 'network', attempt='2')
                self.assertEqual(outcome['status'], 'refused')
                label = 'USER' if role == 'user' else 'network'
                self.assertEqual(outcome['error'],
                                 'original fixture is not the expected ' + label + ' title run/attempt')

    def test_fresh_preview_interpreter_rejects_validator_source_hash_drift(self):
        for role, receipt_name in (('user', 'user-source.json'), ('network', 'network-source.json')):
            with self.subTest(role=role):
                receipt_path = self.data / role / receipt_name
                before = receipt_path.read_bytes()
                receipt = json.loads(before)
                receipt['validator_sha256'] = '0' * 64
                receipt_path.write_text(json.dumps(receipt))
                try:
                    outcome = self._probe(user=role == 'user', network=role == 'network')
                finally:
                    receipt_path.write_bytes(before)
                self.assertEqual(outcome['status'], 'refused')
                label = 'USER' if role == 'user' else 'network'
                self.assertEqual(outcome['error'], label + ' source/recipe/validator differs')


if __name__ == '__main__':
    unittest.main(verbosity=2)
