#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Actual neutral YAML gates and shell recipes on inert owned prerequisites.

This suite does not execute Wine, SDK compilers, hosted jobs, or target images.
The receipt checker itself has a separate actual-command/receipt suite.
"""
import copy
import itertools
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest

import yaml

sys.dont_write_bytecode = True
from test_windows_child_workflow_options import actual_gate, base_context, HEAVY, IPC, PREVIEW, REGULAR, SEED

ROOT = Path(__file__).resolve().parents[1]
LABEL = 'build-focus-neutral-target-compile-only'
CONFLICTS = (REGULAR, PREVIEW, IPC)


def workflow(name='focus-neutral-target-compile'):
    return yaml.load((ROOT / '.github/workflows' / (name + '.yml')).read_text(), Loader=yaml.BaseLoader)


def steps(flow):
    return {s.get('id', s.get('name', str(i))): s
            for i, s in enumerate(flow['jobs']['target-translation-units']['steps'])}


def group(flow, context, prefix):
    expression = flow['concurrency']['group']
    assert expression.startswith(prefix)
    return prefix + str(actual_gate(expression[len(prefix):], context))


def event_contract(neutral, old):
    """Independent truth table spanning both actual workflows, including conflicts."""
    for bits, action, trigger, fork, seed in itertools.product(
            itertools.product((False, True), repeat=4),
            ('opened', 'synchronize', 'reopened', 'labeled', 'unlabeled', 'closed'),
            (LABEL, *CONFLICTS, 'documentation', LABEL + '-other', ''),
            (False, True), (False, True)):
        labels = [label for label, present in zip((LABEL, *CONFLICTS), bits) if present]
        context = base_context(**{'labels': labels, 'github.event.action': action,
            'github.event.label.name': trigger,
            'github.event.pull_request.head.repo.full_name': 'fork/prospero-win' if fork else 'Sleepywalker69/prospero-win',
            'github.event.pull_request.head.ref': SEED if seed else 'reviewed-change'})
        admitted = (not fork and not seed and LABEL in labels and
                    (action in ('opened', 'synchronize', 'reopened') or
                     (action == 'labeled' and trigger == LABEL)))
        conflict = bool(set(CONFLICTS).intersection(labels))
        heavy = admitted and not conflict
        assert actual_gate(neutral['jobs']['target-translation-units']['if'], context) is heavy, context
        rejection_event = admitted or (not fork and not seed and LABEL in labels and
            action == 'labeled' and trigger in CONFLICTS and trigger in labels)
        assert actual_gate(neutral['jobs']['reject-conflicting-options']['if'], context) is (rejection_event and conflict), context
        prefix = 'focus-neutral-target-compile-'
        assert group(neutral, context, prefix) == prefix + (context['github.ref'] if heavy else context['github.run_id']), context
        old_event = ((action in ('opened', 'synchronize', 'reopened') and conflict) or
                     (action == 'labeled' and trigger in CONFLICTS and trigger in labels))
        old_heavy = (not fork and not seed and old_event and LABEL not in labels and
                     not (IPC in labels and PREVIEW in labels))
        for name in HEAVY:
            assert actual_gate(old['jobs'][name]['if'], context) is old_heavy, (name, context)
        ipc = old_heavy and IPC in labels and (action != 'labeled' or trigger == IPC)
        assert actual_gate(old['jobs']['chromium-ipc-reference']['if'], context) is ipc, context
        old_prefix = 'windows-child-fixture-'
        assert group(old, context, old_prefix) == old_prefix + (context['github.ref'] if old_heavy else context['github.run_id']), context
    # Dispatch is specific to the selected workflow, not a cross-workflow event.
    for enabled, labels in itertools.product((True, False, ''), ([], [LABEL], [LABEL, *CONFLICTS])):
        context = base_context(**{'github.event_name': 'workflow_dispatch', 'labels': labels,
            'inputs.focus_neutral_target_compile_only': enabled})
        assert actual_gate(neutral['jobs']['target-translation-units']['if'], context) is (enabled is True)
        assert not actual_gate(neutral['jobs']['reject-conflicting-options']['if'], context)
    for event, ref, deleted in itertools.product(('push', 'pull_request_target', 'issues', 'workflow_run'),
            ('refs/heads/' + SEED, 'refs/heads/other'), (False, True)):
        context = base_context(**{'github.event_name': event, 'github.ref': ref,
                                 'github.event.deleted': deleted, 'labels': [LABEL, *CONFLICTS]})
        for job in neutral['jobs'].values(): assert not actual_gate(job['if'], context), context
        assert group(neutral, context, 'focus-neutral-target-compile-').endswith(context['github.run_id'])


class WorkflowContract(unittest.TestCase):
    def test_both_actual_workflows_exhaustive_event_and_concurrency_truth(self):
        event_contract(workflow(), workflow('windows-child-fixture'))

    def test_recipe_scope_and_pinned_reviewed_head(self):
        flow = workflow(); selected = steps(flow)
        self.assertEqual(flow['on'], {'workflow_dispatch': {'inputs': {
            'focus_neutral_target_compile_only': {'description': 'Compile fresh same-source default962 then neutral963 target translation units only',
                'type': 'boolean', 'required': 'false', 'default': 'false'}}},
            'pull_request': {'types': ['opened', 'synchronize', 'reopened', 'labeled']}})
        self.assertEqual(flow['permissions'], {'contents': 'read'})
        self.assertEqual(flow['concurrency']['cancel-in-progress'], 'false')
        self.assertEqual(set(flow['jobs']), {'reject-conflicting-options', 'target-translation-units'})
        job = flow['jobs']['target-translation-units']
        self.assertNotIn('needs', job); self.assertNotIn('strategy', job)
        self.assertEqual(job['timeout-minutes'], '150')
        checkout = job['steps'][0]
        self.assertEqual(checkout['with'], {'ref': '${{ github.event.pull_request.head.sha || github.sha }}',
                                          'persist-credentials': 'false'})
        self.assertEqual(selected['paths']['env']['EXPECTED_SOURCE_SHA'], checkout['with']['ref'])
        for name in ('host-tools', 'dependencies', 'paired-compile', 'collect'):
            self.assertNotIn('continue-on-error', selected[name])
            self.assertNotIn('if', selected[name])
        combined = '\n'.join(s.get('run', '') + s.get('uses', '') for s in job['steps'])
        for forbidden in ('wine_compile_cache.py', 'actions/cache', 'build_native.sh', 'ps5-native-tool',
                          'native_app_builder.cpp', 'setup-native-dependencies.sh', 'build_wine_service_child',
                          'prepare_windows_child_prefix', 'package_windows_child_fixture', 'check_wine_prx_build',
                          'wine_workflow_join', 'build_windows_child', '--without-gnutls', '--prx-foundation'):
            self.assertNotIn(forbidden, combined)
        self.assertEqual(combined.count('sh tools/build_host_wine.sh'), 1)
        self.assertIn('--tools-only', selected['host-tools']['run'])
        self.assertEqual(combined.count('make -C "$TITLE_FOUNDATION" deps libc'), 1)
        self.assertEqual(combined.count('sh tools/build_tls_ps5.sh'), 1)
        for pin in ('490f6d5dcbb2a5047345b8af88d114bbcaad69a8',
                    '9c0b994a048521af6fb84c73ded364504fe250e9', '4eb701204fc3f8d31e84cf8ca272974e2be9c867'):
            self.assertIn(pin, selected['sources']['run'])
        uploads = [s for s in job['steps'] if s.get('uses', '').startswith('actions/upload-artifact@')]
        self.assertEqual(len(uploads), 2)
        self.assertEqual(uploads[0]['if'], "${{ success() && steps.collect.outcome == 'success' }}")
        self.assertEqual(uploads[0]['with']['name'], 'focus-neutral-target-translation-units-${{ steps.paths.outputs.commit }}-${{ github.run_attempt }}')
        self.assertEqual(uploads[0]['with']['path'], '${{ env.GATE_ARTIFACT }}/')
        self.assertIn('unaccepted', uploads[1]['with']['name'])
        self.assertIn("steps.diagnostics.outcome == 'success'", uploads[1]['if'])
        for s in job['steps']:
            if 'run' in s:
                result = subprocess.run(['bash', '-n'], input=s['run'], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, (s.get('name'), result.stderr))

    def test_rejected_and_ignored_runs_do_not_displace_admitted_runs(self):
        flow = workflow(); prefix = 'focus-neutral-target-compile-'
        admitted = base_context(**{'labels': [LABEL], 'github.event.label.name': LABEL})
        accepted = group(flow, admitted, prefix)
        self.assertEqual(accepted, group(flow, dict(admitted, **{'github.run_id': '987655'}), prefix))
        groups = {accepted}
        for number, change in enumerate(({'labels': [LABEL, REGULAR]}, {'labels': [LABEL, PREVIEW]},
                {'labels': [LABEL, IPC]}, {'github.event.label.name': 'documentation'},
                {'github.event.label.name': 'documentation'}, {'labels': []})):
            context = dict(admitted, **dict(change, **{'github.run_id': str(987660 + number)}))
            selected = group(flow, context, prefix)
            self.assertNotIn(selected, groups); groups.add(selected)

    def test_each_conflict_refusal_is_inert_and_fails_visibly(self):
        reject = workflow()['jobs']['reject-conflicting-options']
        self.assertEqual(reject['timeout-minutes'], '2')
        self.assertEqual(len(reject['steps']), 1)
        self.assertNotIn('needs', reject)
        result = subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', reject['steps'][0]['run']], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn('::error::', result.stdout)


class ActualShell(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='neutral workflow inert ')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name); self.repo = self.base / 'project'; self.repo.mkdir()
        self.tools = self.repo / 'tools'; self.tools.mkdir(); self.bin = self.base / 'bin'; self.bin.mkdir()
        self.runner = self.base / 'runner'; self.runner.mkdir()
        self.root = self.runner / 'focus-target-123456-2'
        self.selected = steps(workflow())
        for filename in ('github-env', 'github-output'): (self.base / filename).touch()
        subprocess.run(['git', 'init', '-q', str(self.repo)], check=True)
        self.write('tools/build_wine_ps5.sh', 'WINE_COMMIT=490f6d5dcbb2a5047345b8af88d114bbcaad69a8\n')
        # Each inert leaf rejects wrong argv/selectors; only the workflow is under test here.
        self.write('tools/build_host_wine.sh', '''#!/bin/sh
set -eu
python3 "$(dirname "$0")/inert.py" host "$@"
''')
        self.write('tools/build_tls_ps5.sh', '''#!/bin/sh
set -eu
python3 "$(dirname "$0")/inert.py" tls "$@"
''')
        self.write('tools/tls_manifest.py', '''import json,os,pathlib,sys
assert sys.argv[1] in ('select-llvm','verify')
if sys.argv[1]=='verify':
    root=pathlib.Path(sys.argv[sys.argv.index('--root')+1])
    expected=json.loads((root/'tls-build-manifest.json').read_text())
    assert expected['path']==os.environ['PATH'], 'TLS PATH differs'
    assert expected['llvm']==os.environ['LLVM_CONFIG'], 'TLS LLVM differs'
print('/usr/bin/llvm-config-18')
''')
        self.write('tools/inert.py', '''import json, os, pathlib, sys
repo = pathlib.Path(__file__).resolve().parents[1]
kind = sys.argv[1]; args = sys.argv[2:]
work = pathlib.Path(args[args.index('--work')+1])
assert not work.exists(), 'stale prerequisite'
for key in ('PW_WINE_CACHED_CC','CCACHE_DIR','PW_CACHE_MATCHED_KEY','PW_WINE_CHILD_UI_ENABLED','PW_WINE_IPC_ENABLED','PS5VK_SDK','CPPFLAGS'):
    assert key not in os.environ, key
assert os.environ['LLVM_CONFIG']=='/usr/bin/llvm-config-18'
if kind=='host':
    assert args[-1]=='--tools-only'
    assert os.environ['PW_WINE_FOCUS_NEUTRAL']=='0'
    (work/'build/tools/winebuild').mkdir(parents=True)
    (work/'build/tools/winebuild/winebuild').write_text('inert host tool')
    (work/'build/.prospero-stamp').write_text('inert stamp')
else:
    (work/'root').mkdir(parents=True)
    (work/'root/tls-build-manifest.json').write_text(json.dumps({'path':os.environ['PATH'],'llvm':os.environ['LLVM_CONFIG']}))
with (repo/'calls.jsonl').open('a') as stream: stream.write(json.dumps({'kind':kind,'args':args})+'\\n')
''')
        self.write('tools/check_focus_target_compile.py', '''import argparse,json,os,pathlib,sys
repo=pathlib.Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('command')
for key in ('repo','wine-source','host-tools','foundation','sdk','sdk-source','tls','work','out','neutral','run-id','run-attempt','jobs','control'):
    p.add_argument('--'+key)
a=p.parse_args(); out=pathlib.Path(a.out)
if a.command=='run':
    assert a.neutral in ('0','1')
    assert os.environ['PW_WINE_FOCUS_NEUTRAL']==a.neutral
    assert os.environ['PW_WINE_PRIVATE_DISPATCH']==os.environ['PW_WINE_SERVICE_FIXTURE']=='1'
    assert os.environ['CFLAGS']=='-O2 -g'
    assert os.environ['PROSPERO_TLS_ROOT']==a.tls
    assert os.environ['LLVM_CONFIG']=='/usr/bin/llvm-config-18'
    assert a.run_id=='123456' and a.run_attempt=='2' and a.jobs in ('1','2','4')
    assert (pathlib.Path(a.host_tools)/'.prospero-stamp').is_file()
    tls=json.loads((pathlib.Path(a.tls)/'tls-build-manifest.json').read_text())
    assert tls=={'path':os.environ['PATH'],'llvm':os.environ['LLVM_CONFIG']}, 'run compiler environment differs'
    for key in ('PW_WINE_CACHED_CC','CCACHE_DIR','PW_CACHE_MATCHED_KEY','PW_WINE_CHILD_UI_ENABLED','PW_WINE_IPC_ENABLED','PS5VK_SDK','CPPFLAGS'):
        assert key not in os.environ,key
    work=pathlib.Path(a.work);assert not work.exists() and not out.exists()
    assert work.parent==out.parent and work!=out and pathlib.Path(a.repo) not in work.parents
    work.mkdir();out.mkdir();(out/'driver.log').write_text('inert driver')
    with (repo/'calls.jsonl').open('a') as stream: stream.write(json.dumps({'kind':'run','args':vars(a),'env':dict(os.environ)})+'\\n')
    if (repo/('fail-'+a.neutral)).exists(): sys.exit(19 if a.neutral=='0' else 23)
    (out/'TARGET-COMPILE.json').write_text(json.dumps({'schema':'pw-focus-target-translation-units/1','neutral':a.neutral,'path':os.environ['PATH'],'llvm':os.environ['LLVM_CONFIG']}))
else:
    assert a.command=='collect' and not out.exists()
    for mode,directory in (('0',a.control),('1',a.neutral)):
        got=json.loads((pathlib.Path(directory)/'TARGET-COMPILE.json').read_text());assert got['neutral']==mode
        assert got['path']==os.environ['PATH'] and got['llvm']==os.environ['LLVM_CONFIG'], 'collect compiler environment differs'
    if (repo/'fail-collect').exists(): sys.exit(29)
    out.mkdir();(out/'TRANSLATION-UNIT-VALIDATION.json').write_text('{}')
    with (repo/'calls.jsonl').open('a') as stream: stream.write(json.dumps({'kind':'collect','args':vars(a)})+'\\n')
''')
        make = self.bin / 'make'
        make.write_text('#!/usr/bin/python3\nimport pathlib,sys\na=sys.argv[1:]\nassert a[0]=="-C" and a[2:]==["deps","libc"]\nsdk=pathlib.Path(a[1])/".deps/native/ps5-payload-sdk/bin"\nsdk.mkdir(parents=True)\n(sdk/"prospero-clang").write_text("inert sdk")\n')
        make.chmod(0o755)
        subprocess.run(['git', '-C', str(self.repo), 'add', '.'], check=True)
        subprocess.run(['git', '-C', str(self.repo), '-c', 'user.name=Inert', '-c', 'user.email=inert@example.invalid', 'commit', '-qm', 'inert shell inputs'], check=True)
        sha = subprocess.check_output(['git', '-C', str(self.repo), 'rev-parse', 'HEAD'], text=True).strip()
        self.env = dict(os.environ, GITHUB_WORKSPACE=str(self.repo), RUNNER_TEMP=str(self.runner),
            GITHUB_RUN_ID='123456', GITHUB_RUN_ATTEMPT='2', EXPECTED_SOURCE_SHA=sha,
            GITHUB_ENV=str(self.base/'github-env'), GITHUB_OUTPUT=str(self.base/'github-output'),
            LLVM_CONFIG='/usr/bin/llvm-config-18', CLEAN_PATH=str(self.bin)+':/usr/bin:/bin', BUILD_JOBS='2',
            # Deliberately poisoned inherited selectors and cache wrappers.
            PW_WINE_CACHED_CC='/invalid/cached-cc', CCACHE_DIR='/invalid/cache',
            PW_CACHE_MATCHED_KEY='stale', PW_WINE_CHILD_UI_ENABLED='1', PW_WINE_IPC_ENABLED='1',
            PS5VK_SDK='/invalid/vulkan', CPPFLAGS='-DWRONG=1')
        self.run_step('paths')
        for key in ('WINE_SOURCE','SDK_SOURCE','TITLE_FOUNDATION'): Path(self.env[key]).mkdir()

    def write(self, name, text):
        (self.repo / name).write_text(textwrap.dedent(text))

    def run_step(self, name, expected=0, script=None):
        result = subprocess.run(['bash', '--noprofile', '--norc', '-e', '-o', 'pipefail', '-c',
            self.selected[name]['run'] if script is None else script], env=self.env, cwd=self.repo,
            capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, expected, result.stdout+result.stderr)
        for line in (self.base/'github-env').read_text().splitlines():
            key, value = line.split('=',1); self.env[key]=value
        return result

    def prepare(self):
        self.run_step('build-resources'); self.run_step('host-tools'); self.run_step('dependencies')

    def calls(self):
        return [json.loads(line) for line in (self.repo/'calls.jsonl').read_text().splitlines()]

    def test_actual_source_fetch_pin_checks_without_network(self):
        git = self.bin / 'git'
        git.write_text('#!/usr/bin/python3\n' + textwrap.dedent("""\
            import os,pathlib,sys
            a=sys.argv[1:]
            if a[0]=='init':
                pathlib.Path(a[-1]).mkdir(exist_ok=True)
            else:
                assert a[0]=='-C'; destination=pathlib.Path(a[1]); command=a[2]
                if command=='fetch':
                    assert a[3]=='--depth=1' and a[4]=='origin'
                    (destination/'.inert-pin').write_text(a[5])
                elif command=='rev-parse':
                    pin=(destination/'.inert-pin').read_text()
                    print('0'*40 if os.environ.get('INERT_BAD_PIN') else pin)
                else:
                    assert command in ('remote','checkout')
            """))
        git.chmod(0o755)
        self.env['PATH']=str(self.bin)+':'+os.environ['PATH']
        self.run_step('sources')
        for key,pin in (('WINE_SOURCE','490f6d5dcbb2a5047345b8af88d114bbcaad69a8'),
                        ('TITLE_FOUNDATION','9c0b994a048521af6fb84c73ded364504fe250e9'),
                        ('SDK_SOURCE','4eb701204fc3f8d31e84cf8ca272974e2be9c867')):
            self.assertEqual((Path(self.env[key])/'.inert-pin').read_text(),pin)
        self.env['INERT_BAD_PIN']='1'
        self.run_step('sources',1)
        self.assertFalse(Path(self.env['HOST_WORK']).exists())

    def test_paths_refuse_reused_root_or_changed_reviewed_commit(self):
        self.run_step('paths',1)
        self.env['EXPECTED_SOURCE_SHA']='0'*40
        self.run_step('paths',1)
        self.assertFalse(Path(self.env['HOST_WORK']).exists())

    def test_actual_shell_orders_shared_uncached_prerequisites_then_fresh_962_963(self):
        self.prepare(); self.run_step('paired-compile'); self.run_step('collect')
        calls=self.calls(); self.assertEqual([c['kind'] for c in calls], ['host','tls','run','run','collect'])
        first,second=[c['args'] for c in calls if c['kind']=='run']
        self.assertEqual((first['neutral'],second['neutral']), ('0','1'))
        for key in ('repo','wine_source','host_tools','foundation','sdk','sdk_source','tls','jobs'):
            self.assertEqual(first[key],second[key],key)
        self.assertNotEqual(first['work'],second['work']);self.assertNotEqual(first['out'],second['out'])
        self.assertTrue((Path(self.env['GATE_ARTIFACT'])/'TRANSLATION-UNIT-VALIDATION.json').is_file())

    def test_actual_environment_binding_refuses_unsanitized_verify_and_collect(self):
        # Exercise precisely the former integration defect, not just a YAML string match.
        self.run_step('host-tools')
        dependencies = self.selected['dependencies']['run']
        marker = 'python3 tools/tls_manifest.py verify'
        start = dependencies.rfind('env -i ', 0, dependencies.index(marker))
        altered = dependencies[:start] + dependencies[dependencies.index(marker):]
        self.run_step('dependencies', 1, altered)
        self.assertFalse(Path(self.env['CONTROL_WORK']).exists())
        # The SDK/TLS fixture already exists after that intentional late failure.
        self.env['PS5_PAYLOAD_SDK'] = str(Path(self.env['TITLE_FOUNDATION'])/'.deps/native/ps5-payload-sdk')
        self.run_step('paired-compile')
        collect = self.selected['collect']['run']
        begin = collect.index('env -i ')
        altered = collect[:begin] + collect[collect.index('python3 tools/check_focus_target_compile.py collect'):]
        self.run_step('collect', 1, altered)
        self.assertFalse(Path(self.env['GATE_ARTIFACT']).exists())
        self.run_step('collect')

    def test_default_failure_prevents_any_neutral_or_collection(self):
        self.prepare();(self.repo/'fail-0').touch();self.run_step('paired-compile',19)
        self.assertEqual([c['args']['neutral'] for c in self.calls() if c['kind']=='run'], ['0'])
        self.assertFalse(Path(self.env['NEUTRAL_WORK']).exists())
        self.assertFalse((Path(self.env['CONTROL_RECEIPTS'])/'TARGET-COMPILE.json').exists())
        self.assertFalse(Path(self.env['GATE_ARTIFACT']).exists())
        self.run_step('diagnostics')
        self.assertFalse(json.loads((self.root/'unaccepted-diagnostics/UNACCEPTED.json').read_text())['accepted'])

    def test_neutral_failure_and_collection_failure_never_produce_success_artifact(self):
        self.prepare();(self.repo/'fail-1').touch();self.run_step('paired-compile',23)
        self.assertEqual([c['args']['neutral'] for c in self.calls() if c['kind']=='run'], ['0','1'])
        self.assertFalse((Path(self.env['NEUTRAL_RECEIPTS'])/'TARGET-COMPILE.json').exists())
        self.assertFalse(Path(self.env['GATE_ARTIFACT']).exists())
        self.run_step('diagnostics')

    def test_collector_failure_is_not_hidden(self):
        self.prepare();self.run_step('paired-compile');(self.repo/'fail-collect').touch()
        self.run_step('collect',29);self.assertFalse(Path(self.env['GATE_ARTIFACT']).exists())
        self.run_step('diagnostics')
        report=json.loads((self.root/'unaccepted-diagnostics/UNACCEPTED.json').read_text())
        for flag in ('accepted','complete_runtime','target_executed','descendants_settled'):
            self.assertIs(report[flag], False)
        self.assertTrue({'control-receipts/driver.log','neutral-receipts/driver.log'} <=
                        {row['path'] for row in report['logs']})

    def test_existing_work_receipt_and_link_refused_before_compilation(self):
        self.prepare()
        for key in ('CONTROL_WORK','CONTROL_RECEIPTS'):
            path=Path(self.env[key]);path.mkdir()
            self.run_step('paired-compile',1);self.assertEqual(len(self.calls()),2);path.rmdir()
            path.symlink_to(self.base/'missing',target_is_directory=True)
            self.run_step('paired-compile',1);self.assertEqual(len(self.calls()),2);path.unlink()

    def test_changed_mode_is_caught_by_actual_inert_helper_contract(self):
        self.prepare()
        script=self.selected['paired-compile']['run'].replace('PW_WINE_FOCUS_NEUTRAL="$mode"','PW_WINE_FOCUS_NEUTRAL=1')
        self.run_step('paired-compile',1,script)
        self.assertFalse(Path(self.env['GATE_ARTIFACT']).exists())

    def test_failure_diagnostics_are_bounded_and_do_not_follow_symlinks(self):
        evidence=self.root/'evidence';(evidence/'large.log').write_bytes(b'x'*(300*1024))
        outside=self.base/'secret.log';outside.write_text('not a log source')
        (evidence/'linked.log').symlink_to(outside)
        (evidence/'linked-directory').symlink_to(self.base,target_is_directory=True)
        for i in range(40): (evidence/('small-%02d.log'%i)).write_text('small')
        (evidence/'not-a-log.bin').write_bytes(b'not retained')
        self.run_step('diagnostics');out=self.root/'unaccepted-diagnostics'
        report=json.loads((out/'UNACCEPTED.json').read_text())
        self.assertEqual(len(report['logs']),32)
        self.assertLessEqual(sum(r['retained_bytes'] for r in report['logs']),8*1024*1024)
        self.assertFalse(report['accepted']);self.assertFalse(report['descendants_settled'])
        self.assertTrue(report['logs'][0]['truncated'])
        self.assertFalse((out/'evidence/linked.log').exists())
        self.assertFalse((out/'evidence/linked-directory').exists())
        self.assertFalse((out/'evidence/not-a-log.bin').exists())

    def test_critical_paired_tails_survive_crowded_prerequisite_and_control_trees(self):
        critical = []
        for mode in ('neutral', 'control'):
            critical.append(mode + '-receipts/driver.log')
            critical.extend(mode + '-work/' + name for name in
                            ('service-translation-units.log', 'configure.log', 'build/config.log', 'focus-neutral-stage.log'))
        for name in critical:
            path = self.root/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'HEAD-MUST-NOT-SURVIVE' + b'x'*(256*1024) + b'INNER-ERROR-TAIL')
        for directory in ('evidence', 'host-tools', 'tls', 'control-work/aaa'):
            root = self.root/directory
            root.mkdir(parents=True, exist_ok=True)
            for i in range(40): (root/('aaa-%02d.log'%i)).write_text('prerequisite')
        self.run_step('diagnostics')
        out = self.root/'unaccepted-diagnostics'
        records = json.loads((out/'UNACCEPTED.json').read_text())['logs']
        self.assertEqual(len(records), 32)
        self.assertEqual(len({r['path'] for r in records}), 32)
        self.assertLessEqual(sum(r['retained_bytes'] for r in records), 8*1024*1024)
        by_name = {r['path']: r for r in records}
        for name in critical:
            self.assertIn(name, by_name)
            self.assertTrue(by_name[name]['truncated'])
            self.assertEqual(by_name[name]['retained_bytes'], 256*1024)
            data = (out/name).read_bytes()
            self.assertTrue(data.endswith(b'INNER-ERROR-TAIL'))
            self.assertNotIn(b'HEAD-MUST-NOT-SURVIVE', data)

    def test_priority_paths_refuse_links_and_fifo_and_keep_exact_tail_boundary(self):
        evidence = self.root/'evidence'
        (evidence/'exact.log').write_bytes(b'e'*(256*1024))
        (evidence/'over.log').write_bytes(b'h' + b't'*(256*1024))
        os.mkfifo(evidence/'pipe.log')
        outside = self.base/'outside'
        outside.mkdir()
        (outside/'driver.log').write_text('must not retain')
        (self.root/'neutral-receipts').symlink_to(outside, target_is_directory=True)
        work = self.root/'neutral-work'
        work.mkdir()
        (work/'configure.log').symlink_to(outside/'driver.log')
        (work/'build').symlink_to(outside, target_is_directory=True)
        (outside/'config.log').write_text('must not retain')
        self.run_step('diagnostics')
        out = self.root/'unaccepted-diagnostics'
        rows = {r['path']: r for r in json.loads((out/'UNACCEPTED.json').read_text())['logs']}
        self.assertEqual(set(rows), {'evidence/exact.log', 'evidence/over.log'})
        self.assertFalse(rows['evidence/exact.log']['truncated'])
        self.assertEqual(rows['evidence/exact.log']['original_bytes'], 256*1024)
        self.assertTrue(rows['evidence/over.log']['truncated'])
        self.assertEqual(rows['evidence/over.log']['original_bytes'], 256*1024+1)
        self.assertEqual((out/'evidence/over.log').read_bytes(), b't'*(256*1024))


if __name__ == '__main__': unittest.main()
