#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Evaluate actual Actions gates; no guest, target or hosted build executes."""
import ast
import copy
import itertools
from pathlib import Path
import re
import subprocess
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
REGULAR = 'build-windows-child-fixture'
PREVIEW = 'build-child-ui-preview-static'
IPC = 'build-windows-chromium-ipc-strict'
SEED = 'perf/windows-child-incremental-cache'
HEAVY = ('original-x64-reference', 'original-user-x64-reference',
         'original-network-x64-reference', 'matched-runtime')
PREVIEW_STEPS = ('Build the opt-in enabled preview in fresh isolated outputs',
                 'Recheck both modes and collect static-only preview evidence with exact sources',
                 'Upload the isolated preview static-validation artifact')


def workflow():
    return yaml.load((ROOT / '.github/workflows/windows-child-fixture.yml').read_text(),
                     Loader=yaml.BaseLoader)


def actual_gate(expression, context):
    """Interpret the bounded grammar used by the actual workflow expressions.

    Operands in these tests are booleans and strings supplied by the typed inputs
    and event contexts. This deliberately does not emulate all Actions syntax.
    """
    value = expression.strip()
    if not value.startswith('${{') or not value.endswith('}}'):
        raise AssertionError('not an Actions expression')
    value = value[3:-2]
    value = re.sub(r"contains\(github\.event\.pull_request\.labels\.\*\.name, '([^']+)'\)",
                   lambda m: repr(m[1].casefold() in [s.casefold() for s in context.get('labels', [])]), value)
    value = re.sub(r'\b(?:github|inputs|env)\.[a-zA-Z0-9_.]+',
                   lambda m: repr(context.get(m[0], '')), value)
    value = value.replace('always()', 'true').replace('&&', ' and ').replace('||', ' or ')
    value = re.sub(r'!(?!=)', ' not ', value)
    value = re.sub(r'\bfalse\b', 'False', value)
    value = re.sub(r'\btrue\b', 'True', value)

    def visit(node):
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bool)):
            return node.value
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return not visit(node.operand)
        if isinstance(node, ast.BoolOp) and isinstance(node.op, (ast.And, ast.Or)):
            result = visit(node.values[0])
            for item in node.values[1:]:
                if isinstance(node.op, ast.And) and not result:
                    return result
                if isinstance(node.op, ast.Or) and result:
                    return result
                result = visit(item)
            return result
        if isinstance(node, ast.Compare) and len(node.ops) == len(node.comparators) == 1:
            left, right = visit(node.left), visit(node.comparators[0])
            if isinstance(left, str) and isinstance(right, str):
                left, right = left.casefold(), right.casefold()
            if isinstance(node.ops[0], ast.Eq):
                return left == right
            if isinstance(node.ops[0], ast.NotEq):
                return left != right
        raise AssertionError('unsupported gate grammar: ' + ast.dump(node))

    return visit(ast.parse('(' + value.strip() + ')', mode='eval').body)


def base_context(**changes):
    return dict({'github.event_name': 'pull_request',
                 'github.repository': 'Sleepywalker69/prospero-win',
                 'github.ref': 'refs/pull/123/merge', 'github.run_id': '987654',
                 'github.event.deleted': False, 'github.event.action': 'labeled',
                 'github.event.label.name': IPC,
                 'github.event.pull_request.head.repo.full_name': 'Sleepywalker69/prospero-win',
                 'github.event.pull_request.head.ref': 'reviewed-change',
                 'inputs.enable_chromium_ipc': False, 'inputs.child_ui_preview': False,
                 'labels': [IPC]}, **changes)


def check_context(flow, context, heavy, ipc, preview, rejected):
    """Check decisions and concurrency against independently expected results."""
    jobs = flow['jobs']
    for name in HEAVY:
        assert actual_gate(jobs[name]['if'], context) is heavy, (name, context)
    assert actual_gate(jobs['chromium-ipc-reference']['if'], context) is ipc, context
    assert actual_gate(jobs['reject-conflicting-options']['if'], context) is rejected, context
    flag = actual_gate(jobs['matched-runtime']['env']['PW_IPC_REQUESTED'], context)
    assert flag == ('1' if ipc else '0'), (flag, context)
    steps = {step.get('name'): step for step in jobs['matched-runtime']['steps']}
    for name in PREVIEW_STEPS:
        if name in steps:
            # A skipped job never executes its step conditions. Retain the
            # established preview recipe verbatim while testing effective use.
            assert (heavy and actual_gate(steps[name]['if'], context)) is preview, (name, context)
    evidence = steps.get('Keep bounded preview logs even when its validation fails')
    if evidence:
        assert (heavy and actual_gate(evidence['if'], context)) is preview, context
    prefix = 'windows-child-fixture-'
    assert flow['concurrency']['group'].startswith(prefix)
    group = prefix + str(actual_gate(flow['concurrency']['group'][len(prefix):], context))
    assert group == prefix + (context['github.ref'] if heavy else context['github.run_id']), context
    return group


def event_contract(flow):
    has_preview = 'child_ui_preview' in flow['on']['workflow_dispatch']['inputs']
    supported = {REGULAR, IPC} | ({PREVIEW} if has_preview else set())
    # All label subsets, trigger labels, allowed/disallowed actions, forks, and
    # duplicate push-backed heads are tested against the real YAML conditions.
    for bits, action, trigger, fork, seed in itertools.product(
            itertools.product((False, True), repeat=3),
            ('opened', 'synchronize', 'reopened', 'labeled', 'unlabeled', 'closed'),
            (REGULAR, PREVIEW, IPC, 'documentation', IPC + '-other', ''),
            (False, True), (False, True)):
        labels = [label for label, present in zip((REGULAR, PREVIEW, IPC), bits) if present]
        context = base_context(**{'labels': labels, 'github.event.action': action,
            'github.event.label.name': trigger,
            'github.event.pull_request.head.repo.full_name': 'fork/prospero-win' if fork else 'Sleepywalker69/prospero-win',
            'github.event.pull_request.head.ref': SEED if seed else 'reviewed-change'})
        event_allowed = (action in ('opened', 'synchronize', 'reopened') and bool(supported.intersection(labels))) or (
            action == 'labeled' and trigger in supported and trigger in labels)
        admitted = not fork and not seed and event_allowed
        conflict = IPC in labels and PREVIEW in labels
        heavy = admitted and not conflict
        ipc = heavy and IPC in labels and (action != 'labeled' or trigger == IPC)
        preview = has_preview and heavy and PREVIEW in labels and (action != 'labeled' or trigger == PREVIEW)
        check_context(flow, context, heavy, ipc, preview, admitted and conflict)
    # Typed boolean dispatch inputs, omitted inputs, and stale PR metadata.
    for ipc, preview, labels in itertools.product((False, True, ''), (False, True, ''),
                                                  ([], [IPC, PREVIEW], [REGULAR])):
        context = base_context(**{'github.event_name': 'workflow_dispatch',
            'inputs.enable_chromium_ipc': ipc, 'inputs.child_ui_preview': preview, 'labels': labels})
        conflict = ipc is True and preview is True
        check_context(flow, context, not conflict, ipc is True and not conflict,
                      has_preview and preview is True and not conflict, conflict)
    for event, ref, deleted in itertools.product(('push', 'pull_request_target', 'issues', 'workflow_run'),
            ('refs/heads/' + SEED, 'refs/heads/other', 'refs/tags/' + SEED), (False, True)):
        context = base_context(**{'github.event_name': event, 'github.ref': ref,
                                 'github.event.deleted': deleted, 'labels': [IPC, PREVIEW]})
        heavy = event == 'push' and ref == 'refs/heads/' + SEED and not deleted
        check_context(flow, context, heavy, False, False, False)
    assert flow['concurrency']['cancel-in-progress'] == 'false'
    assert flow['on']['pull_request']['types'] == ['opened', 'synchronize', 'reopened', 'labeled']


class WorkflowOptions(unittest.TestCase):
    def test_actual_event_input_and_concurrency_matrix(self):
        event_contract(workflow())

    def test_rejected_and_unrelated_events_cannot_displace_accepted_runs(self):
        flow = workflow()
        accepted = check_context(flow, base_context(), True, True, False, False)
        accepted_again = check_context(flow, base_context(**{'github.run_id': '987655'}), True, True, False, False)
        self.assertEqual(accepted, accepted_again)
        groups = {accepted}
        for index, changes in enumerate(({'github.event.label.name': 'documentation'},
                {'github.event.label.name': 'documentation'}, {'labels': [IPC, PREVIEW]},
                {'labels': [IPC, PREVIEW]}, {'github.event.pull_request.head.repo.full_name': 'fork/prospero-win'})):
            context = base_context(**dict(changes, **{'github.run_id': str(987660 + index)}))
            rejected = context['labels'] == [IPC, PREVIEW]
            group = check_context(flow, context, False, False, False, rejected)
            self.assertNotIn(group, groups)
            groups.add(group)

    def test_conflict_rejection_is_inert_and_precedes_all_heavy_work(self):
        flow = workflow()
        reject = flow['jobs']['reject-conflicting-options']
        self.assertEqual(reject['runs-on'], 'ubuntu-24.04')
        self.assertEqual(reject['timeout-minutes'], '2')
        self.assertNotIn('needs', reject)
        self.assertEqual(len(reject['steps']), 1)
        step = reject['steps'][0]
        self.assertEqual(set(step), {'name', 'shell', 'run'})
        self.assertNotIn('continue-on-error', reject)
        result = subprocess.run(['bash', '--noprofile', '--norc', '-e', '-o', 'pipefail', '-c', step['run']],
                                text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 1)
        self.assertIn('::error::', result.stdout)
        check_context(flow, base_context(**{'labels': [IPC, PREVIEW]}), False, False, False, True)

    def test_strict_ipc_option_and_same_cohort_references_are_preserved(self):
        flow = workflow()
        option = flow['on']['workflow_dispatch']['inputs']['enable_chromium_ipc']
        self.assertEqual({key: option[key] for key in ('type', 'required', 'default')},
                         {'type': 'boolean', 'required': 'false', 'default': 'false'})
        reference = flow['jobs']['chromium-ipc-reference']
        self.assertEqual(reference['uses'], './.github/workflows/windows-chromium-ipc-reference.yml')
        self.assertEqual(reference['permissions'], {'contents': 'read', 'actions': 'read'})
        self.assertNotIn('continue-on-error', reference)
        steps = {step.get('name'): step for step in flow['jobs']['matched-runtime']['steps']}
        join = steps['Join both actual IPC references from this complete run attempt']
        prepare = steps['Prepare the dedicated fresh eight-profile IPC prefix']
        for step in (join, prepare):
            self.assertEqual(step['if'], "${{ env.PW_IPC_REQUESTED == '1' }}")
            self.assertNotIn('continue-on-error', step)
        self.assertIn('tools/join_windows_chromium_ipc.py --repo "$GITHUB_WORKSPACE"', join['run'])
        self.assertIn('--run "$GITHUB_RUN_ID" --attempt "$GITHUB_RUN_ATTEMPT"', join['run'])
        self.assertIn('tools/windows_chromium_ipc_contract.py', join['run'])
        self.assertIn('initialize-ipc', prepare['run'])
        self.assertIn('export-ipc', prepare['run'])
        self.assertIn('"${ipc_args[@]}"', steps['Build the full-CRT child once and the matched title']['run'])
        package = steps['Retain corresponding sources and assemble the exact matched package']['run']
        self.assertIn("ipc_enabled = os.environ['PW_IPC_REQUESTED'] == '1'", package)
        self.assertIn("'ipc_enabled': ipc_enabled", package)

    def test_gate_mutations_are_rejected(self):
        original = workflow()
        mutations = (
            lambda f: f['jobs']['matched-runtime'].update(**{'if': '${{ true }}'}),
            lambda f: f['jobs']['chromium-ipc-reference'].update(**{'if': '${{ true }}'}),
            lambda f: f['jobs']['reject-conflicting-options'].update(**{'if': '${{ false }}'}),
            lambda f: f['jobs']['matched-runtime']['env'].update(PW_IPC_REQUESTED="${{ '1' }}"),
            lambda f: f['concurrency'].update(group='windows-child-fixture-${{ github.ref }}'),
            lambda f: f['concurrency'].update(group='windows-child-fixture-${{ github.run_id }}'),
            lambda f: f['concurrency'].update(**{'cancel-in-progress': 'true'}),
            lambda f: f['jobs']['matched-runtime'].update(**{'if': f['jobs']['matched-runtime']['if'].replace(
                "github.event.label.name == '" + IPC + "'", 'true')}),
            lambda f: f['jobs']['matched-runtime'].update(**{'if': f['jobs']['matched-runtime']['if'].replace(
                "contains(github.event.pull_request.labels.*.name, '" + IPC + "')", 'true')}),
            lambda f: f['jobs']['matched-runtime'].update(**{'if': f['jobs']['matched-runtime']['if'].replace(
                'github.event.pull_request.head.repo.full_name == github.repository', 'true')}),
        )
        for index, change in enumerate(mutations):
            with self.subTest(index=index):
                mutant = copy.deepcopy(original)
                change(mutant)
                with self.assertRaises(AssertionError):
                    event_contract(mutant)


if __name__ == '__main__':
    unittest.main()
