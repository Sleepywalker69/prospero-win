#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Synthetic verifier tests. They are not records of Windows execution."""
import importlib.util
from pathlib import Path
import tempfile
import sys
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('ipc_check', ROOT / 'tools/check_windows_chromium_ipc.py')
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


def row(stage, result='pass', **overrides):
    item = dict(schema=1, role='parent', case='self-memory', stage=stage, result=result,
                nonce=10, pid=100, parent=100, bits=64, elapsed_ms=1, deadline_ms=5000,
                error=0, ntstatus=0, bytes=0, a=0, b=0)
    item.update(overrides)
    return item


def good_rows(case='self-memory', role='parent'):
    stages = check.PARENT_STAGES[case] if role == 'parent' else {'handle_list_acknowledged'}
    rows = [row(stage, case=case, role=role) for stage in sorted(stages)]
    rows += [row('guest_cleanup', case=case, role=role),
             row('native_settlement', 'unverified', case=case, role=role),
             row('final', case=case, role=role)]
    return rows


def write(path, rows):
    path.write_text(''.join('PW_CHROMIUM_IPC ' + ' '.join(f'{k}={v}' for k, v in r.items()) + '\n' for r in rows))


def paired_rows(case):
    parent = good_rows(case)
    for item in parent:
        if item['stage'] == 'CreateProcessW_handle_list': item['a'] = 101
        if item['stage'] == 'final': item['a'] = check.CHILD_EXIT
        if item['stage'] == 'child_hello': item['b'] = 1
        if item['stage'] == 'identity_different_control': item['error'] = 1656
        if item['stage'] in ('identity_child_live', 'identity_child_still_live'): item['a'] = 258
        if item['stage'] == 'identity_reference_values': item['a'] = 10;item['b'] = 13
        if item['stage'] == 'identity_capture_reference': item['a'] = 13
        if item['stage'] == 'UpdateProcThreadAttribute_HANDLE_LIST': item['a'] = 5 if case in ('section-readonly', 'mojo-pipe') else 4
        if item['stage'] == 'handle_list_excluded': item['a'] = 1;item['error'] = 1656;item['b'] = 13
    child_stages = {'handle_list_acknowledged'}
    if case in ('live-memory', 'suspended-memory'):
        child_stages |= {'child_actual_private_value', 'WaitForSingleObject_release'}
    elif case.startswith('section-'):
        child_stages |= {'NtQuerySection', 'MapViewOfFile_section', 'section_byte_visibility', 'UnmapViewOfFile_section'}
        if case == 'section-readonly':
            child_stages |= {'MapViewOfFile_write_denied', 'DuplicateHandle_write_upgrade_denied'}
    elif case == 'mojo-pipe':
        child_stages |= {'CreateIoCompletionPort', 'GetQueuedCompletionStatus', 'iocp_peer_record'}
    child = [row(stage, case=case, role='child', pid=101) for stage in sorted(child_stages)]
    next(r for r in child if r['stage'] == 'handle_list_acknowledged')['a'] = 1
    evidence = [('identity_candidate_snapshot', 'observation_only', 1656, 10, 13),
                ('identity_child_reference_values', 'pass', 0, 10, 13),
                ('identity_child_duplicate_same', 'pass', 0, 0, 0),
                ('identity_child_same_control', 'pass', 0, 0, 0),
                ('identity_child_different_control', 'pass', 1656, 0, 0),
                ('identity_child_cross_type_control', 'pass', 1656, 0, 0),
                ('identity_child_invalid_control', 'pass', 6, 0, 0),
                ('identity_child_slot_verdict', 'pass', 1656, 1, 13)]
    child[0:0] = [row(stage, result, case=case, role='child', pid=101, error=error, a=a, b=b)
                  for stage, result, error, a, b in evidence]
    child += [row('guest_cleanup', case=case, role='child', pid=101),
              row('final', case=case, role='child', pid=101, a=check.CHILD_EXIT)]
    if case.startswith('section-'):
        for rows, role, pid in ((parent, 'parent', 100), (child, 'child', 101)):
            rows[:] = [item for item in rows if item['stage'] != 'section_byte_visibility']
            rows[0:0] = [row('section_byte_visibility', case=case, role=role, pid=pid, a=offset)
                         for offset in (0, 4096, 8192, 12288, 65532)]
    if case == 'mojo-pipe':
        parent[:] = [item for item in parent if item['stage'] != 'GetQueuedCompletionStatus']
        parent[0:0] = [row('GetQueuedCompletionStatus', case=case, error=error) for error in (0, 995, 109)]
        parent.insert(0, row('overlapped_ReadFile', 'pending', case=case, error=997))
    return parent, child


class ReferenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.path = self.directory / 'ipc-10-100.log'
        self.rows = good_rows()
        write(self.path, self.rows)

    def verify(self, exit_code=0):
        return check.verify(self.directory, 'self-memory', 64, exit_code)

    def test_accepts_complete_synthetic_reference(self):
        report = self.verify()
        self.assertEqual(report['windows_reference'], 'pass')
        self.assertEqual(report['ps5_execution'], 'not_run')
        self.assertEqual(report['native_settlement'], 'unverified')

    def test_rejects_every_missing_required_stage(self):
        for stage in check.PARENT_STAGES['self-memory']:
            with self.subTest(stage=stage):
                write(self.path, [r for r in self.rows if r['stage'] != stage])
                with self.assertRaises(ValueError): self.verify()

    def test_rejects_actual_nonzero_exit(self):
        for code in (1, 2, 77, 78, check.CHILD_EXIT):
            with self.assertRaises(ValueError): self.verify(code)

    def test_failure_cannot_be_repaired_by_later_pass(self):
        for result in ('fail', 'timeout', 'unsupported', 'not_run', 'cleanup_uncertain', 'uncertain'):
            with self.subTest(result=result):
                write(self.path, [row('bad', result)] + self.rows)
                with self.assertRaises(ValueError): self.verify()

    def test_requires_separate_clean_resource_count(self):
        for field in ('a', 'b'):
            rows = [r.copy() for r in self.rows]
            next(r for r in rows if r['stage'] == 'guest_cleanup')[field] = 1
            write(self.path, rows)
            with self.assertRaises(ValueError): self.verify()

    def test_rejects_mixed_nonce_and_width(self):
        for key, value in (('nonce', 11), ('bits', 32), ('pid', 101), ('parent', 101)):
            rows = [r.copy() for r in self.rows];rows[2][key] = value;write(self.path, rows)
            with self.assertRaises(ValueError): self.verify()

    def test_rejects_truncation_duplicate_field_and_clock_regression(self):
        raw = self.path.read_text()
        for invalid in (raw[:-1], raw.replace('schema=1', 'schema=1 schema=1', 1), raw.replace('elapsed_ms=1', 'elapsed_ms=2', 1)):
            self.path.write_text(invalid)
            with self.assertRaises(ValueError): self.verify()

    def test_rejects_extra_process_logs(self):
        write(self.directory / 'ipc-10-101.log', self.rows)
        with self.assertRaises(ValueError): self.verify()

    def test_requires_final_and_native_boundary(self):
        for stage in ('final', 'native_settlement', 'guest_cleanup'):
            write(self.path, [r for r in self.rows if r['stage'] != stage])
            with self.assertRaises(ValueError): self.verify()

    def test_rejects_unknown_result_overflow_and_native_contradiction(self):
        for key, value in (('result', 'almost_pass'), ('nonce', 1 << 32), ('bytes', 1 << 64), ('stage', 'invalid/stage')):
            rows = [r.copy() for r in self.rows];rows[0][key] = value;write(self.path, rows)
            with self.assertRaises(ValueError): self.verify()
        for result in ('pass', 'unverified'):
            write(self.path, self.rows[:-1] + [row('native_settlement', result)] + self.rows[-1:])
            with self.assertRaises(ValueError): self.verify()

    def test_accepts_all_child_cases_and_rejects_identity_or_full_exit_loss(self):
        for case in check.CASES[1:-1]:
            with self.subTest(case=case):
                parent, child = paired_rows(case)
                child_path = self.directory / 'ipc-10-101.log'
                write(self.path, parent);write(child_path, child)
                self.assertEqual(check.verify(self.directory, case, 64, 0)['windows_reference'], 'pass')
                for target, stage, key, value in ((parent, 'CreateProcessW_handle_list', 'a', 999),
                                                (parent, 'final', 'a', check.CHILD_EXIT & 255),
                                                (child, 'final', 'a', check.CHILD_EXIT & 255)):
                    item = next(r for r in target if r['stage'] == stage);saved = item[key];item[key] = value
                    write(self.path, parent);write(child_path, child)
                    with self.assertRaises(ValueError): check.verify(self.directory, case, 64, 0)
                    item[key] = saved
                child_path.unlink()

    def test_section_boundaries_and_readonly_denials_are_required(self):
        for case in ('section-readonly', 'section-duplicate', 'section-close-source'):
            parent, child = paired_rows(case);child_path = self.directory / 'ipc-10-101.log'
            for role, rows in (('parent', parent), ('child', child)):
                for offset in (0, 4096, 8192, 12288, 65532):
                    changed = [r for r in rows if not (r['stage'] == 'section_byte_visibility' and r['a'] == offset)]
                    write(self.path, changed if role == 'parent' else parent)
                    write(child_path, changed if role == 'child' else child)
                    with self.assertRaises(ValueError): check.verify(self.directory, case, 64, 0)
            if case == 'section-readonly':
                for stage in ('MapViewOfFile_write_denied', 'DuplicateHandle_write_upgrade_denied'):
                    write(self.path, parent);write(child_path, [r for r in child if r['stage'] != stage])
                    with self.assertRaises(ValueError): check.verify(self.directory, case, 64, 0)
            child_path.unlink()

    def test_mojo_requires_pending_and_each_kind_of_completion(self):
        case = 'mojo-pipe';parent, child = paired_rows(case)
        write(self.directory / 'ipc-10-101.log', child)
        for error in (0, 995, 109):
            write(self.path, [r for r in parent if not (r['stage'] == 'GetQueuedCompletionStatus' and r['error'] == error)])
            with self.assertRaises(ValueError): check.verify(self.directory, case, 64, 0)
        write(self.path, [r for r in parent if r['stage'] != 'overlapped_ReadFile'])
        with self.assertRaises(ValueError): check.verify(self.directory, case, 64, 0)

    def test_accepts_page_regression_and_rejects_missing_recommit(self):
        rows = good_rows('page-regression');write(self.path, rows)
        self.assertEqual(check.verify(self.directory, 'page-regression', 64, 0)['windows_reference'], 'pass')
        write(self.path, [r for r in rows if r['stage'] != 'VirtualAlloc_recommit_4KiB'])
        with self.assertRaises(ValueError): check.verify(self.directory, 'page-regression', 64, 0)

    def test_identity_requires_object_controls_live_child_and_bounded_ack(self):
        case = 'live-memory';parent, child = paired_rows(case);child_path = self.directory / 'ipc-10-101.log'
        write(child_path, child)
        for stage, key, bad in (('identity_same_control', 'error', 1656),
                                ('identity_different_control', 'error', 0),
                                ('identity_capture_included', 'error', 6), ('identity_included_control', 'error', 1656),
                                ('identity_child_live', 'a', 0), ('identity_child_still_live', 'a', 0),
                                ('identity_capture_reference', 'error', 5),
                                ('identity_reference_control', 'error', 1656),
                                ('identity_reference_values', 'b', 10),
                                ('UpdateProcThreadAttribute_HANDLE_LIST', 'a', 3),
                                ('handle_list_excluded', 'error', 0)):
            rows = [r.copy() for r in parent];next(r for r in rows if r['stage'] == stage)[key] = bad
            write(self.path, rows)
            with self.assertRaises(ValueError): check.verify(self.directory, case, 64, 0)
        # A genuinely absent slot also passes after the same exact-reference controls.
        next(r for r in parent if r['stage'] == 'handle_list_excluded').update(error=6, a=2)
        next(r for r in parent if r['stage'] == 'child_hello')['b'] = 2
        next(r for r in child if r['stage'] == 'identity_candidate_snapshot')['error'] = 6
        next(r for r in child if r['stage'] == 'identity_child_slot_verdict').update(error=6, a=2)
        write(self.path, parent);write(child_path, child)
        self.assertEqual(check.verify(self.directory, case, 64, 0)['windows_reference'], 'pass')
        next(r for r in child if r['stage'] == 'handle_list_acknowledged')['a'] = 0
        write(child_path, child)
        with self.assertRaises(ValueError): check.verify(self.directory, case, 64, 0)

    def test_slot_witness_requires_every_control_and_exact_binding(self):
        case = 'live-memory';child_path = self.directory / 'ipc-10-101.log'
        mutations = [('identity_candidate_snapshot', 'error', 50),
                     ('identity_candidate_snapshot', 'result', 'pass'),
                     ('identity_candidate_snapshot', 'a', 99),
                     ('identity_child_reference_values', 'b', 99),
                     ('identity_child_same_control', 'error', 1656),
                     ('identity_child_different_control', 'error', 0),
                     ('identity_child_cross_type_control', 'error', 50),
                     ('identity_child_invalid_control', 'error', 1656),
                     ('identity_child_slot_verdict', 'a', 2),
                     ('identity_child_slot_verdict', 'b', 99)]
        for stage, field, bad in mutations:
            parent, child = paired_rows(case)
            next(r for r in child if r['stage'] == stage)[field] = bad
            write(self.path, parent);write(child_path, child)
            with self.assertRaises(ValueError): check.verify(self.directory, case, 64, 0)
        for stage in ('identity_candidate_snapshot', 'identity_child_duplicate_same', 'identity_child_same_control',
                      'identity_child_different_control', 'identity_child_cross_type_control', 'identity_child_invalid_control',
                      'identity_child_slot_verdict'):
            parent, child = paired_rows(case)
            for altered in ([r for r in child if r['stage'] != stage], child[:-1] +
                            [next(r for r in child if r['stage'] == stage).copy()] + child[-1:]):
                write(self.path, parent);write(child_path, altered)
                with self.assertRaises(ValueError): check.verify(self.directory, case, 64, 0)

    def test_snapshot_must_precede_control_allocation(self):
        case = 'live-memory';parent, child = paired_rows(case)
        snapshot = child.pop(0);child.insert(4, snapshot)
        write(self.path, parent);write(self.directory / 'ipc-10-101.log', child)
        with self.assertRaises(ValueError): check.verify(self.directory, case, 64, 0)

    def test_known_reference_cannot_be_closed_before_identity_acknowledgement(self):
        case = 'live-memory'
        for role, handle in (('child', 13), ('parent', 10), ('parent', 13)):
            parent, child = paired_rows(case)
            rows = child if role == 'child' else parent
            rows.insert(0, row('CloseHandle', case=case, role=role, pid=101 if role == 'child' else 100, a=handle))
            write(self.path, parent);write(self.directory / 'ipc-10-101.log', child)
            with self.assertRaises(ValueError): check.verify(self.directory, case, 64, 0)

    def test_type_observations_and_old_file_kind_flags_cannot_authorize_comparison(self):
        case = 'live-memory'
        for error, flag in ((50, 1), (50, 257), (0, 1), (5, 2)):
            parent, child = paired_rows(case)
            child.insert(0, row('identity_candidate_unpinned_racy_EtwRegistration', 'observation_only',
                               case=case, role='child', pid=101, a=19))
            next(r for r in child if r['stage'] == 'identity_candidate_snapshot')['error'] = error
            next(r for r in child if r['stage'] == 'identity_child_slot_verdict').update(error=error, a=flag)
            next(r for r in parent if r['stage'] == 'child_hello')['b'] = flag
            next(r for r in parent if r['stage'] == 'handle_list_excluded').update(error=error, a=flag)
            write(self.path, parent);write(self.directory / 'ipc-10-101.log', child)
            with self.assertRaises(ValueError): check.verify(self.directory, case, 64, 0)

    def test_source_safety_and_independent_identity(self):
        source = (ROOT / 'tests/fixtures/windows_chromium_ipc.c').read_text()
        for forbidden in ('TerminateProcess(', 'INFINITE', '--no-sandbox', '--single-process', 'CreateRemoteThread(', 'AdjustTokenPrivileges('):
            self.assertNotIn(forbidden, source)
        self.assertNotIn('known_file_kind', source)
        self.assertNotIn('identity_capture_child_handle', source)
        self.assertLess(source.index('saved=snapshot_slot('), source.index('start_log();', source.index('static int worker_main')))
        self.assertIn('PIPE_REJECT_REMOTE_CLIENTS', source)
        self.assertIn('static struct io_slot slots[4]', source)
        self.assertIn('overlapped==&slot->ov && key==IO_KEY', source)
        self.assertIn('DUPLICATE_CLOSE_SOURCE', source)
        self.assertNotIn('/DYNAMICBASE:NO', (ROOT / 'tools/build_windows_chromium_ipc.ps1').read_text())
        workflow = (ROOT / '.github/workflows/windows-chromium-ipc-reference.yml').read_text()
        self.assertIn('arch: [x64, x86]', workflow)
        self.assertNotIn('.Kill(', workflow)
        self.assertNotIn('package_windows_child_fixture.py', workflow)


if __name__ == '__main__':
    unittest.main()
