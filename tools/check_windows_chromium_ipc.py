#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Fail-closed original Windows diagnostic log verifier; no execution claims from source."""
import argparse
import json
import re
from pathlib import Path

CASES = ('self-memory', 'live-memory', 'suspended-memory', 'section-readonly',
         'section-duplicate', 'section-close-source', 'mojo-pipe', 'page-regression')
CHILD_EXIT = 0x0052002A
FIELDS = {'schema', 'role', 'case', 'stage', 'result', 'nonce', 'pid', 'parent', 'bits',
          'elapsed_ms', 'deadline_ms', 'error', 'ntstatus', 'bytes', 'a', 'b'}
NUMBERS = FIELDS - {'role', 'case', 'stage', 'result'}
RESULTS = {'attempt', 'pass', 'fail', 'pending', 'immediate', 'timeout', 'not_run',
           'unsupported', 'uncertain', 'cleanup_uncertain', 'unverified', 'observation_only'}
WIDE = {'elapsed_ms', 'bytes', 'a', 'b'}
COMMON_CHILD = {'Windows_child_identity', 'child_hello', 'CreateProcessW_handle_list',
                'InitializeProcThreadAttributeList_size', 'InitializeProcThreadAttributeList',
                'UpdateProcThreadAttribute_HANDLE_LIST', 'wait_child_exit', 'GetExitCodeProcess',
                'identity_same_control', 'identity_different_control', 'identity_child_live',
                'identity_child_still_live', 'identity_capture_included', 'identity_included_control',
                'DuplicateHandle_inherited_reference', 'identity_reference_values',
                'identity_capture_reference', 'identity_reference_control', 'handle_list_excluded'}
PARENT_STAGES = {
    'self-memory': {'OpenProcess_self', 'self_actual_value', 'reduced_WriteProcessMemory', 'reduced_NtWriteVirtualMemory', 'reduced_ReadProcessMemory',
        'reduced_NtReadVirtualMemory', 'self_reduced_unchanged'} |
        {f'{prefix}_{api}' for prefix in ('pseudo_self', 'real_self') for api in
         ('ReadProcessMemory', 'WriteProcessMemory', 'NtReadVirtualMemory', 'NtWriteVirtualMemory')},
    'live-memory': COMMON_CHILD | {'foreign_ReadProcessMemory', 'foreign_WriteProcessMemory',
        'foreign_NtReadVirtualMemory', 'foreign_restore_NtWriteVirtualMemory', 'foreign_restored_NtReadVirtualMemory',
        'foreign_final_NtWriteVirtualMemory', 'parent_private_unchanged', 'peer_confirmed_write', 'reduced_WriteProcessMemory'},
    'section-readonly': COMMON_CHILD | {'section_empty_DACL', 'CreateFileMappingW', 'MapViewOfFile_parent',
        'DuplicateHandle_readonly', 'section_byte_visibility', 'UnmapViewOfFile_parent'},
    'section-duplicate': COMMON_CHILD | {'section_empty_DACL', 'CreateFileMappingW', 'MapViewOfFile_parent',
        'DuplicateHandle_target', 'section_byte_visibility', 'UnmapViewOfFile_parent'},
    'section-close-source': COMMON_CHILD | {'section_empty_DACL', 'CreateFileMappingW', 'MapViewOfFile_parent',
        'DuplicateHandle_CLOSE_SOURCE', 'source_handle_retired', 'section_byte_visibility', 'UnmapViewOfFile_parent'},
    'mojo-pipe': COMMON_CHILD | {'CreateNamedPipeW', 'CreateFileW_pipe_client', 'ConnectNamedPipe_preconnected',
        'CreateIoCompletionPort', 'GetQueuedCompletionStatus', 'iocp_peer_record', 'CancelIoEx'},
    'page-regression': {'VirtualAlloc_16KiB', 'VirtualProtect_one_4KiB', 'VirtualQuery_4KiB',
        'VirtualFree_decommit_4KiB', 'VirtualQuery_decommitted', 'VirtualAlloc_recommit_4KiB',
        'recommit_zeroed', 'neighbor_unchanged', 'VirtualFree_release'},
}
PARENT_STAGES['suspended-memory'] = PARENT_STAGES['live-memory'] | {'suspended_no_application_record', 'ResumeThread'}


def parse_log(path):
    raw = path.read_bytes()
    if not raw or len(raw) > 131072 or not raw.endswith(b'\n'):
        raise ValueError(f'{path.name}: empty, oversized or truncated log')
    rows = []
    for line in raw.decode('ascii').splitlines():
        parts = line.split()
        if not parts or parts.pop(0) != 'PW_CHROMIUM_IPC':
            raise ValueError(f'{path.name}: unexpected log prefix')
        row = {}
        for item in parts:
            key, separator, value = item.partition('=')
            if not separator or key in row:
                raise ValueError(f'{path.name}: malformed or duplicate field')
            row[key] = value
        if set(row) != FIELDS:
            raise ValueError(f'{path.name}: wrong schema fields')
        for key in NUMBERS:
            if not row[key].isascii() or not row[key].isdecimal():
                raise ValueError(f'{path.name}: non-decimal {key}')
            row[key] = int(row[key])
            if row[key] >= 1 << (64 if key in WIDE else 32):
                raise ValueError(f'{path.name}: out-of-range {key}')
        if row['result'] not in RESULTS or not re.fullmatch(r'[A-Za-z0-9_]+', row['stage']):
            raise ValueError(f'{path.name}: unknown result or invalid stage label')
        if row['schema'] != 1 or row['bits'] not in (32, 64) or row['role'] not in ('parent', 'child'):
            raise ValueError(f'{path.name}: unsupported identity')
        rows.append(row)
    identity = tuple(rows[0][k] for k in ('nonce', 'pid', 'parent', 'bits', 'role', 'case'))
    if not identity[0] or not identity[1] or not identity[2]:
        raise ValueError(f'{path.name}: zero process identity')
    elapsed = 0
    for row in rows:
        if tuple(row[k] for k in ('nonce', 'pid', 'parent', 'bits', 'role', 'case')) != identity:
            raise ValueError(f'{path.name}: mixed identity')
        if row['elapsed_ms'] < elapsed:
            raise ValueError(f'{path.name}: clock regression')
        elapsed = row['elapsed_ms']
    return rows


def require_pass(rows, stages):
    passed = {r['stage'] for r in rows if r['result'] == 'pass'}
    if missing := stages - passed:
        raise ValueError(f'missing passed stages: {sorted(missing)}')
    if any(r['result'] in ('fail', 'timeout', 'not_run', 'unsupported', 'cleanup_uncertain', 'uncertain') for r in rows):
        raise ValueError('failed, timed out, unperformed or unsettled stage is not a reference pass')
    finals = [r for r in rows if r['stage'] == 'final']
    if len(finals) != 1 or finals[0]['result'] != 'pass' or rows[-1] != finals[0]:
        raise ValueError('exactly one final pass must end each log')
    cleanup = [r for r in rows if r['stage'] == 'guest_cleanup']
    if len(cleanup) != 1 or cleanup[0]['result'] != 'pass' or cleanup[0]['a'] or cleanup[0]['b']:
        raise ValueError('guest cleanup must separately prove zero owned handles and pending operations')


def verify(directory, case, bits, exit_code):
    if case not in CASES or bits not in (32, 64) or exit_code != 0:
        raise ValueError('case, architecture or actual parent process exit was unsuccessful')
    logs = [parse_log(p) for p in sorted(directory.glob('ipc-*.log'))]
    parents = [r for r in logs if r[0]['role'] == 'parent']
    children = [r for r in logs if r[0]['role'] == 'child']
    expected_children = 0 if case in ('self-memory', 'page-regression') else 1
    if len(parents) != 1 or len(children) != expected_children or len(logs) != 1 + expected_children:
        raise ValueError('wrong process-log cardinality; use a new case directory')
    parent = parents[0]
    if parent[0]['pid'] != parent[0]['parent']:
        raise ValueError('parent identity mismatch')
    for rows in logs:
        if any(r['case'] != case or r['bits'] != bits or r['nonce'] != parent[0]['nonce'] or
               r['parent'] != parent[0]['pid'] for r in rows):
            raise ValueError('case/nonce/architecture/parent mismatch')
    require_pass(parent, PARENT_STAGES[case])
    native = [r for r in parent if r['stage'] == 'native_settlement']
    if len(native) != 1 or native[0]['result'] != 'unverified':
        raise ValueError('exactly one explicit unverified native-settlement boundary required')
    if expected_children:
        child = children[0]
        if child[0]['pid'] == parent[0]['pid']:
            raise ValueError('child must be a distinct Windows process')
        child_controls = ('identity_child_duplicate_same', 'identity_child_same_control',
                          'identity_child_different_control', 'identity_child_cross_type_control',
                          'identity_child_invalid_control')
        require_pass(child, {'handle_list_acknowledged', 'identity_child_reference_values',
                            'identity_child_slot_verdict'} | set(child_controls))
        def unique(rows, stage):
            matches = [r for r in rows if r['stage'] == stage and r['result'] != 'attempt']
            if len(matches) != 1:
                raise ValueError('one conclusive slot-identity observation per stage required')
            return matches[0]
        identity = {stage: unique(parent, stage) for stage in
                    ('identity_same_control', 'identity_different_control', 'identity_child_live',
                     'identity_child_still_live', 'identity_capture_included', 'identity_included_control',
                     'identity_capture_reference', 'identity_reference_control', 'identity_reference_values',
                     'handle_list_excluded', 'child_hello', 'UpdateProcThreadAttribute_HANDLE_LIST')}
        if identity['identity_same_control']['error'] != 0 or identity['identity_different_control']['error'] != 1656:
            raise ValueError('same/different object identity controls invalid')
        if any(identity[stage]['error'] != 0 for stage in ('identity_capture_included', 'identity_included_control',
                                                        'identity_capture_reference', 'identity_reference_control')):
            raise ValueError('included release and exact decoy reference must calibrate foreign capture')
        if any(identity[stage]['a'] != 258 for stage in ('identity_child_live', 'identity_child_still_live')):
            raise ValueError('child must remain live across known reference capture')
        values = identity['identity_reference_values']
        original, reference = values['a'], values['b']
        if original == reference or not 0 < original < (1 << bits) - 1 or not 0 < reference < (1 << bits) - 1:
            raise ValueError('original excluded handle and inherited reference must be distinct valid-width values')
        expected_count = 5 if case in ('section-readonly', 'mojo-pipe') else 4
        if identity['UpdateProcThreadAttribute_HANDLE_LIST']['a'] != expected_count:
            raise ValueError('explicit handle list must include the separate identity reference')
        snapshot = unique(child, 'identity_candidate_snapshot')
        child_values = unique(child, 'identity_child_reference_values')
        verdict = unique(child, 'identity_child_slot_verdict')
        controls = [unique(child, stage) for stage in child_controls]
        if [r['error'] for r in controls] != [0, 0, 1656, 1656, 6]:
            raise ValueError('child same, different, cross-type and invalid comparison controls required')
        if snapshot['result'] != 'observation_only' or (snapshot['a'], snapshot['b']) != (original, reference) or \
                (child_values['a'], child_values['b']) != (original, reference):
            raise ValueError('snapshot must bind the exact original slot and continuously held reference')
        expected_error = {1: 1656, 2: 6}.get(verdict['a'])
        excluded = identity['handle_list_excluded']
        if expected_error is None or any(r['error'] != expected_error for r in (snapshot, verdict, excluded)) or \
                verdict['b'] != reference or excluded['b'] != reference or excluded['a'] != verdict['a'] or \
                identity['child_hello']['b'] != verdict['a'] or identity['identity_capture_reference']['a'] != reference:
            raise ValueError('only calibrated different-object or absent-slot comparisons establish exclusion')
        ordered = [snapshot] + controls + [verdict, unique(child, 'handle_list_acknowledged')]
        positions = [child.index(r) for r in ordered]
        if positions != sorted(positions):
            raise ValueError('candidate snapshot must precede control allocations and the acknowledged verdict')
        if any(r['stage'] == 'CloseHandle' and r['result'] == 'pass' and r['a'] == reference
               for r in child[:positions[-1]]):
            raise ValueError('child identity reference must remain owned through ACK')
        exclusion_position = parent.index(excluded)
        if any(r['stage'] == 'CloseHandle' and r['result'] == 'pass' and r['a'] in (original, reference)
               for r in parent[:exclusion_position]):
            raise ValueError('parent must retain original and reference through identity acceptance')
        acknowledgements = [r for r in child if r['stage'] == 'handle_list_acknowledged' and r['result'] != 'attempt']
        if len(acknowledgements) != 1 or acknowledgements[0]['a'] != 1:
            raise ValueError('child did not acknowledge the parent identity verdict')
        if child[-1]['a'] != CHILD_EXIT or parent[-1]['a'] != CHILD_EXIT:
            raise ValueError('full child exit code mismatch')
        if not any(r['stage'] == 'CreateProcessW_handle_list' and r['result'] == 'pass' and
                   r['a'] == child[0]['pid'] for r in parent):
            raise ValueError('CreateProcess process identity does not match the peer')
        if case in ('live-memory', 'suspended-memory'):
            require_pass(child, {'child_actual_private_value', 'WaitForSingleObject_release'})
        elif case.startswith('section-'):
            require_pass(child, {'NtQuerySection', 'MapViewOfFile_section', 'section_byte_visibility', 'UnmapViewOfFile_section'})
            if case == 'section-readonly':
                require_pass(child, {'MapViewOfFile_write_denied', 'DuplicateHandle_write_upgrade_denied'})
            for rows in (parent, child):
                offsets = {r['a'] for r in rows if r['stage'] == 'section_byte_visibility' and r['result'] == 'pass'}
                if offsets != {0, 4096, 8192, 12288, 65532}:
                    raise ValueError('section boundary observations incomplete')
        elif case == 'mojo-pipe':
            require_pass(child, {'CreateIoCompletionPort', 'GetQueuedCompletionStatus', 'iocp_peer_record'})
            if not any(r['stage'] == 'overlapped_ReadFile' and r['result'] == 'pending' for r in parent):
                raise ValueError('pending read not established')
            errors = {r['error'] for r in parent if r['stage'] == 'GetQueuedCompletionStatus' and r['result'] == 'pass'}
            if not {0, 995, 109} <= errors:
                raise ValueError('ordinary, canceled and peer-close completions all required')
    return {'schema': 'pw-chromium-ipc-reference/1', 'case': case, 'bits': bits,
            'nonce': parent[0]['nonce'], 'parent_pid': parent[0]['pid'],
            'windows_reference': 'pass', 'ps5_execution': 'not_run', 'native_settlement': 'unverified'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--case', choices=CASES, required=True)
    parser.add_argument('--bits', type=int, choices=(32, 64), required=True)
    parser.add_argument('--exit-code', type=int, required=True)
    args = parser.parse_args()
    try:
        report = verify(args.directory, args.case, args.bits, args.exit_code)
    except (ValueError, OSError, UnicodeError) as error:
        parser.exit(1, f'Chromium IPC reference rejected: {error}\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
