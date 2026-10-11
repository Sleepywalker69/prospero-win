#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Read-only inspection of the separately built original AMD64 USER pair.

This does not execute, map or load PE instructions. A trusted hosted artifact
and externally supplied project/run identities remain the evidence anchors.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import ntpath
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
sys.dont_write_bytecode = True
from private_dispatch_wow64 import mapped_pe

NAMES = ('user-parent.exe', 'user-child.exe')
RECEIPT = 'user-source.json'
SOURCE = 'tests/fixtures/windows_child_user.c'
RECIPE = 'tools/build_windows_child_user.ps1'
VALIDATOR = 'tools/windows_child_user_contract.py'
MAX_PE = 16 << 20


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def regular(path, maximum, minimum=0):
    path = Path(path).absolute()
    for ancestor in (path, *path.parents):
        info = ancestor.lstat()
        require(not stat.S_ISLNK(info.st_mode) and
                not getattr(info, 'st_file_attributes', 0) & 0x400,
                'linked/reparse input refused')
    info = path.stat()
    require(stat.S_ISREG(info.st_mode) and minimum <= info.st_size <= maximum,
            'nonregular or unbounded input')
    data = path.read_bytes()
    require(len(data) == info.st_size, 'input changed while reading')
    return data


def decode(data):
    def pairs(items):
        out = {}
        for key, value in items:
            require(key not in out, 'duplicate receipt key')
            out[key] = value
        return out
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def record(data):
    return {'bytes': len(data), 'sha256': digest(data)}


def inspect_pe(data):
    require(256 <= len(data) <= MAX_PE, 'bounded original PE required')
    image = mapped_pe(data, 0x8664)  # Reuse the existing strict raw/virtual overlap reader.
    def field(fmt, offset):
        require(0 <= offset <= len(data) - struct.calcsize(fmt), 'truncated PE field')
        return struct.unpack_from(fmt, data, offset)
    pe = field('<I', 60)[0]
    machine, count, _, _, _, optional_size, characteristics = field('<HHIIIHH', pe + 4)
    optional = pe + 24
    require(machine == 0x8664 and optional_size >= 240 and
            characteristics & 2 and not characteristics & 0x2001,
            'original AMD64 executable/relocations required')
    require(field('<H', optional + 68)[0] == 3 and
            field('<H', optional + 70)[0] & 0x140 == 0x140,
            'original console executable requires NX and ASLR')
    directories = field('<I', optional + 108)[0]
    require(14 <= directories <= (optional_size - 112) // 8, 'PE directory extent invalid')
    sections = []
    for index in range(count):
        at = optional + optional_size + index * 40
        _, rva, size, raw = field('<IIII', at + 8)
        sections.append((rva, size, raw, field('<I', at + 36)[0]))
    headers = field('<I', optional + 60)[0]
    def raw_at(rva, size):
        require(type(rva) is int and type(size) is int and rva >= 0 and size > 0,
                'invalid file-backed RVA')
        if rva + size <= headers:
            return rva
        matches = [raw + rva - base for base, length, raw, _ in sections
                   if base <= rva and rva + size <= base + length]
        require(len(matches) == 1, 'RVA is not uniquely file-backed')
        return matches[0]
    def string(rva):
        value = bytearray()
        for offset in range(256):
            b = data[raw_at(rva + offset, 1)]
            if not b:
                require(value, 'empty import name')
                return value.decode('ascii')
            require(33 <= b <= 126, 'invalid import name byte')
            value.append(b)
        raise ValueError('unterminated import name')
    entry = field('<I', optional + 16)[0]
    raw_at(entry, 1)
    require(any(base <= entry < base + size and flags & 0x20000000
                for base, size, _, flags in sections), 'entry point is not file-backed executable code')
    def directory(index):
        return field('<II', optional + 112 + index * 8)
    require(directory(13) == (0, 0), 'delay imports outside original fixture policy')
    imports_rva, imports_size = directory(1)
    require(imports_rva and 20 <= imports_size <= 65536, 'bounded import directory required')
    raw_at(imports_rva, imports_size)
    imports, terminated = {}, False
    for offset in range(0, min(imports_size - 19, 64 * 20), 20):
        descriptor = field('<IIIII', raw_at(imports_rva + offset, 20))
        if descriptor == (0, 0, 0, 0, 0):
            terminated = True
            break
        original, _, _, dll_name, first = descriptor
        require(dll_name and first, 'incomplete import descriptor')
        dll = string(dll_name).lower()
        require(dll not in imports, 'duplicate import descriptor')
        symbols = []
        for index in range(512):
            thunk = field('<Q', raw_at((original or first) + 8 * index, 8))[0]
            raw_at(first + 8 * index, 8)
            if not thunk:
                break
            require(not thunk & (1 << 63) and thunk < len(image), 'ordinal/invalid import refused')
            raw_at(thunk, 2)
            symbol = string(thunk + 2)
            require(symbol not in symbols, 'duplicate imported symbol')
            symbols.append(symbol)
        else:
            raise ValueError('unterminated import thunks')
        require(symbols, 'empty import descriptor')
        imports[dll] = symbols
    require(terminated and imports, 'import directory lacks terminator')
    reloc_rva, reloc_size = directory(5)
    require(reloc_rva and 8 <= reloc_size <= 4 << 20, 'bounded relocations required')
    raw_at(reloc_rva, reloc_size)
    offset, targets = 0, set()
    while offset < reloc_size:
        require(reloc_size - offset >= 8, 'truncated relocation block')
        page, size = field('<II', raw_at(reloc_rva + offset, 8))
        require(page % 4096 == 0 and page < len(image) and size >= 8 and size % 4 == 0 and size <= reloc_size - offset,
                'invalid relocation block')
        for slot in range(8, size, 2):
            item = field('<H', raw_at(reloc_rva + offset + slot, 2))[0]
            kind, delta = item >> 12, item & 4095
            if not kind:
                continue
            require(kind == 10, 'non-DIR64 original relocation')
            target = page + delta
            raw_at(target, 8)
            require(target not in targets, 'duplicate relocation target')
            targets.add(target)
        offset += size
    require(targets, 'no actual DIR64 relocation entries')
    return {'machine': 'AMD64', 'entry_rva': entry, 'imports': imports,
            'dir64_relocations': len(targets), 'nx': True, 'aslr': True}


REQUIRED = {
    'parent': {'kernel32.dll': {'CreateProcessW', 'WaitForSingleObject', 'GetExitCodeProcess',
                               'CloseHandle', 'CreateFileA', 'WriteFile'}},
    'child': {'kernel32.dll': {'CreateThread', 'GetExitCodeThread', 'CloseHandle', 'CreateFileA', 'WriteFile'},
              'user32.dll': {'GetAncestor', 'GetWindowRect', 'GetClientRect', 'CreateWindowExW',
                             'RegisterClassW', 'DestroyWindow', 'UnregisterClassW',
                             'MsgWaitForMultipleObjects', 'PeekMessageW'},
              'gdi32.dll': {'CreateCompatibleDC', 'CreateDIBSection', 'GetObjectW', 'SelectObject',
                            'GetPixel', 'DeleteObject', 'DeleteDC'}}}


def inspect_role(data, role):
    report = inspect_pe(data)
    require(set(report['imports']) == set(REQUIRED[role]), 'unexpected original role DLL imports')
    for dll, symbols in REQUIRED[role].items():
        require(symbols <= set(report['imports'][dll]), 'required original role imports missing')
    return report


def parse_log(data, role):
    require(0 < len(data) <= 65536, 'bounded role log required')
    rows = []
    for line in data.decode('ascii').splitlines():
        parts = line.split()
        require(parts and parts[0] == 'PW_CHILD_USER', 'foreign role log line')
        row = {}
        for part in parts[1:]:
            require(part.count('=') == 1, 'malformed role field')
            key, value = part.split('=')
            require(key and value and key not in row, 'empty/duplicate role field')
            row[key] = value
        require(row.get('role') == role and all(re.fullmatch('[1-9][0-9]*', row.get(k, '')) and
                int(row[k]) <= 0xffffffff for k in ('pid', 'tid')), 'role process/thread identity invalid')
        require(row.get('result') != 'failed' and row.get('stage') != 'self_exit', 'failed reference log')
        rows.append(row)
    return rows


def inspect_logs(parent_data, child_data):
    parent, child = parse_log(parent_data, 'parent'), parse_log(child_data, 'child')
    require([x.get('stage') for x in parent] == ['start', 'create_process', 'create_process', 'child_exit', 'finish'],
            'parent reference stage order differs')
    require([x.get('stage') for x in child] == ['start', 'top_window', 'worker_first_user', 'ancestor',
            'geometry', 'static', 'custom_class', 'dib', 'worker_cleanup', 'worker_exit', 'finish'],
            'child reference stage order differs')
    pid, main, worker = child[0]['pid'], child[0]['tid'], child[2]['tid']
    require(pid != parent[0]['pid'] and main != worker and
            all(x['pid'] == pid for x in child) and
            all(x['pid'] == parent[0]['pid'] and x['tid'] == parent[0]['tid'] for x in parent) and
            all(child[i]['tid'] == (worker if 2 <= i <= 8 else main) for i in range(len(child))),
            'reference identity changed between stages')
    def fields(row, expected):
        require(all(row.get(k) == v for k, v in expected.items()), 'reference observation differs: ' + row['stage'])
    parent_fields = [
        {'mode','child_presentation','child_input'}, {'result','child','inherited_handles','arguments'},
        {'result','child_pid','child_tid','initialized'}, {'query_ok','observed_code','expected','matches','native_settlement'},
        {'planned_exit','prior_status','diagnostic_cleanup','final_log_close','native_settlement'}]
    child_fields = [
        {'mode','child_presentation','child_input'}, {'hwnd','width','height','visible'},
        {'next','top','main_tid'}, {'returned','expected','matches'},
        {'window_match','client_match','width','height'}, {'created','visible','hwnd'},
        {'registered','created','visible'}, {'width','height','stride','local_readback','presentation'},
        {'status','local_operations_only'}, {'query_ok','observed_code','recorded_code','finished','distinct_tid'},
        {'planned_exit','prior_status','diagnostic_cleanup','final_log_close','native_settlement'}]
    for rows, sets in ((parent,parent_fields),(child,child_fields)):
        for row, expected in zip(rows,sets):
            require(set(row) == expected | {'role','stage','pid','tid'}, 'unexpected/missing role fields: '+row['stage'])
    for rows in (parent, child):
        fields(rows[0], {'mode': 'original_user_control', 'child_presentation': 'unverified', 'child_input': 'unverified'})
        fields(rows[-1], {'prior_status': '0', 'diagnostic_cleanup': 'completed',
                          'final_log_close': 'pending', 'native_settlement': 'unverified'})
    fields(parent[1], {'result': 'attempt', 'child': 'user-child.exe', 'inherited_handles': '0', 'arguments': 'none'})
    fields(parent[2], {'result': 'returned_success', 'child_pid': pid, 'child_tid': main, 'initialized': 'unverified'})
    fields(parent[3], {'query_ok': '1', 'observed_code': '37', 'expected': '37', 'matches': '1', 'native_settlement':'unverified'})
    fields(parent[-1], {'planned_exit': '0'})
    top = child[1].get('hwnd', '')
    require(re.fullmatch('[1-9][0-9]*', top) and int(top) <= (1 << 64) - 1, 'invalid original HWND')
    fields(child[1], {'width': '320', 'height': '240', 'visible': '0'})
    fields(child[2], {'next': 'GetAncestor_GA_ROOT', 'top': top, 'main_tid': main})
    fields(child[3], {'returned': top, 'expected': top, 'matches': '1'})
    fields(child[4], {'window_match': '1', 'client_match': '1', 'width': '320', 'height': '240'})
    fields(child[5], {'created': '1', 'visible': '0'})
    require(re.fullmatch('[1-9][0-9]*', child[5].get('hwnd', '')) and
            int(child[5]['hwnd']) <= (1 << 64)-1 and child[5]['hwnd'] != top, 'STATIC handle absent/invalid/reused')
    fields(child[6], {'registered': '1', 'created': '1', 'visible': '0'})
    fields(child[7], {'width': '32', 'height': '16', 'stride': '128', 'local_readback': 'matched', 'presentation': 'unverified'})
    fields(child[8], {'status': '0', 'local_operations_only': '1'})
    fields(child[9], {'query_ok': '1', 'observed_code': '0', 'recorded_code': '0', 'finished': '1', 'distinct_tid': '1'})
    fields(child[-1], {'planned_exit': '37'})
    return {'parent_pid': parent[0]['pid'], 'child_pid': pid, 'main_tid': main, 'worker_tid': worker,
            'observed_child_exit': 37, 'native_settlement': 'unverified'}



def windows_path(value):
    require(isinstance(value,str) and re.fullmatch(r'[A-Za-z]:\\[^"\r\n%!]+',value),
            'bounded absolute hosted Windows path required')
    require(len(value)<=4096 and all(p not in ('','.','..') for p in value[3:].split('\\')),
            'ambiguous hosted Windows path')
    return ntpath.normcase(value)


def inspect_commands(commands, headers, data_file):
    require(isinstance(commands,dict) and set(commands)=={'parent','child'}, 'both exact role commands required')
    path=r'([A-Za-z]:\\[^"\r\n%!]+)'
    pattern=(r'call "'+path+r'" > nul && "'+path+r'" /nologo /std:c11 /W4 /WX /O2 /MT '
             r'/D_CRT_SECURE_NO_WARNINGS /DPW_USER_CHILD=([01]) /sourceDependencies "'+path+r'" "'+path+
             r'" user32\.lib gdi32\.lib /Fe:"'+path+r'" /Fo:"'+path+
             r'" /link /DYNAMICBASE /FIXED:NO /NXCOMPAT /INCREMENTAL:NO')
    normalized_headers={}
    for name,record_ in headers.items():
        key=windows_path(name)
        require(key not in normalized_headers,'ambiguous header path aliases')
        normalized_headers[key]=record_
    shared=None; consumed=set(); result={}
    for selector,role in enumerate(('parent','child')):
        command=commands[role]
        require(isinstance(command,str) and len(command)<=32768,'bounded compile command required')
        match=re.fullmatch(pattern,command)
        require(match is not None,'compile flags/arguments differ from the original recipe')
        vcvars,compiler,actual_selector,deps,source,exe,obj=match.groups()
        vcvars,compiler,deps,source,exe,obj=map(windows_path,(vcvars,compiler,deps,source,exe,obj))
        require(actual_selector==str(selector) and vcvars.endswith(r'\vc\auxiliary\build\vcvars64.bat') and
                compiler.endswith(r'\bin\hostx64\x64\cl.exe') and
                source.endswith(r'\tests\fixtures\windows_child_user.c'),'role/compiler/source path differs')
        parent=ntpath.dirname(exe)
        require(ntpath.basename(exe)=='user-'+role+'.exe' and ntpath.dirname(obj)==parent and
                ntpath.basename(obj)=='user-'+role+'.obj' and ntpath.dirname(deps)==parent and
                ntpath.basename(deps)=='dependencies-'+role+'.json','role output paths differ')
        identity=(vcvars,compiler,source,parent)
        require(shared is None or shared==identity,'role compile providers/source/output differ')
        shared=identity
        dependency=decode(data_file('dependencies-'+role+'.json',4<<20,1))
        require(dependency.get('Version') in ('1.1','1.2') and isinstance(dependency.get('Data'),dict),
                'compiler source dependency schema differs')
        dep=dependency['Data']; includes=dep.get('Includes')
        require(windows_path(dep.get('Source'))==source and isinstance(includes,list) and 0<len(includes)<=512,
                'compiler dependency source/includes differ')
        require(dep.get('ProvidedModule') in (None,'') and dep.get('ImportedModules') in (None,[]) and
                dep.get('ImportedHeaderUnits') in (None,[]),'unexpected module inputs in C fixture')
        for name in includes:
            key=windows_path(name)
            require(key in normalized_headers,'consumed compiler header lacks receipt')
            consumed.add(key)
        result[role]={'selector':selector,'command_sha256':digest(command.encode()),
                      'dependency_sha256':digest(data_file('dependencies-'+role+'.json',4<<20,1)),
                      'header_count':len(set(map(windows_path,includes)))}
    require(consumed==set(normalized_headers),'unconsumed header receipt or missing dependency')
    return result

def verify_pair_copy(directory, metadata):
    for name in NAMES:
        data = regular(Path(directory) / name, MAX_PE, 256)
        require(record(data) == {k: metadata['files'][name][k] for k in ('bytes', 'sha256')},
                'USER exported image differs')


def validate_contents(read, names, expected_project, expected_run, expected_attempt, source_hashes, details=None):
    """Validate already bounded archive bytes; no extraction or code execution."""
    require(isinstance(names, (set, frozenset)) and 1 <= len(names) <= 64, 'bounded file-name set required')
    require(all(isinstance(n,str) and re.fullmatch('[A-Za-z0-9_.-]+',n) and n not in ('.','..')
                for n in names) and len({n.casefold() for n in names}) == len(names), 'unsafe/duplicate artifact names')
    allowed = {RECEIPT, *NAMES, 'windows_child_user.c','build_windows_child_user.ps1',
               'user-parent.obj','user-child.obj','build-parent.log','build-child.log',
               'inspect-parent.log','inspect-child.log','dependencies-parent.json','dependencies-child.json',
               'reference.stdout.log','reference.stderr.log','user-inspection.json','SHA256SUMS'}
    require(all(n in allowed or re.fullmatch(r'user-(parent|child)-[1-9][0-9]*-(0|[1-9][0-9]*)\.log',n)
                for n in names), 'unexpected original artifact file or role image')
    def data_file(name, maximum, minimum=0):
        require(name in names, 'missing original input: '+name)
        data=read(name)
        require(type(data) is bytes and minimum <= len(data) <= maximum, 'unbounded/nonbyte original input')
        return data
    require(isinstance(expected_project,dict) and set(expected_project)=={'commit','tree'} and
            all(isinstance(v,str) and re.fullmatch('[0-9a-f]{40}',v) for v in expected_project.values()),
            'external project identity required')
    require(isinstance(source_hashes,dict) and set(source_hashes)=={'source_sha256','recipe_sha256','validator_sha256'} and
            all(isinstance(v,str) and re.fullmatch('[0-9a-f]{64}',v) for v in source_hashes.values()),
            'independently bound current source hashes required')
    run, attempt = expected_run, expected_attempt
    require(isinstance(run, str) and re.fullmatch('[1-9][0-9]*', run) and
            isinstance(attempt, str) and re.fullmatch('[1-9][0-9]*', attempt), 'external run/attempt required')
    meta = decode(data_file(RECEIPT, 8 << 20, 1))
    require(meta.get('schema') == 'pw-original-windows-child-user-msvc/1' and
            meta.get('project') == expected_project and meta.get('architecture') == 'x64' and
            meta.get('run_id') == run and meta.get('run_attempt') == attempt, 'USER producer identity differs')
    for key, expected in source_hashes.items():
        require(meta.get(key) == expected, 'USER source/recipe/validator differs')
    for name,key in [('windows_child_user.c','source_sha256'),('build_windows_child_user.ps1','recipe_sha256')]:
        require(digest(data_file(name,4<<20,1))==source_hashes[key], 'copied original source/recipe differs')
    require(meta.get('runtime_validated') is False and meta.get('child_presentation') is False and
            meta.get('child_input') is False and meta.get('import_policy_verified') is False and
            meta.get('relocation_entries_verified') is False, 'USER producer overstates its evidence')
    compiler = meta.get('compiler', {})
    require(compiler.get('name') == 'MSVC cl.exe' and isinstance(compiler.get('file_version'), str) and
            compiler['file_version'] and re.fullmatch('[0-9a-f]{64}', compiler.get('sha256', '')),
            'exact MSVC compiler identity required')
    require(meta.get('inspector', {}).get('name') == 'MSVC dumpbin.exe' and
            re.fullmatch('[0-9a-f]{64}', meta['inspector'].get('sha256', '')), 'inspector identity required')
    headers = meta.get('headers')
    require(isinstance(headers, dict) and 0 < len(headers) <= 1024, 'consumed header receipts missing')
    for name, value in headers.items():
        require(isinstance(name, str) and 0 < len(name) <= 4096 and isinstance(value, dict) and
                type(value.get('bytes')) is int and 0 < value['bytes'] <= 16 << 20 and
                re.fullmatch('[0-9a-f]{64}', value.get('sha256', '')), 'invalid consumed header receipt')
    commands = inspect_commands(meta.get('compile_commands'), headers, data_file)
    require(isinstance(meta.get('files'), dict) and set(meta['files']) == set(NAMES), 'USER role images differ')
    images, inspected = {}, {}
    for selector, (name, role) in enumerate(zip(NAMES, ('parent', 'child'))):
        images[name] = data_file(name, MAX_PE, 256)
        require(type(meta['files'][name].get('selector')) is int and meta['files'][name] == {**record(images[name]), 'machine': 'AMD64', 'selector': selector},
                'USER role image binding differs')
        inspected[role] = inspect_role(images[name], role)
    require(images[NAMES[0]] != images[NAMES[1]], 'distinct compiled role images required')
    reference = meta.get('reference', {})
    require(reference.get('executed') is True and type(reference.get('exit')) is int and
            reference['exit'] == 0 and reference.get('deadline_seconds') == 105, 'fresh Windows reference required')
    for role in ('stdout', 'stderr'):
        data = data_file('reference.' + role + '.log', 128 << 10)
        require(reference.get(role) == record(data), 'reference stream differs')
        if role == 'stderr':
            require(not data, 'unexpected reference stderr')
    logs = reference.get('role_logs')
    require(isinstance(logs, dict) and len(logs) == 2, 'exactly two role logs required')
    role_data, role_names = {}, {}
    for name, expected in logs.items():
        match = re.fullmatch(r'user-(parent|child)-([1-9][0-9]*)-([0-9]+)\.log', name)
        require(match and match[1] not in role_data and int(match[2]) <= 0xffffffff and
                int(match[3]) <= (1 << 64)-1, 'ambiguous/unsafe role log')
        data = data_file(name, 65536, 1)
        require(record(data) == expected, 'role log bytes differ')
        rows = parse_log(data, match[1])
        require(all(row['pid'] == match[2] for row in rows), 'role log filename PID differs')
        role_data[match[1]], role_names[match[1]] = data, name
    require(set(role_data) == {'parent', 'child'}, 'missing role log')
    observed = inspect_logs(role_data['parent'], role_data['child'])
    require({n for n in names if n.startswith('user-') and n.endswith('.log')} == set(logs), 'extra ambiguous role logs')
    if details is not None:
        details.update(schema='pw-original-windows-child-user-inspection/1', project=expected_project,
                       run_id=run, run_attempt=attempt, receipt_sha256=digest(data_file(RECEIPT, 8 << 20, 1)),
                       images=inspected, observed=observed, role_logs=role_names, compile_commands=commands,
                       import_policy_verified=True, relocation_entries_verified=True,
                       runtime_validated=False, console_validated=False)
    return meta


def validate_pair(directory, expected_project, root, expected_run=None, expected_attempt=None, *, details=None):
    directory, root = Path(directory), Path(root)
    names=set()
    for path in directory.iterdir():
        # The original producer creates a flat fresh directory. Do not follow
        # links or accept hidden alternate role images from an unlisted tree.
        regular(path,MAX_PE)
        names.add(path.name)
    hashes={key:digest(regular(root/relative,4<<20,1)) for key,relative in
            [('source_sha256',SOURCE),('recipe_sha256',RECIPE),('validator_sha256',VALIDATOR)]}
    return validate_contents(lambda name:regular(directory/name,MAX_PE), names, expected_project,
        expected_run if expected_run is not None else os.environ.get('GITHUB_RUN_ID'),
        expected_attempt if expected_attempt is not None else os.environ.get('GITHUB_RUN_ATTEMPT'),
        hashes, details)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--run')
    parser.add_argument('--attempt')
    args = parser.parse_args()
    def git(*parts):
        return subprocess.run(['git', '-C', str(args.repo), *parts], check=True,
                              capture_output=True, text=True, timeout=60).stdout.strip()
    require(not git('status', '--porcelain', '--untracked-files=no'), 'tracked project inputs are dirty')
    project = {'commit': git('rev-parse', 'HEAD'), 'tree': git('rev-parse', 'HEAD^{tree}')}
    result = {}
    validate_pair(args.directory, project, args.repo, args.run, args.attempt, details=result)
    with args.report.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write('\n')


if __name__ == '__main__':
    main()
