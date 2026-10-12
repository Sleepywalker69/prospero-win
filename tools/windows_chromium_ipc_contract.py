#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Bounded, nonexecuting admission of two independently anchored Windows references.

ZIP identity is supplied by the caller from the completed Actions artifact API,
never obtained from BUILD-INFO or ENTRY-REFERENCE. No ZIP member is extracted.
The local source-bound checker is rerun against every actual log and exit receipt.
"""
from __future__ import annotations
import argparse
from collections import Counter
import fnmatch
import io
import json
from pathlib import Path
import re
import stat
import struct
import subprocess
import zipfile
from check_windows_chromium_ipc import CASES, verify, parse_log
from windows_child_user_contract import require, digest, regular, decode, record
from private_dispatch_wow64 import mapped_pe

REPOSITORY = 'Sleepywalker69/prospero-win'
SOURCE_FILES = {
    'source_sha256': 'tests/fixtures/windows_chromium_ipc.c',
    'contract_sha256': 'tests/fixtures/windows_chromium_ipc_contract.h',
    'recipe_sha256': 'tools/build_windows_chromium_ipc.ps1',
    'checker_sha256': 'tools/check_windows_chromium_ipc.py',
    'reference_workflow_sha256': '.github/workflows/windows-chromium-ipc-reference.yml'}
IMAGES = tuple('pw-ipc-' + case + '.exe' for case in CASES)
MAX_ZIP = 32 << 20
MAX_FILE = 16 << 20
MAX_TOTAL = 64 << 20


def identity(project, run, attempt):
    require(type(project) is dict and set(project) == {'commit', 'tree'} and
            all(type(v) is str and re.fullmatch('[0-9a-f]{40}', v) for v in project.values()),
            'external complete project identity required')
    require(all(type(v) is str and re.fullmatch('[1-9][0-9]*', v) for v in (run, attempt)),
            'external run and attempt required')


def anchors(value, project, run, attempt):
    identity(project, run, attempt)
    require(type(value) is dict and set(value) == {'schema', 'repository', 'project', 'run_id', 'run_attempt', 'artifacts'} and
            value['schema'] == 'pw-chromium-ipc-artifact-anchors/1' and value['repository'] == REPOSITORY and
            value['project'] == project and value['run_id'] == run and value['run_attempt'] == attempt,
            'external IPC artifact/project/run anchors differ')
    require(type(value['artifacts']) is dict and set(value['artifacts']) == {'x64', 'x86'},
            'both architecture artifact anchors required')
    ids = set()
    for arch, item in value['artifacts'].items():
        require(type(item) is dict and set(item) == {'id', 'name', 'bytes', 'sha256'} and
                type(item['id']) is str and re.fullmatch('[1-9][0-9]*', item['id']) and
                type(item['bytes']) is int and 0 < item['bytes'] <= MAX_ZIP and
                type(item['sha256']) is str and re.fullmatch('[0-9a-f]{64}', item['sha256']) and
                item['name'] == f'windows-chromium-ipc-reference-{arch}-{project["commit"]}-{attempt}',
                'invalid external IPC artifact identity')
        require(item['id'] not in ids, 'architecture artifact IDs must differ')
        ids.add(item['id'])
    return value


def zip_contents(data, anchor):
    require(type(data) is bytes and 0 < len(data) <= MAX_ZIP and record(data) ==
            {k: anchor[k] for k in ('bytes', 'sha256')}, 'IPC ZIP differs from external artifact digest')
    files, seen, total = {}, set(), 0
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        members = archive.infolist()
        require(0 < len(members) <= 512, 'IPC ZIP member count exceeds bound')
        for member in members:
            name = member.filename
            require(name and not name.startswith('/') and '\\' not in name and
                    all(re.fullmatch('[A-Za-z0-9_.-]+', p) and p not in ('.', '..') for p in name.split('/')) and
                    name.casefold() not in seen, 'unsafe or duplicate IPC ZIP path')
            seen.add(name.casefold())
            mode = member.external_attr >> 16
            require(not member.is_dir() and (not stat.S_IFMT(mode) or stat.S_ISREG(mode)) and
                    not member.flag_bits & 1 and 0 <= member.file_size <= MAX_FILE and
                    member.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED),
                    'linked, encrypted, nonregular or oversized IPC ZIP member')
            total += member.file_size
            require(total <= MAX_TOTAL, 'IPC ZIP uncompressed bound exceeded')
            with archive.open(member) as stream:
                value = stream.read(member.file_size + 1)
            require(len(value) == member.file_size, 'IPC ZIP member length differs')
            files[name] = value
    return files


class LogFile:
    def __init__(self, name, data): self.name, self.data = name, data
    def read_bytes(self): return self.data
    def __lt__(self, other): return self.name < other.name


class LogDirectory:
    def __init__(self, files): self.files = files
    def glob(self, pattern):
        return [LogFile(name, data) for name, data in self.files.items() if fnmatch.fnmatchcase(name, pattern)]



def inspect_image(data, arch):
    require(type(data) is bytes and 256 <= len(data) <= MAX_FILE, 'bounded IPC PE required')
    machine, magic = (0x8664, 0x20b) if arch == 'x64' else (0x14c, 0x10b)
    mapped_pe(data, machine)
    offset = struct.unpack_from('<I', data, 60)[0]
    characteristics = struct.unpack_from('<H', data, offset + 22)[0]
    optional = offset + 24
    require(struct.unpack_from('<H', data, optional)[0] == magic and characteristics & 2 and
            not characteristics & 0x2001 and struct.unpack_from('<H', data, optional + 68)[0] == 3 and
            struct.unpack_from('<H', data, optional + 70)[0] & 0x140 == 0x140,
            'IPC requires original relocatable NX/ASLR console executable')
    return {**record(data), 'machine': 'AMD64' if arch == 'x64' else 'I386'}


def validate_contents(files, arch, project, run, attempt, source_hashes):
    identity(project, run, attempt)
    require(arch in ('x64', 'x86') and type(source_hashes) is dict and set(source_hashes) == set(SOURCE_FILES) and
            all(type(v) is str and re.fullmatch('[0-9a-f]{64}', v) for v in source_hashes.values()),
            'independently bound IPC source/recipe/checker/workflow hashes required')
    base = 'chromium-ipc-' + arch + '/'
    require(type(files) is dict and 0 < len(files) <= 512 and all(type(v) is bytes for v in files.values()),
            'bounded IPC contents required')
    originals = {'BUILD-INFO.txt', 'build.log', 'child.exe', 'fixture.obj', 'parent.exe', 'SHA256SUMS'}
    require({n for n in files if not n.startswith(base)} == {'original-' + arch + '/' + n for n in originals},
            'unexpected original baseline files or architecture tree')
    local = {n[len(base):]: v for n, v in files.items() if n.startswith(base)}
    def take(name, maximum=MAX_FILE, minimum=0):
        require(name in local and minimum <= len(local[name]) <= maximum, 'missing/unbounded IPC input: ' + name)
        return local[name]
    meta = decode(take('BUILD-INFO.json', 65536, 1))
    bits, machine = (64, 0x8664) if arch == 'x64' else (32, 0x14c)
    require(meta.get('schema') == 'pw-chromium-ipc-build/2' and meta.get('arch') == arch and
            meta.get('pe_machine') == machine and meta.get('project') == project and
            meta.get('ci') == {'repository': REPOSITORY, 'run_id': run, 'run_attempt': attempt},
            'IPC producer identity differs from external complete cohort')
    for field, relative in SOURCE_FILES.items():
        require(meta.get(field) == source_hashes[field] and
                digest(take(Path(relative).name, 4 << 20, 1)) == source_hashes[field],
                'IPC source/recipe/checker/workflow bytes differ: ' + field)
    require(meta.get('windows_execution') == 'not_run' and meta.get('ps5_execution') == 'not_run' and
            meta.get('native_admission') == 'not_implemented' and
            re.fullmatch('[0-9a-f]{64}', meta.get('compiler_sha256', '')) and
            meta.get('compiler_selection') == 'Exact where cl.exe and /Bv output retained in build.log',
            'IPC producer overstates evidence or lacks compiler identity')
    executable = take('chromium-ipc.exe', MAX_FILE, 256)
    image = inspect_image(executable, arch)
    require(image['sha256'] == meta.get('executable_sha256'), 'IPC canonical PE digest differs')
    entries = [{'file': name, 'case': case, 'sha256': image['sha256'], 'arguments': [],
                'proposed_profile_id': 'windows-chromium-ipc-' + case + '-v1', 'native_admission': 'not_implemented'}
               for name, case in zip(IMAGES, CASES)]
    require(meta.get('empty_argument_entries') == entries, 'IPC exact empty-argument alias table differs')
    for name in IMAGES:
        require(take(name) == executable, 'IPC alias is not byte-identical to canonical PE')
    require(take('entry-rejection-controls/unregistered-ipc.exe') == executable,
            'IPC unknown-entry rejection control is not the same executable')
    summary = {'schema': 'pw-chromium-ipc-empty-argument-reference/1', 'bits': bits,
        'project_commit': project['commit'], 'run_id': run, 'run_attempt': attempt,
        'explicit_cases': list(CASES), 'empty_argument_cases': list(CASES), 'rejection_controls': 12,
        'windows_reference': 'pass', 'native_admission': 'not_implemented', 'ps5_execution': 'not_run',
        'native_settlement': 'unverified'}
    require(decode(take('ENTRY-REFERENCE.json', 65536, 1)) == summary, 'IPC reference declaration differs')
    allowed = {'BUILD-INFO.json', 'ENTRY-REFERENCE.json', 'chromium-ipc.exe', 'chromium-ipc.obj', 'build.log', 'SHA256SUMS',
               *IMAGES, *(Path(p).name for p in SOURCE_FILES.values()), 'entry-rejection-controls/unregistered-ipc.exe'}
    observed, identities = {}, set()
    for route in ('', 'empty-argument-reference/'):
        for case in CASES:
            directory = route + case + '/'
            contents = {n[len(directory):]: v for n, v in local.items() if n.startswith(directory)}
            logs = {n for n in contents if re.fullmatch(r'ipc-[1-9][0-9]*-[1-9][0-9]*\.log', n)}
            require(set(contents) == logs | {'reference.exit', 'REFERENCE.json', 'stdout.log', 'stderr.log'} and
                    contents['reference.exit'] in (b'reference_exit=0\n', b'reference_exit=0\r\n') and
                    not contents['stderr.log'], 'IPC case file set or actual exit differs')
            require(Counter(contents['stdout.log'].splitlines()) == Counter(
                line for name in logs for line in contents[name].splitlines()), 'IPC stdout differs from actual process logs')
            result = verify(LogDirectory(contents), case, bits, 0)
            require(decode(contents['REFERENCE.json']) == result, 'IPC saved checker result differs from actual logs')
            for name in logs:
                rows = parse_log(LogFile(name, contents[name])); first = rows[0]
                require(name == f'ipc-{first["nonce"]}-{first["pid"]}.log', 'IPC log filename identity differs')
                require(all(row['elapsed_ms'] <= 60000 for row in rows), 'IPC log exceeds child budget')
            key = (result['nonce'], result['parent_pid'])
            require(key not in identities, 'IPC launch evidence reused between entries')
            identities.add(key); observed[route + case] = result
            allowed.update(directory + n for n in contents)
    controls = ('canonical-no-case', 'canonical-extra', 'unknown-no-case', 'unknown-explicit-case',
                *('alias-arguments-' + case for case in CASES))
    for control in controls:
        directory = 'entry-rejection-controls/' + control + '/'
        contents = {n[len(directory):]: v for n, v in local.items() if n.startswith(directory)}
        require(set(contents) == {'reference.exit', 'stdout.log', 'stderr.log'} and
                contents['reference.exit'] in (b'reference_exit=2\n', b'reference_exit=2\r\n') and
                not any(b'PW_CHROMIUM_IPC' in contents[n] for n in ('stdout.log', 'stderr.log')),
                'IPC negative entry lacks actual exit 2 or entered a case')
        allowed.update(directory + n for n in contents)
    for name in ('reference.exit', 'stdout.log', 'stderr.log'):
        take('original-baseline/' + name, 131072)
        allowed.add('original-baseline/' + name)
    require(take('original-baseline/reference.exit') in (b'reference_exit=0\n', b'reference_exit=0\r\n') and
            not take('original-baseline/stderr.log'), 'original Windows baseline failed')
    require(set(local) == allowed, 'extra IPC artifact payload or missing evidence')
    sums = {}
    for line in take('SHA256SUMS', 65536, 1).decode('ascii').splitlines():
        match = re.fullmatch('([0-9a-f]{64})  ([A-Za-z0-9_.-]+)', line)
        require(match is not None and match[2] not in sums, 'invalid or duplicate IPC checksum')
        sums[match[2]] = match[1]
    expected_sums = {'chromium-ipc.exe', 'windows_chromium_ipc.c', 'windows_chromium_ipc_contract.h', 'build.log',
                     'BUILD-INFO.json', *IMAGES, *(Path(p).name for p in list(SOURCE_FILES.values())[2:])}
    require(set(sums) == expected_sums and all(digest(take(n)) == h for n, h in sums.items()),
            'IPC producer checksum table differs')
    return {'schema': 'pw-chromium-ipc-validated-reference/1', 'project': project,
            'run_id': run, 'run_attempt': attempt, 'architecture': arch, 'image': image,
            'source_hashes': source_hashes, 'build_receipt': record(take('BUILD-INFO.json')),
            'entry_receipt': record(take('ENTRY-REFERENCE.json')), 'cases': observed,
            'empty_argument_cases': list(CASES), 'rejection_controls': len(controls),
            'runtime_validated': False, 'console_validated': False, 'native_settlement': 'unverified'}


def validate_archives(archives, expected_anchors, project, run, attempt, source_hashes):
    anchors(expected_anchors, project, run, attempt)
    require(type(archives) is dict and set(archives) == {'x64', 'x86'}, 'two actual Windows reference archives required')
    results = {arch: validate_contents(zip_contents(data, expected_anchors['artifacts'][arch]), arch,
               project, run, attempt, source_hashes) for arch, data in archives.items()}
    require(results['x64']['image']['sha256'] != results['x86']['image']['sha256'], 'architecture images must differ')
    return {'schema': 'pw-chromium-ipc-reference-cohort/1', 'project': project, 'run_id': run, 'run_attempt': attempt,
            'anchors': expected_anchors, 'references': results, 'admitted_architecture': 'x64',
            'runtime_validated': False, 'console_validated': False}


def validate_bundle(directory, project, root, run, attempt):
    directory, root = Path(directory), Path(root)
    require({p.name for p in directory.iterdir()} == {'x64.zip', 'x86.zip', 'anchors.json'},
            'IPC bundle requires exact ZIPs and externally supplied anchors')
    expected = decode(regular(directory / 'anchors.json', 65536, 1))
    hashes = {field: digest(regular(root / relative, 4 << 20, 1)) for field, relative in SOURCE_FILES.items()}
    return validate_archives({arch: regular(directory / (arch + '.zip'), MAX_ZIP, 1) for arch in ('x64', 'x86')},
                             expected, project, run, attempt, hashes)


def images(directory, cohort):
    # Every use rechecks the trusted ZIP digest; never accept an unpacked substitute.
    files = zip_contents(regular(Path(directory) / 'x64.zip', MAX_ZIP, 1), cohort['anchors']['artifacts']['x64'])
    return {name: files['chromium-ipc-x64/' + name] for name in IMAGES}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--run', required=True); parser.add_argument('--attempt', required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    def git(*parts):
        return subprocess.check_output(['git', '-C', str(args.repo), *parts], text=True, timeout=60).strip()
    require(not git('status', '--porcelain', '--untracked-files=no'), 'IPC cohort requires clean committed source')
    project = {'commit': git('rev-parse', 'HEAD'), 'tree': git('rev-parse', 'HEAD^{tree}')}
    result = validate_bundle(args.directory, project, args.repo, args.run, args.attempt)
    with args.report.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2, sort_keys=True); stream.write('\n')


if __name__ == '__main__': main()
