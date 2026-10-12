#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Read bounded selected proof from a pinned archive; never extract or execute payloads."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile
import zipfile

ZIP_BYTES = 754378842
ZIP_SHA = '542e980e3ac21d3064481daf22a5817c666aa35a194e55a22cf3bd7dfd88a6d8'
TAR_BYTES = 758102289
TAR_SHA = 'd8f35234b740af9c5517a4c5ef441aa9574aa0518c563b3e9969c1bf172a67e8'
CANDIDATE = 'bbfa02476c6794538be1aad46886ec45976a4af9'
COMPILED = '7acf08abea63640a737c7cec0cae4c0da61b82f5'
TREE = 'e28679c3d6c1a8735b9069509062c4114c166c47'
RUN = 38241186538
ARTIFACT = 11747362547
NATIVE = 'PPSA99995/native-wine-child-build.json'
SELF = 'PPSA99995/native-wine-child.self'
PACKAGE = 'provenance/windows-child-fixture.json'
JSON_MEMBERS = (NATIVE, PACKAGE, 'provenance/title.json', 'provenance/title-compile.json',
                'provenance/fixture-source.json', 'provenance/private-dispatch-abi.json',
                'provenance/retained-sources.json')
SELECTED = (*JSON_MEMBERS, 'SHA256SUMS', 'BUILD-INFO.txt')
BATTLE = 'console/data/prospero-win/prefixes/battlenet-experimental-v1'
BATTLE_PROFILE = 'console/data/prospero-win/profiles/battlenet-experimental-v1.profile'
EXCLUDE = ('battlenet-experimental-v1', 'battlenet-experimental-v1.profile')
FIXTURES = ('windows-child-fixture-v1', 'windows-child-user-v1', 'windows-child-net-v1')
MAX_JSON = 8 << 20
MAX_SAVED = 32 << 20
MAX_FILE = 2 << 30
MAX_TOTAL = 12 << 30
MAX_ENTRIES = 20000

def require(value, message):
    if not value:
        raise ValueError(message)

def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode()

def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    def constant(_):
        raise ValueError('non-finite JSON number')
    return json.loads(data.decode('utf-8'), object_pairs_hook=pairs, parse_constant=constant)

def safe_name(name):
    require(isinstance(name, str) and 0 < len(name) <= 4096 and
            all(32 <= ord(c) < 127 for c in name) and not any(c in name for c in '\\<>:"|?*'),
            'unsafe archive path')
    require(not name.startswith('/') and all(p not in ('', '.', '..') for p in name.split('/')),
            'noncanonical archive path')
    for part in name.split('/'):
        require(not part.endswith((' ', '.')) and
                not re.fullmatch(r'CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9]', part.split('.')[0], re.I),
                'Windows-unsafe archive path')
    return name

def digest(path, size, expected):
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_size == size, 'wrong archive type/size')
    h = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1 << 20), b''):
            h.update(block)
        after = os.fstat(source.fileno())
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), 'archive changed')
    require(h.hexdigest() == expected, 'archive SHA256 mismatch')

def zip_to_new_tar(source, destination, outer_size=ZIP_BYTES, outer_sha=ZIP_SHA,
                   inner_size=TAR_BYTES, inner_sha=TAR_SHA):
    digest(source, outer_size, outer_sha)
    require(not destination.exists() and not destination.is_symlink(), 'output already exists')
    with zipfile.ZipFile(source) as archive:
        members = archive.infolist()
        require(len(members) == 1, 'ZIP must contain exactly one member')
        item = members[0]
        require(item.filename == 'windows-child-fixture.tar.gz' and not item.is_dir() and
                item.file_size == inner_size and not item.flag_bits & 1 and
                not stat.S_ISLNK(item.external_attr >> 16), 'wrong ZIP member')
        h, total = hashlib.sha256(), 0
        with archive.open(item) as reader, destination.open('xb') as target:
            for block in iter(lambda: reader.read(1 << 20), b''):
                total += len(block)
                require(total <= inner_size, 'ZIP expansion exceeds exact size')
                h.update(block)
                target.write(block)
        require(total == inner_size and h.hexdigest() == inner_sha, 'inner TAR identity differs')

def scan_tar(path, selected=SELECTED):
    values, contents, folded = {}, {}, set()
    total = saved = 0
    with tarfile.open(path, 'r:gz') as archive:
        for item in archive:
            name = safe_name(item.name.rstrip('/') if item.isdir() else item.name)
            require(name.casefold() not in folded, 'duplicate/case-colliding member')
            folded.add(name.casefold())
            require(not item.linkname and item.type in (tarfile.REGTYPE, tarfile.DIRTYPE),
                    'link or special member')
            require(item.uid == item.gid == item.mtime == 0 and not item.uname and not item.gname and
                    set(item.pax_headers) <= {'path'}, 'unexpected TAR metadata')
            if item.isdir():
                require(item.mode == 0o755 and item.size == 0, 'invalid directory')
                values[name] = {'type': 'directory', 'mode': item.mode}
            else:
                require(item.mode in (0o644, 0o755) and 0 <= item.size <= MAX_FILE, 'invalid file')
                total += item.size
                require(total <= MAX_TOTAL, 'TAR total exceeds bound')
                keep = name in selected
                if keep:
                    require(item.size <= MAX_JSON, 'selected file exceeds bound')
                    saved += item.size
                    require(saved <= MAX_SAVED, 'selected total exceeds bound')
                h, count, data = hashlib.sha256(), 0, bytearray()
                with archive.extractfile(item) as reader:
                    for block in iter(lambda: reader.read(1 << 20), b''):
                        count += len(block)
                        require(count <= item.size, 'member exceeds header size')
                        h.update(block)
                        if keep:
                            data.extend(block)
                require(count == item.size, 'truncated member')
                values[name] = {'type': 'file', 'mode': item.mode, 'bytes': count, 'sha256': h.hexdigest()}
                if keep:
                    contents[name] = bytes(data)
            require(len(values) <= MAX_ENTRIES, 'too many archive entries')
    for name in values:
        for parent in PurePosixPath(name).parents:
            if str(parent) != '.':
                require(values.get(str(parent), {}).get('type') == 'directory', 'missing/non-directory parent')
    require(set(contents) == set(selected), 'selected file missing')
    if 'SHA256SUMS' in selected:
        sums = ''.join(v['sha256'] + '  ' + n + '\n' for n, v in sorted(values.items())
                       if v['type'] == 'file' and n != 'SHA256SUMS').encode()
        require(contents['SHA256SUMS'] == sums, 'SHA256SUMS differs')
    return values, contents

def deployment_inventory(values):
    roots = ('PPSA99995', 'console/data/prospero-win')
    deploy = {n: v for n, v in values.items() if any(n == r or n.startswith(r + '/') for r in roots)}
    hits = sorted(n for n in deploy if n.rsplit('/', 1)[-1].casefold() in EXCLUDE)
    require(hits == sorted((BATTLE, BATTLE_PROFILE)), 'global basename exclusions are not unique')
    require(values[BATTLE]['type'] == 'directory' and values[BATTLE_PROFILE]['type'] == 'file',
            'Battle exclusions have wrong types')
    omitted = {n: v for n, v in deploy.items() if n == BATTLE or n.startswith(BATTLE + '/') or n == BATTLE_PROFILE}
    included = {n: v for n, v in deploy.items() if n not in omitted}
    critical = {}
    pe_names = {'windows-child-fixture-v1': ('windows-child-fixture/parent.exe', 'windows-child-fixture/child.exe'),
                'windows-child-user-v1': ('windows-child-user/user-parent.exe', 'windows-child-user/user-child.exe'),
                'windows-child-net-v1': ('windows-child-net/net-parent.exe', 'windows-child-net/net-child.exe')}
    for slug in FIXTURES:
        prefix = 'console/data/prospero-win/prefixes/' + slug
        profile = 'console/data/prospero-win/profiles/' + slug + '.profile'
        expected = [profile, prefix + '/system.reg', prefix + '/user.reg', prefix + '/userdef.reg']
        expected += [prefix + '/drive_c/' + n for n in pe_names[slug]]
        for name in expected:
            require(included.get(name, {}).get('type') == 'file', 'matched fixture file absent')
        for name, value in included.items():
            if name in expected or (name.startswith(prefix + '/') and
                    name.rsplit('/', 1)[-1].lower() in ('ntdll.dll', 'win32u.dll', 'wowprospero.dll')):
                critical[name] = value
    def totals(items):
        return {'entries': len(items), 'files': sum(v['type'] == 'file' for v in items.values()),
                'bytes': sum(v.get('bytes', 0) for v in items.values()),
                'inventory_sha256': hashlib.sha256(canonical(items)).hexdigest()}
    return {'schema': 'pw-fixture-only-deployment-plan/1', 'partial_deployment': True,
            'exclude_global_basenames': list(EXCLUDE), 'exact_exclusion_hits': hits,
            'included': totals(included), 'omitted': totals(omitted), 'critical_files': critical,
            'battle_launch_allowed': False, 'console_changed': False,
            'scope': 'inventory plan only; no upload or runtime validation'}, included, omitted

def selected_native(value, values):
    require(value.get('schema') == 'pw-wine-service-child/2', 'native schema differs')
    require(value['project']['commit'] == COMPILED and value['project']['tree'] == TREE, 'native source differs')
    require(values[SELF]['bytes'] == value['worker']['bytes'] and
            values[SELF]['sha256'] == value['worker']['sha256'], 'native SELF identity differs')
    for key in ('console_execution_verified', 'windows_process_support', 'platform_authentication_verified'):
        require(value[key] is False, 'unexpected runtime claim')
    observation = value['net_target_observation']
    require(observation['schema'] == 'pw-wine-child-net-target-observation/1' and
            observation['stage'] == 5 and observation['wire_bytes'] == 136 and
            observation['target_executed'] is False and observation['runtime_validated'] is False,
            'diagnostic schema/claims differ')
    keys = ('schema', 'stage', 'wire_bytes', 'functions', 'got_slots', 'observation_instructions',
            'anchor_instruction', 'original_call_instructions', 'focused_disassembly',
            'target_executed', 'runtime_validated')
    require(set(observation) == set(keys), 'unexpected diagnostic fields')
    require(len(canonical(observation)) <= 128 << 10, 'diagnostic log exceeds bound')
    result = {k: value[k] for k in ('schema', 'project', 'worker', 'linked', 'converted', 'reconstructed',
                                  'reconstruction', 'framing', 'console_execution_verified',
                                  'windows_process_support', 'platform_authentication_verified')}
    result['linkage'] = {n: value['linkage'][n] for n in ('sceNetSocket', 'sceNetErrnoLoc')}
    result['net_target_observation'] = observation
    require(len(canonical(result)) <= 192 << 10, 'selected native log exceeds bound')
    return result

def inspect(source, output):
    require(not output.exists() and not output.is_symlink(), 'evidence output exists')
    output.mkdir()
    inner = output / 'windows-child-fixture.tar.gz'
    zip_to_new_tar(source, inner)
    values, contents = scan_tar(inner)
    require(len(values) == 9971 and sum(v['type'] == 'file' for v in values.values()) == 9192,
            'accepted archive inventory differs')
    parsed = {n: strict_json(contents[n]) for n in JSON_MEMBERS}
    package = parsed[PACKAGE]
    require(package['project']['commit'] == COMPILED and package['project']['tree'] == TREE and
            package['run_url'] == 'https://github.com/Sleepywalker69/prospero-win/actions/runs/' + str(RUN) and
            str(package['run_attempt']) == '1', 'package source/run identity differs')
    native = selected_native(parsed[NATIVE], values)
    deployment, included, omitted = deployment_inventory(values)
    for name, data in contents.items():
        target = output / 'selected' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    for name, data in [('archive-inventory.json', values), ('included-inventory.json', included),
                       ('omitted-inventory.json', omitted), ('deployment-plan.json', deployment)]:
        (output / name).write_bytes(canonical(data))
    receipt = {'schema': 'pw-matched-archive-evidence/1', 'source_artifact_id': ARTIFACT,
               'source_run_id': RUN, 'source_run_attempt': 1, 'candidate_commit': CANDIDATE,
               'compiled_commit': COMPILED, 'compiled_tree': TREE,
               'original_zip': {'bytes': ZIP_BYTES, 'sha256': ZIP_SHA},
               'original_tar': {'bytes': TAR_BYTES, 'sha256': TAR_SHA},
               'selected_members': {n: values[n] for n in SELECTED},
               'native_self': values[SELF], 'archive_inventory_sha256': hashlib.sha256(canonical(values)).hexdigest(),
               'transport': {'run_id': os.environ.get('GITHUB_RUN_ID'), 'commit': os.environ.get('GITHUB_SHA')},
               'console_execution_verified': False}
    (output / 'EVIDENCE-RECEIPT.json').write_bytes(canonical(receipt))
    # Every line begins with a fixed prefix. JSON escapes all embedded line breaks.
    # No environment, arbitrary build logs, registry content or binaries are printed.
    for kind, data in [('receipt', receipt), ('native', native), ('deployment', deployment)]:
        encoded = canonical(data).decode().rstrip('\n')
        print('PW_MATCHED_EVIDENCE ' + json.dumps({'kind': kind, 'data': strict_json(encoded.encode())},
                                                ensure_ascii=True, separators=(',', ':')))
    return receipt

if __name__ == '__main__':
    require(len(sys.argv) == 3, 'usage: inspect_matched_artifact.py ORIGINAL.zip NEW_EVIDENCE_DIR')
    inspect(Path(sys.argv[1]), Path(sys.argv[2]))
