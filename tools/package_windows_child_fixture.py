#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Assemble/check the one experimental AMD64 Windows-child source cohort.

This is a distinct producer, not a switch around package_release.sh's refusal.
No console executable is run. Source/build identities are static evidence only.
"""
from __future__ import annotations
import argparse
import configparser
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile

sys.dont_write_bytecode = True
import prepare_windows_child_prefix as prefix

SLUG = 'windows-child-fixture-v1'
APP = 'PPSA99995'
RUNTIME = APP + '/win/wine'
LIB = RUNTIME + '/lib/wine'
CONSOLE_PREFIX = 'console/data/prospero-win/prefixes/' + SLUG
FIXTURE = CONSOLE_PREFIX + '/drive_c/windows-child-fixture'
PROFILE = 'console/data/prospero-win/profiles/' + SLUG + '.profile'
BATTLE_SLUG = 'battlenet-experimental-v1'
BATTLE_PREFIX = 'console/data/prospero-win/prefixes/' + BATTLE_SLUG
BATTLE_PROFILE = 'console/data/prospero-win/profiles/' + BATTLE_SLUG + '.profile'
BATTLE_REPORT = 'provenance/battlenet-prefix.json'
BATTLE_CAPABILITY = 'provenance/battlenet-capability.json'
BATTLE_INSTALLER = BATTLE_PREFIX + '/drive_c/installer/Battle.net-Setup.exe'
BATTLE_CPU = 'provenance/battlenet-cpu-build.json'
MANIFEST = 'provenance/windows-child-fixture.json'
ABI_REPORT = 'provenance/private-dispatch-abi.json'
SUMS = 'SHA256SUMS'
MAX_FILE = 2 << 30
MAX_TOTAL = 12 << 30
MAX_ENTRIES = 20000
MAX_JSON = 64 << 20
require = prefix.require


def digest_file(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            result.update(block)
    return result.hexdigest()


def safe_name(name):
    require(isinstance(name, str) and 0 < len(name) <= 4096 and
            all(32 <= ord(c) < 127 for c in name) and not any(c in name for c in '\\<>:"|?*'),
            'unsafe archive path')
    parts = name.split('/')
    require(not name.startswith('/') and all(p not in ('', '.', '..') for p in parts),
            'noncanonical archive path')
    for part in parts:
        require(not part.endswith((' ', '.')) and
                not re.fullmatch(r'CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9]', part.split('.')[0], re.I),
                'Windows-unsafe archive component')
    return name


def record(path):
    prefix.ordinary(path)
    info = path.stat()
    require(info.st_size <= MAX_FILE, 'oversized input')
    return {'bytes': info.st_size, 'sha256': digest_file(path)}


def decode_json(value):
    def pairs(items):
        result = {}
        for key, data in items:
            require(key not in result, 'duplicate JSON key')
            result[key] = data
        return result
    return json.loads(value, object_pairs_hook=pairs)


def read_json(path):
    prefix.ordinary(path)
    require(path.stat().st_size <= MAX_JSON, 'oversized JSON')
    return decode_json(path.read_bytes())

def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def inventory(root):
    prefix.ordinary(root, True)
    values, folded, total = {}, set(), 0
    for path in sorted(root.rglob('*')):
        name = safe_name(path.relative_to(root).as_posix())
        require(name.casefold() not in folded, 'case-colliding archive paths')
        folded.add(name.casefold())
        info = path.lstat()
        require(not stat.S_ISLNK(info.st_mode), 'archive symlink refused')
        mode = stat.S_IMODE(info.st_mode)
        if stat.S_ISDIR(info.st_mode):
            require(mode == 0o755, 'directory mode must be0755')
            values[name] = {'type': 'directory', 'mode': mode}
        else:
            require(stat.S_ISREG(info.st_mode), 'archive special file refused')
            require(mode in (0o644, 0o755), 'file mode must be0644 or0755')
            values[name] = {'type': 'file', 'mode': mode, **record(path)}
            total += info.st_size
        require(len(values) <= MAX_ENTRIES and total <= MAX_TOTAL, 'archive inventory exceeds bounds')
    return values


def normal_mode(name):
    return 0o755 if name.endswith(('.prx', '.self')) or name == APP + '/eboot.bin' else 0o644


def put(root, name, source, expected=None):
    safe_name(name)
    before = record(source)
    if expected is not None:
        require(before == expected, 'source bytes disagree: ' + name)
    destination = root / name
    require(not destination.exists() and not destination.is_symlink(), 'duplicate package destination: ' + name)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    shutil.copyfile(source, destination)
    destination.chmod(normal_mode(name))
    require(record(destination) == before and record(source) == before, 'source changed during copy: ' + name)


def put_bytes(root, name, value):
    safe_name(name)
    destination = root / name
    require(not destination.exists(), 'duplicate generated path')
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    with destination.open('xb') as stream:
        stream.write(value)
    destination.chmod(0o644)


def copy_tree(root, target, source, *, expected=None):
    actual = prefix.inventory(source)
    if expected is not None:
        require(actual == expected, 'source tree differs from manifest: ' + target)
    for name, value in actual.items():
        destination = target if name == '.' else target + '/' + safe_name(name)
        if value['type'] == 'directory':
            (root / destination).mkdir(parents=True, exist_ok=True, mode=0o755)
        else:
            require(value['type'] == 'file', 'source tree link/special object')
            put(root, destination, source / name,
                {'bytes': value['bytes'], 'sha256': value['sha256']})
    require(prefix.inventory(source) == actual, 'source tree changed during copy')


def normalize_directories(root):
    # Only a freshly created, owned output tree reaches this operation.
    for path in (root, *root.rglob('*')):
        require(not path.is_symlink(), 'output symlink refused')
        if path.is_dir(): path.chmod(0o755)


def checksums(values):
    return ''.join(v['sha256'] + '  ' + n + '\n' for n, v in sorted(values.items())
                   if v['type'] == 'file' and n != SUMS).encode()


def copied_inventory(values, target, source, exact=True):
    expected_names = set()
    for name, entry in source.items():
        full = target if name == '.' else target + '/' + safe_name(name)
        expected_names.add(full)
        require(entry.get('type') in ('directory', 'file'), 'source inventory has a link/special entry')
        wanted = {'type': entry['type'], 'mode': 0o755 if entry['type'] == 'directory' else normal_mode(full)}
        if entry['type'] == 'file':
            wanted.update(bytes=entry['bytes'], sha256=entry['sha256'])
        require(values.get(full) == wanted, 'copied inventory mismatch: ' + full)
    if exact:
        require({n for n in values if n == target or n.startswith(target + '/')} == expected_names,
                'extra/missing copied tree member: ' + target)


def title_files(values):
    return {n: {k: entry[k] for k in ('bytes', 'sha256', 'mode')}
            for n, entry in values.items() if entry['type'] == 'file'}


def title_inventory(files):
    result = {'.': {'type': 'directory', 'mode': 0o755}}
    for name, value in files.items():
        safe_name(name)
        result[name] = {'type': 'file', **value}
        for parent in PurePosixPath(name).parents:
            if str(parent) != '.': result[str(parent)] = {'type': 'directory', 'mode': 0o755}
    return result


def validate_console_scope(values, slug=SLUG):
    require(slug in (SLUG, BATTLE_SLUG), 'unknown console profile scope')
    base = 'data/prospero-win'
    guest = base + '/prefixes/' + slug
    profile = base + '/profiles/' + slug + '.profile'
    directories = {'.', 'data', base, base + '/prefixes', base + '/profiles'}
    for name, entry in values.items():
        require(name == guest or name.startswith(guest + '/') or
                (name == profile and entry['type'] == 'file') or
                (name in directories and entry['type'] == 'directory'),
                'unreviewed console profile/prefix in fixture package')


def merge_console_inventories(fixture, battle):
    validate_console_scope(fixture)
    validate_console_scope(battle, BATTLE_SLUG)
    combined = dict(fixture)
    for name, entry in battle.items():
        if name in combined:
            require(entry == combined[name] and entry['type'] == 'directory',
                    'overlapping console file or differing ancestor directory')
        else:
            combined[name] = entry
    installer_directory = BATTLE_PREFIX.removeprefix('console/') + '/drive_c/installer'
    require(combined.get(installer_directory, {}).get('type') == 'directory' and
            not any(name.startswith(installer_directory + '/') for name in combined),
            'user installer directory must be present and empty')
    return combined


def battle_profile_fields(data):
    parsed = configparser.ConfigParser(interpolation=None, strict=True)
    parsed.optionxform = str
    parsed.read_string(data.decode('utf-8'))
    expected = {'id': BATTLE_SLUG, 'prefix': BATTLE_SLUG,
                'executable': 'C:\\installer\\Battle.net-Setup.exe',
                'working_directory': 'C:\\installer', 'runtime': 'wine-wow64',
                'architecture': 'pe32', 'graphics': 'auto'}
    require(not parsed.defaults() and set(parsed.sections()) == {'application', 'runtime'},
            'Battle profile contains unreviewed sections/defaults')
    app = dict(parsed['application'])
    require(set(expected) <= set(app) <= set(expected) | {'name', 'arguments'} and
            all(app[k] == v for k, v in expected.items()) and not app.get('arguments') and
            dict(parsed['runtime']) == {'cpu': 'translator'}, 'Battle profile configuration differs')
    return {'id': BATTLE_SLUG, 'runtime': 'wine-wow64', 'architecture': 'pe32',
            'cpu': 'translator', 'executable': expected['executable'],
            'cwd': expected['working_directory'], 'args': []}


def battle_capability(project, profile_bytes, prefix_report_bytes, runtime_check):
    return {'schema': 'pw-battlenet-experimental-capability/1', 'project': project,
            'battlenet_enabled': True, 'installer_included': False, 'runtime_validated': False,
            'installer_executed': False, 'descendants_supported': False, 'child_gui_supported': False,
            'profile': {'path': BATTLE_PROFILE, 'sha256': hashlib.sha256(profile_bytes).hexdigest(),
                        **battle_profile_fields(profile_bytes)},
            'prefix': {'path': BATTLE_PREFIX, 'report_path': BATTLE_REPORT,
                       'report_sha256': hashlib.sha256(prefix_report_bytes).hexdigest()},
            'installer': {'path': BATTLE_INSTALLER, 'included': False, 'user_supplied': True},
            'runtime_check': runtime_check}


def validate_battle(manifest, values, read, prepared, abi, build):
    enabled = manifest.get('battlenet_enabled')
    require(type(enabled) is bool, 'Battle capability selection must be boolean')
    optional = {BATTLE_REPORT, BATTLE_CAPABILITY, BATTLE_CPU, BATTLE_PROFILE}
    if not enabled:
        require(not any(n in values for n in optional) and not manifest.get('optional_roles'),
                'disabled package contains Battle capability/profile')
        copied_inventory(values, 'console', prepared['inventory'])
        return
    require(all(values.get(n, {}).get('type') == 'file' for n in optional),
            'Battle capability/prefix/profile/CPU report missing')
    roles = {'battlenet_profile': BATTLE_PROFILE, 'battlenet_capability': BATTLE_CAPABILITY}
    require(manifest.get('optional_roles') == roles, 'Battle consumer roles differ')
    capability = decode_json(read(BATTLE_CAPABILITY))
    battle_bytes = read(BATTLE_REPORT)
    battle = decode_json(battle_bytes)
    check = capability.get('runtime_check', {})
    require(capability == battle_capability(manifest['project'], read(BATTLE_PROFILE), battle_bytes, check),
            'Battle capability scope/profile/installer identity differs')
    require(battle.get('schema') == 'pw-battlenet-experimental-prefix/1' and
            battle.get('project') == manifest['project'] and battle.get('wine_commit') == prefix.WINE and
            battle.get('patches') == manifest['patches'] and battle.get('private_dispatcher') == abi and
            battle.get('installer_included') is False and battle.get('console_execution_verified') is False,
            'Battle prefix source/ABI/scope differs')
    combined = merge_console_inventories(prepared['inventory'], battle['inventory'])
    copied_inventory(values, 'console', combined)
    require(BATTLE_INSTALLER not in values, 'user installer must not be distributed')
    require(check.get('private_dispatcher') == abi and check.get('runtime_validated') is False and
            check.get('cpu') == battle.get('cpu') == prepared.get('cpu'), 'Battle runtime/CPU cohort differs')
    require(decode_json(read(BATTLE_CPU)) == check['cpu'] and
            values[BATTLE_CPU]['sha256'] == check.get('cpu_manifest_sha256'), 'Battle CPU manifest identity differs')
    wow = abi.get('wow64', {})
    require(wow.get('schema') == 'pw-private-dispatch-wow64-build/1' and wow.get('abi') == 1 and
            wow.get('native_export') == '__wine_ps5_private_dispatch_wow64_abi' and
            wow.get('runtime_validated') is False and wow.get('executed') is False and
            wow.get('cpu_pe_required_separately') is True, 'actual translated-I386 capability absent')
    for name, digest in build['pe'].items():
        arch, leaf = name.split('/')
        relative = 'drive_c/windows/' + ('system32' if arch == 'x86_64-windows' else 'syswow64') + '/' + leaf
        require(values.get(BATTLE_PREFIX + '/' + relative, {}).get('sha256') == digest and
                battle.get('patched_pe_delta', {}).get(relative, {}).get('after', {}).get('sha256') == digest,
                'Battle prefix patched PE mismatch: ' + name)
    require(len(battle.get('patched_pe_delta', {})) == 22, 'Battle prefix22PE overlay report missing')
    cpu = check.get('translator_pe')
    for name in (LIB + '/x86_64-windows/wowprospero.dll',
                 BATTLE_PREFIX + '/drive_c/windows/system32/wowprospero.dll'):
        require(cpu == {k: values.get(name, {}).get(k) for k in ('bytes', 'sha256')},
                'Battle translator PE differs')
    for key, name in (('translator_prx', 'wowprospero'), ('native', 'ntdll')):
        declared = wow.get(key, {}) if key != 'native' else wow.get('native', {}).get('self', {})
        actual = values.get(LIB + '/x86_64-unix/' + name + '.prx', {})
        require(all(declared.get(k) == actual.get(k) for k in ('bytes', 'sha256')) and actual.get('type') == 'file',
                'Battle native capability/translator PRX differs')
    # Assembly replays the C thunk validator and complete ELF/provider checks.
    # Here bind those reports to archive bytes; the independently pinned archive
    # is the external trust anchor, not a self-authenticating report.
    import private_dispatch_wow64 as wow_checker
    for name, anchor, export in (('ntdll', 'NtClose', '__wine_syscall_dispatcher'),
                                  ('win32u', 'NtUserGetThreadState', 'Wow64Transition')):
        data = read(LIB + '/i386-windows/' + name + '.dll')
        module = wow.get('i386_modules', {}).get(name, {})
        require(module.get('sha256') == hashlib.sha256(data).hexdigest() and module.get('machine') == 'I386' and
                module.get('anchor') == anchor and module.get('dispatcher_export') == export and
                module.get('executed') is False and module.get('preferred_base_mapping_sha256') ==
                hashlib.sha256(wow_checker.mapped_pe(data)).hexdigest(), 'Battle I386 module report differs')
    require(wow.get('backend') == wow_checker.check_backend(read(LIB + '/x86_64-windows/wow64.dll')),
            'Battle private CPU selection differs')


def validate_manifest(manifest, values, read):
    require(manifest.get('schema') == 'pw-windows-child-fixture/1' and
            manifest.get('fixture_executed') is False and manifest.get('console_validated') is False,
            'wrong fixture package schema/scope')
    require(type(manifest.get('battlenet_enabled')) is bool, 'Battle capability selection must be boolean')
    project = manifest.get('project', {})
    require(set(project) == {'commit', 'tree'} and
            all(re.fullmatch('[0-9a-f]{40}', project[k]) for k in project), 'invalid project identity')
    run_url = manifest.get('run_url', '')
    require(re.fullmatch(r'https://github\.com/Sleepywalker69/prospero-win/actions/runs/[1-9][0-9]*', run_url),
            'package producer run URL absent')
    expected = {n: v for n, v in values.items() if n not in (MANIFEST, SUMS)}
    require(manifest.get('inventory') == expected, 'complete package inventory differs')
    required = {APP + '/eboot.bin', APP + '/native-wine-child.self', APP + '/native-wine-child-build.json',
                FIXTURE + '/parent.exe', FIXTURE + '/child.exe', PROFILE, ABI_REPORT, 'BUILD-INFO.txt',
                APP + '/LICENSE', APP + '/THIRD_PARTY.md', RUNTIME + '/share/wine/ca-certificates.crt',
                'provenance/prefix.json', 'provenance/retained-sources.json', 'provenance/title.json',
                'provenance/fixture-source.json', 'provenance/wine-prx-checks.json', 'provenance/wine-build.json'}
    require(all(values.get(n, {}).get('type') == 'file' for n in required), 'required package file missing')
    info = read('BUILD-INFO.txt').decode('utf-8').splitlines()
    for key, expected in (('Mode', 'windows-child-fixture'), ('Commit', project['commit']), ('Run', run_url)):
        require([line for line in info if line.startswith(key + ':')] == [key + ': ' + expected],
                'BUILD-INFO consumer identity differs')
    require(values[FIXTURE + '/parent.exe']['sha256'] == values[FIXTURE + '/child.exe']['sha256'],
            'packaged fixture pair differs')
    require(set(n.split('/')[0] for n in values) <= {APP, 'console', 'provenance', 'sources', 'BUILD-INFO.txt', SUMS},
            'unexpected archive root')
    abi = decode_json(read(ABI_REPORT))
    require(abi.get('mode') == 1 and abi.get('executed') is False and
            abi.get('pe_identity', {}).get('abi') == 1, 'package requires private ABI1')
    for name, anchor in (('ntdll', 'NtClose'), ('win32u', 'NtUserGetThreadState')):
        package_pe = LIB + '/x86_64-windows/' + name + '.dll'
        prefix_pe = CONSOLE_PREFIX + '/drive_c/windows/system32/' + name + '.dll'
        require(values.get(package_pe, {}).get('sha256') == values.get(prefix_pe, {}).get('sha256') and
                values.get(package_pe, {}).get('type') == 'file', 'prefix/runtime dispatcher PE mismatch')
        import check_private_dispatch_abi as dispatcher
        require(dispatcher.check_image(read(package_pe), anchor, 1) == abi['pe_identity']['modules'][name],
                'actual packaged dispatcher ABI differs')
    worker = decode_json(read(APP + '/native-wine-child-build.json'))
    require(worker.get('schema') == 'pw-wine-service-child/1' and worker.get('project') == project,
            'worker/project identity differs')
    require(worker.get('runtime', {}).get('private_dispatch_abi') == 1 and
            worker['runtime'].get('ntdll_sha256') == values[LIB + '/x86_64-unix/ntdll.prx']['sha256'],
            'worker/runtime identity differs')
    require(worker.get('worker', {}).get('sha256') == values[APP + '/native-wine-child.self']['sha256'] and
            worker['worker'].get('bytes') == values[APP + '/native-wine-child.self']['bytes'], 'worker bytes differ')
    from check_wine_prx_build import MODULES, PE
    prx_root = LIB + '/x86_64-unix/'
    require({n[len(prx_root):] for n, v in values.items() if n.startswith(prx_root) and v['type'] == 'file'} ==
            {n + '.prx' for n in MODULES}, 'wrong14PRX package cohort')
    checked = decode_json(read('provenance/wine-prx-checks.json'))
    require(checked.get('schema') == 'pw-prx-ci-check/1' and set(checked.get('modules', {})) == set(MODULES),
            'complete PRX check report absent')
    for name in MODULES:
        require(checked['modules'][name]['sha256'] == values[prx_root + name + '.prx']['sha256'], 'PRX check hash differs')
    prepared = decode_json(read('provenance/prefix.json'))
    require(prepared.get('schema') == 'pw-windows-child-prefix/1' and prepared.get('project') == project and
            prepared.get('private_dispatcher') == abi and prepared.get('fixture_executed') is False,
            'packaged prefix provenance differs')
    validate_console_scope(prepared['inventory'])
    build = decode_json(read('provenance/wine-build.json'))
    expected_pe = {arch + '/' + name + '.dll' for arch in ('i386-windows', 'x86_64-windows') for name in PE}
    expected_pe |= {'x86_64-windows/wow64.dll', 'x86_64-windows/wow64win.dll'}
    require(set(build.get('pe', {})) == expected_pe and len(expected_pe) == 22 and
            build.get('wine_commit') == prefix.WINE and build.get('patches') == sorted(manifest['patches']) and
            prepared.get('patches') == manifest['patches'], 'Wine source/22PE provenance differs')
    require(len(prepared.get('patched_pe_delta', {})) == 22, 'prefix22PE overlay report missing')
    for name, digest in build['pe'].items():
        arch, leaf = name.split('/')
        relative = 'drive_c/windows/' + ('system32' if arch == 'x86_64-windows' else 'syswow64') + '/' + leaf
        require(values.get(LIB + '/' + name, {}).get('sha256') == digest and
                values.get(CONSOLE_PREFIX + '/' + relative, {}).get('sha256') == digest and
                prepared['patched_pe_delta'].get(relative, {}).get('after', {}).get('sha256') == digest,
                'runtime/prefix patched PE mismatch: ' + name)
    cpu_name = 'x86_64-windows/wowprospero.dll'
    cpu = prepared.get('cpu', {}).get('outputs', {}).get(cpu_name)
    require(isinstance(cpu, dict) and cpu == {k: values.get(LIB + '/' + cpu_name, {}).get(k) for k in ('bytes', 'sha256')} and
            cpu == {k: values.get(CONSOLE_PREFIX + '/drive_c/windows/system32/wowprospero.dll', {}).get(k)
                    for k in ('bytes', 'sha256')}, 'source-built CPU DLL binding differs')
    validate_battle(manifest, values, read, prepared, abi, build)
    pair = decode_json(read('provenance/fixture-source.json'))
    require(pair.get('project') == project and pair == prepared['fixture'] and pair.get('architecture') == 'x64',
            'packaged fixture producer differs')
    for name in ('parent.exe', 'child.exe'):
        require(pair['files'][name] == {k: values[FIXTURE + '/' + name][k] for k in ('bytes', 'sha256')},
                'packaged fixture bytes differ from producer')
    sources = decode_json(read('provenance/retained-sources.json'))
    require(sources.get('schema') == 'pw-windows-child-retained-sources/1' and sources.get('project') == project,
            'packaged source provenance differs')
    copied_inventory(values, 'sources', sources['inventory'])
    title = decode_json(read('provenance/title.json'))
    require(title.get('schema') == 'pw-windows-child-title/1' and title.get('project') == project and
            title.get('fixture_child_sha256') == pair['files']['child.exe']['sha256'],
            'packaged title provenance differs')
    copied_inventory(values, APP, title_inventory(title['files']), exact=False)
    return manifest


def verify_directory(root):
    values = inventory(root)
    require(MANIFEST in values and SUMS in values, 'package manifests absent')
    require((root / SUMS).read_bytes() == checksums(values), 'SHA256SUMS incomplete or changed')
    return validate_manifest(read_json(root / MANIFEST), values, lambda n: (root / safe_name(n)).read_bytes())


def write_archive(root, target):
    require(not target.exists() and not target.is_symlink(), 'archive output exists')
    before = inventory(root)
    with target.open('xb') as raw, gzip.GzipFile(fileobj=raw, mode='wb', filename='', mtime=0) as zipped:
        with tarfile.open(fileobj=zipped, mode='w', format=tarfile.PAX_FORMAT) as archive:
            for name, value in before.items():
                item = tarfile.TarInfo(name)
                item.mode, item.uid, item.gid, item.mtime = value['mode'], 0, 0, 0
                if value['type'] == 'directory':
                    item.type = tarfile.DIRTYPE
                    archive.addfile(item)
                else:
                    item.size = value['bytes']
                    with (root / name).open('rb') as stream:
                        archive.addfile(item, stream)
    target.chmod(0o644)
    require(inventory(root) == before, 'package changed during archive creation')


def verify_archive(path):
    prefix.ordinary(path)
    values, contents, folded, total = {}, {}, set(), 0
    # Do not extract any member. Every file is streamed and checked, including sources.
    with tarfile.open(path, 'r:gz') as archive:
        for item in archive:
            name = safe_name(item.name.rstrip('/') if item.isdir() else item.name)
            require(name not in values and name.casefold() not in folded, 'duplicate/case-colliding tar member')
            require(not item.linkname and item.type in (tarfile.REGTYPE, tarfile.DIRTYPE), 'tar link/special member')
            require(item.uid == item.gid == item.mtime == 0 and not item.uname and not item.gname and
                    set(item.pax_headers) <= {'path'}, 'unexpected archive metadata')
            folded.add(name.casefold())
            if item.isdir():
                require(item.mode == 0o755 and item.size == 0, 'bad directory mode/size')
                values[name] = {'type': 'directory', 'mode': item.mode}
            else:
                require(item.mode in (0o644, 0o755) and 0 <= item.size <= MAX_FILE, 'bad file mode/size')
                total += item.size
                h, size, saved = hashlib.sha256(), 0, bytearray()
                retain = name.startswith('provenance/') and name.endswith('.json') or \
                    name in (MANIFEST, SUMS, ABI_REPORT, BATTLE_PROFILE, 'BUILD-INFO.txt', APP + '/native-wine-child-build.json') or \
                    name in (LIB + '/x86_64-windows/ntdll.dll', LIB + '/x86_64-windows/win32u.dll',
                             LIB + '/x86_64-windows/wow64.dll', LIB + '/i386-windows/ntdll.dll',
                             LIB + '/i386-windows/win32u.dll')
                if retain:
                    require(item.size <= MAX_JSON, 'oversized inspection input')
                stream = archive.extractfile(item)
                for block in iter(lambda: stream.read(1 << 20), b''):
                    h.update(block); size += len(block)
                    if retain: saved.extend(block)
                require(size == item.size, 'truncated archive member')
                values[name] = {'type': 'file', 'mode': item.mode, 'bytes': size, 'sha256': h.hexdigest()}
                if retain: contents[name] = bytes(saved)
            require(len(values) <= MAX_ENTRIES and total <= MAX_TOTAL, 'archive exceeds bounds')
    for name in values:
        for parent in PurePosixPath(name).parents:
            if str(parent) != '.':
                require(values.get(str(parent), {}).get('type') == 'directory', 'missing/non-directory tar parent')
    require(contents.get(SUMS) == checksums(values), 'archive SHA256SUMS incomplete or changed')
    require(MANIFEST in contents, 'archive manifest absent')
    return validate_manifest(decode_json(contents[MANIFEST]), values, contents.__getitem__)


def validate_service(repo, directory, project, wine_work, abi, sdk, foundation, bindir, inspection):
    # Reuse the producer's complete source/compiler/provider/ELF identity checks.
    # This calls only host analyzers and source readers; it never builds or runs the child.
    builder = prefix.load_tool(repo, 'build_wine_service_child')
    args = argparse.Namespace(work=repo, sdk=sdk, foundation=foundation, runtime=wine_work,
                              llvm_bindir=bindir, service_work=directory)
    value, _ = builder.verify_child(args, builder.Commands(inspection))
    require(value['project'] == project and value['runtime']['abi_check'] == abi,
            'child/runtime/source cohort differs')
    return value

def retained_sources(root, source_root, manifest_path, project, wine_archive, service, sdk, foundation, wine_work):
    value = read_json(manifest_path)
    require(value.get('schema') == 'pw-windows-child-retained-sources/1' and value.get('project') == project,
            'retained sources have another project identity')
    files = prefix.inventory(source_root)
    require(value.get('inventory') == files, 'retained source inventory differs')
    roles = value.get('roles', {})
    required = {'project', 'wine', 'title-foundation', 'prx-foundation', 'sdk', 'freetype',
                'gnutls', 'nettle', 'zlib', 'ca-bundle', 'lapy'}
    require(set(roles) == required, 'complete retained source roles required')
    expected_revisions = {'project': project['commit'], 'wine': prefix.WINE,
                          'title-foundation': service['title_foundation'],
                          'prx-foundation': service['prx_foundation']}
    require(service['converter_foundation'] == service['title_foundation'],
            'child executable converter differs from its retained title foundation')
    for role, item in roles.items():
        path = safe_name(item['path'])
        require(files.get(path, {}).get('type') == 'file' and item.get('revision') and item.get('url'),
                'source role lacks retained bytes/revision/URL: ' + role)
        require(item.get('notices') and all(files.get(safe_name(n), {}).get('type') == 'file'
                                           for n in item['notices']), 'retained source notices missing: ' + role)
        if role in expected_revisions:
            require(item['revision'] == expected_revisions[role], 'retained source revision mismatch: ' + role)
    # The prefix exporter checked this exact upstream archive against git archive.
    require(record(source_root / roles['wine']['path']) == record(wine_archive), 'retained Wine archive differs')
    project_source = source_root / roles['project']['path']
    expected = subprocess.run(['git', '-C', str(root), 'archive', project['commit']], check=True,
                              capture_output=True, timeout=120).stdout
    require(gzip.decompress(project_source.read_bytes()) == expected, 'retained project archive is not exact source')
    for role, checkout in (('title-foundation', sdk.parent.parent.parent), ('prx-foundation', foundation)):
        require(prefix.git(checkout, 'rev-parse', 'HEAD') == expected_revisions[role], 'foundation checkout differs')
        expected = subprocess.run(['git', '-C', str(checkout), 'archive', expected_revisions[role]],
                                  check=True, capture_output=True, timeout=120).stdout
        require(gzip.decompress((source_root / roles[role]['path']).read_bytes()) == expected,
                'retained foundation archive differs from exact source')
    from check_native_suite import source_archive
    sdk_actual = source_archive(source_root / roles['sdk']['path'])
    require(sdk_actual == value['sdk_source'], 'retained SDK tree identity differs')
    actual = read_json(wine_work / 'report.json')['tls']['build']['inputs']['sources']
    for role, key in (('gnutls', 'gnutls'), ('nettle', 'nettle'), ('ca-bundle', 'ca_bundle')):
        require(digest_file(source_root / roles[role]['path']) == actual[key]['sha256'],
                'retained dependency differs from compiled manifest: ' + role)
    for role, pins, field in (('freetype', script_pins(root / 'tools/build_wine_ps5.sh'), 'FREETYPE_SHA256'),
                              ('zlib', script_pins(foundation / 'tools/setup-native-dependencies.sh'), 'zlib_hash')):
        require(digest_file(source_root / roles[role]['path']) == pins[field], 'retained pinned source changed: ' + role)
    return value


def validate_title(paths, expected, inspection):
    builder = prefix.load_tool(paths['repo'], 'build_wine_service_child')
    args = argparse.Namespace(work=paths['repo'], sdk=paths['sdk'], foundation=paths['foundation'],
                              runtime=paths['wine_work'], llvm_bindir=paths['llvm_bindir'],
                              service_work=paths['service_work'], app=paths['title'], build=paths['title_build'],
                              sdk_source_archive=paths['sdk_source_archive'], fixture=paths['fixture'], out=inspection)
    actual = builder.check_title(args)
    require(actual == expected, 'replayed title import/compiled/embedded identity differs')
    return actual


def check_battle_inputs(paths, project, fixture, abi, host_stamp):
    # The prefix producer owns the actual native/PE/translator checker. Absence
    # or any refusal is fatal; no readiness flag substitutes for that call.
    runtime = prefix.check_battlenet_runtime(paths['repo'], paths['host_work'], paths['wine_work'],
                                            paths['cohort'], paths['cpu_output'], paths['llvm_bindir'])
    battle = read_json(paths['battlenet_prefix_report'])
    require(battle.get('schema') == 'pw-battlenet-experimental-prefix/1' and
            battle.get('project') == project and battle.get('wine_commit') == prefix.WINE and
            battle.get('patches') == fixture['patches'] and battle.get('host_stamp') == host_stamp and
            battle.get('private_dispatcher') == abi == runtime.get('private_dispatcher') and
            battle.get('cpu') == fixture.get('cpu') == runtime.get('cpu') and
            battle.get('installer_included') is False and battle.get('console_execution_verified') is False and
            runtime.get('runtime_validated') is False, 'Battle prepared/runtime/source cohort differs')
    require(prefix.inventory(paths['battlenet_prefix']) == battle.get('inventory'), 'Battle prefix changed')
    merge_console_inventories(fixture['inventory'], battle['inventory'])
    profile = paths['battlenet_prefix'] / BATTLE_PROFILE.removeprefix('console/')
    actual = profile.read_bytes()
    wanted = prefix.battle_profile(paths['repo'])
    if isinstance(wanted, str): wanted = wanted.encode()
    require(actual == wanted, 'Battle profile differs from bound fixed generator')
    battle_profile_fields(actual)
    require(record(paths['cpu_output'] / 'cpu-build.json')['sha256'] == runtime.get('cpu_manifest_sha256'),
            'Battle CPU build record differs')
    return battle, runtime, actual


def script_pins(path):
    result = {}
    for key, value in re.findall(r'^([A-Za-z_][A-Za-z_0-9]*)=([^\n]+)$', path.read_text(), re.M):
        value = value.strip().strip('"').strip("'")
        for existing, replacement in result.items():
            value = value.replace('$' + existing, replacement)
        result[key] = value
    return result


def archive_notices(path, destination, target, strip=0):
    names = []
    with tarfile.open(path, 'r:*') as archive:
        for item in archive:
            if not item.isfile() or not PurePosixPath(item.name).name.startswith(('LICENSE', 'COPYING', 'COPYRIGHT', 'NOTICE')):
                continue
            parts = PurePosixPath(item.name).parts[strip:]
            name = safe_name('/'.join(parts))
            require(item.size <= 8 << 20, 'source notice exceeds bound')
            output = target + '/' + name
            put_bytes(destination, output, archive.extractfile(item).read())
            names.append(output)
    require(names, 'source archive has no retained licence text')
    return names


def retain_sources(config, output, report):
    require(config.get('schema') == 'pw-windows-child-source-inputs/1', 'wrong source-retention inputs')
    names = {'repo', 'wine_source', 'wine_archive', 'title_foundation', 'foundation', 'sdk_source_archive',
             'tls_work', 'wine_work', 'title_build', 'freetype_archive', 'zlib_archive'}
    require(set(config.get('paths', {})) == names, 'source-retention paths incomplete')
    p = {n: Path(config['paths'][n]).absolute() for n in names}
    for name, path in p.items():
        prefix.ordinary(path, not name.endswith('_archive'))
    project = prefix.project(p['repo'])
    builder = script_pins(p['repo'] / 'tools/build_wine_ps5.sh')
    title_pins = script_pins(p['repo'] / 'tools/build_native.sh')
    dependency = script_pins(p['foundation'] / 'tools/setup-native-dependencies.sh')
    require(prefix.git(p['title_foundation'], 'rev-parse', 'HEAD') == title_pins['pin'] and
            prefix.git(p['foundation'], 'rev-parse', 'HEAD') == builder['MODULE_EXPORTS_COMMIT'] and
            prefix.git(p['wine_source'], 'rev-parse', 'HEAD') == prefix.WINE, 'source checkout pin mismatch')
    from check_native_suite import source_archive
    sdk_source = source_archive(p['sdk_source_archive'])
    runtime = read_json(p['wine_work'] / 'report.json')
    require(runtime['wine_commit'] == prefix.WINE and runtime['sources']['prx_foundation'] == builder['MODULE_EXPORTS_COMMIT'],
            'runtime source pins differ')
    tls = prefix.load_tool(p['repo'], 'tls_manifest').verify(p['tls_work'] / 'root')
    require(runtime['tls']['build'] == tls, 'runtime TLS source identity differs')
    out = prefix.absent(output, tuple(p.values())); prefix.absent(report, (*p.values(), out))
    out.mkdir(mode=0o755)
    roles = {}

    def archive_role(role, checkout, revision, url):
        value = subprocess.run(['git', '-C', str(checkout), 'archive', revision], check=True,
                               capture_output=True, timeout=120).stdout
        name = role + '.tar.gz'
        put_bytes(out, name, gzip.compress(value, mtime=0))
        notices = archive_notices(out / name, out, 'notices/' + role)
        roles[role] = {'path': name, 'revision': revision, 'url': url, 'notices': notices, 'kind': 'source-archive'}

    archive_role('project', p['repo'], project['commit'], 'https://github.com/Sleepywalker69/prospero-win')
    for role, key, revision in (('title-foundation', 'title_foundation', title_pins['pin']),
                                ('prx-foundation', 'foundation', builder['MODULE_EXPORTS_COMMIT'])):
        archive_role(role, p[key], revision, 'https://github.com/mpereiraesaa/ps5-native-app-boilerplate')
    expected_wine = subprocess.run(['git', '-C', str(p['wine_source']), 'archive', prefix.WINE],
                                   check=True, capture_output=True, timeout=120).stdout
    require(gzip.decompress(p['wine_archive'].read_bytes()) == expected_wine, 'Wine archive differs from pinned source')

    def source_role(role, original, revision, url, digest, strip=0):
        actual = record(original)
        require(re.fullmatch('[0-9a-f]{64}', digest) and actual['sha256'] == digest, 'source archive hash mismatch: ' + role)
        extension = '.tar.xz' if original.name.endswith('.tar.xz') else '.tar.gz'
        name = role + extension
        put(out, name, original, actual)
        notices = archive_notices(out / name, out, 'notices/' + role, strip)
        roles[role] = {'path': name, 'revision': revision, 'url': url, 'notices': notices, 'kind': 'source-archive'}

    source_role('wine', p['wine_archive'], prefix.WINE, 'https://gitlab.winehq.org/wine/wine', digest_file(p['wine_archive']))
    source_role('sdk', p['sdk_source_archive'], sdk_source['commit'], 'https://github.com/ps5-payload-dev/sdk', sdk_source['sha256'])
    source_role('freetype', p['freetype_archive'], builder['FREETYPE_VERSION'], builder['FREETYPE_URL'], builder['FREETYPE_SHA256'], 1)
    source_role('zlib', p['zlib_archive'], dependency['zlib_version'], dependency['zlib_url'], dependency['zlib_hash'], 1)
    for role, extension in (('gnutls', 'xz'), ('nettle', 'gz')):
        item = tls['inputs']['sources'][role]
        source_role(role, p['tls_work'] / (role + '-' + item['version'] + '.tar.' + extension),
                    item['version'], item['url'], item['sha256'], 1)
    ca = tls['inputs']['sources']['ca_bundle']
    source = p['tls_work'] / 'root/ca-certificates.crt'
    require(digest_file(source) == ca['sha256'], 'CA bundle differs from pinned source')
    put(out, 'ca-certificates.crt', source)
    put(out, 'notices/ca-bundle/MPL-2.0.txt', p['repo'] / 'LICENSES/MPL-2.0.txt')
    roles['ca-bundle'] = {'path': 'ca-certificates.crt', 'revision': ca['date'], 'url': ca['url'],
                          'notices': ['notices/ca-bundle/MPL-2.0.txt'], 'kind': 'source-data'}
    release = read_json(p['title_build'] / 'lapy-helper-release.json')
    helper = read_json(p['title_build'] / 'lapy-helper-manifest.json')
    require(release.get('tag_name') == title_pins['lapy_release'] and helper.get('elf_sha256') == title_pins['lapy_elf_sha256']
            and release.get('repository') == 'mpereiraesaa/PS5-Lapy-JB-Daemon' and
            release.get('release_url') == 'https://github.com/mpereiraesaa/PS5-Lapy-JB-Daemon/releases/tag/' + title_pins['lapy_release'],
            'Lapy release provenance differs from accepted title pin')
    for name in ('lapy-helper-release.json', 'lapy-helper-manifest.json'):
        put(out, name, p['title_build'] / name)
    put(out, 'notices/lapy/Lapy-MIT.txt', p['repo'] / 'LICENSES/Lapy-MIT.txt')
    roles['lapy'] = {'path': 'lapy-helper-release.json', 'revision': release['tag_name'], 'url': release['release_url'],
                     'notices': ['notices/lapy/Lapy-MIT.txt'], 'kind': 'release-record',
                     'source_commit_verified': False, 'helper_manifest': 'lapy-helper-manifest.json'}
    require(prefix.project(p['repo']) == project, 'project changed during source retention')
    normalize_directories(out)
    result = {'schema': 'pw-windows-child-retained-sources/1', 'project': project, 'roles': roles,
              'inventory': prefix.inventory(out), 'sdk_source': sdk_source,
              'scope': 'retained source archives and notices; Lapy retains the existing exact release record, not an inferred commit'}
    prefix.json_out(report, result)
    return result


def assemble(config, output):
    require(config.get('schema') == 'pw-windows-child-package-inputs/1', 'wrong assembler input schema')
    require(re.fullmatch(r'https://github\.com/Sleepywalker69/prospero-win/actions/runs/[1-9][0-9]*',
                         config.get('run_url', '')), 'actual producer run URL required')
    enabled = config.get('battlenet_enabled', False)
    require(type(enabled) is bool, 'Battle capability selection must be boolean')
    names = {'repo', 'host_work', 'wine_work', 'cohort', 'prefix', 'prefix_report', 'fixture', 'service_work',
             'title', 'title_build', 'title_report', 'sources_root', 'sources_manifest', 'wine_archive',
             'sdk_source_archive', 'sdk', 'foundation', 'llvm_bindir'}
    if enabled: names |= {'battlenet_prefix', 'battlenet_prefix_report', 'cpu_output'}
    require(set(config.get('paths', {})) == names, 'incomplete/unexpected assembler paths')
    p = {name: Path(config['paths'][name]).absolute() for name in names}
    for name, path in p.items():
        prefix.ordinary(path, name not in {'cohort', 'prefix_report', 'title_report', 'sources_manifest', 'wine_archive',
                                         'sdk_source_archive', 'battlenet_prefix_report'})
    repo, wine, host = p['repo'], p['wine_work'], p['host_work']
    project = prefix.project(repo)
    out = prefix.absent(output, tuple(p.values())); out.mkdir(mode=0o755)
    stage = out / 'windows-child-fixture'; stage.mkdir(mode=0o755)
    inspection = out / 'inspection'; inspection.mkdir(mode=0o755)
    # This also rechecks all actual staged sources and the complete host installation.
    host_identity, host_tree = prefix.host_identity(repo, host, p['cohort'])
    patches = {f.name: digest_file(f) for f in sorted((repo / 'wine/patches').glob('*.patch'))}
    cohort = read_json(p['cohort'])
    prefix.verify_source_snapshot(wine / 'source', cohort['ps5_source'])
    prepared = read_json(p['prefix_report'])
    require(prepared.get('schema') == 'pw-windows-child-prefix/1' and prepared.get('project') == project and
            prepared.get('patches') == patches and prepared.get('wine_commit') == prefix.WINE and
            prepared.get('host_stamp') == host_identity['stamp'] and prepared.get('fixture_executed') is False and
            prepared.get('console_execution_verified') is False, 'prepared prefix/source cohort mismatch')
    require(prefix.inventory(p['prefix']) == prepared['inventory'], 'prepared prefix bytes changed')
    validate_console_scope(prepared['inventory'])
    fixture = prefix.validate_pair(p['fixture'], project)
    require(fixture == prepared['fixture'] and fixture.get('source_sha256') ==
            digest_file(repo / 'tests/fixtures/windows_child_process.c'), 'original fixture source differs')
    expected_pe = prefix.patched_pe_set(repo, wine)
    abi_checker = prefix.load_tool(repo, 'check_private_dispatch_abi')
    abi = abi_checker.check_build(wine, 1, p['llvm_bindir'] / 'llvm-readelf')
    require(prepared['private_dispatcher'] == abi, 'prefix/runtime private ABI cohort differs')
    battle = check_battle_inputs(p, project, prepared, abi, host_identity['stamp']) if enabled else None
    service = validate_service(repo, p['service_work'], project, wine, abi, p['sdk'], p['foundation'],
                               p['llvm_bindir'], inspection / 'service-before')
    require(read_json(wine / 'report.json')['tls']['build']['inputs']['host_llvm'] == service['host_llvm'],
            'runtime TLS and child compiler cohorts differ')
    title = read_json(p['title_report'])
    require(title.get('schema') == 'pw-windows-child-title/1' and title.get('project') == project and
            title.get('fixture_child_sha256') == fixture['files']['child.exe']['sha256'] and
            title.get('service_manifest_sha256') == digest_file(p['service_work'] / 'native-wine-child-build.json') and
            title.get('runtime') == service['runtime'] and title.get('compiler') == service['host_llvm'] and
            title.get('console_execution_verified') is False, 'title/child/compiler cohort differs')
    title_tree = prefix.inventory(p['title'])
    require(title.get('files') == title_files(title_tree), 'title bytes changed after inspection')
    validate_title(p, title, inspection / 'title-before')
    source_record = retained_sources(repo, p['sources_root'], p['sources_manifest'], project,
                                     p['wine_archive'], service, p['sdk'], p['foundation'], wine)
    before = {n: record(p[n]) for n in ('cohort', 'prefix_report', 'title_report', 'sources_manifest', 'wine_archive', 'sdk_source_archive')}
    if enabled: before['battlenet_prefix_report'] = record(p['battlenet_prefix_report'])
    checker = prefix.load_tool(repo, 'check_wine_prx_build')
    script = (repo / 'tools/build_wine_ps5.sh').read_text()
    pin = re.search(r'^MODULE_EXPORTS_COMMIT=([0-9a-f]{40})$', script, re.M)
    require(pin, 'Wine converter pin absent')
    # Complete existing checker, including imports/providers/SELF reconstruction.
    checked = checker.validate(wine, p['sdk'], p['foundation'], p['llvm_bindir'], inspection,
                               prefix.WINE, pin.group(1), sorted(patches))
    subprocess.run([sys.executable, str(repo / 'tools/tls_manifest.py'), 'verify-runtime', '--root', str(wine)],
                   check=True, timeout=120)
    require(set(checked['modules']) == set(checker.MODULES), 'incomplete14-module inspection')
    for name, value in title_tree.items():
        if name == '.' or value['type'] == 'directory':
            continue
        require(name in ('eboot.bin', 'lapy.elf') or name.startswith(('sce_sys/', 'sce_module/')) or
                name in ('native-wine-child.self', 'native-wine-child-build.json'), 'unexpected title payload: ' + name)
        if name.startswith('native-wine-child'):
            require(record(p['title'] / name) == record(p['service_work'] / name), 'title contains stale child')
        else:
            put(stage, APP + '/' + name, p['title'] / name)
    require((stage / APP / 'eboot.bin').is_file(), 'title eboot absent')
    require(record(stage / APP / 'sce_module/libc.prx') == service['libc_companion'], 'title/child libc companion differs')
    for name in ('native-wine-child.self', 'native-wine-child-build.json'):
        put(stage, APP + '/' + name, p['service_work'] / name)
    omitted = {'.a', 'winex11.drv', 'winegstreamer.dll', 'wpcap.dll', 'sane.ds', 'gphoto2.ds'}
    for arch in ('i386-windows', 'x86_64-windows'):
        for source in sorted((host_tree / 'lib/wine' / arch).iterdir()):
            if source.suffix == '.a' or source.name in omitted:
                continue
            relative = arch + '/' + source.name
            if relative in expected_pe:
                source = wine / 'pe' / relative
                expected = {'bytes': source.stat().st_size, 'sha256': expected_pe[relative]}
            else:
                source = source.resolve(strict=True)
                require(source.is_relative_to(host_tree), 'host PE link escapes retained runtime')
                expected = host_identity['host_files']['pc/host-wine/usr/lib/wine/' + relative]
            put(stage, LIB + '/' + relative, source, expected)
    for name, digest in expected_pe.items():
        require((stage / LIB / name).is_file() and digest_file(stage / LIB / name) == digest,
                'matched22PE overlay incomplete')
    for name in checker.MODULES:
        put(stage, LIB + '/x86_64-unix/' + name + '.prx', wine / 'prx/sce_module' / (name + '.prx'))
    nls_prefix = 'share/wine/nls'
    nls_inventory = {'.' if name == nls_prefix else name[len(nls_prefix) + 1:]: value
                     for name, value in host_identity['files'].items()
                     if name == nls_prefix or name.startswith(nls_prefix + '/')}
    copy_tree(stage, RUNTIME + '/share/wine/nls', host_tree / nls_prefix, expected=nls_inventory)
    fonts = sorted((wine / 'source/fonts').glob('*.ttf'))
    require(fonts and {p.name for p in (wine / 'prx/fonts').iterdir()} == {p.name for p in fonts}, 'Wine font set differs')
    for font in fonts:
        put(stage, RUNTIME + '/share/wine/fonts/' + font.name, wine / 'prx/fonts' / font.name, record(font))
    put(stage, RUNTIME + '/share/wine/ca-certificates.crt', wine / 'prx/ca-certificates.crt')
    copy_tree(stage, 'console', p['prefix'], expected=prepared['inventory'])
    if enabled:
        copy_tree(stage, 'console', p['battlenet_prefix'], expected=battle[0]['inventory'])
        put_bytes(stage, BATTLE_REPORT, json_bytes(battle[0]))
        put_bytes(stage, BATTLE_CAPABILITY,
                  json_bytes(battle_capability(project, battle[2], json_bytes(battle[0]), battle[1])))
        put(stage, BATTLE_CPU, p['cpu_output'] / 'cpu-build.json')
    cpu = stage / CONSOLE_PREFIX / 'drive_c/windows/system32/wowprospero.dll'
    put(stage, LIB + '/x86_64-windows/wowprospero.dll', cpu,
        prepared['cpu']['outputs']['x86_64-windows/wowprospero.dll'])
    for name in ('LICENSE', 'THIRD_PARTY.md'):
        put(stage, APP + '/' + name, repo / name)
    copy_tree(stage, APP + '/LICENSES', repo / 'LICENSES')
    for name in ('LICENSE', 'COPYING.LIB', 'AUTHORS', 'NOTICES.md'):
        put(stage, APP + '/LICENSES/wine/' + name, wine / 'source' / name)
    for source in sorted((wine / 'source/libs').glob('*/*')):
        if source.is_file() and source.name.startswith(('LICENSE', 'COPYING', 'COPYRIGHT')):
            put(stage, APP + '/LICENSES/wine/libs/' + source.parent.name + '/' + source.name, source)
    for name in ('LICENSE.TXT', 'docs/FTL.TXT'):
        put(stage, APP + '/LICENSES/freetype/' + Path(name).name, wine / 'freetype/src' / name)
    for name in ('gnutls', 'nettle'):
        copy_tree(stage, APP + '/LICENSES/' + name, wine / 'prx/licenses' / name)
    copy_tree(stage, 'sources', p['sources_root'], expected=source_record['inventory'])
    reports = {'prefix.json': prepared, 'fixture-source.json': fixture, 'wine-prx-checks.json': checked,
               'title.json': title, 'retained-sources.json': source_record, 'wine-build.json': read_json(wine / 'report.json')}
    for name, value in reports.items():
        put_bytes(stage, 'provenance/' + name, json_bytes(value))
    put_bytes(stage, ABI_REPORT, json_bytes(abi))
    info = ('Mode: windows-child-fixture\nCommit: ' + project['commit'] + '\nRun: ' + config['run_url'] + '\n'
            'Project tree: ' + project['tree'] + '\n'
            'Wine: ' + prefix.WINE + '\nBuild/static checks only; no console execution or Windows compatibility claim.\n'
            'Install only as the separately reviewed complete fixture package.\n')
    put_bytes(stage, 'BUILD-INFO.txt', info.encode())
    require(prefix.project(repo) == project and prefix.host_identity(repo, host, p['cohort'])[0] == host_identity,
            'project or host inputs changed during packaging')
    require(all(record(p[n]) == v for n, v in before.items()), 'package reports changed during assembly')
    require(prefix.inventory(p['prefix']) == prepared['inventory'] and prefix.inventory(p['title']) == title_tree and
            prefix.inventory(p['sources_root']) == source_record['inventory'], 'input tree changed during assembly')
    require(prefix.patched_pe_set(repo, wine) == expected_pe and
            abi_checker.check_build(wine, 1, p['llvm_bindir'] / 'llvm-readelf') == abi and
            validate_service(repo, p['service_work'], project, wine, abi, p['sdk'], p['foundation'],
                             p['llvm_bindir'], inspection / 'service-after') == service, 'runtime/worker inputs changed')
    validate_title(p, title, inspection / 'title-after')
    if enabled:
        require(check_battle_inputs(p, project, prepared, abi, host_identity['stamp']) == battle,
                'Battle source/runtime/profile changed during assembly')
    normalize_directories(stage)
    values = inventory(stage)
    manifest = {'schema': 'pw-windows-child-fixture/1', 'project': project, 'wine_commit': prefix.WINE,
                'patches': patches, 'inventory': values, 'inputs': before, 'run_url': config['run_url'],
                'source_parents': prefix.git(repo, 'show', '-s', '--format=%P', project['commit']).split(),
                'fixture_executed': False, 'console_validated': False, 'battlenet_enabled': enabled,
                'scope': 'source/build/static package checks only; no target execution or native reaping evidence'}
    if enabled:
        manifest['optional_roles'] = {'battlenet_profile': BATTLE_PROFILE, 'battlenet_capability': BATTLE_CAPABILITY}
    put_bytes(stage, MANIFEST, json_bytes(manifest))
    put_bytes(stage, SUMS, checksums(inventory(stage)))
    verify_directory(stage)
    archive = out / 'windows-child-fixture.tar.gz'
    write_archive(stage, archive)
    require(verify_archive(archive) == manifest, 'archive round-trip identity differs')
    final = inventory(stage)
    result = {'archive': record(archive), 'project': project, 'entries': len(final),
              'regular_files': sum(v['type'] == 'file' for v in final.values()),
              'checksum_entries': sum(v['type'] == 'file' and n != SUMS for n, v in final.items()),
              'directories': sum(v['type'] == 'directory' for v in final.values()),
              'maximum_path_length': max(map(len, final)), 'battlenet_enabled': enabled, 'console_validated': False}
    (out / 'ARCHIVE-CHECK.json').write_bytes(json_bytes(result))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('assemble', 'verify', 'retain-sources'))
    parser.add_argument('--package', type=Path)
    parser.add_argument('--archive', type=Path)
    parser.add_argument('--inputs', type=Path)
    parser.add_argument('--out', type=Path)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    if args.operation == 'verify':
        require(bool(args.package) != bool(args.archive), 'give exactly one package or archive')
        result = verify_directory(args.package.absolute()) if args.package else verify_archive(args.archive.absolute())
        print('PASS: complete original-fixture archive/source hashes and ABI; no target execution')
    elif args.operation == 'retain-sources':
        require(args.inputs and args.out and args.report, 'source retention requires --inputs --out --report')
        result = retain_sources(read_json(args.inputs.absolute()), args.out.absolute(), args.report.absolute())
        print(json.dumps({'project': result['project'], 'roles': sorted(result['roles'])}, sort_keys=True))
    else:
        require(args.inputs and args.out, 'assemble requires --inputs and --out')
        result = assemble(read_json(args.inputs.absolute()), args.out.absolute())
        print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
