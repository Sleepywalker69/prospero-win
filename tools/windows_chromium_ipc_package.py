#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Pure exact-profile and package operations for the default-disabled IPC cohort."""
from __future__ import annotations
import configparser
import hashlib
import io
import re
import tarfile
from windows_chromium_ipc_contract import CASES, IMAGES, SOURCE_FILES, require

SLUG = 'windows-chromium-ipc-v1'
PREFIX = 'console/data/prospero-win/prefixes/' + SLUG
APP = PREFIX + '/drive_c/windows-chromium-ipc'
PROFILES = {case: 'console/data/prospero-win/profiles/windows-chromium-ipc-' + case + '-v1.profile' for case in CASES}
REPORT = 'provenance/windows-chromium-ipc-prefix.json'
REFERENCE_ROOT = 'provenance/windows-chromium-ipc-reference'
REFERENCE = REFERENCE_ROOT + '/cohort.json'
SOURCE_ROOT = 'provenance/windows-chromium-ipc-source'
CAPABILITY = 'provenance/windows-chromium-ipc-capability.json'
ROLES = {'ipc_profile_' + case.replace('-', '_'): name for case, name in PROFILES.items()}
ROLES['ipc_capability'] = CAPABILITY


def profile(case):
    require(case in CASES, 'unregistered IPC case')
    return (f'; Original diagnostic only; native and console execution remain unverified.\n'
            f'[application]\nid=windows-chromium-ipc-{case}-v1\nname=Original IPC {case}\n'
            f'prefix={SLUG}\nexecutable=C:\\windows-chromium-ipc\\pw-ipc-{case}.exe\n'
            f'working_directory=C:\\windows-chromium-ipc\\{case}\narguments=\n'
            'runtime=wine-wow64\narchitecture=pe64\ngraphics=auto\n'
            '[display]\ndesktop=800x600\nview=desktop\nshow_fps=false\n').encode('ascii')


def profile_fields(data, case):
    require(case in CASES and type(data) is bytes and 0 < len(data) <= 16384, 'bounded registered IPC profile required')
    parsed = configparser.ConfigParser(interpolation=None, strict=True); parsed.optionxform = str
    parsed.read_string(data.decode('utf-8'))
    expected = {'id': 'windows-chromium-ipc-' + case + '-v1', 'prefix': SLUG,
                'executable': 'C:\\windows-chromium-ipc\\pw-ipc-' + case + '.exe',
                'working_directory': 'C:\\windows-chromium-ipc\\' + case,
                'runtime': 'wine-wow64', 'architecture': 'pe64', 'graphics': 'auto', 'arguments': ''}
    require(not parsed.defaults() and set(parsed.sections()) == {'application', 'display'}, 'IPC profile sections/defaults differ')
    app = dict(parsed['application'])
    require(set(expected) <= set(app) <= set(expected) | {'name'} and
            all(app[k] == v for k, v in expected.items()), 'IPC exact application fields/empty arguments differ')
    require(dict(parsed['display']) == {'desktop': '800x600', 'view': 'desktop', 'show_fps': 'false'},
            'IPC desktop fields differ')
    return {'id': expected['id'], 'mode': 16 + CASES.index(case), 'prefix': SLUG,
            'runtime': 'wine-wow64', 'architecture': 'pe64', 'cpu': 'default',
            'executable': expected['executable'], 'cwd': expected['working_directory'], 'args': [],
            'desktop': '800x600', 'view': 'desktop', 'show_fps': False}


def worker_capabilities():
    return [{'mode': 16 + i, 'prefix': SLUG, 'guest_machine': 'AMD64', 'backend': 'native-amd64',
             'runtime_validated': False} for i, case in enumerate(CASES)]


def merge_inventory(existing, extra):
    require(type(existing) is dict and type(extra) is dict, 'IPC inventory mapping required')
    base = 'data/prospero-win'; guest = PREFIX.removeprefix('console/'); app = APP.removeprefix('console/')
    profiles = {n.removeprefix('console/') for n in PROFILES.values()}
    ancestors = {'.', 'data', base, base + '/prefixes', base + '/profiles'}
    expected_app = {app: 'directory', **{app + '/' + n: 'file' for n in IMAGES},
                    **{app + '/' + case: 'directory' for case in CASES}}
    combined = dict(existing)
    for name, entry in extra.items():
        require(type(name) is str and type(entry) is dict and (name == '.' or
                (not name.startswith('/') and '\\' not in name and all(p not in ('', '.', '..') for p in name.split('/')))),
                'noncanonical IPC inventory path')
        require((name in ancestors and entry.get('type') == 'directory') or
                (name == guest and entry.get('type') == 'directory') or name.startswith(guest + '/') or
                (name in profiles and entry.get('type') == 'file'), 'IPC inventory escapes dedicated prefix/profiles')
        require(entry.get('type') in ('file', 'directory'), 'IPC nonregular inventory entry')
        if name == app or name.startswith(app + '/'):
            require(name in expected_app and entry['type'] == expected_app[name], 'IPC application has extra executable/log/path')
        if name in combined:
            require(entry == combined[name] and entry['type'] == 'directory', 'IPC inventory replaces an existing file')
        else: combined[name] = entry
    required = {guest: 'directory', **expected_app, **{n: 'file' for n in profiles}}
    require(all(extra.get(n, {}).get('type') == kind for n, kind in required.items()), 'IPC exact eight aliases/profiles/CWDs absent')
    digests = {extra[app + '/' + n].get('sha256') for n in IMAGES}
    require(len(digests) == 1 and re.fullmatch('[0-9a-f]{64}', next(iter(digests)) or ''), 'IPC alias hashes differ')
    return combined


def capability(project, profiles, prefix_report_bytes, reference_bytes, worker_build_id, child_sha256):
    require(type(project) is dict and set(project) == {'commit', 'tree'} and
            all(type(v) is str and re.fullmatch('[0-9a-f]{40}', v) for v in project.values()), 'IPC project identity invalid')
    require(type(profiles) is dict and set(profiles) == set(CASES) and
            type(prefix_report_bytes) is bytes and type(reference_bytes) is bytes and
            re.fullmatch('[0-9a-f]{40}', worker_build_id) and re.fullmatch('[0-9a-f]{64}', child_sha256),
            'IPC capability inputs incomplete')
    digest = lambda data: hashlib.sha256(data).hexdigest()
    return {'schema': 'pw-windows-chromium-ipc-capability/1', 'project': project,
        'profiles': {case: {'path': PROFILES[case], 'sha256': digest(profiles[case]),
                     **profile_fields(profiles[case], case), 'maximum_direct_helpers': 0 if case in ('self-memory', 'page-regression') else 1,
                     'maximum_direct_generations': 0 if case in ('self-memory', 'page-regression') else 1}
                     for case in CASES},
        'prefix': {'path': PREFIX, 'report_path': REPORT, 'report_sha256': digest(prefix_report_bytes)},
        'reference': {'path': REFERENCE, 'sha256': digest(reference_bytes), 'required_architectures': ['x64', 'x86']},
        'images': {name: {'path': APP + '/' + name, 'sha256': child_sha256, 'architecture': 'pe64'} for name in IMAGES},
        'worker_build_id': worker_build_id, 'native_child_budget_ms': 60000, 'attempt_budget_ms': 180000,
        'maximum_depth': 1, 'descendant_admission': False, 'x86_admission': False,
        'runtime_validated': False, 'console_validated': False, 'child_presentation': False, 'child_input': False,
        'scope': 'eight original empty-argument diagnostic entries; no general Chromium compatibility claim'}


def source_copies(archive_bytes, copies):
    require(type(archive_bytes) is bytes and len(archive_bytes) <= 64 << 20 and type(copies) is dict and
            set(copies) == set(SOURCE_FILES.values()) and all(type(v) is bytes and 0 < len(v) <= 4 << 20 for v in copies.values()),
            'bounded complete IPC project/source copies required')
    seen, found, total = set(), {}, 0
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode='r|gz') as archive:
        for index, member in enumerate(archive):
            total += member.size
            require(index < 20000 and member.size >= 0 and total <= 128 << 20 and member.name not in seen,
                    'duplicate or oversized IPC source archive')
            seen.add(member.name)
            if member.name in copies:
                require(member.isfile() and member.size <= 4 << 20, 'nonregular IPC source archive member')
                data = archive.extractfile(member).read(member.size + 1)
                require(data == copies[member.name], 'IPC source copy differs from complete project archive')
                found[member.name] = hashlib.sha256(data).hexdigest()
    require(set(found) == set(copies), 'IPC retained project input absent')
    return {field: found[path] for field, path in SOURCE_FILES.items()}
