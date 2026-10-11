#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Pure, bounded metadata operations for the separate original USER profile.

No build, reference execution, native admission or archive acceptance is implied
by these helpers. The enclosing producer must validate every input receipt.
"""
from __future__ import annotations
import configparser
import hashlib

SLUG = 'windows-child-user-v1'
PREFIX = 'console/data/prospero-win/prefixes/' + SLUG
PROFILE = 'console/data/prospero-win/profiles/' + SLUG + '.profile'
APP = PREFIX + '/drive_c/windows-child-user'
REPORT = 'provenance/windows-child-user-prefix.json'
REFERENCE_ROOT = 'provenance/windows-child-user-reference'
REFERENCE = REFERENCE_ROOT + '/user-source.json'
SOURCE_ROOT = 'provenance/windows-child-user-source'
SOURCE_FILES = {'source_sha256': 'tests/fixtures/windows_child_user.c',
                'recipe_sha256': 'tools/build_windows_child_user.ps1',
                'validator_sha256': 'tools/windows_child_user_contract.py'}
CAPABILITY = 'provenance/windows-child-user-capability.json'
ROLES = {'user_profile': PROFILE, 'user_capability': CAPABILITY}
IMAGES = ('user-parent.exe', 'user-child.exe')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def profile_fields(data):
    require(isinstance(data, bytes) and 0 < len(data) <= 16384,
            'USER profile must be bounded bytes')
    parsed = configparser.ConfigParser(interpolation=None, strict=True)
    parsed.optionxform = str
    parsed.read_string(data.decode('utf-8'))
    expected = {'id': SLUG, 'prefix': SLUG,
                'executable': 'C:\\windows-child-user\\user-parent.exe',
                'working_directory': 'C:\\windows-child-user',
                'runtime': 'wine-wow64', 'architecture': 'pe64', 'graphics': 'auto'}
    require(not parsed.defaults() and set(parsed.sections()) == {'application', 'display'},
            'USER profile has unreviewed sections/defaults')
    app = dict(parsed['application'])
    require(set(expected) <= set(app) <= set(expected) | {'name', 'arguments'} and
            all(app[k] == value for k, value in expected.items()) and not app.get('arguments'),
            'USER application configuration differs')
    require(dict(parsed['display']) == {'desktop': '800x600', 'view': 'desktop', 'show_fps': 'false'},
            'USER desktop configuration differs')
    return {'id': SLUG, 'runtime': 'wine-wow64', 'architecture': 'pe64',
            'cpu': 'default', 'executable': expected['executable'],
            'cwd': expected['working_directory'], 'args': [],
            'desktop': '800x600', 'view': 'desktop', 'show_fps': False}


def merge_inventory(existing, extra):
    """Merge a validated USER prefix without replacing any existing file."""
    require(isinstance(existing, dict) and isinstance(extra, dict), 'inventory must be a mapping')
    base = 'data/prospero-win'
    guest = base + '/prefixes/' + SLUG
    profile = base + '/profiles/' + SLUG + '.profile'
    ancestors = {'.', 'data', base, base + '/prefixes', base + '/profiles'}
    combined = dict(existing)
    for name, entry in extra.items():
        require(isinstance(name, str) and isinstance(entry, dict), 'invalid USER inventory entry')
        # The outer inventory reader also enforces archive-safe canonical names.
        require(name == '.' or (not name.startswith('/') and '\\' not in name and
                all(part not in ('', '.', '..') for part in name.split('/'))),
                'noncanonical USER inventory name')
        require((name in ancestors and entry.get('type') == 'directory') or
                (name == guest and entry.get('type') == 'directory') or
                name.startswith(guest + '/') or
                (name == profile and entry.get('type') == 'file'),
                'USER inventory escapes its dedicated prefix/profile')
        require(entry.get('type') in ('file', 'directory'), 'USER inventory has a nonregular entry')
        if name in combined:
            require(entry == combined[name] and entry['type'] == 'directory',
                    'USER inventory overwrites a file or changes an ancestor directory')
        else:
            combined[name] = entry
    require(extra.get(guest, {}).get('type') == 'directory' and
            extra.get(profile, {}).get('type') == 'file', 'USER prefix/profile absent')
    for image in IMAGES:
        require(extra.get(guest + '/drive_c/windows-child-user/' + image, {}).get('type') == 'file',
                'USER original image absent')
    return combined


def capability(project, profile_bytes, prefix_report_bytes, reference_bytes,
               worker_build_id, child_sha256):
    """Declare the narrow scope; inputs must be independently bound by caller."""
    import re
    require(isinstance(project, dict) and set(project) == {'commit', 'tree'} and
            all(isinstance(v, str) and re.fullmatch('[0-9a-f]{40}', v) for v in project.values()),
            'USER project identity invalid')
    require(isinstance(worker_build_id, str) and re.fullmatch('[0-9a-f]{40}', worker_build_id) and
            isinstance(child_sha256, str) and re.fullmatch('[0-9a-f]{64}', child_sha256),
            'USER worker or original child identity invalid')
    require(isinstance(prefix_report_bytes, bytes) and isinstance(reference_bytes, bytes),
            'USER receipts must be exact bytes')
    return {'schema': 'pw-windows-child-user-capability/1', 'project': dict(project),
            'profile': {'path': PROFILE, 'sha256': hashlib.sha256(profile_bytes).hexdigest(),
                        **profile_fields(profile_bytes)},
            'prefix': {'path': PREFIX, 'report_path': REPORT,
                       'report_sha256': hashlib.sha256(prefix_report_bytes).hexdigest()},
            'reference': {'path': REFERENCE, 'sha256': hashlib.sha256(reference_bytes).hexdigest()},
            'child': {'path': APP + '/user-child.exe', 'sha256': child_sha256,
                      'architecture': 'pe64', 'maximum_direct_generations': 1},
            'worker_build_id': worker_build_id, 'native_child_budget_ms': 120000,
            'attempt_budget_ms': 180000, 'runtime_validated': False,
            'console_validated': False, 'child_presentation': False,
            'child_input': False, 'descendant_admission': False,
            'scope': 'original same-process worker first USER call; local geometry/classes/GDI only'}


def source_copies(archive_bytes, copies):
    """Join the three copied inputs to retained project archive members, without extraction."""
    import io
    import tarfile
    require(isinstance(archive_bytes, bytes) and len(archive_bytes) <= 64 << 20,
            'bounded project source archive required')
    require(set(copies) == set(SOURCE_FILES.values()) and
            all(isinstance(data, bytes) and 0 < len(data) <= 4 << 20 for data in copies.values()),
            'complete bounded USER source copies required')
    seen, found, total = set(), {}, 0
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode='r|gz') as archive:
        for index, member in enumerate(archive):
            require(index < 20000 and member.size >= 0, 'source member bound exceeded')
            total += member.size
            require(total <= 128 << 20 and member.name not in seen, 'duplicate or oversized source archive')
            seen.add(member.name)
            if member.name in copies:
                require(member.isfile() and member.size <= 4 << 20, 'USER source member is not a bounded file')
                value = archive.extractfile(member).read(member.size + 1)
                require(value == copies[member.name], 'USER source copy differs from retained project')
                found[member.name] = hashlib.sha256(value).hexdigest()
    require(set(found) == set(copies), 'USER source missing from retained project')
    return {field: found[path] for field, path in SOURCE_FILES.items()}
