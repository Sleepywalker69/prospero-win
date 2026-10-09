#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Reviewed portable-prefix audit/conversion helpers, extracted with one explicit archive binding parameter.

Source: prospero-win PR20 at e317bacdefbb5ec17b85212648309cb40cd68fcd.
The 19 generated-source member identities remain fixed.
The producer supplies fresh, hash-bound host inputs; old artifact pins and
Notepad-specific artifact orchestration are intentionally not part of this module.
"""
from __future__ import annotations


import argparse


import hashlib


import importlib.util


import json


import os


from pathlib import Path, PurePosixPath


import re


import shutil


import stat


import struct


import sys
sys.dont_write_bytecode = True


import tarfile


import zipfile


MAX_FILES, MAX_BYTES, MAX_FILE = 16000, 4 << 30, 256 << 20
MAX_METADATA_BYTES, MAX_METADATA_PATH = 32 << 20, 1024
MAX_TEXT_FINDINGS, MAX_TEXT_METADATA_BYTES = 1024, 4 << 20

VULKAN_JSON_SHA = '21f30d7ef5dd82189dfd91e09c8a01a92a3d94a95518443db444e2894b712aea'


REGISTRIES = {'system.reg', 'user.reg', 'userdef.reg'}


GENERATED_TEXT = {'drive_c/windows/win.ini', 'drive_c/windows/system.ini'}


TEXT_KEYS = {
    r'Software\Microsoft\Windows NT\CurrentVersion\Fonts',
    r'Software\Microsoft\Windows\CurrentVersion\Fonts',
    r'Software\Wine\Fonts', r'Software\Wine\Fonts\External Fonts',
    r'Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders',
    r'Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders',
    r'Software\Microsoft\Windows NT\CurrentVersion\ProfileList',
    r'System\CurrentControlSet\Control\Session Manager\Environment',
    'Environment',
}


TEXT_NAMES = {'', 'Path', 'PATH', 'TEMP', 'TMP', 'ProfilesDirectory', 'ProgramData',
              'Public', 'Default', 'Personal', 'Desktop', 'AppData', 'Local AppData'}


TEXT_CLASSIFICATIONS = {'host-' + name for name in
                        ('home', 'root', 'tmp', 'run', 'opt', 'usr', 'etc', 'mnt', 'workspace', 'github')}


TEXT_CLASSIFICATIONS |= {'environment-marker', 'nul', 'invalid-utf8', 'invalid-registry-header', 'oversized'}


FONT_FACES = {'marlett.ttf': 'Marlett', 'symbol.ttf': 'Symbol', 'tahoma.ttf': 'Tahoma',
              'tahomabd.ttf': 'Tahoma Bold', 'webdings.ttf': 'Webdings', 'wingding.ttf': 'Wingdings'}


FONT_KEYS = {
    'system.reg': (r'Software\Microsoft\Windows\CurrentVersion\Fonts',
                   r'Software\Microsoft\Windows NT\CurrentVersion\Fonts'),
    'user.reg': (r'Software\Wine\Fonts\External Fonts',),
    'userdef.reg': (),
}


ROOT_DEVICE_KEYS = {
    r'System\ControlSet001\Enum\ROOT\WINE\winebth',
    r'System\ControlSet001\Enum\ROOT\WINE\winebth\Device Parameters',
    r'System\ControlSet001\Enum\ROOT\WINE\winebus',
    r'System\ControlSet001\Enum\ROOT\WINE\winebus\Device Parameters',
    r'System\ControlSet001\Enum\ROOT\WINE\winebus\Properties\{4340A6C5-93FA-4706-972C-7B648008A5A7}\0009',
    r'System\ControlSet001\Enum\ROOT\WINE\winebus\Properties\{83DA6326-97A6-4088-9453-A1923F573B29}\0065',
    r'System\ControlSet001\Enum\ROOT\WINE\wineusb',
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for data in iter(lambda: stream.read(1 << 20), b''):
            digest.update(data)
    return digest.hexdigest()


def safe_relative(name):
    require(isinstance(name, str) and name and '\\' not in name and
            not any(ord(c) < 32 or ord(c) == 127 for c in name), 'invalid relative name')
    while name.startswith('./'):
        name = name[2:]
    parts = name.split('/')
    require(name and not name.startswith('/') and all(p not in ('', '.', '..') for p in parts),
            'unsafe relative name')
    return PurePosixPath(name)


def read_json(path):
    require(path.is_file() and path.stat().st_size <= 16 << 20, 'missing/oversized JSON')
    return json.loads(path.read_text())


class FilesystemRemote:
    """Only a fresh owned export root, never a console or existing prefix."""
    def __init__(self, root):
        self.root = Path(root).resolve()
        require(not self.root.exists(), 'export root already exists')
        self.root.mkdir()

    def path(self, remote):
        require(remote == '/data/prospero-win' or remote.startswith('/data/prospero-win/'), 'remote root escape')
        rel = safe_relative(remote.lstrip('/'))
        path = self.root / rel
        require(path.resolve().is_relative_to(self.root), 'filesystem remote escape')
        cursor = self.root
        for part in rel.parts:
            cursor /= part
            require(not cursor.is_symlink(), 'filesystem remote symlink')
        return path

    def exists(self, remote):
        return self.path(remote).exists()

    def size(self, remote):
        path = self.path(remote)
        return path.stat().st_size if path.is_file() else None

    def makedirs(self, remote):
        self.path(remote).mkdir(parents=True, exist_ok=True)

    def write(self, remote, data):
        with self.path(remote).open('xb') as stream:
            stream.write(data)

    def write_stream(self, remote, stream):
        with self.path(remote).open('xb') as dest:
            shutil.copyfileobj(stream, dest, 1 << 20)

    def read(self, remote):
        return self.path(remote).read_bytes()

    def listdir(self, remote):
        return {p.name: ('dir' if p.is_dir() else 'file', p.stat().st_size if p.is_file() else 0)
                for p in self.path(remote).iterdir()}

    def delete(self, remote):
        raise ValueError('deletion is never supported by seed export')


def audit_text(data, name):
    require(len(data) <= 16 << 20, 'oversized generated text: ' + name)
    text = data.decode('utf-8')
    inspected = text
    if name == 'system.reg':
        known = {key.replace('\\', '\\\\') for key in ROOT_DEVICE_KEYS}
        kept = []
        for line in text.split('\n'):
            match = re.fullmatch(r'\[(.*)\] [0-9]{1,10}', line)
            if not (match and match[1] in known):
                kept.append(line)
        inspected = '\n'.join(kept)
    # Registry backslashes are doubled. Normalize solely for inspection.
    folded = inspected.replace('\\', '/').lower()
    folded = re.sub('/+', '/', folded)
    require(not any(x in folded for x in ('/home/', '/root/', '/tmp/', '/run/', '/opt/', '/usr/', '/etc/',
                                          '/mnt/', '/workspace/', '/github/', 'github_token', 'runner_temp')),
            'host path/environment in generated text: ' + name)
    require('\x00' not in text, 'NUL in generated text')


def copy_portable_fonts(prefix, host, host_files):
    """Add only six exact bound fonts to this fresh owned prefix before its audit."""
    destination = prefix
    for name in ('drive_c', 'windows', 'Fonts'):
        require(destination.is_dir() and not destination.is_symlink(), 'unsafe portable-font parent')
        found = [p for p in destination.iterdir() if p.name.casefold() == name.casefold()]
        require(len(found) <= 1, 'case-colliding portable-font directory')
        destination = found[0] if found else destination / name
        if not found:
            require(name == 'Fonts', 'missing initialized portable-font parent')
            destination.mkdir()
        require(destination.is_dir() and not destination.is_symlink(), 'unsafe portable-font directory')
    assets = {}
    for filename in sorted(FONT_FACES):
        relative = 'share/wine/fonts/' + filename
        source = host / relative
        bound = host_files.get('pc/host-wine/usr/' + relative, {})
        require(source.is_file() and not source.is_symlink() and
                source.resolve().is_relative_to(host.resolve()) and sha(source) == bound.get('sha256'),
                'portable font differs from bound runtime')
        found = [p for p in destination.iterdir() if p.name.casefold() == filename.casefold()]
        require(len(found) <= 1, 'case-colliding portable-font file')
        target = found[0] if found else destination / filename
        if found:
            resolved = target.resolve(strict=True)
            require(resolved.is_relative_to(prefix.resolve()) or resolved.is_relative_to(host.resolve()),
                    'portable-font destination escapes audited sources')
            require(target.is_file() and sha(target) == bound['sha256'], 'existing portable font differs')
        else:
            with source.open('rb') as inp, target.open('xb') as out:
                shutil.copyfileobj(inp, out, 1 << 20)
        require(sha(target) == bound['sha256'], 'copied portable font differs')
        assets[filename] = {'source': relative, 'destination': target.relative_to(prefix).as_posix(),
                            'sha256': bound['sha256'], 'bytes': source.stat().st_size}
    return assets


def font_registry_line(face, path):
    # Both fields come only from static source names and a verified owned path.
    require(not any(c in path for c in '\r\n\x00"'), 'unsupported font source path')
    return ('"' + face + ' (TrueType)"="' + path.replace('\\', '\\\\') + '"').encode('ascii')


def portable_registry(name, data, host):
    """Relocate exactly the 18 observed source-derived REG_SZ records, in memory."""
    require(name in REGISTRIES and len(data) <= 16 << 20 and
            data.startswith(b'WINE REGISTRY Version 2'), 'invalid portable-registry input')
    keys = {key.replace('\\', '\\\\').encode('ascii') for key in FONT_KEYS[name]}
    records = {}
    names = {(face + ' (TrueType)').encode('ascii').lower() for face in FONT_FACES.values()}
    for filename, face in FONT_FACES.items():
        source = 'Z:' + str((host / 'share/wine/fonts' / filename).resolve()).replace('/', '\\')
        original = font_registry_line(face, source)
        converted = font_registry_line(face, 'C:\\windows\\Fonts\\' + filename)
        records[original] = (converted, filename)
    output, rewrites, seen_keys, seen_values = [], [], set(), set()
    key = None
    for line in data.splitlines(keepends=True):
        raw = line[:-1] if line.endswith(b'\n') else line
        if raw.startswith(b'['):
            key = None
            match = re.fullmatch(rb'\[((?:[^\]\\]|\\.)*)\] [0-9]{1,10}', raw)
            if match:
                key = match[1]
                if key in keys:
                    require(key not in seen_keys, 'duplicate portable-font registry section')
                    seen_keys.add(key)
        if key in keys and raw.startswith(b'"'):
            named = re.match(rb'"([^"\\]*)"=', raw)
            require(named is not None, 'unsupported portable-font value name')
            if named[1].lower() in names:
                require(raw in records, 'unexpected portable-font registry value/type/path')
        if key in keys and raw in records:
            converted, filename = records[raw]
            require((key, filename) not in seen_values, 'duplicate portable-font registry value')
            seen_values.add((key, filename))
            output.append(converted + (b'\n' if line.endswith(b'\n') else b''))
            rewrites.append({'font': filename, 'source_record_sha256': hashlib.sha256(raw).hexdigest(),
                             'portable_record_sha256': hashlib.sha256(converted).hexdigest()})
        else:
            output.append(line)
    require(seen_keys == keys and len(seen_values) == 6 * len(keys), 'missing exact portable-font registry records')
    result = b''.join(output)
    return {'data': result, 'source_sha256': hashlib.sha256(data).hexdigest(),
            'portable_sha256': hashlib.sha256(result).hexdigest(), 'rewrites': rewrites}


def sync_portable_registry(converter, arguments, remote, plans, prefix):
    """Compose with the isolated original converter so its hashes/sizes stay true."""
    original = converter.to_console
    def adapted(name, data):
        if name in REGISTRIES:
            plan = plans[name]
            require(hashlib.sha256(data).hexdigest() == plan['source_sha256'], 'registry changed after source audit')
            data = plan['data']
        return original(name, data)
    converter.to_console = adapted
    try:
        return converter.main(arguments, remote)
    finally:
        converter.to_console = original
        for name, plan in plans.items():
            require(sha(prefix / name) == plan['source_sha256'], 'original registry changed during conversion')


def text_classifications(text):
    """Same literal path inspection as audit_text; this never grants acceptance."""
    folded = re.sub('/+', '/', text.replace('\\', '/').lower())
    found = {'host-' + name for name in
             ('home', 'root', 'tmp', 'run', 'opt', 'usr', 'etc', 'mnt', 'workspace', 'github')
             if '/' + name + '/' in folded}
    if 'github_token' in folded or 'runner_temp' in folded:
        found.add('environment-marker')
    if '\x00' in text:
        found.add('nul')
    return found


def text_findings(data, name):
    """Locate literal guard failures without returning a registry value or line.

    This is a conservative diagnostic recognizer of server/registry.c's saved
    key/value prefixes, not a registry decoder or a conversion implementation.
    Unknown/escaped names remain hashes. It does not interpret hex value data.
    """
    require(name in REGISTRIES | GENERATED_TEXT, 'unexpected generated-text file')
    report = {'path': name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
              'scan_complete': True, 'findings': []}
    key = None
    def finding(line_number, raw, location, classes, value=None):
        def identity(token, allowed):
            if token is None:
                return None, None
            # The source writer doubles backslashes. No other escape is decoded.
            label = token.replace(b'\\\\', b'\\').decode('ascii', errors='replace')
            return (label if label in allowed else None), hashlib.sha256(token).hexdigest()
        key_label, key_hash = identity(key, TEXT_KEYS)
        value_label, value_hash = identity(value, TEXT_NAMES)
        return {'line': line_number, 'record_bytes': len(raw),
                'record_sha256': hashlib.sha256(raw).hexdigest(), 'location': location,
                'key': key_label, 'key_sha256': key_hash,
                'value_name': value_label, 'value_name_sha256': value_hash,
                'classifications': sorted(classes)}
    if len(data) > 16 << 20:
        report['scan_complete'] = False
        report['findings'].append(finding(0, b'', 'file', {'oversized'}))
        return report
    # Use LF only: Wine's dump_strW escapes control characters within records.
    for number, raw in enumerate(data.split(b'\n'), 1):
        classes = set()
        try:
            line = raw.decode('utf-8')
        except UnicodeDecodeError:
            line = raw.decode('utf-8', errors='replace')
            classes.add('invalid-utf8')
        classes.update(text_classifications(line))
        if number == 1 and name in REGISTRIES and not data.startswith(b'WINE REGISTRY Version 2'):
            classes.add('invalid-registry-header')
        location, value = 'other', None
        if name in REGISTRIES:
            if raw.startswith(b'['):
                key = None
                match = re.fullmatch(rb'\[((?:[^\]\\]|\\.)*)\](?: [0-9]+)?\r?', raw)
                if match:
                    key = match[1]
                    location = 'key'
            elif raw.startswith((b'#', b';')):
                location = 'comment'
            else:
                match = re.match(rb'"((?:[^"\\]|\\.)*)"=', raw)
                if match:
                    location, value = 'value', match[1]
                elif raw.startswith(b'@='):
                    location, value = 'value', b''
        if classes:
            if len(report['findings']) == MAX_TEXT_FINDINGS:
                report['scan_complete'] = False
                break
            report['findings'].append(finding(number, raw, location, classes, value))
    return report


def text_metadata(issues):
    """Independently validate every emitted field before diagnostic retention."""
    require(isinstance(issues, dict) and set(issues) == {'schema', 'files', 'scan_complete'} and
            issues['schema'] == 'pw-seed-text-audit/1' and type(issues['scan_complete']) is bool and
            isinstance(issues['files'], list) and len(issues['files']) <= 5, 'invalid text-audit metadata')
    def digest(value):
        return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value)
    previous = ''
    for record in issues['files']:
        require(isinstance(record, dict) and
                set(record) == {'path', 'bytes', 'sha256', 'scan_complete', 'findings'}, 'unexpected text-file field')
        require(record['path'] in REGISTRIES | GENERATED_TEXT and record['path'] > previous and
                type(record['bytes']) is int and 0 <= record['bytes'] <= MAX_FILE and digest(record['sha256']) and
                type(record['scan_complete']) is bool and isinstance(record['findings'], list) and
                len(record['findings']) <= MAX_TEXT_FINDINGS, 'invalid text-file identity')
        previous = record['path']
        last_line = -1
        for entry in record['findings']:
            require(isinstance(entry, dict) and set(entry) == {
                'line', 'record_bytes', 'record_sha256', 'location', 'key', 'key_sha256',
                'value_name', 'value_name_sha256', 'classifications'}, 'unexpected text-finding field')
            require(type(entry['line']) is int and last_line < entry['line'] <= record['bytes'] + 1 and
                    type(entry['record_bytes']) is int and 0 <= entry['record_bytes'] <= record['bytes'] and
                    digest(entry['record_sha256']) and entry['location'] in ('file', 'key', 'value', 'comment', 'other'),
                    'invalid text-finding position')
            last_line = entry['line']
            for label, hashed, allowed in (('key', 'key_sha256', TEXT_KEYS),
                                           ('value_name', 'value_name_sha256', TEXT_NAMES)):
                require(entry[label] is None or isinstance(entry[label], str) and entry[label] in allowed,
                        'unrecognized text-finding label')
                require(entry[hashed] is None or digest(entry[hashed]), 'invalid text-finding name hash')
                require(entry[label] is None or entry[hashed] is not None, 'text label without hash')
            classes = entry['classifications']
            require(isinstance(classes, list) and 0 < len(classes) <= len(TEXT_CLASSIFICATIONS) and
                    all(isinstance(c, str) and c in TEXT_CLASSIFICATIONS for c in classes) and
                    classes == sorted(set(classes)), 'invalid text-finding classification')
        require(not issues['scan_complete'] or record['scan_complete'], 'inconsistent text-scan completeness')
    encoded = json.dumps(issues, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode('ascii')
    require(len(encoded) + 1 <= MAX_TEXT_METADATA_BYTES, 'text-audit metadata exceeds bound')
    return encoded + b'\n'


def wine_resources(path, vulkan_manifest=False):
    """Read only bounded WINE_DATA_FILE and WINE_MANIFEST resource bytes.

    Matches pinned Wine setupapi/queue.c:do_file_copy and
    setupapi/fakedll.c:register_manifest. No PE execution or general loading.
    """
    data = path.read_bytes()
    if len(data) < 64 or data[:2] != b'MZ':
        return []
    def integer(at, size):
        require(0 <= at <= len(data) - size, 'truncated PE resource input')
        return int.from_bytes(data[at:at + size], 'little')
    pe = integer(60, 4)
    if pe > len(data) - 24 or data[pe:pe + 4] != b'PE\0\0':
        return []
    sections, optional_size = integer(pe + 6, 2), integer(pe + 20, 2)
    require(0 < sections <= 96, 'invalid PE section count')
    optional = pe + 24
    magic = integer(optional, 2)
    require(magic in (0x10b, 0x20b), 'unsupported PE resource format')
    directory = optional + (96 if magic == 0x10b else 112)
    require(directory + 24 <= optional + optional_size, 'missing PE resource directory')
    resource_rva, resource_size = integer(directory + 16, 4), integer(directory + 20, 4)
    if not resource_rva or not resource_size:
        return []
    require(resource_size <= 16 << 20, 'oversized PE resources')
    ranges = []
    for index in range(sections):
        at = optional + optional_size + 40 * index
        ranges.append((integer(at + 12, 4), integer(at + 20, 4), integer(at + 16, 4)))
    def rva(at, size):
        matches = [raw + at - va for va, raw, length in ranges if va <= at and size <= length - (at - va)]
        require(len(matches) == 1 and matches[0] <= len(data) - size, 'unmapped/ambiguous PE resource')
        return matches[0]
    base = rva(resource_rva, resource_size)
    def resource_integer(offset, size):
        require(0 <= offset <= resource_size - size, 'resource directory escape')
        return integer(base + offset, size)
    def resource_name(value):
        if not value & 0x80000000:
            return value
        offset = value & 0x7fffffff
        length = resource_integer(offset, 2)
        require(length <= 128 and offset + 2 + 2 * length <= resource_size, 'bad resource name')
        return data[base + offset + 2:base + offset + 2 + 2 * length].decode('utf-16le')
    found, visited = [], set()
    def walk(offset, keys):
        require(len(keys) <= 2 and offset not in visited, 'cyclic/deep resource directory')
        visited.add(offset)
        count = resource_integer(offset + 12, 2) + resource_integer(offset + 14, 2)
        require(count <= 4096, 'oversized resource directory')
        for index in range(count):
            entry = offset + 16 + 8 * index
            name = resource_name(resource_integer(entry, 4))
            child = resource_integer(entry + 4, 4)
            path_keys = keys + [name]
            if not keys and name not in (('WINE_DATA_FILE', 24, 10) if vulkan_manifest else ('WINE_DATA_FILE', 24)):
                continue
            if len(path_keys) == 2 and path_keys[0] == 24 and not (
                    isinstance(name, str) and name.startswith('WINE_MANIFEST')):
                continue
            # wrc uppercases named resource IDs in the compiled PE table.
            if len(path_keys) == 2 and path_keys[0] == 10 and name != 'WINEVULKAN_JSON':
                continue
            if child & 0x80000000:
                walk(child & 0x7fffffff, path_keys)
            else:
                require(len(path_keys) == 3, 'unexpected resource leaf depth')
                payload_rva = resource_integer(child, 4)
                payload_size = resource_integer(child + 4, 4)
                require(payload_size <= 4 << 20, 'oversized copied resource')
                start = rva(payload_rva, payload_size)
                found.append((path_keys[0], data[start:start + payload_size]))
    walk(0, [])
    return found


def resource_hashes(host, host_files):
    allowed = {}
    for name in sorted(host_files):
        if not name.startswith('pc/host-wine/usr/lib/wine/'):
            continue
        relative = name.removeprefix('pc/host-wine/usr/')
        path = host / relative
        if path.suffix.lower() not in ('.dll', '.exe', '.sys', '.drv', '.ocx', '.cpl'):
            continue
        architecture = 'amd64' if '/x86_64-windows/' in name else 'x86'
        for kind, content in wine_resources(path):
            candidates = [content]
            if kind == 24:
                # Pinned register_manifest inserts the current architecture
                # only when processorArchitecture is empty; retain all bytes.
                candidates.append(re.sub(rb'processorArchitecture=([\'"])\1',
                    lambda m: b'processorArchitecture=' + m[1] + architecture.encode() + m[1], content, count=1))
            for candidate in candidates:
                digest = hashlib.sha256(candidate).hexdigest()
                allowed.setdefault(digest, {'module': relative, 'resource_type': str(kind)})
    return allowed


def embedded_ne_image(path):
    """Reproduce pinned setupapi extract_16bit_image on a bound PE container.

    Its exported DOS header stores the image extent in e_res2[0..1]. The
    initializer clears that DWORD before writing the extracted NE image.
    """
    data = path.read_bytes()
    def integer(at, size):
        require(0 <= at <= len(data) - size, 'truncated 16-bit container')
        return int.from_bytes(data[at:at + size], 'little')
    require(len(data) >= 96 and data[:2] == b'MZ' and
            (data[64:81] == b'Wine builtin DLL\0' or data[64:85] == b'Wine placeholder DLL\0'),
            'not a bound Wine 16-bit container')
    pe = integer(60, 4)
    require(pe >= 96 and pe <= len(data) - 24 and data[pe:pe + 4] == b'PE\0\0', 'invalid 16-bit container PE')
    require(integer(pe + 4, 2) == 0x14c and integer(pe + 24, 2) == 0x10b,
            '16-bit container must be the pinned i386 PE format')
    sections, optional_size = integer(pe + 6, 2), integer(pe + 20, 2)
    require(0 < sections <= 96 and optional_size >= 104, 'invalid 16-bit container sections')
    ranges = []
    for index in range(sections):
        at = pe + 24 + optional_size + 40 * index
        ranges.append((integer(at + 12, 4), integer(at + 20, 4), integer(at + 16, 4)))
    def rva(value, size):
        matches = [raw + value - va for va, raw, length in ranges if
                   va <= value and size <= length - (value - va)]
        require(len(matches) == 1 and matches[0] <= len(data) - size, 'invalid 16-bit container RVA')
        return matches[0]
    export_rva, export_size = integer(pe + 24 + 96, 4), integer(pe + 24 + 100, 4)
    require(export_size >= 40, 'missing 16-bit image exports')
    exports = rva(export_rva, export_size)
    functions, names = integer(exports + 20, 4), integer(exports + 24, 4)
    require(0 < names <= functions <= 65536, 'invalid 16-bit image export counts')
    function_table = rva(integer(exports + 28, 4), functions * 4)
    name_table = rva(integer(exports + 32, 4), names * 4)
    ordinal_table = rva(integer(exports + 36, 4), names * 2)
    found = []
    for index in range(names):
        name_at = rva(integer(name_table + 4 * index, 4), 1)
        name_end = data.find(b'\0', name_at, min(len(data), name_at + 129))
        require(name_end >= 0, 'unterminated 16-bit image export name')
        if data[name_at:name_end] != b'__wine_spec_dos_header':
            continue
        ordinal = integer(ordinal_table + 2 * index, 2)
        require(ordinal < functions, 'invalid 16-bit image ordinal')
        start = rva(integer(function_table + 4 * ordinal, 4), 64)
        require(data[start:start + 2] == b'MZ', 'missing embedded DOS header')
        declared = integer(start + 40, 4)  # IMAGE_DOS_HEADER.e_res2, per pinned winnt.h
        # Wine clips with min(); this audit accepts only intact bound images.
        require(64 <= declared <= min(4 << 20, len(data) - start), 'invalid embedded 16-bit extent')
        size = declared
        ne = integer(start + 60, 4)
        require(64 <= ne <= size - 64 and data[start + ne:start + ne + 2] == b'NE', 'invalid embedded NE header')
        image = bytearray(data[start:start + size])
        image[40:44] = b'\0' * 4
        found.append(bytes(image))
    require(len(found) == 1, 'missing/duplicate embedded 16-bit image')
    return found[0]


def placeholder_i386(is_dll):
    """Exact deterministic build_fake_dll bytes, not a signature exemption.

    The pinned Wine INF requests these only from FakeDllsWin32. Layout and
    constants are IMAGE_DOS_HEADER/NT_HEADERS32/SECTION_HEADER in winnt.h;
    xwrite leaves zero-filled gaps and ends after the 8-byte relocation block.
    """
    output = bytearray(1032)
    def word(at, value): struct.pack_into('<H', output, at, value)
    def dword(at, value): struct.pack_into('<I', output, at, value)
    for at, value in ((0, 0x5a4d), (2, 64), (4, 1), (8, 6), (12, 0xffff), (16, 0xb8), (24, 96)):
        word(at, value)
    dword(60, 96)
    output[64:85] = b'Wine placeholder DLL\0'
    output[96:100] = b'PE\0\0'
    word(100, 0x14c); word(102, 2); word(116, 224); word(118, 0x2000 if is_dll else 0)
    opt = 120
    code = b'\x31\xc0\xc2\x0c\x00' if is_dll else b'\xb8\x01\x00\x00\x00\xc2\x04\x00'
    word(opt, 0x10b); output[opt + 2] = 1
    for at, value in ((4, len(code)), (16, 4096), (20, 4096), (28, 0x10000000),
                      (32, 4096), (36, 512), (56, 12288), (60, 512), (92, 16), (136, 8192), (140, 8)):
        dword(opt + at, value)
    for at, value in ((40, 1), (44, 1), (48, 4), (68, 2)):
        word(opt + at, value)
    for at, name, va, size, raw, flags in ((344, b'.text', 4096, len(code), 512, 0x60000020),
                                          (384, b'.reloc', 8192, 8, 1024, 0x42000040)):
        output[at:at + len(name)] = name
        for offset, value in ((8, 4096), (12, va), (16, size), (20, raw), (36, flags)):
            dword(at + offset, value)
    output[512:512 + len(code)] = code
    return bytes(output)


def generated_module_hashes(host, host_files, source_archive, expected_source_sha256):
    require(sha(source_archive) == expected_source_sha256, 'generated-module source archive changed')
    source_hashes = {'dlls/setupapi/fakedll.c': '1df365043c2a84dc2b44129641178fd325eb809126a1c44639cf1b77055c7b4c',
                     'include/winnt.h': '030dfb2b3fbdebad4c386d96cb31d081ac635914ab2ff674cbf12b5cecbf8834',
                     'dlls/setupapi/dirid.c': '7409a51e12814df2e35b08fce392b4319e4464d26512c599cce68dd4f2966fb2',
                     'dlls/ntdll/unix/file.c': 'bc6c1d35deaa2ee7396ff940aac75ba379a976a72e9b3d5ee6d3619c36db8af4',
                     'dlls/winevulkan/winevulkan.json': VULKAN_JSON_SHA,
                     'dlls/winevulkan/loader.c': '00669ab341904b567ada54aee7a7f17fd6c3fa21ed051ac90d6bca5ecb166df2',
                     'programs/wineboot/wineboot.c': 'f60dc3396d6d314aabee35712726c8a4db97c94723929719c62137bd46c0abd2',
                     'dlls/setupapi/devinst.c': 'ce5bad1bd0c71822039c379e4d2626e25313dec230708cc260a3eb9443f4ddbe',
                     'dlls/ntoskrnl.exe/pnp.c': '524f6c5df8ad2b4a3c179436a6e87a0c636413c2af5ab21ae378c03f71d75590',
                     'include/devpkey.h': '55c38bfd0164d16023544780ad581c11925be0b88ff0bfb120a72ebe6990a80e',
                     'server/registry.c': 'c29125d9590afc0f2d864208a7c681f97657b1a2e925780524e31095de02a0f8',
                     'dlls/win32u/font.c': '2506cc3a28701f18775eab1bbe6ac829bc0ea958411e5e3ee2eb6a031f1de1a5',
                     'fonts/marlett.sfd': 'eaaf88567db49cdacac4ec9e61a4ce14648e682f48343d8b9c9056cb5a1d3970',
                     'fonts/symbol.sfd': 'b146fffd2713a55b7f5101f32b3199b47542c2d5234f61cb5626ce2c886193d6',
                     'fonts/tahoma.sfd': '0c1a3182a3a6b3d444113421121cbacf87322111aff245ee616109bd47479710',
                     'fonts/tahomabd.sfd': '90e42b98fc092034e6485a7f8f811195ca2ca148b6704e5d2df56a4c97dfca49',
                     'fonts/webdings.sfd': '52eea2ba6ea5bb5e5db89ce2a01e578d7bb768e8da04a0e235fa04a1c1821b09',
                     'fonts/wingding.sfd': '6d8d42e70c405f41d9a9a3c54479cee0b022b5b0509ab8c9ada0402ac3007478'}
    with tarfile.open(source_archive, 'r:gz') as archive:
        for name, digest in source_hashes.items():
            member = archive.getmember(name)
            require(member.isfile() and member.size <= 2 << 20, 'invalid generated-module source member')
            require(hashlib.sha256(archive.extractfile(member).read()).hexdigest() == digest,
                    'generated-module algorithm/layout source changed')
    inf_path = host / 'share/wine/wine.inf'
    require(sha(inf_path) == host_files.get('pc/host-wine/usr/share/wine/wine.inf', {}).get('sha256'),
            'generated-module INF bytes changed')
    inf = inf_path.read_text()
    section = re.search(r'(?ms)^\[FakeDllsWin32\]\r?\n(.*?)(?=^\[)', inf)
    require(section is not None, 'missing pinned placeholder INF section')
    direct_paths = {}
    for line in section[1].splitlines():
        fields = line.strip().split(',')
        if len(fields) != 4 or not fields[3].endswith('16'):
            continue
        require(fields[0] in ('10', '52') and fields[2] == fields[3][:-2], 'unexpected 16-bit INF alias')
        # DIRID_WINDOWS=10. DIRID_SPOOLDRIVERS=52 is system32/spool/drivers;
        # ntdll's no_redirect list explicitly exempts system32/spool in WoW64.
        base = 'drive_c/windows' if fields[0] == '10' else 'drive_c/windows/system32/spool/drivers'
        relative = '/'.join(part for part in (base, fields[1].replace('\\', '/'), fields[2]) if part)
        safe_relative(relative)
        direct_paths.setdefault(fields[3], []).append(relative.casefold())
    require(len(direct_paths) == 6, 'pinned 16-bit INF alias set changed')
    allowed = {}
    for name in sorted(host_files):
        if not name.startswith('pc/host-wine/usr/lib/wine/i386-windows/') or not name.endswith('16'):
            continue
        relative = name.removeprefix('pc/host-wine/usr/')
        path = host / relative
        require(sha(path) == host_files[name]['sha256'], '16-bit parent bytes changed')
        image = embedded_ne_image(path)
        digest = hashlib.sha256(image).hexdigest()
        allowed[digest] = {'method': 'setupapi-extract-16bit-image', 'module': relative,
                           'parent_sha256': host_files[name]['sha256'], 'bytes': len(image),
                           'names': [path.name[:-2].casefold()],
                           # Explicit INF entries mark the basename handled,
                           # so the later wildcard does not create a second copy.
                           'paths': direct_paths.get(path.name) or
                                    ['drive_c/windows/syswow64/' + path.name[:-2].casefold()]}
    # Only the source=* rows request synthesis; the wildcard-copy row has
    # three columns and is deliberately not included here.
    names = set(re.findall(r'(?m)^11,,([a-z0-9.]+),\*\r?$', section[1]))
    require(names == {'ddhelp.exe', 'dosx.exe', 'dsound.vxd'}, 'pinned placeholder INF rows changed')
    for is_dll, selected in ((False, ['ddhelp.exe', 'dosx.exe']), (True, ['dsound.vxd'])):
        image = placeholder_i386(is_dll)
        allowed[hashlib.sha256(image).hexdigest()] = {
            'method': 'setupapi-build-fake-dll-i386', 'source_member': 'dlls/setupapi/fakedll.c',
            'source_sha256': source_hashes['dlls/setupapi/fakedll.c'], 'bytes': len(image),
            'names': selected, 'paths': ['drive_c/windows/syswow64/' + name for name in selected]}
    # DllRegisterServer writes this exact resource with WriteFile. No text-mode
    # conversion, arbitrary JSON equivalence, external DLL path or extra keys.
    expected = {'file_format_version': '1.0.0',
                'ICD': {'library_path': '.\\winevulkan.dll', 'api_version': '1.4.357'}}
    for arch, destination in (('x86_64-windows', 'system32'), ('i386-windows', 'syswow64')):
        relative = 'lib/wine/' + arch + '/winevulkan.dll'
        parent = host / relative
        record = host_files.get('pc/host-wine/usr/' + relative, {})
        require(sha(parent) == record.get('sha256'), 'Vulkan JSON parent bytes changed')
        payloads = [data for kind, data in wine_resources(parent, vulkan_manifest=True) if kind == 10]
        require(len(payloads) == 1 and hashlib.sha256(payloads[0]).hexdigest() == VULKAN_JSON_SHA and
                json.loads(payloads[0].decode('ascii')) == expected, 'Vulkan JSON resource differs from pinned source')
        entry = allowed.setdefault(VULKAN_JSON_SHA, {'method': 'winevulkan-DllRegisterServer-RT_RCDATA',
            'kind': 'data', 'source_member': 'dlls/winevulkan/winevulkan.json', 'source_sha256': VULKAN_JSON_SHA,
            'bytes': len(payloads[0]), 'names': ['winevulkan.json'], 'paths': [], 'parents': []})
        path = 'drive_c/windows/' + destination + '/winevulkan.json'
        entry['paths'].append(path)
        entry['parents'].append({'module': relative, 'sha256': record['sha256'], 'destination': path})
    return allowed


def audit_source(converter, prefix, host, host_files, resources=None, generated=None, issues=None, text_issues=None,
                 registry_plans=None):
    files, directories, links = converter.local_tree(prefix)
    require(len(files) <= MAX_FILES and len(directories) <= MAX_FILES, 'prefix too large')
    approved = {record['sha256'] for name, record in host_files.items() if name.startswith('pc/host-wine/usr/')}
    resources = resources or {}
    generated = generated or {}
    issues = issues if issues is not None else {}
    issues.update(files=[], scan_complete=False)
    text_issues = text_issues if text_issues is not None else {}
    text_issues.update(schema='pw-seed-text-audit/1', files=[], scan_complete=False)
    audit, total, folded_paths = {}, 0, set()
    for path in prefix.rglob('*'):
        if '.wineserver' in path.relative_to(prefix).parts:
            continue
        require(path.is_symlink() or path.is_dir() or stat.S_ISREG(path.lstat().st_mode),
                'special object in fresh prefix')
    virtual_paths = {str(PurePosixPath(directory) / name)
                     for directory, table in links.items() for name in table}
    for name in sorted(set(files) | (set(directories) - {''}) | virtual_paths):
        safe_relative(name)
        require(len(name.encode('utf-8')) <= MAX_METADATA_PATH, 'prefix path exceeds diagnostic/runtime bound')
        require(name.casefold() not in folded_paths, 'case-colliding prefix path')
        folded_paths.add(name.casefold())
    folded_paths.clear()
    for name, path in sorted(files.items()):
        safe_relative(name)
        require(name.casefold() not in folded_paths, 'case-colliding prefix files')
        folded_paths.add(name.casefold())
        resolved = path.resolve(strict=True)
        require(resolved.is_relative_to(prefix.resolve()) or resolved.is_relative_to(host.resolve()),
                'unapproved dereferenced file: ' + name)
        mode = resolved.stat().st_mode
        require(stat.S_ISREG(mode) and resolved.stat().st_size <= MAX_FILE, 'nonregular/oversized prefix file')
        total += resolved.stat().st_size
        require(total <= MAX_BYTES, 'prefix byte limit')
        digest = sha(resolved)
        if name in REGISTRIES:
            source = 'generated-registry'
        elif name == '.update-timestamp':
            source = 'generated-timestamp'
        elif name in GENERATED_TEXT:
            source = 'generated-ini'
        else:
            # Every copied PE/font/data file must match the hash-bound runtime.
            record = generated.get(digest)
            derived = record and Path(name).name.casefold() in record['names'] and (
                'paths' not in record or name.casefold() in record['paths'])
            if not (digest in approved or digest in resources or derived):
                issues['files'].append({'path': name, 'bytes': resolved.stat().st_size, 'sha256': digest})
                continue
            source = ('bound-host-runtime' if digest in approved else
                      'bound-runtime-resource' if digest in resources else
                      'bound-runtime-generated-data' if record.get('kind') == 'data' else 'bound-runtime-generated-module')
        audit[name] = {'sha256': digest, 'bytes': resolved.stat().st_size, 'source': source}
        if source == 'bound-runtime-resource':
            audit[name]['origin'] = resources[digest]
        elif source in ('bound-runtime-generated-module', 'bound-runtime-generated-data'):
            audit[name]['origin'] = generated[digest]
    issues['scan_complete'] = True
    require(not issues['files'], 'unapproved generated/copied file: ' +
            (issues['files'][0]['path'] if issues['files'] else '-') +
            f" ({len(issues['files'])} total; export refused)")
    # Collect all safely reached text failures before the original first-error
    # guards run. Diagnostic output never changes their acceptance behavior.
    for name in sorted((REGISTRIES | GENERATED_TEXT) & set(files)):
        text_issues['files'].append(text_findings(files[name].read_bytes(), name))
    text_issues['scan_complete'] = (REGISTRIES <= set(files) and
                                   all(r['scan_complete'] for r in text_issues['files']))
    # These strict content checks are deferred only until the unknown-content
    # inventory is complete. None is bypassed before a successful export.
    for name, record in audit.items():
        if name in REGISTRIES:
            data = files[name].read_bytes()
            require(data.startswith(b'WINE REGISTRY Version 2'), 'invalid registry header')
            if registry_plans is not None:
                plan = registry_plans[name]
                require(hashlib.sha256(data).hexdigest() == plan['source_sha256'], 'registry changed before audit')
                data = plan['data']
                record['font_portability'] = {key: value for key, value in plan.items() if key != 'data'}
            audit_text(data, name)
        elif name == '.update-timestamp':
            # wineboot text-mode output is CRLF; retain the original bytes.
            require(re.fullmatch(rb'[0-9]+(?:\r?\n)?', files[name].read_bytes()), 'invalid initialization timestamp')
        elif name in GENERATED_TEXT:
            audit_text(files[name].read_bytes(), name)
    require(REGISTRIES <= set(files), 'missing initialized registry')
    core = {'drive_c/windows/system32/notepad.exe': 'x86_64-windows/notepad.exe',
            'drive_c/windows/system32/kernel32.dll': 'x86_64-windows/kernel32.dll',
            'drive_c/windows/syswow64/kernel32.dll': 'i386-windows/kernel32.dll'}
    for required, original in core.items():
        require(required in files, 'missing initialized module: ' + required)
        record = host_files.get('pc/host-wine/usr/lib/wine/' + original, {})
        require(audit[required]['sha256'] == record.get('sha256'), 'wrong initialized core module: ' + required)
    for directory in directories:
        if directory:
            safe_relative(directory)
    require(sum(len(t) for t in links.values()) <= 64, 'virtual link count exceeds runtime limit')
    for directory, table in links.items():
        formatted = ''.join(f'{name}\t{target}\n' for name, target in table.items()).encode()
        require(len(formatted) < 4096, 'virtual link table exceeds runtime buffer')
        for name, target in table.items():
            safe_relative(str(PurePosixPath(directory) / name))
            require(not any(ord(c) < 32 or ord(c) == 127 for c in target), 'control byte in link target')
            require(target == '/' and directory == 'dosdevices' and name == 'z:' or
                    not target.startswith('/') and (prefix / directory / target).resolve().is_relative_to(prefix.resolve()),
                    'unapproved virtual link target')
    require(links.get('dosdevices', {}).get('c:') == '../drive_c' and
            links.get('dosdevices', {}).get('z:') == '/', 'missing canonical DOS mappings')
    return audit


def unapproved_metadata(issues):
    """Whitelisted metadata only, bounded independently before persistence/upload."""
    require(isinstance(issues, dict) and set(issues) == {'files', 'scan_complete'} and
            type(issues['scan_complete']) is bool and isinstance(issues['files'], list) and
            len(issues['files']) <= MAX_FILES, 'invalid unapproved-file metadata')
    previous = ''
    for entry in issues['files']:
        require(isinstance(entry, dict) and set(entry) == {'path', 'bytes', 'sha256'}, 'unexpected metadata field')
        safe_relative(entry['path'])
        require(len(entry['path'].encode('utf-8')) <= MAX_METADATA_PATH and entry['path'] > previous,
                'unordered/oversized metadata path')
        previous = entry['path']
        require(type(entry['bytes']) is int and 0 <= entry['bytes'] <= MAX_FILE and
                isinstance(entry['sha256'], str) and re.fullmatch('[0-9a-f]{64}', entry['sha256']),
                'invalid unapproved-file identity')
    encoded = json.dumps(issues, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')
    require(len(encoded) + 1 <= MAX_METADATA_BYTES, 'unapproved-file metadata exceeds bound')
    return encoded + b'\n'
