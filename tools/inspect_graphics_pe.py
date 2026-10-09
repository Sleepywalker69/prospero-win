#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Bounded AMD64 PE metadata/import graph checks; no image execution."""
import hashlib
from pathlib import Path
import re
import struct


def require(ok, message):
    if not ok:
        raise ValueError(message)


def dll_name(value):
    require(isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_.+-]+', value), 'unsafe DLL name')
    value = value.lower()
    return value if value.endswith('.dll') else value + '.dll'


class Image:
    def __init__(self, path):
        self.path = Path(path)
        require(self.path.is_file() and 64 <= self.path.stat().st_size <= 128 << 20, 'missing/oversized PE')
        self.raw = self.path.read_bytes()
        require(self.read(0, 2) == b'MZ', 'not a PE image')
        nt = self.u32(60)
        require(nt >= 64 and self.read(nt, 4) == b'PE\0\0', 'invalid PE signature')
        machine, count = self.unpack('<HH', nt + 4)
        optional = self.u16(nt + 20)
        self.characteristics = self.u16(nt + 22)
        require(machine == 0x8664 and 0 < count <= 96 and optional >= 240, 'PE is not bounded AMD64')
        op = nt + 24
        require(self.u16(op) == 0x20b, 'PE64 optional header required')
        self.entry = self.u32(op + 16)
        self.header_size = self.u32(op + 60)
        require(op + optional <= len(self.raw) and self.header_size <= len(self.raw), 'invalid PE headers')
        directory_count = self.u32(op + 108)
        require(14 <= directory_count <= 16 and 112 + 8 * directory_count <= optional, 'invalid PE directories')
        self.directories = [self.unpack('<II', op + 112 + 8 * i) for i in range(directory_count)]
        self.sections = []
        for i in range(count):
            at = op + optional + 40 * i
            name = self.read(at, 8).split(b'\0', 1)[0]
            virtual, address, size, offset = self.unpack('<IIII', at + 8)
            flags = self.u32(at + 36)
            require(offset + size <= len(self.raw) and address + max(virtual, size) <= 1 << 32,
                    'invalid PE section range')
            self.sections.append((name, address, max(virtual, size), offset, size, flags))
        self.exports = self.read_exports()
        self.imports = self.read_imports(1, False) + self.read_imports(13, True)
        self.sha256 = hashlib.sha256(self.raw).hexdigest()

    def read(self, offset, count):
        require(isinstance(offset, int) and 0 <= offset <= len(self.raw) - count and count >= 0,
                'PE byte range outside file')
        return self.raw[offset:offset + count]

    def unpack(self, fmt, offset):
        return struct.unpack(fmt, self.read(offset, struct.calcsize(fmt)))

    def u16(self, offset):
        return self.unpack('<H', offset)[0]

    def u32(self, offset):
        return self.unpack('<I', offset)[0]

    def offset(self, address, size):
        if address < self.header_size:
            require(address + size <= self.header_size, 'RVA crosses PE headers')
            self.read(address, size)
            return address
        matches = [(offset + address - start, flags) for _, start, virtual, offset, raw, flags in self.sections
                   if start <= address and address + size <= start + virtual and address + size <= start + raw]
        require(len(matches) == 1, 'unmapped/ambiguous PE RVA')
        self.read(matches[0][0], size)
        return matches[0][0]

    def at(self, address, fmt):
        return self.unpack(fmt, self.offset(address, struct.calcsize(fmt)))

    def string(self, address):
        result = bytearray()
        for i in range(1024):
            value = self.read(self.offset(address + i, 1), 1)[0]
            if not value:
                require(result and all(32 <= x < 127 for x in result), 'invalid PE ASCII name')
                return result.decode('ascii')
            result.append(value)
        raise ValueError('unterminated PE name')

    def executable(self, address):
        matches = [(start, raw, flags) for _, start, virtual, _, raw, flags in self.sections
                   if start <= address < start + virtual]
        require(len(matches) == 1, 'unmapped/ambiguous exported RVA')
        start, raw, flags = matches[0]
        require(not flags & 0x20000000 or address < start + raw, 'exported code is not file-backed')
        return bool(flags & 0x20000000)

    def read_exports(self):
        address, size = self.directories[0]
        if not address and not size:
            return {}
        require(address and size >= 40 and address + size <= 1 << 32, 'invalid export directory')
        _, _, _, _, _, ordinal_base, count, names, functions, name_table, ordinals = self.at(address, '<IIHHIIIIIII')
        require(count <= 65536 and names <= 65536, 'oversized export table')
        exports = {}
        for i in range(count):
            target = self.at(functions + 4 * i, '<I')[0]
            if not target:
                continue
            if address <= target < address + size:
                forward = self.string(target)
                require(target + len(forward) + 1 <= address + size, 'forwarder exceeds export directory')
                value = {'forward': forward}
            else:
                value = {'rva': target, 'executable': self.executable(target)}
            exports[ordinal_base + i] = value
        for i in range(names):
            name = self.string(self.at(name_table + 4 * i, '<I')[0])
            index = self.at(ordinals + 2 * i, '<H')[0]
            require(index < count and ordinal_base + index in exports and name not in exports, 'invalid named export')
            exports[name] = exports[ordinal_base + index]
        return exports

    def read_imports(self, index, delayed):
        address, size = self.directories[index]
        if not address and not size:
            return []
        width = 32 if delayed else 20
        require(address and width <= size <= 4 << 20, 'invalid import directory')
        imports = []
        for i in range(min(size // width, 4096)):
            record = self.at(address + i * width, '<8I' if delayed else '<5I')
            if not any(record):
                return imports
            if delayed:
                require(record[0] == 1, 'delay imports must use RVAs')
                name, thunk, iat = record[1], record[4] or record[3], record[3]
            else:
                name, thunk, iat = record[3], record[0] or record[4], record[4]
            library = dll_name(self.string(name))
            require(thunk and iat, 'missing import thunk table')
            for j in range(65536):
                target = iat + j * 8
                require(sum(start <= target and target + 8 <= start + virtual
                            for _, start, virtual, _, _, _ in self.sections) == 1, 'invalid IAT write range')
                value = self.at(thunk + j * 8, '<Q')[0]
                if not value:
                    break
                if value & (1 << 63):
                    require(value & ~((1 << 63) | 0xffff) == 0, 'invalid ordinal import')
                    symbol = value & 0xffff
                else:
                    require(value <= 0xffffffff, 'invalid import-name RVA')
                    self.at(value, '<H')  # The complete hint must be mapped too.
                    symbol = self.string(value + 2)
                imports.append((library, symbol, 'delay' if delayed else 'normal'))
                require(len(imports) <= 65536, 'too many imported symbols')
            else:
                raise ValueError('unterminated import thunk table')
        raise ValueError('unterminated import descriptor table')


def api_sets(image):
    matches = [x for x in image.sections if x[0] == b'.apiset']
    require(len(matches) == 1, 'missing/ambiguous API-set namespace')
    _, _, _, offset, raw_size, _ = matches[0]
    data = image.read(offset, raw_size)
    limit = len(data)
    def values(at, count):
        require(0 <= at <= limit - count * 4, 'API-set record outside section')
        return struct.unpack_from('<' + 'I' * count, data, at)
    version, size, _, count, entries, _, _ = values(0, 7)
    require(version == 6 and 28 <= size <= len(data) and count <= 65536, 'unsupported API-set namespace')
    limit = size
    def string(at, length):
        require(length % 2 == 0 and 0 <= at <= size - length, 'invalid API-set string')
        result = data[at:at + length].decode('utf-16-le')
        require(result and len(result) <= 1024, 'empty/oversized API-set name')
        return result
    result = {}
    for i in range(count):
        _, name, length, _, table, entries_count = values(entries + i * 24, 6)
        require(entries_count <= 64, 'oversized API-set values')
        key = dll_name(string(name, length))
        require(key not in result, 'duplicate API-set contract')
        choices = {}
        for j in range(entries_count):
            _, alias, alias_length, host, host_length = values(table + j * 20, 5)
            # Empty values are unavailable contracts, never silent success.
            if not host_length:
                continue
            caller = string(alias, alias_length).lower() if alias_length else ''
            if caller:
                require(re.fullmatch(r'[a-z0-9_.+-]+', caller), 'unsafe API-set caller')
                if not caller.endswith(('.dll', '.exe')):
                    caller += '.dll'
            require(caller not in choices, 'ambiguous API-set host')
            choices[caller] = dll_name(string(host, host_length))
        result[key] = choices
    return result


def verify_graph(base, application, required):
    """Resolve all static/delay imports and export forwarders, without loading."""
    base, application = Path(base), Path(application)
    providers = {}
    for folder in (base, application):
        seen = set()
        for path in sorted(folder.iterdir()):
            if not path.is_file() or path.suffix.lower() not in ('.dll', '.exe'):
                continue
            key = path.name.lower()
            require(key not in seen, 'case-ambiguous PE provider')
            seen.add(key)
            providers[key] = path
    cache, aliases, edges = {}, None, []
    def image(name):
        require(name in providers, 'missing PE provider: ' + name)
        if name not in cache:
            require(len(cache) < 1024, 'PE graph grew beyond bound')
            cache[name] = Image(providers[name])
        return cache[name]
    aliases = api_sets(image('apisetschema.dll'))
    def provider(name, caller):
        name = dll_name(name)
        if name in aliases:
            choices = aliases[name]
            name = choices.get(caller, choices.get(''))
            require(name, 'unavailable API-set contract')
        return name
    def resolve(library, symbol, caller, trail=()):
        library = provider(library, caller)
        key = (library, symbol)
        require(key not in trail and len(trail) < 32, 'cyclic/deep export forwarding')
        pe = image(library)
        require(symbol in pe.exports, f'missing PE export: {library}!{symbol}')
        value = pe.exports[symbol]
        if 'forward' in value:
            require('.' in value['forward'], 'invalid export forwarder')
            name, target = value['forward'].rsplit('.', 1)
            if target.startswith('#'):
                require(target[1:].isdigit(), 'invalid forwarded ordinal')
                target = int(target[1:])
            return resolve(name, target, library, trail + (key,))
        return library, symbol, value
    for name, exports in required.items():
        pe = image(name)
        for symbol in exports:
            value = pe.exports.get(symbol, {})
            require(value.get('executable'), f'missing real function export: {name}!{symbol}')
    roots = list(required) + [p.name.lower() for p in application.glob('*.exe')]
    # DXVK's pinned Windows loader tries these two names dynamically.
    for name in ('winevulkan.dll', 'vulkan-1.dll'):
        library, symbol, value = resolve(name, 'vkGetInstanceProcAddr', '')
        require(value['executable'], 'Vulkan PE loader export is not a function')
        roots.append(name)
        edges.append({'consumer': 'DXVK dynamic loader', 'library': name, 'symbol': 'vkGetInstanceProcAddr',
                      'resolved_library': library, 'resolved_symbol': symbol})
    done = set()
    while roots:
        name = roots.pop()
        if name in done:
            continue
        pe = image(name); done.add(name)
        for library, symbol, kind in pe.imports:
            selected = provider(library, name)
            target, target_symbol, value = resolve(library, symbol, name)
            edges.append({'consumer': name, 'library': library, 'symbol': symbol, 'kind': kind,
                          'resolved_library': target, 'resolved_symbol': target_symbol,
                          'export_kind': 'code' if value['executable'] else 'data'})
            roots += [selected, target]
        roots += [loaded for loaded in cache if loaded not in done]
    return {'scope': 'PE names/ordinals/API sets/forwarders/static+delay import closure; no implementation or runtime proof',
            'files': {name: {'file': str(pe.path), 'sha256': pe.sha256} for name, pe in sorted(cache.items())},
            'edges': edges}
