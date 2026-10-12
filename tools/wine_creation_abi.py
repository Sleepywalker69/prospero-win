#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Static identity of the matched creation broker; never executes target code."""
from pathlib import Path
import struct
from native_probe_elf import Elf, extract_self, require, sha
from private_dispatch_wow64 import descriptor, function

ABI = 1
PROTOCOL = 962
ABI_EXPORT = '__wine_ps5_creation_abi'
PROTOCOL_EXPORT = '__wine_ps5_creation_protocol'
EXPORTS = {
    'ntdll': (ABI_EXPORT, PROTOCOL_EXPORT, 'pw_wine_creation_install', 'pw_wine_creation_child_install'),
    'wineserver': (ABI_EXPORT, PROTOCOL_EXPORT, 'pw_wineserver_creation_install'),
}
DECLARATION = {'abi': ABI, 'protocol': PROTOCOL, 'profile': 2, 'maximum_depth': 2,
               'runtime_validated': False}


def record(data):
    return {'bytes': len(data), 'sha256': sha(data)}


def returns(code, value):
    if code.startswith(bytes.fromhex('f30f1efa')):
        code = code[4:]
    move = b'\xb8' + struct.pack('<I', value)
    require(code in (move + b'\xc3', b'\x55\x48\x89\xe5' + move + b'\x5d\xc3'),
            'creation marker has an unrecognized constant-return body')


def module_identity(data, name, *, protocol=PROTOCOL, focus=None):
    """Replay descriptor and marker admission on the actual packaged SELF."""
    require(name in EXPORTS, 'unexpected creation module')
    require(protocol == (963 if focus is not None else PROTOCOL), 'creation/focus protocol selection differs')
    marker_values = {ABI_EXPORT: ABI, PROTOCOL_EXPORT: protocol}
    if focus is not None:
        from wine_focus_neutral import markers
        marker_values.update(markers(focus))
    recovered = extract_self(data, module=True)
    elf = Elf(recovered, module=True)
    exports = {}
    for export in (*EXPORTS[name], *(k for k in marker_values if k not in EXPORTS[name])):
        table, address = descriptor(elf, export)
        elf.offset(address, 1, 1)
        exports[export] = table
    for export, value in marker_values.items():
        address = int(exports[export]['function_address'], 16)
        # Both admitted bodies are bounded and end at ret; read each permitted
        # form separately so a short function never borrows a following body.
        forms = [b'\xb8' + struct.pack('<I', value) + b'\xc3',
                 b'\x55\x48\x89\xe5\xb8' + struct.pack('<I', value) + b'\x5d\xc3']
        forms += [bytes.fromhex('f30f1efa') + body for body in list(forms)]
        matches = []
        for body in forms:
            try:
                at = elf.offset(address, len(body), 1)
            except ValueError:
                # A shorter admitted body may end exactly at its executable
                # LOAD boundary; a longer candidate then simply cannot match.
                continue
            if recovered[at:at + len(body)] == body:
                matches.append(body)
        require(len(matches) == 1, 'packaged creation marker differs: ' + export)
        exports[export]['code_sha256'] = sha(matches[0])
    return {'self': record(data), 'recovered': record(recovered), 'exports': exports}


def check_runtime(work, report, *, focus=None):
    work = Path(work)
    protocol = 963 if focus is not None else PROTOCOL
    declaration = {**DECLARATION, 'protocol': protocol}
    require(('focus_neutral' in report) == (focus is not None), 'focus mode requires explicit validator selection')
    if focus is not None:
        from wine_focus_neutral import checked, header, markers
        require(checked(report['focus_neutral']) == checked(focus), 'focus runtime source differs')
        require((work/'focus-neutral.json').read_text().strip() == __import__('json').dumps(focus,indent=2,sort_keys=True), 'focus staging receipt differs')
        require((work/'source/include/wine/pw_focus_build.h').read_text() == header(focus), 'focus generated source header differs')
    require(report.get('creation') == declaration, 'matched creation capability declaration absent or different')
    result = {'schema': 'pw-wine-creation-build/1', **declaration, 'executed': False, 'modules': {}}
    for name, original_exports in EXPORTS.items():
        marker_values = {ABI_EXPORT: ABI, PROTOCOL_EXPORT: protocol}
        if focus is not None: marker_values.update(markers(focus))
        exports = (*original_exports, *(k for k in marker_values if k not in original_exports))
        native_path = 'dlls/ntdll/ntdll.so' if name == 'ntdll' else 'server/wineserver'
        native = (work / 'build' / native_path).read_bytes()
        require(report.get('targets', {}).get(native_path, {}).get('sha256') == sha(native),
                'native creation module differs from build report: ' + name)
        shared_data = (work / 'prx' / (name + '.shared.elf')).read_bytes()
        converted_data = (work / 'prx' / (name + '.elf')).read_bytes()
        self_data = (work / 'prx/sce_module' / (name + '.prx')).read_bytes()
        require(report.get('prx', {}).get('modules', {}).get(name, {}).get('sha256') == sha(self_data),
                'creation SELF differs from build report: ' + name)
        shared = Elf(shared_data, module=True)
        converted = Elf(converted_data, module=True)
        packaged = module_identity(self_data, name, protocol=protocol, focus=focus)
        for export in exports:
            symbols = [s for s in shared.symbols if s['name'] == export]
            require(len(symbols) == 1, 'creation export missing or ambiguous: ' + export)
            symbol = symbols[0]
            require(symbol['type'] == 2 and symbol['binding'] == 1 and symbol['visibility'] == 0 and
                    symbol['section'] and 0 < symbol['size'] <= 65536, 'creation export is not a bounded visible function')
            table, address = descriptor(shared, export)
            require(address == symbol['value'], 'creation descriptor differs from ELF export')
            at = shared.offset(address, symbol['size'], 1)
            code = shared_data[at:at + symbol['size']]
            if export in marker_values:
                returns(code, marker_values[export])
            converted_table, converted_address = descriptor(converted, export)
            require(table == converted_table == {k: packaged['exports'][export][k] for k in table},
                    'conversion changed creation descriptor identity')
            at = converted.offset(converted_address, len(code), 1)
            require(converted_data[at:at + len(code)] == code, 'conversion changed creation function bytes')
        recovered_data = extract_self(self_data, module=True)
        recovered = Elf(recovered_data, module=True)
        require(converted.programs == recovered.programs and all(
            converted_data[p[2]:p[2] + p[5]] == recovered_data[p[2]:p[2] + p[5]]
            for p in converted.programs if p[0] == 1), 'SELF changed creation LOAD bytes')
        if name == 'ntdll':
            _, code = function(Elf(native, module=True), PROTOCOL_EXPORT)
            returns(code, protocol)
        result['modules'][name] = {'native': record(native), 'shared': record(shared_data),
                                   'converted': record(converted_data), **packaged}
    if focus is not None: result['focus_neutral'] = focus
    return result


def check_package(checked, report, read_module):
    require(isinstance(checked, dict) and checked.get('schema') == 'pw-wine-creation-build/1' and
            checked.get('executed') is False and all(checked.get(k) == v for k, v in DECLARATION.items()) and
            report.get('creation') == DECLARATION and set(checked.get('modules', {})) == set(EXPORTS),
            'packaged creation declaration differs')
    for name in EXPORTS:
        actual = module_identity(read_module(name), name)
        declared = checked['modules'][name]
        require(all(declared.get(k) == v for k, v in actual.items()), 'packaged creation bytes/descriptor differ')
        native_path = 'dlls/ntdll/ntdll.so' if name == 'ntdll' else 'server/wineserver'
        require(declared.get('native', {}).get('sha256') == report.get('targets', {}).get(native_path, {}).get('sha256') and
                actual['self']['sha256'] == report.get('prx', {}).get('modules', {}).get(name, {}).get('sha256'),
                'packaged creation report binding differs')
