#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Build and statically inspect a full-CRT service child from one Wine cohort.

The original app_crt/high layout stay unchanged. A separate source copy of
the pinned converter adds the already reviewed service preload pointer.
No resulting target binary is executed by this tool.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys

sys.dont_write_bytecode = True
from check_wine_prx_build import Commands, require
from check_native_suite import (provider, inspect_bindings, compiled_identity, embedded_image,
                                index_sdk_providers, source_archive, SERVICE_CALLS)
from native_probe_elf import Elf, extract_self
from native_service_converter import (prepare_converter_source, inspect_service_preload,
                                      service_writer_bytes, service_converter_provenance,
                                      FOUNDATION, TITLE_FOUNDATION)
from build_native_child_probe import streamable_self, verify_reconstruction, compare_service_preload
from check_private_dispatch_abi import check_build
from tls_manifest import llvm_identity, tree_files
from windows_chromium_ipc_package import worker_capabilities as ipc_worker_capabilities

ROOT = Path(__file__).resolve().parents[1]
CRT_SHA = 'a99fe406e36d8ce82e68e0245898ba064e28a56a9853f746e9cf13d23cc17a00'
LAYOUT_SHA = '72ee9a1605cce2836d2290fa9a6a6fba0c3c277e78094e7f07562e92dd5b4e49'
WRAPPER_SHA = 'c90881bd828048981da08644ae1e1730a0ef10692b6322cbd6a294de8c5c5346'
UNITS = ('native/pw_wine_child_wire.c', 'native/pw_wine_child_bootstrap.c', 'native/pw_wine_child_main.c', 'native/pw_wine_child_data.c',
         'native/pw_native_child_protocol.c', 'src/pw_wine_start.c', 'wine/ps5/pw_wine_prx.c', 'wine/ps5/pw_wine_threads.c',
         'native/pw_wine_child_ui.c', 'native/pw_wine_child_ui_handoff.c', 'native/pw_wine_child_ui_channel.c')
HEADERS = ('native/pw_wine_child_data.h', 'native/pw_wine_ipc_profile.h', 'native/lapy_elevation_protocol.h', 'native/pw_lapy_client.h', 'native/pw_wine_child_wire.h', 'native/pw_wine_child_bootstrap.h', 'src/pw_wine_start.h',
           'native/pw_native_child_protocol.h', 'src/pw_wine_launch.h', 'include/prospero_win.h',
           'wine/ps5/pw_wine_prx.h', 'wine/ps5/pw_wine_threads.h', 'wine/ps5/pw_wine_fixture_socket.h', 'wine/ps5/pw_wine_creation.h',
           'native/pw_wine_child_ui_config.h', 'native/pw_wine_child_ui.h', 'native/pw_wine_child_ui_handoff.h',
           'native/pw_wine_child_ui_channel.h', 'wine/ps5/pw_wine_sink.h')
PROVIDERS = {'libSceLibcInternal.sprx': 'libSceLibcInternal.so', 'libkernel.sprx': 'libkernel.so',
             'libSceNet.sprx': 'libSceNet.so'}
NET_FUNCTIONS = ('sceNetSocket', 'sceNetConnect', 'sceNetSend', 'sceNetRecv',
                 'sceNetSetsockopt', 'sceNetSocketClose', 'sceNetErrnoLoc')
CRT_IMPORTS = {'_init_env': 'libSceLibcInternal.sprx', 'atexit': 'libSceLibcInternal.sprx',
               'exit': 'libSceLibcInternal.sprx', 'pthread_create': 'libkernel.sprx',
               'sceKernelLoadStartModule': 'libkernel.sprx',
               **{name: 'libSceNet.sprx' for name in NET_FUNCTIONS}}
TITLE_MARKER = 'pw-wine-child-fixture/1'
TITLE_FUNCTIONS = ('pw_wine_fixture_owner_init', 'pw_wine_fixture_owner_pump')


def child_ui_contract(enabled=False):
    require(type(enabled) is bool, 'child UI flag must be boolean')
    return {'enabled': enabled, 'bootstrap_version': 3 if enabled else 2,
            'bootstrap_rights': 2 if enabled else 1, 'preview_only': enabled,
            'input_enabled': False, 'socket_identity': 'nonzero-distinct-fstat' if enabled else None,
            'runtime_validated': False}


def checked_child_ui(bound):
    value = bound.get('child_ui', child_ui_contract(False))
    require(isinstance(value, dict) and value == child_ui_contract(value.get('enabled')),
            'child UI contract differs')
    return value


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def record(path):
    return {'bytes': path.stat().st_size, 'sha256': sha(path)}


def source_identity(root, commands):
    require(not commands.run('git', '-C', root, 'status', '--porcelain', '--untracked-files=normal').strip(),
            'service child requires clean committed project source')
    project = {'commit': commands.run('git', '-C', root, 'rev-parse', 'HEAD').strip(),
               'tree': commands.run('git', '-C', root, 'rev-parse', 'HEAD^{tree}').strip()}
    sources = {name: sha(root / name) for name in (*UNITS, *HEADERS, 'tools/build_wine_service_child.py',
               'tools/native_service_converter.py', 'tools/native_probe_elf.py', 'tools/check_native_suite.py',
               'tools/build_owned_helper.py', 'tools/build_native.sh', 'tools/wine_creation_abi.py',
               'wine/ps5/pw_wine_fixture_provider.c', 'wine/ps5/pw_wine_fixture_provider.h',
               'tools/windows_chromium_ipc_contract.py', 'tools/windows_chromium_ipc_package.py')}
    return project, sources


def identity(inputs):
    return hashlib.sha256(json.dumps(inputs, sort_keys=True, separators=(',', ':')).encode()).hexdigest()[:40]


def output_directory(path, inputs):
    path = path.absolute()
    require(not path.exists() and not path.is_symlink(), 'service output must be absent')
    for part in (path.parent, *path.parent.parents):
        require(not part.is_symlink(), 'service output has a symlink parent')
    require(path.parent.is_dir(), 'service output parent does not exist')
    for original in inputs:
        original = original.resolve(strict=True)
        require(not path.is_relative_to(original) and not original.is_relative_to(path), 'service output overlaps an input')
    path.mkdir()
    return path


def ordinary_graph(linked, converted, providers):
    require(set(linked.needed) == set(PROVIDERS) and len(linked.needed) == 3,
            'full-CRT child needs exactly ordinary libc, kernel and Net providers')
    graph = inspect_bindings(linked, converted, providers)
    for index, symbol in enumerate(linked.symbols[1:], 1):
        name = symbol['name']; entry = graph[name]
        selected = entry['provider']
        require(symbol['type'] in (0, 2) and symbol['binding'] == 1 and symbol['visibility'] == 0 and
                providers[selected]['definitions'][name] == 'FUNC', 'unsupported child import type/provider: ' + name)
        require(entry['relocations'] and all(r['type'] in (6, 7) and r['addend'] == 0 for r in entry['relocations']),
                'unsupported child function relocation: ' + name)
        for relocation in entry['relocations']:
            linked.offset(relocation['address'], 8, 6)
            converted.offset(relocation['address'], 8, 6)
    require(all(name in graph and graph[name]['provider'] == expected for name, expected in CRT_IMPORTS.items()),
            'full-CRT lifecycle imports missing or bound to wrong providers')
    require({name for name, entry in graph.items() if entry['provider'] == 'libSceNet.sprx'} ==
            set(NET_FUNCTIONS) and {name for name in graph if name.startswith('sceNet')} == set(NET_FUNCTIONS),
            'child requires exactly seven native-root Net imports')
    require('sceKernelDlsym' not in graph and not any(name.startswith('sceSysmodule') for name in graph),
            'child must not use dynamic Net acquisition')
    return graph


def helper_inputs(args, root, project, sdk):
    """Admit actual producer output, including source, object and SDK evidence."""
    from build_owned_helper import validate_owned_helper
    work = getattr(args, 'service_work', None)
    directory = work / 'owned-helper' if work else getattr(args, 'helper_directory', None)
    require(directory is not None, 'child build needs source-bound helper directory')
    return validate_owned_helper(directory, root, project, sdk)


def retain_helper(source, destination):
    from build_owned_helper import OUTPUTS, UNITS
    destination.mkdir()
    (destination / 'obj').mkdir()
    for name in (*OUTPUTS, 'owned_identity.h', 'lapy.map',
                 *('obj/' + unit + '.o' for unit in UNITS)):
        original = source / name
        require(original.is_file() and not original.is_symlink(), 'linked/missing helper evidence')
        shutil.copyfile(original, destination / name)


def helper_digest(bound):
    helper = bound.get('helper', {})
    digest = helper.get('elf', {}).get('sha256', '')
    require(re.fullmatch('[0-9a-f]{64}', digest) and
            helper.get('project') == bound.get('project') and bool(bound.get('project')) and
            helper.get('toolchain_reverified') is True and helper.get('runtime_validated') is False,
            'helper actual digest/source/toolchain binding differs')
    return digest


def net_inputs(sdk, bindir, commands):
    name = 'libSceNet.sprx'; path = sdk / 'target/lib' / PROVIDERS[name]
    item = provider(path, bindir, commands)
    require(item['soname'] == name and all(item['definitions'].get(call) == 'FUNC' for call in NET_FUNCTIONS),
            'child static Net provider/exports differ')
    return {'provider': {'soname': name, **record(path)}, 'functions': list(NET_FUNCTIONS),
            'acquisition': 'static-imports', 'initialization': 'native-root-transport',
            'explicit_net_init': False, 'runtime_validated': False}


def check_disassembly(disassembly):
    require(re.search(r'^\s*[0-9a-f]+:\s+\S', disassembly, re.M), 'child disassembly is empty')
    require(not re.search(r'\(bad\)|<unknown>|\.byte\b', disassembly, re.I), 'child analyzer has undecoded bytes')
    require(not re.search(r'^\s*[0-9a-f]+:\s+(?:syscall|sysenter)(?:\s|$)|'
                          r'^\s*[0-9a-f]+:\s+int\w*\s+\$?(?:0x80|128)(?:\s|$)', disassembly, re.M | re.I),
            'child contains raw syscall')


def inspect_code(path, bindir, commands):
    image = Elf(path.read_bytes())
    image.offset(image.entry, 1, 1)
    sections = commands.run(bindir / 'llvm-readelf', '--section-headers', '-W', path)
    unwind = re.findall(r'^\s*\[\s*\d+\]\s+(\.eh_frame(?:_hdr)?)\s+(PROGBITS|X86_64_UNWIND)'
                        r'\s+[0-9a-fA-F]+\s+[0-9a-fA-F]+\s+([0-9a-fA-F]+)\b', sections, re.M)
    require(len(unwind) == 2 and {n for n, _, _ in unwind} == {'.eh_frame', '.eh_frame_hdr'} and
            all(int(size, 16) > 0 for _, _, size in unwind), 'full-CRT child lacks unwind records')
    disassembly = commands.run(bindir / 'llvm-objdump', '-d', '--no-show-raw-insn', path)
    check_disassembly(disassembly)
    symbols = commands.run(bindir / 'llvm-readelf', '-sW', path)
    for name in ('_start', 'main', '_init', '_fini'):
        rows = [line.split() for line in symbols.splitlines() if len(line.split()) >= 8 and line.split()[7] == name]
        require(rows and all(r[3] == 'FUNC' and r[6] != 'UND' for r in rows), 'missing full-CRT function: ' + name)
        if name == '_start':
            require(all(int(r[1], 16) == image.entry for r in rows), 'ELF entry differs from app_crt _start')
    return {'entry': hex(image.entry), 'unwind_bytes': {n: int(s, 16) for n, _, s in unwind},
            'raw_syscalls': [], 'app_crt_functions': ['_start', '_init', '_fini', 'main']}


def inputs(args, commands):
    require(getattr(args, 'ipc_fixture', None) is None or not getattr(args, 'child_ui', False),
            'child preview and IPC admission require separate matched cohorts')
    root, sdk, foundation, runtime, bindir = [Path(p).resolve(strict=True) for p in
        (args.work, args.sdk, args.foundation, args.runtime, args.llvm_bindir)]
    require(sdk.name == 'ps5-payload-sdk' and sdk.parent.name == 'native' and sdk.parent.parent.name == '.deps',
            'SDK must use its supported title foundation layout')
    title = sdk.parent.parent.parent
    require(commands.run('git', '-C', title, 'rev-parse', 'HEAD').strip() == TITLE_FOUNDATION and
            commands.run('git', '-C', foundation, 'rev-parse', 'HEAD').strip() == FOUNDATION, 'wrong foundation source')
    for checkout in (title, foundation):
        require(not commands.run('git', '-C', checkout, 'status', '--porcelain', '--untracked-files=all',
                                 '--', 'tooling').strip(), 'foundation source differs from its pin')
    native = title / 'tooling/native'
    require(sha(native / 'app_crt.cpp') == CRT_SHA and sha(native / 'ps5-pie-high.ld') == LAYOUT_SHA and
            sha(title / 'tooling/prospero-clang18') == WRAPPER_SHA, 'full-CRT/layout/compiler wrapper pin differs')
    llvm = llvm_identity(sdk)
    require(Path(llvm['bindir']).resolve() == bindir, 'child analyzer/compiler selection differs from SDK')
    require(re.search(r'LLVM version 18(?:\.|\b)', commands.run(bindir / 'llvm-readelf', '--version')),
            'child requires LLVM18')
    project, sources = source_identity(root, commands)
    abi = check_build(runtime, 1, bindir / 'llvm-readelf', require_wow64=True)
    require(abi.get('wow64', {}).get('abi') == 1 and abi['wow64'].get('runtime_validated') is False,
            'full-CRT child requires the checked translated-I386 runtime capability')
    declaration = json.loads((runtime / 'report.json').read_text()).get('service_fixture')
    require(declaration == {'enabled': True, 'unix_define': 'PW_WINE_SERVICE_FIXTURE=1',
                            'abi': 1, 'runtime_validated': False}, 'Wine service consumers were not explicitly built')
    require(abi.get('creation', {}).get('abi') == 1 and abi['creation'].get('protocol') == 962,
            'child requires actual matched creation protocol and broker')
    helper = helper_inputs(args, root, project, sdk)
    net = net_inputs(sdk, bindir, commands)
    result = {'helper': helper, 'net_transport': net, 'child_ui': child_ui_contract(getattr(args, 'child_ui', False)),
              'project': project, 'sources': sources, 'runtime': {'ntdll_sha256': sha(runtime / 'prx/sce_module/ntdll.prx'),
              'creation_abi': 1, 'creation_protocol': 962, 'private_dispatch_abi': 1, 'private_dispatch_wow64_abi': 1, 'report_sha256': sha(runtime / 'report.json'), 'abi_check': abi},
              'candidate_capabilities': [
                  {'mode': 1, 'prefix': 'windows-child-fixture-v1', 'guest_machine': 'AMD64',
                   'backend': 'native-amd64', 'runtime_validated': False},
                  {'mode': 2, 'prefix': 'battlenet-experimental-v1', 'guest_machine': 'I386',
                   'backend': 'wowprospero', 'runtime_validated': False},
                  {'mode': 3, 'prefix': 'windows-child-user-v1', 'guest_machine': 'AMD64',
                   'backend': 'native-amd64', 'runtime_validated': False},
                  {'mode': 4, 'prefix': 'windows-child-net-v1', 'guest_machine': 'AMD64',
                   'backend': 'native-amd64', 'runtime_validated': False},
                  *([] if getattr(args, 'child_ui', False) else ipc_worker_capabilities())],
              'title_foundation': TITLE_FOUNDATION, 'converter_foundation': TITLE_FOUNDATION,
              'prx_foundation': FOUNDATION,
              'app_crt_sha256': CRT_SHA, 'layout_sha256': LAYOUT_SHA, 'wrapper_sha256': WRAPPER_SHA,
              'libc_companion': record(title / 'runtime/libc.prx'), 'host_llvm': llvm,
              'sdk_headers': tree_files(sdk / 'target/include'), 'sdk_wrappers': tree_files(sdk / 'bin'),
              'providers': {name: record(sdk / 'target/lib' / leaf) for name, leaf in PROVIDERS.items()}}
    return result, (root, sdk, foundation, runtime, bindir, title)


def child_header(bound, build_id):
    require(bound['runtime'].get('creation_abi') == 1 and bound['runtime'].get('creation_protocol') == 962 and
            bound['runtime'].get('private_dispatch_abi') == 1 and
            bound['runtime'].get('private_dispatch_wow64_abi') == 1,
            'child header cannot assert an absent ABI capability')
    require(re.fullmatch('[0-9a-f]{40}', build_id) and
            re.fullmatch('[0-9a-f]{64}', bound['runtime']['ntdll_sha256']) and
            helper_digest(bound), 'invalid child header identity')
    child_ui = checked_child_ui(bound)
    return ('#define PW_WINE_CHILD_UI_COHORT ' + str(int(child_ui['enabled'])) + '\n' +
            '#define PW_WINE_CHILD_BUILD_ID "' + build_id + '"\n' +
            '#define PW_WINE_CHILD_NTDLL_SHA256 "' + bound['runtime']['ntdll_sha256'] + '"\n' +
            '#define PW_WINE_CHILD_PRIVATE_DISPATCH_ABI 1\n' +
            '#define PW_WINE_CHILD_WOW64_ABI 1\n' +
            '#define PW_WINE_CHILD_CREATION_ABI 1\n' +
            '#define PW_WINE_CHILD_CREATION_PROTOCOL 962\n' +
            '#define PW_WINE_CHILD_HELPER_SHA256 \"' + bound['helper']['elf']['sha256'] + '\"\n')


def build(args):
    require(getattr(args, 'ipc_fixture', None) is None or not getattr(args, 'child_ui', False),
            'child preview and IPC admission require separate matched cohorts')
    require(args.helper_directory is not None, 'child build needs source-bound helper directory')
    out = output_directory(args.out, (args.sdk, args.foundation, args.runtime, args.helper_directory))
    commands = Commands(out / 'inspection')
    bound, paths = inputs(args, commands)
    root, sdk, foundation, runtime, bindir, title = paths
    build_id = identity(bound)
    header = out / 'wine-child-build.h'
    header.write_text(child_header(bound, build_id))
    environment = ['env', '-i', 'PATH=/usr/bin:/bin', 'LANG=C', 'LC_ALL=C',
                   'PS5_PAYLOAD_SDK=' + str(sdk), 'PS5_CLANG=' + str(bindir / 'clang'),
                   'LLVM_CONFIG=' + bound['host_llvm']['config']]
    cc = [*environment, 'sh', title / 'tooling/prospero-clang18', '--no-default-config']
    macros = commands.run(*cc, '-dM', '-E', '-x', 'c', '/dev/null')
    for name in ('__PROSPERO__', '__FreeBSD__', '__x86_64__'):
        require(re.search(r'^#define ' + name + r' [1-9][0-9]*$', macros, re.M), 'wrong target macro: ' + name)
    objects = []
    for name in UNITS:
        obj = out / (name.replace('/', '_') + '.o')
        commands.run(*cc, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-ffunction-sections', '-fdata-sections',
                     '-fasynchronous-unwind-tables', '-DPW_WINE_CHILD_UI_ENABLED=' + str(int(bound['child_ui']['enabled'])),
                     '-I' + str(out), '-I' + str(root / 'include'), '-I' + str(root / 'src'), '-I' + str(root / 'native'),
                     '-I' + str(root / 'wine/ps5'), '-c', root / name, '-o', obj)
        objects.append(obj)
    crt = out / 'app_crt.o'
    commands.run(*cc, '-std=c++20', '-O2', '-Wall', '-Wextra', '-Werror', '-fno-exceptions', '-fno-rtti',
                 '-ffunction-sections', '-fdata-sections', '-fasynchronous-unwind-tables',
                 '-c', title / 'tooling/native/app_crt.cpp', '-o', crt)
    linked = out / 'child.linked.elf'
    stubs = [sdk / 'target/lib' / name for name in PROVIDERS.values()]
    commands.run(*environment, sdk / 'bin/prospero-lld', '-T', title / 'tooling/native/ps5-pie-high.ld',
                 '--eh-frame-hdr', '-e', '_start', '-z', 'defs', '-o', linked, crt, *objects, '--as-needed', *stubs)
    # The high layout and its executable converter are a matched title input.
    # The PRX converter expects zero-based text and remains the runtime producer.
    native = title / 'tooling/native'
    writer, specialized = prepare_converter_source(native / 'sce_module_writer.cpp', out / 'sce_module_writer.service.cpp',
                                                  service=True, foundation=TITLE_FOUNDATION)
    zroot = foundation / '.deps/native/zlib/root'
    archives = sorted(zroot.rglob('libz.a'))
    require(len(archives) == 1, 'converter requires one pinned built zlib archive')
    tool = out / 'ps5-native-tool'
    commands.run(*environment, bindir / 'clang++', '--no-default-config', '-std=c++20', '-O2', '-Wall', '-Wextra', '-Werror',
                 '-I', zroot / 'usr/include', '-I', native, native / 'native_app_builder.cpp', native / 'self_container.cpp',
                 native / 'elf_object.cpp', writer, archives[0], '-o', tool)
    converted, signed, final = out / 'child.elf', out / 'child.original.self', out / 'native-wine-child.self'
    commands.run(tool, 'link', '--in', linked, '--out', converted, *[arg for stub in stubs for arg in ('--stub', stub)],
                 '--module-sdk', '0x02000009', '--companion-sdk', '0x08050001', '--file-name', 'native-wine-child.elf',
                 '--component', 'pw_wine_service_child')
    providers = {name: provider(sdk / 'target/lib' / leaf, bindir, commands) for name, leaf in PROVIDERS.items()}
    require(all(p['soname'] == name for name, p in providers.items()), 'SDK provider SONAME differs')
    graph = ordinary_graph(Elf(linked.read_bytes()), Elf(converted.read_bytes()), providers)
    code = inspect_code(linked, bindir, commands)
    preload = inspect_service_preload(converted.read_bytes())
    commands.run(tool, 'self', '--sign', '--in', converted, '--out', signed, '--magic', '0x1D3D154F')
    framing = streamable_self(signed, final, tool, commands)
    recovered = final.with_suffix('.after.elf')
    reconstruction = verify_reconstruction(converted, recovered)
    require(extract_self(final.read_bytes()) == recovered.read_bytes(), 'independent SELF recovery differs')
    after = inspect_service_preload(recovered.read_bytes()); compare_service_preload(preload, after)
    compiled_identity(Elf(recovered.read_bytes()), build_id)
    compiled_identity(Elf(recovered.read_bytes()), helper_digest(bound))
    final.chmod(0o755)
    require(inputs(args, commands)[0] == bound, 'service build inputs changed')
    manifest = {'schema': 'pw-wine-service-child/2', **bound,
                'worker': {**record(final), 'build_id': build_id},
                'linked': record(linked), 'converted': record(converted), 'reconstructed': record(recovered),
                'linkage': graph, 'code': code, 'reconstruction': reconstruction, 'framing': framing,
                'converter_specialization': specialized, 'converter_sha256': sha(tool),
                'converter_sources': {p.name: sha(p) for p in sorted(native.iterdir()) if p.is_file()},
                'zlib_archive': record(archives[0]), 'zlib_headers': tree_files(zroot / 'usr/include'),
                'preload_before_signing': preload, 'preload_after_recovery': after,
                'console_execution_verified': False, 'windows_process_support': False,
                'platform_authentication_verified': False}
    (out / 'native-wine-child-build.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    (out / 'native-wine-child-build.h').write_text(header.read_text() +
        '#define PW_WINE_CHILD_SELF_SHA256 "' + manifest['worker']['sha256'] + '"\n' +
        '#define PW_WINE_CHILD_SELF_BYTES ' + str(manifest['worker']['bytes']) + '\n')
    value = final.read_bytes()
    with (out / 'native-wine-child-image.c').open('w') as stream:
        stream.write('/* Generated from the checked original full-CRT service SELF. */\n#include <stddef.h>\n'
                     'const unsigned char pw_wine_child_image[] = {\n')
        for start in range(0, len(value), 16):
            stream.write(','.join(str(v) for v in value[start:start + 16]) + ',\n')
        stream.write('};\nconst size_t pw_wine_child_image_size = sizeof(pw_wine_child_image);\n')
    retain_helper(args.helper_directory, out / 'owned-helper')
    require(helper_inputs(argparse.Namespace(service_work=out), root, bound['project'], sdk) == bound['helper'],
            'retained helper cohort differs')
    for name, leaf in PROVIDERS.items():
        shutil.copyfile(sdk / 'target/lib' / leaf, out / leaf)
    return manifest


def verify_converter_copy(native, work, manifest):
    original = (native / 'sce_module_writer.cpp').read_bytes()
    require((work / 'sce_module_writer.service.cpp').read_bytes() ==
            service_writer_bytes(original, foundation=TITLE_FOUNDATION), 'service converter source copy differs')
    require(manifest['converter_specialization'] ==
            service_converter_provenance(original, foundation=TITLE_FOUNDATION),
            'service converter specialization report differs')


def verify_child(args, commands):
    """Recheck a retained build graph without trusting its previous report alone."""
    bound, paths = inputs(args, commands)
    root, sdk, foundation, runtime, bindir, title = paths
    work = args.service_work.resolve(strict=True)
    manifest = json.loads((work / 'native-wine-child-build.json').read_text())
    require(manifest.get('schema') == 'pw-wine-service-child/2' and
            all(manifest.get(k) == v for k, v in bound.items()), 'service child source/runtime inputs differ')
    require(manifest['worker']['build_id'] == identity(bound), 'service child build ID differs')
    for field, name in (('worker', 'native-wine-child.self'), ('linked', 'child.linked.elf'),
                        ('converted', 'child.elf'), ('reconstructed', 'native-wine-child.after.elf')):
        require(all(manifest[field].get(k) == v for k, v in record(work / name).items()), 'stale child artifact: ' + name)
    value = extract_self((work / 'native-wine-child.self').read_bytes())
    require(value == (work / 'native-wine-child.after.elf').read_bytes(), 'child SELF recovery differs')
    compiled_identity(Elf(value), manifest['worker']['build_id'])
    compiled_identity(Elf(value), helper_digest(bound))
    require(inspect_service_preload((work / 'child.elf').read_bytes()) == manifest['preload_before_signing'] and
            inspect_service_preload(value) == manifest['preload_after_recovery'], 'child preload report differs')
    compare_service_preload(manifest['preload_before_signing'], manifest['preload_after_recovery'])
    require(verify_reconstruction(work / 'child.elf', work / 'native-wine-child.after.elf') == manifest['reconstruction'],
            'child reconstruction report differs')
    providers = {name: provider(sdk / 'target/lib' / leaf, bindir, commands) for name, leaf in PROVIDERS.items()}
    require(ordinary_graph(Elf((work / 'child.linked.elf').read_bytes()), Elf((work / 'child.elf').read_bytes()), providers)
            == manifest['linkage'], 'child actual import graph differs')
    require(inspect_code(work / 'child.linked.elf', bindir, commands) == manifest['code'], 'child code inspection differs')
    native = title / 'tooling/native'
    verify_converter_copy(native, work, manifest)
    require(manifest['converter_sources'] == {p.name: sha(p) for p in sorted(native.iterdir()) if p.is_file()} and
            manifest['converter_sha256'] == sha(work / 'ps5-native-tool'), 'converter retained inputs/output differ')
    zroot = foundation / '.deps/native/zlib/root'; archives = sorted(zroot.rglob('libz.a'))
    require(len(archives) == 1 and manifest['zlib_archive'] == record(archives[0]) and
            manifest['zlib_headers'] == tree_files(zroot / 'usr/include'), 'converter zlib inputs differ')
    for name, leaf in PROVIDERS.items():
        require(record(work / leaf) == bound['providers'][name], 'retained service provider differs')
    require((work / 'wine-child-build.h').read_text() == child_header(bound, identity(bound)), 'child generated helper/ABI header differs')
    for key in ('console_execution_verified', 'windows_process_support', 'platform_authentication_verified'):
        require(manifest.get(key) is False, 'child manifest makes unsupported execution claim')
    return manifest, paths


def check_route(linked, recovered, symbols, functions_to_check=TITLE_FUNCTIONS):
    marker = compiled_identity(recovered, TITLE_MARKER)
    functions = {}
    for name in functions_to_check:
        rows = [line.split() for line in symbols.splitlines() if len(line.split()) >= 8 and line.split()[7] == name]
        require(len(rows) == 1 and rows[0][3] == 'FUNC' and rows[0][6] != 'UND', 'missing defined fixture route: ' + name)
        address, size = int(rows[0][1], 16), int(rows[0][2])
        require(address > 0 and size > 0, 'empty fixture route function')
        before = linked.offset(address, size, 1); after = recovered.offset(address, size, 1)
        original, actual = linked.data[before:before + size], recovered.data[after:after + size]
        require(original == actual, 'fixture route bytes changed through conversion')
        functions[name] = {'address': address, 'bytes': size, 'sha256': hashlib.sha256(actual).hexdigest()}
    return {'mode': 1, 'marker': marker, 'functions': functions, 'runtime_validated': False}


def fixture_title_identity(image, title_inputs, pair):
    expected = pair['files']['child.exe']
    require(expected == pair['files']['parent.exe'] and
            title_inputs.get('fixture_child_sha256') == expected['sha256'],
            'title input differs from the validated same-byte original fixture')
    result = compiled_identity(image, expected['sha256'])
    # Require a standalone C string, not a suffix of another diagnostic string.
    for address in result['addresses']:
        offset = image.offset(address, 65, 4)
        require(any(p[0] == 1 and p[3] == address for p in image.programs) or
                (offset > 0 and image.data[offset - 1] == 0), 'fixture hash is not a standalone title literal')
    return result


TITLE_USER_FUNCTIONS = ('pw_wine_child_title_profile', 'pw_wine_child_title_prepare')
TITLE_USER_SOURCES = ('native/wine64_main.c', 'native/pw_wine_child_title.c', 'native/pw_wine_child_title.h',
                      'native/pw_wine_fixture_owner.c', 'native/pw_wine_fixture_owner.h',
                      'native/pw_data_mount.c', 'native/pw_data_mount.h',
                      'native/pw_lapy_elevation.c', 'native/pw_lapy_elevation.h',
                      'native/lapy_elevation_protocol.h', 'native/pw_lapy_client.h', 'native/pw_sha256.h', 'native/pw_wine_ipc_profile.h',
                      'native/pw_wine_child_ui_config.h', 'native/pw_wine_child_ui.c', 'native/pw_wine_child_ui.h',
                      'native/pw_wine_child_ui_handoff.c', 'native/pw_wine_child_ui_handoff.h',
                      'native/pw_wine_child_ui_channel.c', 'native/pw_wine_child_ui_channel.h',
                      'native/pw_wine_child_ui_runtime.c', 'native/pw_wine_child_ui_runtime.h',
                      'native/pw_wine_child_ui_preview.c', 'native/pw_wine_child_ui_preview.h',
                      'native/pw_wine_controller_settings.c', 'native/pw_wine_controller_settings.h',
                      'src/pw_controller_settings.c', 'src/pw_controller_settings.h',
                      'native/pw_wine_display.c', 'native/pw_wine_display.h',
                      'native/pw_wine_library.c', 'native/pw_wine_library.h',
                      'src/pw_game_profile.c', 'src/pw_game_profile.h',
                      'src/pw_launcher_render.c', 'src/pw_launcher_render.h',
                      'src/pw_pad.c', 'src/pw_pad.h', 'native/pw_pad_ps5.c', 'native/pw_pad_ps5.h')


def title_input_contract(root, service_work, fixture, user_fixture=None, run_id=None, run_attempt=None):
    """Validate original bytes before admitting optional mode3; no reference-derived run authority."""
    from prepare_windows_child_prefix import validate_pair
    manifest_path = service_work / 'native-wine-child-build.json'
    manifest = json.loads(manifest_path.read_text())
    pair = validate_pair(fixture.resolve(strict=True), manifest['project'])
    require(pair['source_sha256'] == sha(root / 'tests/fixtures/windows_child_process.c') and
            pair['recipe_sha256'] == sha(root / 'tools/build_windows_child_fixture.ps1'), 'title fixture source/recipe differs')
    child_sha = pair['files']['child.exe']['sha256']
    result = {'schema': 'pw-windows-child-title-inputs/1', 'project': manifest['project'],
              'mode': 1, 'define': 'PW_WINE_CHILD_FIXTURE_MODE=1', 'fixture_child_sha256': child_sha,
              'child_ui': checked_child_ui(manifest),
              'build_script_sha256': sha(root / 'tools/build_native.sh'), 'service_manifest_sha256': sha(manifest_path)}
    user_pair = None
    if user_fixture is not None:
        require(isinstance(run_id, str) and re.fullmatch('[1-9][0-9]*', run_id) and
                isinstance(run_attempt, str) and re.fullmatch('[1-9][0-9]*', run_attempt),
                'enabled USER title requires explicit expected run/attempt')
        require(pair.get('run_id') == run_id and pair.get('run_attempt') == run_attempt,
                'original fixture is not the expected USER title run/attempt')
        import windows_child_user_contract as user_contract
        require(Path(user_contract.__file__).resolve() == (root / 'tools/windows_child_user_contract.py').resolve(),
                'USER validator loaded from another project')
        details = {}
        user_pair = user_contract.validate_pair(user_fixture.resolve(strict=True), manifest['project'], root,
                                               run_id, run_attempt, details=details)
        require(user_pair.get('project') == manifest['project'] and user_pair.get('run_id') == run_id and
                user_pair.get('run_attempt') == run_attempt, 'USER validator identity differs')
        result.update({'user_enabled': True, 'user_child_sha256': user_pair['files']['user-child.exe']['sha256'],
                       'user_reference_sha256': sha(user_fixture / 'user-source.json'),
                       'user_validator_sha256': sha(root / 'tools/windows_child_user_contract.py'),
                       'run_id': run_id, 'run_attempt': run_attempt})
    enabled = int(user_pair is not None)
    header = '#define PW_WINE_FIXTURE_CHILD_SHA256 "' + child_sha + '"\n'
    header += '#define PW_WINE_USER_PROFILE_ENABLED ' + str(enabled) + '\n'
    if enabled:
        header += '#define PW_WINE_USER_CHILD_SHA256 "' + result['user_child_sha256'] + '"\n'
    return result, header, pair, user_pair



def title_profiles_input_contract(root, service_work, fixture, user_fixture=None,
                                  run_id=None, run_attempt=None, network_fixture=None, ipc_fixture=None):
    """Keep leaf/USER admission independent; optional network needs its own original pair."""
    result, header, pair, user_pair = title_input_contract(root, service_work, fixture,
                                                         user_fixture, run_id, run_attempt)
    require(ipc_fixture is None or not result['child_ui']['enabled'],
            'child preview and IPC admission require separate matched cohorts')
    network_pair = None
    if network_fixture is not None:
        require(isinstance(run_id, str) and re.fullmatch('[1-9][0-9]*', run_id) and
                isinstance(run_attempt, str) and re.fullmatch('[1-9][0-9]*', run_attempt),
                'enabled network title requires explicit expected run/attempt')
        require(pair.get('run_id') == run_id and pair.get('run_attempt') == run_attempt,
                'original fixture is not the expected network title run/attempt')
        import windows_child_network_contract as network_contract
        require(Path(network_contract.__file__).resolve() ==
                (root / 'tools/windows_child_network_contract.py').resolve(),
                'network validator loaded from another project')
        details = {}
        network_pair = network_contract.validate_pair(network_fixture.resolve(strict=True), result['project'], root,
                                                      run_id, run_attempt, details=details)
        require(network_pair.get('project') == result['project'] and network_pair.get('run_id') == run_id and
                network_pair.get('run_attempt') == run_attempt, 'network validator identity differs')
        require(network_pair.get('header_sha256') == sha(root / 'tests/fixtures/windows_child_network_contract.h'),
                'network original contract header differs')
        result.update({'network_enabled': True, 'network_child_sha256': network_pair['files']['net-child.exe']['sha256'],
                       'network_reference_sha256': sha(network_fixture / 'network-source.json'),
                       'network_validator_sha256': sha(root / 'tools/windows_child_network_contract.py'),
                       'network_header_sha256': network_pair['header_sha256'],
                       'run_id': run_id, 'run_attempt': run_attempt})
        header += '#define PW_WINE_NET_PROFILE_ENABLED 1\n'
        header += '#define PW_WINE_NET_CHILD_SHA256 "' + result['network_child_sha256'] + '"\n'
    if ipc_fixture is not None:
        require(pair.get('run_id') == run_id and pair.get('run_attempt') == run_attempt,
                'original fixture is not the expected IPC run/attempt')
        import windows_chromium_ipc_contract as ipc_contract
        require(Path(ipc_contract.__file__).resolve() == (root / 'tools/windows_chromium_ipc_contract.py').resolve(),
                'IPC validator loaded from another project')
        cohort = ipc_contract.validate_bundle(ipc_fixture, result['project'], root, run_id, run_attempt)
        require(cohort.get('project') == result['project'] and cohort.get('run_id') == run_id and
                cohort.get('run_attempt') == run_attempt and cohort.get('admitted_architecture') == 'x64',
                'IPC validator returned a different complete cohort')
        result.update(ipc_enabled=True, ipc_child_sha256=cohort['references']['x64']['image']['sha256'],
                      ipc_reference=cohort, ipc_validator_sha256=sha(root / 'tools/windows_chromium_ipc_contract.py'),
                      run_id=run_id, run_attempt=run_attempt)
        header += '#define PW_WINE_IPC_PROFILE_ENABLED 1\n'
        header += '#define PW_WINE_IPC_CHILD_SHA256 "' + result['ipc_child_sha256'] + '"\n'
    return result, header, pair, user_pair, network_pair


def network_title_identity(image, title_inputs, pair):
    digest = pair['files']['net-child.exe']['sha256']
    require(title_inputs.get('network_enabled') is True and title_inputs.get('network_child_sha256') == digest,
            'network title hash differs from validated actual child')
    result = compiled_identity(image, digest)
    for address in result['addresses']:
        offset = image.offset(address, 65, 4)
        require(any(p[0] == 1 and p[3] == address for p in image.programs) or
                (offset > 0 and image.data[offset - 1] == 0), 'network child hash is not a standalone title literal')
    return result

def user_title_identity(image, title_inputs, pair):
    digest = pair['files']['user-child.exe']['sha256']
    require(title_inputs.get('user_enabled') is True and title_inputs.get('user_child_sha256') == digest,
            'USER title hash differs from validated actual child')
    result = compiled_identity(image, digest)
    for address in result['addresses']:
        offset = image.offset(address, 65, 4)
        require(any(p[0] == 1 and p[3] == address for p in image.programs) or
                (offset > 0 and image.data[offset - 1] == 0), 'USER child hash is not a standalone title literal')
    return result


def title_compile_record(root, build, project, compiler, common, units):
    """Called after successful actual compile commands using their same shell arrays."""
    require(len(compiler) == 4 and compiler[0] == 'env' and compiler[1].startswith('PS5_PAYLOAD_SDK=') and
            compiler[2] == 'sh' and common and len(units) == len(set(units)), 'empty/unsupported title compile inputs')
    sources = {}
    for name in units:
        require(re.fullmatch(r'(native|src|wine/ps5)/[A-Za-z0-9_./-]+\.c', name) and '..' not in Path(name).parts,
                'unsupported title source path')
        obj = 'obj/' + name.replace('/', '_') + '.o'
        sources[name] = {'source': record(root / name), 'object_path': obj, 'object': record(build / obj),
                         'argv': [*compiler, '-std=c11', *common, '-c', str(root / name), '-o', str(build / obj)]}
    return {'schema': 'pw-windows-child-title-compile/1', 'project': project,
            'compiler_argv': compiler, 'compiler_wrapper': record(Path(compiler[3])), 'common_flags': common, 'sources': sources,
            'native_source_inputs': {name: record(root / name) for name in TITLE_USER_SOURCES}}


def verify_title_compile_record(root, build, project, enabled, sdk, title, network_enabled=False, child_ui_enabled=False, *, ipc_enabled=False):
    require(type(ipc_enabled) is bool and type(child_ui_enabled) is bool and
            not (ipc_enabled and child_ui_enabled),
            'child preview and IPC admission require separate matched cohorts')
    path = build / 'wine-child-title-compile.json'
    actual = json.loads(path.read_text())
    require(actual.get('schema') == 'pw-windows-child-title-compile/1' and actual.get('project') == project,
            'title compile project/schema differs')
    compiler, common = actual.get('compiler_argv'), actual.get('common_flags')
    require(isinstance(compiler, list) and all(isinstance(v, str) for v in compiler) and
            isinstance(common, list) and all(isinstance(v, str) for v in common), 'malformed title compiler argv')
    require(len(compiler) == 4 and compiler[:1] == ['env'] and compiler[2] == 'sh' and
            compiler[1].startswith('PS5_PAYLOAD_SDK=') and Path(compiler[1].split('=', 1)[1]).resolve() == sdk.resolve() and
            Path(compiler[3]).resolve() == (title / 'tooling/prospero-clang18').resolve() and
            sha(Path(compiler[3])) == WRAPPER_SHA, 'title compiler launcher/wrapper differs')
    require(not any(v in ('-D', '-U', '-include', '-imacros', '-undef') or
                    v.startswith(('-UPW_WINE_USER_PROFILE_ENABLED', '-UPW_WINE_NET_PROFILE_ENABLED', '-UPW_WINE_IPC_PROFILE_ENABLED', '-UPW_WINE_CHILD_UI_ENABLED',
                                  '-DPW_WINE_CHILD_UI_COHORT', '-UPW_WINE_CHILD_UI_COHORT')) for v in common), 'ambiguous title preprocessor flags')
    require([v for v in common if v.startswith('-DPW_WINE_USER_PROFILE_ENABLED')] ==
            ['-DPW_WINE_USER_PROFILE_ENABLED=' + str(int(enabled))] and
            [v for v in common if v.startswith('-DPW_WINE_CHILD_FIXTURE_MODE')] == ['-DPW_WINE_CHILD_FIXTURE_MODE=1'],
            'title compile enable flags differ')
    require(type(network_enabled) is bool and
            [v for v in common if v.startswith('-DPW_WINE_NET_PROFILE_ENABLED')] ==
            (['-DPW_WINE_NET_PROFILE_ENABLED=1'] if network_enabled else []),
            'title network compile enable flags differ')
    require(type(child_ui_enabled) is bool, 'child UI title flag must be boolean')
    ui_flags = [v for v in common if v.startswith('-DPW_WINE_CHILD_UI_ENABLED')]
    require(ui_flags == ['-DPW_WINE_CHILD_UI_ENABLED=1'] if child_ui_enabled else
            ui_flags in ([], ['-DPW_WINE_CHILD_UI_ENABLED=0']), 'title child UI enable flag differs')
    require(not any(v.startswith(('-DPW_WINE_NET_CHILD_SHA256', '-UPW_WINE_NET_CHILD_SHA256')) for v in common),
            'network child hash must come only from the validated generated header')
    require(type(ipc_enabled) is bool and
            [v for v in common if v.startswith('-DPW_WINE_IPC_PROFILE_ENABLED')] ==
            (['-DPW_WINE_IPC_PROFILE_ENABLED=1'] if ipc_enabled else []), 'title IPC enable flags differ')
    require(not any(v.startswith(('-DPW_WINE_IPC_CHILD_SHA256', '-UPW_WINE_IPC_CHILD_SHA256')) for v in common),
            'IPC image hash must come only from the validated generated header')
    from build_owned_helper import validate_owned_helper
    admitted = validate_owned_helper(build / 'owned-helper', root, project, sdk)
    require([v for v in common if v.startswith(('-DPW_LAPY_HELPER_SHA256', '-UPW_LAPY_HELPER_SHA256'))] ==
            ['-DPW_LAPY_HELPER_SHA256="' + admitted['elf']['sha256'] + '"'],
            'title helper hash differs from admitted actual ELF')
    units = actual.get('sources', {})
    require(isinstance(units, dict) and all(n in units for n in TITLE_USER_SOURCES if n.endswith('.c')),
            'title compile source cohort incomplete')
    require(actual == title_compile_record(root, build, project, compiler, common, list(units)),
            'title actual source/object/command record differs')
    return {**record(path), 'user_enabled': bool(enabled), 'network_enabled': network_enabled,
            'child_ui': child_ui_contract(child_ui_enabled),
            'network_hash_source': 'validated-generated-header' if network_enabled else None,
            'ipc_enabled': ipc_enabled, 'ipc_hash_source': 'validated-generated-header' if ipc_enabled else None, 'record': actual,
            'source_to_binary_reproducibility_verified': False}


def check_title(args):
    user_fixture = getattr(args, 'user_fixture', None)
    network_fixture = getattr(args, 'network_fixture', None)
    ipc_fixture = getattr(args, 'ipc_fixture', None)
    require(ipc_fixture is None or not getattr(args, 'child_ui', False),
            'child preview and IPC admission require separate matched cohorts')
    inputs = (args.app, args.build, args.service_work, args.sdk, args.runtime, args.fixture)
    out = output_directory(args.out, inputs + tuple(p for p in (user_fixture, network_fixture, ipc_fixture) if p is not None))
    commands = Commands(out / 'inspection')
    manifest, paths = verify_child(args, commands)
    root, sdk, foundation, runtime, bindir, title = paths
    app, build = args.app.resolve(strict=True), args.build.resolve(strict=True)
    title_inputs = json.loads((build / 'wine-child-title-inputs.json').read_text())
    expected_inputs, header, pair, user_pair, network_pair = title_profiles_input_contract(root, args.service_work, args.fixture,
        user_fixture, getattr(args, 'run_id', None), getattr(args, 'run_attempt', None), network_fixture, ipc_fixture)
    fixture_sha = pair['files']['child.exe']['sha256']
    require(title_inputs == expected_inputs and (build / 'wine-child-title-config.h').read_text() == header,
            'title fixture/USER macro/source input record differs')
    compile_inputs = verify_title_compile_record(root, build, manifest['project'], user_pair is not None, sdk, title, network_pair is not None,
                                                checked_child_ui(manifest)['enabled'], ipc_enabled=ipc_fixture is not None)
    # Retain actual bytes before parser/analyzer refusal for independent review.
    for name, original in (('title.linked.elf', build / 'llvm-pie.elf'), ('title.converted.elf', build / 'eboot.elf'),
                            ('title.self', app / 'eboot.bin')):
        shutil.copyfile(original, out / name)
    for name in ('native-wine-child.self', 'native-wine-child-build.json'):
        require((app / name).read_bytes() == (args.service_work / name).read_bytes(), 'packaged child differs: ' + name)
    from build_owned_helper import validate_owned_helper
    require(record(app / 'lapy.elf') == manifest['helper']['elf'] and
            validate_owned_helper(build / 'owned-helper', root, manifest['project'], sdk) == manifest['helper'],
            'packaged/title helper differs from child binding')
    require(record(app / 'sce_module/libc.prx') == manifest['libc_companion'], 'title/child libc companions differ')
    linked, converted = Elf((build / 'llvm-pie.elf').read_bytes()), Elf((build / 'eboot.elf').read_bytes())
    index = index_sdk_providers(sdk, out, bindir, commands)
    for path in sorted((build / 'import-stubs').glob('*.so')):
        item = provider(path, bindir, commands)
        require(item['soname'] not in index, 'duplicate title provider')
        index[item['soname']] = path
    require(all(name in index for name in linked.needed), 'title provider unavailable')
    providers = {name: provider(index[name], bindir, commands) for name in linked.needed}
    require(not any(n.split('.', 1)[0] in {'libkernel_sys', 'libkernel_web', 'libScePosixForWebKit'} for n in linked.needed),
            'title uses forbidden provider')
    graph = inspect_bindings(linked, converted, providers, SERVICE_CALLS)
    recovered = extract_self((app / 'eboot.bin').read_bytes())
    recovered_path = out / 'title.recovered.elf'; recovered_path.write_bytes(recovered)
    reconstruction = verify_reconstruction(build / 'eboot.elf', recovered_path)
    image = Elf(recovered)
    compiled = compiled_identity(image, manifest['project']['commit'])
    helper_identity = compiled_identity(image, helper_digest(manifest))
    fixture_identity = fixture_title_identity(image, title_inputs, pair)
    user_identity = user_title_identity(image, title_inputs, user_pair) if user_pair is not None else None
    network_identity = network_title_identity(image, title_inputs, network_pair) if network_pair is not None else None
    ipc_identity = None
    if ipc_fixture is not None:
        ipc_identity = compiled_identity(image, title_inputs['ipc_child_sha256'])
        for address in ipc_identity['addresses']:
            offset = image.offset(address, 65, 4)
            require(any(p[0] == 1 and p[3] == address for p in image.programs) or
                    (offset > 0 and image.data[offset - 1] == 0), 'IPC hash is not a standalone title literal')
    embedded = embedded_image(image, (app / 'native-wine-child.self').read_bytes())
    route = check_route(linked, image, commands.run(bindir / 'llvm-readelf', '-sW', build / 'llvm-pie.elf'))
    user_route = {**check_route(linked, image, commands.run(bindir / 'llvm-readelf', '-sW', build / 'llvm-pie.elf'), TITLE_USER_FUNCTIONS),
                  'mode': 3, 'enabled': user_pair is not None}
    network_route = {**check_route(linked, image, commands.run(bindir / 'llvm-readelf', '-sW', build / 'llvm-pie.elf'), TITLE_USER_FUNCTIONS),
                     'mode': 4, 'enabled': network_pair is not None}
    sdk_source = source_archive(args.sdk_source_archive)
    for name in linked.needed:
        destination = out / 'providers' / (name + '.elf')
        destination.parent.mkdir(exist_ok=True)
        shutil.copyfile(index[name], destination)
    files = {}
    for path in sorted(app.rglob('*')):
        require(not path.is_symlink(), 'title contains symlink')
        if path.is_file():
            name = path.relative_to(app).as_posix()
            require(name != 'dev.conf', 'private dev.conf must never be packaged')
            files[name] = {**record(path), 'mode': path.stat().st_mode & 0o777}
    require(helper_inputs(args, root, manifest['project'], sdk) == manifest['helper'] and
            validate_owned_helper(build / 'owned-helper', root, manifest['project'], sdk) == manifest['helper'] and
            record(app / 'lapy.elf') == manifest['helper']['elf'], 'helper changed during title inspection')
    require(source_identity(root, commands)[0] == manifest['project'], 'project changed during title inspection')
    require(title_profiles_input_contract(root, args.service_work, args.fixture, user_fixture,
        getattr(args, 'run_id', None), getattr(args, 'run_attempt', None), network_fixture, ipc_fixture) ==
        (expected_inputs, header, pair, user_pair, network_pair), 'original/USER/network fixture changed during title inspection')
    require(verify_title_compile_record(root, build, manifest['project'], user_pair is not None, sdk, title, network_pair is not None,
                                                checked_child_ui(manifest)['enabled'], ipc_enabled=ipc_fixture is not None) == compile_inputs,
            'title compile inputs changed during inspection')
    report = {'schema': 'pw-windows-child-title/2', 'project': manifest['project'],
              'build_id': manifest['project']['commit'], 'compiler': manifest['host_llvm'],
              'sdk_headers': manifest['sdk_headers'], 'sdk_wrappers': manifest['sdk_wrappers'], 'sdk_source': sdk_source,
              'files': files, 'title_compiled_identity': compiled, 'helper': manifest['helper'],
              'helper_compiled_identity': helper_identity, 'embedded_child': embedded,
              'fixture_route': route, 'build_inputs': title_inputs,
              'fixture_child_sha256': fixture_sha, 'fixture_child_identity': fixture_identity,
              'user_enabled': user_pair is not None, 'user_child_sha256': title_inputs.get('user_child_sha256'),
              'user_reference_sha256': title_inputs.get('user_reference_sha256'), 'user_child_identity': user_identity,
              'user_route': user_route, 'network_enabled': network_pair is not None,
              'network_child_sha256': title_inputs.get('network_child_sha256'),
              'network_reference_sha256': title_inputs.get('network_reference_sha256'),
              'network_child_identity': network_identity, 'network_route': network_route,
              'ipc_enabled': ipc_fixture is not None, 'ipc_child_sha256': title_inputs.get('ipc_child_sha256'),
              'ipc_reference': title_inputs.get('ipc_reference'), 'ipc_child_identity': ipc_identity,
              'ipc_route': {**network_route, 'mode': None, 'modes': list(range(16, 24)), 'enabled': ipc_fixture is not None},
              'title_compile_inputs': compile_inputs,
              'title_compile_receipt': record(build / 'wine-child-title-compile.json'),
              'service_manifest_sha256': sha(args.service_work / 'native-wine-child-build.json'),
              'runtime': manifest['runtime'], 'imports': graph, 'reconstruction': reconstruction,
              'console_execution_verified': False, 'scope': 'matched source/build/static import and image identity only'}
    (out / 'native-wine-child-title.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, default=ROOT)
    parser.add_argument('--check-title', action='store_true')
    parser.add_argument('--child-ui', action='store_true', help='opt-in matched v3 child software-frame preview; input disabled')
    for name in ('sdk', 'foundation', 'runtime', 'out', 'llvm-bindir'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('build', 'app', 'service-work', 'sdk-source-archive', 'fixture', 'user-fixture', 'network-fixture', 'ipc-fixture', 'helper-directory'):
        parser.add_argument('--' + name, type=Path)
    parser.add_argument('--run-id')
    parser.add_argument('--run-attempt')
    args = parser.parse_args()
    require(args.ipc_fixture is None or not args.child_ui,
            'child preview and IPC admission require separate matched cohorts')
    if args.check_title:
        require(all((args.build, args.app, args.service_work, args.sdk_source_archive, args.fixture)), 'title check requires title/child/SDK source inputs')
        result = check_title(args)
        print(json.dumps({'build_id': result['build_id'], 'scope': result['scope']}))
    else:
        result = build(args)
        print(json.dumps({'build_id': result['worker']['build_id'], 'worker': result['worker'], 'scope': 'static build only'}))


if __name__ == '__main__':
    main()
