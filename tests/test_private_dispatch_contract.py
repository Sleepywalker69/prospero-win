#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Independent pure/compile-only ABI controls; no Wine, mapping or allocator runs."""
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('abi_check', ROOT/'tools/check_private_dispatch_abi.py')
abi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(abi)
CLANG = os.environ.get('PW_DISPATCH_CLANG') or shutil.which('clang-18') or shutil.which('clang')
PATCH = ROOT/'wine/patches/0910-ntdll-private-dispatcher-abi-proposal.patch'
WINE_COMMIT = '490f6d5dcbb2a5047345b8af88d114bbcaad69a8'
WINE_FILES = ['include/wine/asm.h', 'dlls/ntdll/unix/unix_private.h',
              'dlls/ntdll/unix/loader.c', 'dlls/ntdll/unix/virtual.c', 'dlls/ntdll/unix/signal_x86_64.c']


def new_side(path):
    section = PATCH.read_text().split('+++ b/'+path+'\n', 1)[1].split('\n--- ', 1)[0]
    return '\n'.join(line[1:] for hunk in ('\n'+section).split('\n@@')[1:]
                     for line in hunk.splitlines()[1:] if line.startswith((' ', '+'))) + '\n'


def source_pair(directory):
    source = os.environ.get('PROSPERO_WINE_SOURCE')
    if not source and (ROOT/'.deps/wine/source').is_dir():
        source = str(ROOT/'.deps/wine/source')
    if not source:
        return None
    source = Path(source).resolve()
    before, after = directory/'before', directory/'after'
    for name in WINE_FILES:
        result = subprocess.run(['git', '-C', str(source), 'show', WINE_COMMIT+':'+name],
                                check=True, capture_output=True)
        path = before/name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(result.stdout)
    includes = ['--include='+name for name in WINE_FILES]
    for patch in sorted((ROOT/'wine/patches').glob('[0-9][0-9][0-9][0-9]-*.patch')):
        if patch.name >= PATCH.name:
            break
        if any('+++ b/'+name+'\n' in patch.read_text() for name in WINE_FILES):
            subprocess.run(['git', 'apply', *includes, str(patch)], cwd=before, check=True, capture_output=True)
    shutil.copytree(before, after)
    subprocess.run(['git', 'apply', *includes, '--include=include/wine/pw_private_dispatch.h', str(PATCH)],
                   cwd=after, check=True, capture_output=True)
    return before, after


def compile_thunk(include, mode, out):
    source = out.with_suffix('.c')
    source.write_text('#include "wine/asm.h"\n__ASM_SYSCALL_FUNC(7,probe_syscall)\n')
    command = [CLANG, '--target=x86_64-w64-windows-gnu', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
               '-D__WINE_PE_BUILD', '-I'+str(include), '-c', str(source), '-o', str(out)]
    if mode is not None:
        command.insert(1, '-DWINE_PS5_PRIVATE_DISPATCH='+str(mode))
    subprocess.run(command, check=True, capture_output=True, text=True)
    data = out.read_bytes()
    machine, count = struct.unpack_from('<HH', data)
    assert machine == 0x8664
    bodies = []
    for i in range(count):
        section = 20 + 40*i
        length, raw = struct.unpack_from('<II', data, section+16)
        body = data[raw:raw+length]
        if body.startswith(abi.PREFIX):
            bodies.append(body)
    assert len(bodies) == 1 and len(bodies[0]) == 32
    return bodies[0]


def without_opt_in(source):
    """Resolve only our opt-in blocks; preserve every unrelated preprocessor line."""
    output = []
    skipping = False
    depth = 0
    for line in source.splitlines():
        if not depth and line == '#if defined(WINE_PS5_PRIVATE_DISPATCH) && WINE_PS5_PRIVATE_DISPATCH':
            depth, skipping = 1, True
        elif depth:
            if line.startswith(('#if ', '#ifdef ', '#ifndef ')):
                depth += 1
            elif line == '#endif':
                depth -= 1
                if not depth:
                    skipping = False
                    continue
            elif depth == 1 and line == '#else':
                skipping = False
                continue
            if not skipping:
                output.append(line)
        else:
            output.append(line)
    if depth:
        raise ValueError('unclosed opt-in block')
    return '\n'.join(line.rstrip() for line in output if line.strip())


class PrivateDispatcherContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        cls.include = cls.directory/'pure/include'
        header = cls.include/'wine/pw_private_dispatch.h'
        header.parent.mkdir(parents=True); header.write_text(new_side('include/wine/pw_private_dispatch.h'))
        cls.pair = source_pair(cls.directory)

    def after_text(self, name):
        return (self.pair[1]/name).read_text() if self.pair else new_side(name)

    def test_actual_thunk_bytes_off_unchanged_and_baseline_fails_private_contract(self):
        if not self.pair or not CLANG:
            self.skipTest("pinned Wine source and Clang are required for actual thunk compilation")
        with tempfile.TemporaryDirectory() as directory:
            d = Path(directory)
            baseline = compile_thunk(self.pair[0]/'include', None, d/'baseline.obj')
            absent = compile_thunk(self.pair[1]/'include', None, d/'absent.obj')
            off = compile_thunk(self.pair[1]/'include', 0, d/'off.obj')
            on = compile_thunk(self.pair[1]/'include', 1, d/'on.obj')
        self.assertEqual(baseline, absent)
        self.assertEqual(baseline, off)
        self.assertTrue(abi.thunk_shape(on))
        self.assertEqual(on[:27], baseline[:27])
        self.assertEqual(on[31:], baseline[31:])
        self.assertEqual(struct.unpack_from('<I', baseline, 27)[0], 0x7ffe1000)
        self.assertNotEqual(struct.unpack_from('<I', baseline, 27)[0], 0x7ffe4000)
        self.assertEqual(struct.unpack_from('<I', on, 27)[0], 0x7ffe4000)
        result = {'scope': 'compiled inert COFF thunk bytes only; no thunk execution',
                  'baseline_private_contract': 'fails: actual operand remains 0x7ffe1000',
                  'off_matches_baseline': True, 'on_only_operand_changed': True,
                  'baseline_body': baseline.hex(), 'on_body': on.hex()}
        self.assertEqual(result['scope'], 'compiled inert COFF thunk bytes only; no thunk execution')

    def test_off_unix_and_platform_sources_keep_existing_statements(self):
        if not self.pair:
            self.skipTest('pinned Wine source is required for full OFF-source comparison')
        for name in ['dlls/ntdll/unix/unix_private.h', 'dlls/ntdll/unix/loader.c',
                     'dlls/ntdll/unix/virtual.c', 'dlls/ntdll/unix/signal_x86_64.c']:
            with self.subTest(name=name):
                self.assertEqual(without_opt_in((self.pair[1]/name).read_text()),
                                 without_opt_in((self.pair[0]/name).read_text()))
        self.assertEqual(hashlib.sha256(without_opt_in((ROOT/'wine/ps5/pw_wine_dmem_ps5.c').read_text()).encode()).hexdigest(),
                         'a5b81d0a02ac5bf1ec522e6ab2bd87d225159af38541d4c3d9745eacd29810b4')

    def test_pure_local_bytes_and_counter_decisions(self):
        # This translation unit includes only the new pure header. It has no
        # Wine/allocator/platform sources, system calls or fixed-address access.
        source = r'''
#include <assert.h>
#include <string.h>
#include "wine/pw_private_dispatch.h"
int main(void) {
    unsigned char code[32] = {0x4c,0x8b,0xd1,0xb8,7,0,0,0,
        0xf6,0x04,0x25,0x08,0x03,0xfe,0x7f,0x01,0x75,0x03,
        0x0f,0x05,0xc3,0xeb,0x01,0xc3,0xff,0x14,0x25,0,0x40,0xfe,0x7f,0xc3};
    unsigned char saved[32];
    unsigned int i;
    assert(pw_private_dispatch_thunk_valid(code, sizeof(code)));
    assert(!pw_private_dispatch_thunk_valid(code, 31));
    memcpy(saved, code, 32);
    code[28] = 0x10; /* real baseline operand */
    assert(!pw_private_dispatch_thunk_valid(code, 32));
    for(i=0;i<32;i++) {
        memcpy(code,saved,32); code[i] ^= 0x80;
        assert(pw_private_dispatch_thunk_valid(code,32) == (i>=4 && i<8));
    }
    assert(pw_private_dispatch_adoption_valid(0,3,3,0,0x4000));
    assert(!pw_private_dispatch_adoption_valid(-1,3,3,0,0x4000));
    assert(!pw_private_dispatch_adoption_valid(0,3,4,0,0x4000));
    assert(!pw_private_dispatch_adoption_valid(0,3,3,0x4000,0x4000));
    assert(!pw_private_dispatch_adoption_valid(0,3,3,0,0));
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            d = Path(directory); (d/'pure.c').write_text(source)
            subprocess.run([shutil.which('cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-I'+str(self.include), str(d/'pure.c'), '-o', str(d/'pure')],
                           check=True, capture_output=True, text=True)
            subprocess.run([str(d/'pure')], check=True, capture_output=True, text=True)

    def test_refusal_scope_and_early_usd_counterexample_remain_explicit(self):
        source = self.after_text('dlls/ntdll/unix/virtual.c')
        self.assertIn('MEM_RESERVE | MEM_COMMIT, PAGE_READONLY', source)
        self.assertIn('pe_mapping->image.machine != IMAGE_FILE_MACHINE_AMD64', source)
        self.assertIn('pe_mapping->image.is_hybrid', source)
        self.assertIn('pw_private_dispatch_validate_module( view->base', source)
        self.assertIn('checked USD mapping failed before guest entry', source)
        self.assertIn('_exit(1)', source)
        patch = (ROOT/'wine/patches/0910-ntdll-private-dispatcher-abi-proposal.patch').read_text()
        self.assertNotIn('--- a/dlls/ntdll/unix/process.c', patch)
        self.assertTrue(abi.general_release_admissible({'wine_commit': 'legacy'}))
        for report in [None, [], {'private_dispatcher': {'abi': 1}},
                       {'private_dispatcher': {'abi': 2}}, {'private_dispatcher': None}]:
            self.assertFalse(abi.general_release_admissible(report))

    def test_pure_mapped_image_bounds_and_anchor_ambiguity(self):
        source = r'''
#include <assert.h>
#include <string.h>
#include "wine/pw_private_dispatch.h"
static unsigned char original[4096], image[4096];
static void u16(unsigned int p,unsigned int v) { image[p]=(unsigned char)v; image[p+1]=(unsigned char)(v>>8); }
static void u32(unsigned int p,unsigned int v) { u16(p,v); u16(p+2,v>>16); }
static int valid(void) { return pw_private_dispatch_image_valid(image,sizeof(image),"NtClose"); }
static void reset(void) { memcpy(image,original,sizeof(image)); }
int main(void) {
    const unsigned char thunk[32]={0x4c,0x8b,0xd1,0xb8,7,0,0,0,
        0xf6,0x04,0x25,0x08,0x03,0xfe,0x7f,0x01,0x75,0x03,
        0x0f,0x05,0xc3,0xeb,0x01,0xc3,0xff,0x14,0x25,0,0x40,0xfe,0x7f,0xc3};
    image[0]='M';image[1]='Z';u32(60,0x80);u32(0x80,0x4550);
    u16(0x84,0x8664);u16(0x86,1);u16(0x94,0xf0);u16(0x98,0x20b);
    u32(0x98+56,4096);u32(0x98+60,0x200);u32(0x98+108,1);
    u32(0x98+112,0x800);u32(0x98+116,0x80);
    u32(0x188+8,0xc00);u32(0x188+12,0x400);u32(0x188+36,0x60000020);
    u32(0x800+20,1);u32(0x800+24,1);u32(0x800+28,0x900);
    u32(0x800+32,0x920);u32(0x800+36,0x940);
    u32(0x900,0x400);u32(0x920,0x960);memcpy(image+0x960,"NtClose",8);
    memcpy(image+0x400,thunk,32);memcpy(original,image,sizeof(image));assert(valid());
    assert(!pw_private_dispatch_image_valid(image,63,"NtClose"));
    u32(60,0xffffffff);assert(!valid());reset();
    u32(0x98+112,0xffffffff);assert(!valid());reset();
    u32(0x800+28,0xffffffff);assert(!valid());reset();
    u32(0x800+32,0xffffffff);assert(!valid());reset();
    u32(0x800+36,0xffffffff);assert(!valid());reset();
    u32(0x920,0xffffffff);assert(!valid());reset();
    u32(0x920,0x200);assert(!valid());reset(); /* unreadable section gap */
    u16(0x940,1);assert(!valid());reset();
    u32(0x900,0x810);assert(!valid());reset(); /* forwarded anchor */
    u32(0x800+24,2);u32(0x924,0x960);u16(0x942,0);assert(!valid());reset();
    image[0x400+28]=0x10;assert(!valid());reset();
    memset(image+0x960,'A',512);assert(!valid());reset();
    u32(0x188+36,0x20000020);assert(!valid());reset(); /* execute-only */
    u16(0x86,2);u32(0x1b0+8,0x100);u32(0x1b0+12,0x700);assert(!valid());reset();
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            d = Path(directory); (d/'mapped_bytes.c').write_text(source)
            subprocess.run([shutil.which('cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-I'+str(self.include), str(d/'mapped_bytes.c'), '-o', str(d/'mapped_bytes')],
                           check=True, capture_output=True, text=True)
            subprocess.run([str(d/'mapped_bytes')], check=True, capture_output=True, text=True)

    def test_new_loader_helper_compiles_without_running_wine(self):
        # Exact emitted helper source, with declarations for its existing Wine
        # dependencies. Syntax-only: no mapping code is linked or executed.
        prologue = r'''
#include <stddef.h>
#include <stdint.h>
#include "wine/pw_private_dispatch.h"
typedef uint16_t WCHAR;
typedef uintptr_t ULONG_PTR;
typedef size_t SIZE_T;
typedef int NTSTATUS;
typedef struct { unsigned short Length, MaximumLength; WCHAR *Buffer; } UNICODE_STRING;
typedef struct image_export_directory IMAGE_EXPORT_DIRECTORY;
#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
#define IMAGE_DIRECTORY_ENTRY_EXPORT 0
#define STATUS_SUCCESS 0
#define STATUS_INVALID_IMAGE_FORMAT (-1)
extern int wcsnicmp(const WCHAR *, const WCHAR *, size_t);
extern const IMAGE_EXPORT_DIRECTORY *get_module_data_dir(void *, unsigned int, void *);
extern ULONG_PTR find_named_export(void *, const IMAGE_EXPORT_DIRECTORY *, const char *);
extern const char *debugstr_us(const UNICODE_STRING *);
extern void diagnostic(const char *, ...);
#define ERR(...) diagnostic(__VA_ARGS__)
'''
        source = self.after_text('dlls/ntdll/unix/loader.c')
        start = source.index('static const char *private_dispatch_anchor(')
        source = source[start:source.index('\n#endif', start)]
        # Recreate the retained escaping defect as a syntax-only negative.
        before = source.replace(r"== '\\'", r"== '\'")
        self.assertNotEqual(before, source)
        with tempfile.TemporaryDirectory() as directory:
            d = Path(directory)
            for label, body, expected in [('before', before, False), ('after', source, True)]:
                path = d/(label+'.c'); path.write_text(prologue+body)
                result = subprocess.run([shutil.which('cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-I'+str(self.include), '-fsyntax-only', str(path)], capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, expected, result.stderr)

    def test_build_selector_owns_macro_without_running_builder(self):
        build = (ROOT/'tools/build_wine_ps5.sh').read_text()
        start = build.index('# Private dispatcher ABI is a separate experimental runtime build')
        stop = build.index('opengl_cflags=${CFLAGS:--g -O2}', start)
        fragment = 'fail() { exit 23; };\n' + build[start:stop] + '\nprintf "%s" "$private_dispatch"\n'
        for values, code, output in [({}, 0, '0'), ({'PW_WINE_PRIVATE_DISPATCH': '1'}, 0, '1'),
                                     ({'PW_WINE_PRIVATE_DISPATCH': '2'}, 23, '')]:
            env = {key: value for key, value in os.environ.items()
                   if key not in ('CFLAGS','CPPFLAGS','CROSSCFLAGS','x86_64_CFLAGS','i386_CFLAGS','PW_WINE_PRIVATE_DISPATCH')}
            env.update(values)
            result = subprocess.run(['sh', '-c', fragment], env=env, capture_output=True, text=True)
            self.assertEqual((result.returncode, result.stdout), (code, output))
            for flag in ('CFLAGS','CPPFLAGS','CROSSCFLAGS','x86_64_CFLAGS','i386_CFLAGS'):
                altered = dict(env, **{flag: '-DWINE_PS5_PRIVATE_DISPATCH=1'})
                result = subprocess.run(['sh', '-c', fragment], env=altered, capture_output=True, text=True)
                self.assertEqual(result.returncode, 23)


if __name__ == '__main__':
    unittest.main()
