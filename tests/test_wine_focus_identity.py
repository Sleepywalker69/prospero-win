#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Actual static marker readers on inert ELF/SELF fixtures, no target execution."""
import copy
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import wine_focus_neutral as focus
import wine_creation_abi as creation
import build_wine_service_child as child
from test_wine_creation_abi import creation_elf
from test_native_suite import self_fixture


def image(name,c,kind=3):
    exports=(*creation.EXPORTS[name],*focus.markers(c))
    # Reuse the independent ELF fixture writer; only its export names and
    # constant-return bodies are extended. The production reader is untouched.
    with patch.dict(creation.EXPORTS,{name:exports}):data=bytearray(creation_elf(name,kind=kind,protocol=963))
    for i,name in enumerate(exports):
        if name in focus.markers(c):data[0x400+i*32:0x406+i*32]=b'\xb8'+struct.pack('<I',focus.markers(c)[name])+b'\xc3'
    return bytes(data)


def runtime(root,c):
    report={'creation':{**creation.DECLARATION,'protocol':963},'focus_neutral':c,'targets':{},'prx':{'modules':{}}}
    (root/'focus-neutral.json').write_text(json.dumps(c,indent=2,sort_keys=True)+'\n')
    h=root/'source/include/wine/pw_focus_build.h';h.parent.mkdir(parents=True);h.write_text(focus.header(c))
    for name in creation.EXPORTS:
        native='dlls/ntdll/ntdll.so' if name=='ntdll' else 'server/wineserver'
        images={'build/'+native:image(name,c),'prx/'+name+'.shared.elf':image(name,c),
                'prx/'+name+'.elf':image(name,c,0xfe18)}
        images['prx/sce_module/'+name+'.prx']=self_fixture(images['prx/'+name+'.elf'])
        for path,data in images.items():
            p=root/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
        report['targets'][native]=creation.record(images['build/'+native]);report['prx']['modules'][name]=creation.record(images['prx/sce_module/'+name+'.prx'])
    return report


class Identity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.c=focus.contract(ROOT)
    def test_all_actual_markers_admitted(self):
        for name in creation.EXPORTS:
            got=creation.module_identity(self_fixture(image(name,self.c,0xfe18)),name,protocol=963,focus=self.c)
            self.assertTrue(set(focus.markers(self.c))<=set(got['exports']))
    def test_each_actual_word_and_mode_corruption_refused(self):
        for name in creation.EXPORTS:
            exports=(*creation.EXPORTS[name],*focus.markers(self.c))
            for i,marker in enumerate(exports):
                if marker not in focus.markers(self.c):continue
                data=bytearray(image(name,self.c,0xfe18));data[0x401+i*32]^=1
                with self.assertRaises(ValueError):creation.module_identity(self_fixture(bytes(data)),name,protocol=963,focus=self.c)
    def test_old_new_both_directions_refused(self):
        for name in creation.EXPORTS:
            with self.assertRaises(ValueError):creation.module_identity(self_fixture(image(name,self.c,0xfe18)),name)
            with self.assertRaises(ValueError):creation.module_identity(self_fixture(creation_elf(name,kind=0xfe18)),name,protocol=963,focus=self.c)
    def test_runtime_replays_actual_shared_converted_self(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);report=runtime(root,self.c);got=creation.check_runtime(root,report,focus=self.c)
            self.assertEqual(got['focus_neutral'],self.c)
            with self.assertRaises(ValueError):creation.check_runtime(root,report)
            with self.assertRaises(ValueError):creation.check_package(got,report,lambda name:(root/'prx/sce_module'/f'{name}.prx').read_bytes())
            (root/'source/include/wine/pw_focus_build.h').write_text(focus.header(self.c).replace('MODE 1','MODE 2'))
            with self.assertRaises(ValueError):creation.check_runtime(root,report,focus=self.c)
    def test_worker_header_and_identity_binding(self):
        from test_wine_service_child_build import build
        bound={'runtime':{'creation_abi':1,'creation_protocol':963,'private_dispatch_abi':1,'private_dispatch_wow64_abi':1,'ntdll_sha256':'a'*64},
               'project':{'commit':'a'*40,'tree':'b'*40},'child_ui':child.child_ui_contract(False),'focus_neutral':self.c}
        bound['helper']={'elf':{'sha256':'b'*64},'project':bound['project'],'toolchain_reverified':True,'runtime_validated':False}
        head=child.child_header(bound,child.identity(bound));self.assertIn('CREATION_PROTOCOL 963',head);self.assertIn('FOCUS_NEUTRAL 1',head)
        self.assertEqual(child.focus_flags(bound),['-DPW_WINE_FOCUS_NEUTRAL=1'])
        old=copy.deepcopy(bound);old.pop('focus_neutral');old['runtime']['creation_protocol']=962
        self.assertNotEqual(child.identity(bound),child.identity(old));self.assertNotIn('FOCUS_NEUTRAL',child.child_header(old,child.identity(old)))
        for mismatch in (dict(bound,runtime=old['runtime']),dict(old,runtime=bound['runtime'])):
            with self.assertRaises(ValueError):child.child_header(mismatch,child.identity(mismatch))
    def test_source_digest_does_not_accept_changed_inputs(self):
        modified=copy.deepcopy(self.c);key=next(iter(modified['sources']));modified['sources'][key]='0'*64
        with self.assertRaises(ValueError):focus.checked(modified)
    def test_optional_source_pair_never_hides_configured_errors(self):
        from test_wine_focus_source import source_inputs
        self.assertFalse(source_inputs(None,None))
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);wine=root/'wine';config=root/'config.h';config.write_text('/* inert */\n')
            for args in (['--wine-source',str(wine)],['--host-config',str(config)],
                         ['--wine-source',str(wine),'--host-config',str(config)],
                         ['--wine-source',str(wine),'--host-config',str(root/'missing')]):
                out=root/'must-not-be-created'
                result=subprocess.run([sys.executable,ROOT/'tests/test_wine_focus_source.py','--out',out,*args],capture_output=True,text=True,timeout=30)
                self.assertEqual(result.returncode,2,result.stdout+result.stderr)
                self.assertFalse(out.exists())
            for name in ('server/main.c','include/wine/server_protocol.h','dlls/ntdll/unix/server.c'):
                path=wine/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('/* inert */\n')
            self.assertTrue(source_inputs(wine,config))

    def test_header_registry_and_source_binding_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            source = Path(d)
            include = source/'include'
            (include/'wine').mkdir(parents=True)
            registry = include/'Makefile.in'
            good = 'SOURCES = \\\n' + ''.join('\t' + name + ' \\\n' for name in focus.HEADERS) + '\twinbase.h\n'
            registry.write_text(good)
            for name in focus.HEADERS:
                (include/name).write_text(focus.header(self.c) if name.endswith('pw_focus_build.h') else '/* inert header */\n')
            focus.verify_headers(source, self.c)
            for name in focus.HEADERS:
                row = '\t' + name + ' \\\n'
                for altered in (good.replace(row, ''), good.replace(row, row + row),
                                good.replace(row, row.replace('.h', '.h.in')),
                                good.replace(row, '').replace('winbase.h\n', 'winbase.h\n' + row)):
                    registry.write_text(altered)
                    with self.assertRaisesRegex(ValueError, 'registration'):
                        focus.verify_headers(source, self.c)
                registry.write_text(good)
                path = include/name
                original = path.read_text()
                path.unlink()
                with self.assertRaisesRegex(ValueError, 'missing or linked'):
                    focus.verify_headers(source, self.c)
                path.symlink_to(registry)
                with self.assertRaisesRegex(ValueError, 'missing or linked'):
                    focus.verify_headers(source, self.c)
                path.unlink()
                path.write_text(original)
            registry.write_text(good + ' SOURCES = winbase.h\n')
            with self.assertRaisesRegex(ValueError, 'assignment'):
                focus.verify_headers(source, self.c)
            registry.write_text(good.replace('SOURCES =', 'SOURCES +='))
            with self.assertRaisesRegex(ValueError, 'assignment'):
                focus.verify_headers(source, self.c)
            registry.write_text(good)
            (include/'wine/pw_focus_build.h').write_text(focus.header(self.c).replace('MODE 1', 'MODE 2'))
            with self.assertRaisesRegex(ValueError, 'generated focus header'):
                focus.verify_headers(source, self.c)

    def test_header_repair_keeps_accepted_patch_inventory_and_stage_order(self):
        self.assertEqual(focus.OPTIONAL, ('0001-server-adapter.patch', '0002-server-requests.patch',
                                         '0003-neutral-cohort.patch', '0004-tracked-mouse-button.patch'))
        self.assertEqual(focus.ACCEPTED, ('5b4f6fb8d06b5878669ad2ac7ad784ac1e9b37b2596f9e21b51f24325a51cde6',
            '8d3924c4539a064f311d3638e34de3f773d2f5e64a69b8d5ba86beeb2e2f7894'))
        focus.contract(ROOT)  # production fixed-hash and exact inventory checks
        patch3 = (ROOT/'wine/focus-neutral/0003-neutral-cohort.patch').read_text()
        registry = patch3.split('diff --git a/include/Makefile.in', 1)[1].split('diff --git ', 1)[0]
        additions = [line[1:] for line in registry.splitlines() if line.startswith('+') and not line.startswith('+++')]
        self.assertEqual(additions, ['\t' + name + ' \\' for name in focus.HEADERS])
        build = (ROOT/'tools/build_wine_ps5.sh').read_text()
        self.assertLess(build.index('python3 "$root/tools/wine_focus_neutral.py"'),
                        build.index('(cd "$build" && "$tree/configure"'))

    def test_makedep_dependency_parser_and_required_ci_path(self):
        import check_focus_makedep as makedep
        generated = ('dlls/ntdll/unix/server.o: /source/include/wine/pw_focus_build.h \\\n'
                     ' /source/include/wine/pw_focus_protocol.h\n'
                     'dlls/ntdll/unix/server.o: /source/include/wine/pw_focus_cohort.h\n')
        self.assertEqual(makedep.dependencies(generated, 'dlls/ntdll/unix/server.o'),
                         {'/source/include/' + name for name in focus.HEADERS})
        with self.assertRaisesRegex(AssertionError, 'missing generated object rule'):
            makedep.dependencies(generated, 'server/pw_focus_requests.o')
        flow = (ROOT/'.github/workflows/ci.yml').read_text()
        self.assertIn('python3 tools/check_focus_makedep.py --wine-source "$PROSPERO_WINE_SOURCE"', flow)
        self.assertIn('--work "$RUNNER_TEMP/focus-makedep" --out "$RUNNER_TEMP/wine-evidence/focus-makedep"', flow)

    def test_makedep_source_header_rules_allow_only_empty_fallbacks(self):
        import check_focus_makedep as makedep
        header = 'pw_focus_build.h'
        for text in ('object.o: /src/include/wine/pw_focus_build.h\n\tcc -c source.c\n',
                     '/src/a.h \\\n /src/include/wine/pw_focus_build.h /src/z.h:\n\nnext:\n\ttrue\n',
                     '/src/include/wine/pw_focus_build.h:\n# empty fallback\n'):
            makedep.verify_source_header_rules(text, header)
        for text in ('/src/include/wine/pw_focus_build.h: input.in\n',
                     '/src/a.h /src/include/wine/pw_focus_build.h: ; generate\n',
                     '/src/include/wine/pw_focus_build.h:\n\tgenerate\n',
                     '/src/a.h \\\n /src/include/wine/pw_focus_build.h:\n\n# comment\n\tgenerate\n'):
            with self.assertRaisesRegex(AssertionError, 'generator'):
                makedep.verify_source_header_rules(text, header)

if __name__=='__main__':unittest.main()
