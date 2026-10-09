#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Original malformed-image, binding, assembly and workflow controls."""
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import types
import unittest
from unittest.mock import patch
import yaml

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import graphics_overlay_files as files
import inspect_graphics_pe as pe
import package_graphics_overlay as package


def image_bytes(forward=None, data_export=False, delayed=False):
    data = bytearray(0x1400); data[:2] = b'MZ'; struct.pack_into('<I', data, 60, 0x80)
    data[0x80:0x84] = b'PE\0\0'; struct.pack_into('<HH', data, 0x84, 0x8664, 2)
    struct.pack_into('<HH', data, 0x94, 240, 0x2002); op = 0x98
    struct.pack_into('<H', data, op, 0x20b); struct.pack_into('<I', data, op + 16, 0x3000)
    struct.pack_into('<I', data, op + 60, 0x200); struct.pack_into('<I', data, op + 108, 16)
    struct.pack_into('<II', data, op + 112, 0x1000, 0x300)
    struct.pack_into('<II', data, op + 120, 0x1400, 40)
    section = op + 240
    data[section:section+8] = b'.rdata\0\0'; struct.pack_into('<IIII', data, section+8, 0x1000,0x1000,0x1000,0x200)
    struct.pack_into('<I',data,section+36,0x40000040)
    data[section+40:section+48] = b'.text\0\0\0'; struct.pack_into('<IIII',data,section+48,0x200,0x3000,0x200,0x1200)
    struct.pack_into('<I',data,section+76,0x60000020);data[0x1200]=0xc3
    struct.pack_into('<IIHHIIIIIII',data,0x200,0,0,0,0,0x1130,1,1,1,0x1100,0x1110,0x1118)
    struct.pack_into('<I',data,0x300,0x1200 if forward else 0x1300 if data_export else 0x3000)
    struct.pack_into('<I',data,0x310,0x1120);struct.pack_into('<H',data,0x318,0)
    data[0x320:0x326]=b'entry\0';data[0x330:0x33c]=b'fixture.dll\0'
    if forward:data[0x400:0x400+len(forward)+1]=forward.encode()+b'\0'
    struct.pack_into('<IIIII',data,0x600,0x1490,0,0,0x1480,0x1490)
    data[0x680:0x68d]=b'provider.dll\0';struct.pack_into('<Q',data,0x690,0x14c0)
    data[0x6c2:0x6c8]=b'entry\0'
    if delayed:
        struct.pack_into('<II',data,op+112+13*8,0x1500,64)
        struct.pack_into('<8I',data,0x700,1,0x1480,0,0x1490,0x1490,0,0,0)
    return data


def api_image():
    raw=bytearray(512)
    struct.pack_into('<7I',raw,0,6,len(raw),0,1,28,0,0)
    name='api-test-l1-1-0'.encode('utf-16-le');host='provider.dll'.encode('utf-16-le')
    struct.pack_into('<6I',raw,28,0,100,len(name),len(name),52,1)
    struct.pack_into('<5I',raw,52,0,0,0,200,len(host));raw[100:100+len(name)]=name;raw[200:200+len(host)]=host
    return types.SimpleNamespace(sections=[(b'.apiset',0,512,0,512,0)],read=lambda offset,size:bytes(raw[offset:offset+size])),raw


def base_fixture(root):
    root.mkdir();(root/'data.txt').write_text('fixed accepted source')
    value={'schema':'pw-diagnostic-kit/1','scope':'software-gdi-kit',
           'project':{'repository':'https://github.com/Sleepywalker69/prospero-win','commit':files.BASE_COMMIT,'tree':files.BASE_TREE},
           'wine_commit':files.WINE,'prefix_included':False}
    (root/'KIT-MANIFEST.json').write_text(json.dumps(value));records=files.inventory(root)
    (root/'FILES.json').write_text(json.dumps(records));(root/'SHA256SUMS').write_text('fixture')
    return files.sha(root/'FILES.json')


def overlay_fixture(root):
    root.mkdir()
    for name in files.PAYLOAD:
        path=root/'overlay'/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(name)
        path.chmod(0o755 if name==files.DRIVER_DEST else 0o644)
    value={'schema':'pw-graphics-overlay/1','scope':'x64-d3d11-diagnostic','base_tree':files.BASE_TREE,
           'driver_tree':files.DRIVER_TREE,'dxvk_commit':files.DXVK,'runtime_verified':False,'prefix_included':False,
           'topology':files.topology(root),'files':files.inventory(root)}
    (root/'GRAPHICS-MANIFEST.json').write_text(json.dumps(value))
    (root/'GRAPHICS-SHA256SUMS').write_text(''.join(f'{files.sha(path)}  {path.relative_to(root)}\n' for path in sorted(root.rglob('*')) if path.is_file()))
    return files.sha(root/'GRAPHICS-MANIFEST.json'),files.sha(root/'overlay'/files.DRIVER_DEST)


class GraphicsTests(unittest.TestCase):
    def test_real_pe_fields_imports_ordinals_and_function_exports(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'fixture.dll';path.write_bytes(image_bytes(delayed=True));value=pe.Image(path)
            self.assertTrue(value.exports['entry']['executable']);self.assertEqual(value.exports[1],value.exports['entry'])
            self.assertEqual(value.imports,[('provider.dll','entry','normal'),('provider.dll','entry','delay')])
            path.write_bytes(image_bytes(forward='other.#7'));self.assertEqual(pe.Image(path).exports['entry'],{'forward':'other.#7'})
            path.write_bytes(image_bytes(data_export=True));self.assertFalse(pe.Image(path).exports['entry']['executable'])

    def test_malformed_pe_is_rejected_instead_of_silently_losing_imports(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'bad.dll'
            edits=[(0x84,'<H',0x14c),(0x98,'<H',0x10b),(0x690,'<Q',0xffffffff),
                   (0x610,'<I',0xffffffff),(0x310,'<I',0xffffffff),(0x318,'<H',2),(0x700,'<I',0)]
            for offset,fmt,value in edits:
                data=image_bytes(delayed=True);struct.pack_into(fmt,data,offset,value);path.write_bytes(data)
                with self.subTest(offset=offset),self.assertRaises(ValueError):pe.Image(path)
            path.write_bytes(image_bytes()[:0x1200])
            with self.assertRaises(ValueError):pe.Image(path)

    def test_actual_api_set_namespace_bounds_and_duplicate_hosts(self):
        value,raw=api_image();self.assertEqual(pe.api_sets(value),{'api-test-l1-1-0.dll':{'':'provider.dll'}})
        for offset,bad in [(0,5),(4,28),(16,500),(28+20,65),(52+12,510)]:
            value,raw=api_image();struct.pack_into('<I',raw,offset,bad)
            with self.subTest(offset=offset),self.assertRaises(ValueError):pe.api_sets(value)

    def test_import_graph_resolves_forwarders_and_rejects_missing_or_cyclic_symbols(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);base=root/'base';app=root/'app';base.mkdir();app.mkdir()
            names=('apisetschema.dll','provider.dll','target.dll','winevulkan.dll','vulkan-1.dll')
            objects={}
            for name in (*names,'d3d11.dll','smoke.exe'):
                folder=base if name in names else app;path=folder/name;path.write_bytes(b'owned fixture')
                objects[name]=types.SimpleNamespace(path=path,sha256=files.sha(path),imports=[],exports={})
            code={'rva':0x1000,'executable':True}
            objects['d3d11.dll'].exports={'entry':code};objects['d3d11.dll'].imports=[('api-test.dll','call','normal')]
            objects['provider.dll'].exports={'call':{'forward':'target.#7'}};objects['target.dll'].exports={7:code}
            for name in ('winevulkan.dll','vulkan-1.dll'):objects[name].exports={'vkGetInstanceProcAddr':code}
            with patch.object(pe,'Image',lambda path:objects[Path(path).name]),patch.object(pe,'api_sets',return_value={'api-test.dll':{'':'provider.dll'}}):
                result=pe.verify_graph(base,app,{'d3d11.dll':{'entry'}})
                self.assertTrue(any(e['resolved_symbol']==7 for e in result['edges']))
                objects['target.dll'].exports={}
                with self.assertRaisesRegex(ValueError,'missing PE export'):pe.verify_graph(base,app,{'d3d11.dll':{'entry'}})
                objects['target.dll'].exports={7:{'forward':'provider.call'}}
                with self.assertRaisesRegex(ValueError,'cyclic'):pe.verify_graph(base,app,{'d3d11.dll':{'entry'}})
                objects['target.dll'].exports={7:code};objects['d3d11.dll'].exports={'entry':{'rva':1,'executable':False}}
                with self.assertRaisesRegex(ValueError,'real function'):pe.verify_graph(base,app,{'d3d11.dll':{'entry'}})

    def test_unmapped_import_hint_is_rejected_for_normal_and_delay_tables(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'hint.dll'
            for delayed in (False,True):
                data=image_bytes(delayed=delayed)
                if delayed:struct.pack_into('<II',data,0x98+120,0,0)
                struct.pack_into('<Q',data,0x690,0x2fff);data[0x1201:0x1207]=b'entry\0';path.write_bytes(data)
                with self.subTest(delayed=delayed),self.assertRaisesRegex(ValueError,'unmapped'):
                    pe.Image(path)

    def test_actual_smoke_surface_mapping_and_absolute_watchdog_contract(self):
        source = r"""
#include <assert.h>
#include <stdint.h>
#include "d3d11_smoke_contract.h"
int main(void) {
    size_t offset=0; uint64_t last=1000; uint32_t remaining=0;
    assert(pw_d3d11_surface_valid(1920,1080,28,28,1,0,1,1));
    assert(!pw_d3d11_surface_valid(1,1,28,28,1,0,1,1));
    assert(!pw_d3d11_surface_valid(1920,1080,87,28,1,0,1,1));
    assert(!pw_d3d11_surface_valid(1920,1080,28,28,2,0,1,1));
    assert(!pw_d3d11_surface_valid(1920,1080,28,28,1,1,1,1));
    assert(!pw_d3d11_surface_valid(1920,1080,28,28,1,0,2,1));
    assert(!pw_d3d11_surface_valid(1920,1080,28,28,1,0,1,2));
    assert(pw_d3d11_center_offset(1,7680,1920,1080,&offset));
    assert(offset == 540u*7680u + 960u*4u);
    assert(!pw_d3d11_center_offset(0,7680,1920,1080,&offset));
    assert(!pw_d3d11_center_offset(1,7679,1920,1080,&offset));
    assert(!pw_d3d11_center_offset(UINTPTR_MAX,7680,1920,1080,&offset));
    assert(!pw_d3d11_center_offset(1,7680,1920,1080,0));
    assert(!pw_d3d11_remaining(1000,&last,2000,&remaining) && remaining==24000);
    assert(pw_d3d11_remaining(1000,&last,1500,&remaining)==PW_D3D11_CLOCK_ERROR);
    assert(last==2000);
    assert(pw_d3d11_remaining(1000,&last,26000,&remaining)==PW_D3D11_DEADLINE);
    last=1000; assert(!pw_d3d11_remaining(1000,&last,25999,&remaining) && remaining==1);
    assert(pw_d3d11_remaining(1000,&last,26000,&remaining)==PW_D3D11_DEADLINE);
    assert(!pw_d3d11_completed(1,0,1));
    assert(pw_d3d11_completed(1,0,0)==PW_D3D11_WORKER_ERROR);
    assert(pw_d3d11_completed(1,0xc0000005,1)!=0);
    assert(pw_d3d11_completed(0,0,1)==PW_D3D11_HANDLE_ERROR);
    assert(pw_d3d11_finalize(1,0,PW_D3D11_DEADLINE)==1);
    assert(pw_d3d11_finalize(0,0,0)==PW_D3D11_HANDLE_ERROR);
    assert(pw_d3d11_finalize(0,1,PW_D3D11_DEADLINE)==PW_D3D11_DEADLINE);
    return 0;
}
"""
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);file=root/'contract.c';file.write_text(source)
            subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-I',str(ROOT/'tools'),
                            str(file),'-o',str(root/'contract')],check=True)
            subprocess.run([str(root/'contract')],check=True)
        fixture=(ROOT/'tools/d3d11_clear_smoke.c').read_text()
        self.assertLess(fixture.index('UnregisterClassA(wc.lpszClassName'),fixture.index('InterlockedExchange(&completion->finished, 1)'))
        self.assertIn('GetExitCodeThread(worker, &worker_code)',fixture)
        self.assertLess(fixture.index('closed = CloseHandle(worker)'),fixture.rindex('pw_d3d11_remaining('))

    def test_fixed_run_and_artifact_binding(self):
        for kind,fixed in package.INPUTS.items():
            run={'id':fixed['run'],'head_sha':fixed['head'],'run_attempt':1,'status':'completed','conclusion':'success',
                 'path':fixed['workflow'],'repository':{'full_name':package.REPO}}
            item={'id':fixed['artifact'],'digest':'sha256:'+fixed['sha256'],'expired':False,
                  'workflow_run':{'id':fixed['run'],'head_sha':fixed['head'],'repository_id':1410835302,'head_repository_id':1410835302}}
            package.metadata(kind,run,item)
            for key,bad in [('id',1),('digest','sha256:'+'0'*64),('expired',True)]:
                changed=dict(item);changed[key]=bad
                with self.subTest(kind=kind,key=key),self.assertRaises(ValueError):package.metadata(kind,run,changed)
            run['conclusion']='failure'
            with self.assertRaises(ValueError):package.metadata(kind,run,item)

    def test_new_copy_assembly_preserves_base_and_refuses_changed_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);base=root/'base';overlay=root/'overlay';base_sha=base_fixture(base);manifest_sha,driver_sha=overlay_fixture(overlay)
            with patch.object(files,'BASE_TOPOLOGY_SHA',files.topology_sha(base)),patch.object(files,'BASE_FILES_SHA',base_sha),patch.object(files,'BASE_SUMS_SHA',hashlib.sha256(b'fixture').hexdigest()),patch.object(files,'DRIVER_SHA',driver_sha):
                original=(base/'FILES.json').read_bytes();files.assemble(base,overlay,root/'output',manifest_sha)
                self.assertEqual((base/'FILES.json').read_bytes(),original)
                self.assertEqual((root/'output/FILES.json').read_bytes(),original)
                self.assertTrue((root/'output'/files.DRIVER_DEST).is_file())
                self.assertTrue((root/'output/graphics-evidence/GRAPHICS-MANIFEST.json').is_file())
                with self.assertRaises(ValueError):files.assemble(base,overlay,root/'output',manifest_sha)
                with self.assertRaises(ValueError):files.verify_overlay(overlay,'0'*64)
                (base/'data.txt').write_text('changed')
                with self.assertRaises(ValueError):files.verify_base(base)
                path=overlay/'overlay'/files.DRIVER_DEST;path.chmod(0o644)
                with self.assertRaises(ValueError):files.verify_overlay(overlay,manifest_sha)

    def test_directory_symlink_cannot_write_back_into_either_input(self):
        def snapshot(root):
            return {str(path.relative_to(root)):{'mode':path.lstat().st_mode,
                    'link':os.readlink(path) if path.is_symlink() else None,
                    'sha':files.sha(path) if path.is_file() and not path.is_symlink() else None}
                    for path in root.rglob('*')}
        for absolute in (False,True):
            with tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);base=root/'base';overlay=root/'overlay';digest=base_fixture(base)
                ohash,dhash=overlay_fixture(overlay);(base/'empty').mkdir();(base/'pc').mkdir()
                clean_topology=files.topology_sha(base)
                (base/'pc/graphics-smoke').symlink_to(base/'empty' if absolute else '../empty',target_is_directory=True)
                before_base,before_overlay=snapshot(base),snapshot(overlay)
                with patch.object(files,'BASE_TOPOLOGY_SHA',clean_topology),patch.object(files,'BASE_FILES_SHA',digest),\
                     patch.object(files,'BASE_SUMS_SHA',files.sha(base/'SHA256SUMS')),patch.object(files,'DRIVER_SHA',dhash):
                    with self.assertRaises(ValueError):files.assemble(base,overlay,root/'out',ohash)
                    self.assertFalse((root/'out').exists())
                    # Even if a future base identity bound a relative directory
                    # link, parent validation must independently stop writes.
                    if not absolute:
                        with patch.object(files,'BASE_TOPOLOGY_SHA',files.topology_sha(base)),self.assertRaisesRegex(ValueError,'parent is a symlink'):
                            files.assemble(base,overlay,root/'out',ohash)
                self.assertEqual(snapshot(base),before_base);self.assertEqual(snapshot(overlay),before_overlay)
                self.assertFalse((root/'out').exists())

    def test_file_graph_refuses_escape_extra_file_and_json_duplicates(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);base=root/'base';digest=base_fixture(base)
            with patch.object(files,'BASE_TOPOLOGY_SHA',files.topology_sha(base)),patch.object(files,'BASE_FILES_SHA',digest),patch.object(files,'BASE_SUMS_SHA',hashlib.sha256(b'fixture').hexdigest()):
                (base/'extra').write_text('unexpected')
                with self.assertRaises(ValueError):files.verify_base(base)
                (base/'extra').unlink();outside=root/'outside';outside.write_text('outside')
                (base/'escape').symlink_to(outside)
                with self.assertRaisesRegex(ValueError,'relative|escape'):files.verify_base(base)
            bad=root/'bad.json';bad.write_text('{"x":1,"x":2}')
            with self.assertRaisesRegex(ValueError,'duplicate'):files.read_json(bad)

    def test_selected_runtime_notices_and_library_hashes_are_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);sources=root/'sources';sources.mkdir();docs=root/'docs';libraries=root/'libraries';libraries.mkdir();licenses=root/'licenses';licenses.mkdir()
            for name in package.COMMON_LICENSES:(licenses/name).write_text('full licence fixture '+name)
            for name in package.RUNTIME_PACKAGES:
                path=docs/name/'copyright';path.parent.mkdir(parents=True);path.write_text('runtime licence and exception '+name)
            for name in package.RUNTIME_LIBRARIES:(libraries/name).write_bytes(name.encode())
            def command(argv,**kwargs):
                if argv[0]=='dpkg-query':return argv[-1]+'\t1\tsource-package\t1\n'
                self.assertEqual(argv[0],'x86_64-w64-mingw32-g++-posix')
                return str(libraries/argv[1].split('=',1)[1])+'\n'
            with patch.object(package.subprocess,'check_output',command):
                package.collect_runtime_notices(sources,docs,licenses);record=package.verify_runtime_notices(sources,docs,licenses)
                self.assertEqual(len(record['libraries']),8)
                (libraries/'libstdc++.a').write_bytes(b'changed runtime')
                with self.assertRaisesRegex(ValueError,'archive changed'):package.verify_runtime_notices(sources,docs,licenses)
                (libraries/'libstdc++.a').write_bytes(b'libstdc++.a')
                (sources/'compiler-runtime/gcc-mingw-w64-base-copyright').write_text('missing exception')
                with self.assertRaisesRegex(ValueError,'notice changed'):package.verify_runtime_notices(sources,docs,licenses)
                (sources/'compiler-runtime/gcc-mingw-w64-base-copyright').write_text((docs/'gcc-mingw-w64-base/copyright').read_text())
                (sources/'compiler-runtime/GPL-3').write_text('truncated licence')
                with self.assertRaisesRegex(ValueError,'licence text changed'):package.verify_runtime_notices(sources,docs,licenses)

    def test_world_writable_installed_licences_round_trip_as_portable_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);sources=root/'sources';sources.mkdir();docs=root/'docs';libraries=root/'libraries';libraries.mkdir();licenses=root/'licenses';licenses.mkdir()
            for name in package.COMMON_LICENSES:
                path=licenses/name;path.write_text('original full licence '+name);path.chmod(0o777)
            for name in package.RUNTIME_PACKAGES:
                path=docs/name/'copyright';path.parent.mkdir(parents=True);path.write_text('runtime notice '+name)
            for name in package.RUNTIME_LIBRARIES:(libraries/name).write_bytes(name.encode())
            def command(argv,**kwargs):
                if argv[0]=='dpkg-query':return argv[-1]+'\t1\tsource-package\t1\n'
                return str(libraries/argv[1].split('=',1)[1])+'\n'
            with patch.object(package.subprocess,'check_output',command):
                package.collect_runtime_notices(sources,docs,licenses)
                package.verify_runtime_notices(sources,docs,licenses)
                for name in package.COMMON_LICENSES:
                    copied=sources/'compiler-runtime'/name
                    self.assertEqual(copied.read_bytes(),(licenses/name).read_bytes())
                    self.assertEqual(stat.S_IMODE(copied.stat().st_mode),0o644)
                    self.assertEqual(stat.S_IMODE((licenses/name).stat().st_mode),0o777)
                # Exercise the same two packaging destinations and the standard
                # data filter that exposed the real artifact's0777 mismatch.
                artifact=root/'artifact'
                package.copy_owned_tree(sources,artifact/'sources/dxvk')
                package.copy_owned_tree(sources/'compiler-runtime',artifact/'LICENSES/compiler-runtime')
                before=files.inventory(artifact)
                archive=root/'artifact.tar.gz'
                with tarfile.open(archive,'w:gz') as tar:tar.add(artifact,arcname='.')
                restored=root/'restored'
                package.unpack_tar(archive,restored)
                self.assertEqual(files.inventory(restored),before)
                bad=sources/'compiler-runtime/GPL-3';bad.chmod(0o777)
                with self.assertRaisesRegex(ValueError,'mode changed'):
                    package.verify_runtime_notices(sources,docs,licenses)

    def test_recipe_uses_only_local_hash_bound_files_and_prefix_copy_tasks(self):
        with tempfile.TemporaryDirectory() as tmp:
            app=Path(tmp)
            for name in ('d3d11.dll','dxgi.dll','d3d11-clear.exe'):(app/name).write_text(name)
            recipe=yaml.safe_load(package.recipe(app));script=recipe['script']
            self.assertEqual(recipe['prospero']['graphics'],'auto');self.assertFalse(script['wine']['dxvk'])
            self.assertEqual(script['wine']['overrides'],{'d3d11':'n','dxgi':'n'})
            self.assertEqual([next(iter(step)) for step in script['installer']],['task','copy','copy','copy'])
            self.assertEqual(script['installer'][0]['task']['name'],'create_prefix')
            self.assertFalse(script['installer'][0]['task']['install_gecko'])
            self.assertFalse(script['installer'][0]['task']['install_mono'])
            for item in script['files']:
                name,value=next(iter(item.items()));self.assertTrue(value['url'].startswith('file://$SCRIPTDIR/'))
                self.assertEqual(value['sha256'],files.sha(app/name))

    def test_existing_installer_exercises_recipe_with_controlled_prefix_operation(self):
        import pw_install
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);app=root/'pc/graphics-smoke/x64';app.mkdir(parents=True)
            for name in ('d3d11.dll','dxgi.dll','d3d11-clear.exe'):(app/name).write_bytes(image_bytes())
            recipes=root/'pc/recipes';recipes.mkdir();path=recipes/'diagnostic-d3d11.yml';path.write_text(package.recipe(app))
            host=root/'host';host.mkdir();wine=host/'wine';wine.write_text('not executed');(host/'wineserver').write_text('not executed')
            args=types.SimpleNamespace(slug=None,library=str(root/'library'),wine=str(wine),resolution=None,
                                       file=[],input=[],disc=None,mesa_zink=None)
            installer=pw_install.Installer(yaml.safe_load(path.read_text()),path,args)
            calls=[]
            def prefix_operation(command,env,cwd=None,codes=(0,)):
                self.assertEqual(command,[wine,'wineboot','--init']);calls.append(command)
                self.assertIn('mshtml=',env['WINEDLLOVERRIDES']);self.assertIn('mscoree=',env['WINEDLLOVERRIDES'])
                self.assertEqual(env['USER'],'prospero')
                prefix=Path(env['WINEPREFIX']);(prefix/'drive_c/users/prospero').mkdir(parents=True)
                (prefix/'system.reg').write_text('controlled prefix')
            def server_wait(command,**kwargs):
                self.assertEqual(command,[str(host/'wineserver'),'-w']);return types.SimpleNamespace(returncode=0)
            with patch.object(installer,'run',prefix_operation),patch.object(pw_install.subprocess,'run',server_wait),\
                 patch.object(pw_install,'DOWNLOADS',root/'cache'):
                profile=installer.install()
            self.assertEqual(len(calls),1)
            text=profile.read_text();self.assertIn('graphics = auto',text);self.assertIn('dll_overrides = d3d11,dxgi=n',text)
            self.assertIn('architecture = pe64',text)
            for name in ('d3d11.dll','dxgi.dll','d3d11-clear.exe'):
                self.assertEqual((root/'library/prefixes/diagnostic-d3d11/drive_c/graphics-smoke'/name).read_bytes(),(app/name).read_bytes())
            with self.assertRaises(pw_install.InstallError):installer.install()

    def test_read_only_bounded_source_producer_and_unchanged_release_pin(self):
        w=yaml.load((ROOT/'.github/workflows/graphics-overlay.yml').read_text(),Loader=yaml.BaseLoader)
        self.assertEqual(w['permissions'],{'contents':'read','actions':'read'});self.assertNotIn('pull_request_target',w['on'])
        job=w['jobs']['graphics-overlay'];self.assertEqual(job['runs-on'],'ubuntu-24.04');self.assertEqual(job['timeout-minutes'],'60')
        self.assertIn('head.repo.full_name == github.repository',job['if'])
        runs='\n'.join(s.get('run','') for s in job['steps'])
        for needed in ('--wrap-mode=nodownload','-j2 install','tools/d3d11_clear_smoke.c','11588549010','11592264803'):
            self.assertIn(needed,runs)
        for forbidden in ('wineboot','wineexec','build_wine_ps5.sh','--force','continue-on-error'):
            self.assertNotIn(forbidden,runs)
        for step in job['steps']:
            self.assertNotIn('continue-on-error',step)
            if 'uses' in step:self.assertRegex(step['uses'],r'^actions/[a-z-]+@[0-9a-f]{40}$')
        sys.path.insert(0,str(ROOT/'tools'));import pw_install
        self.assertEqual(pw_install.DXVK_RELEASES['2.6.2'][1],'17761876556afd55736cb895d184f5a1c55d43350f1b1e3b129f8d28706d7992')


if __name__ == '__main__':
    unittest.main()
