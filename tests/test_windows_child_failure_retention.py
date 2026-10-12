#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Original filesystem-only evidence-retention controls."""
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import retain_windows_child_failure as retention

class FailureRetention(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)

    def test_actual_mode_bytes_and_fresh_output(self):
        source=self.root/'source';source.mkdir();path=source/'worker.elf';path.write_bytes(b'original target bytes');path.chmod(0o755)
        c=retention.Collector(self.root/'out');c.copy(path,source,'target')
        result=c.finish({});record=result['files']['target/worker.elf']
        self.assertEqual(record['original_mode'],0o755);self.assertEqual(record['retained_mode'],0o644)
        self.assertEqual((self.root/'out/target/worker.elf').read_bytes(),path.read_bytes());self.assertFalse(result['accepted'])
        with self.assertRaises(ValueError):retention.Collector(self.root/'out')

    def test_dnsapi_objects_precede_large_evidence_and_keep_exact_bytes(self):
        names=('repo','title_foundation','foundation','wine_work','tls_work','title_build')
        args=argparse.Namespace(**{name:self.root/name for name in names},wine_archive=self.root/'wine.tar.gz',
                                sdk_source_archive=self.root/'sdk.tar.gz',out=self.root/'retained')
        for name in names:getattr(args,name).mkdir()
        expected={}
        for arch in ('i386','x86_64'):
            for unit in ('main','query'):
                name='build/dlls/dnsapi/'+arch+'-windows/'+unit+'.o'
                path=args.wine_work/name;path.parent.mkdir(parents=True,exist_ok=True)
                path.write_bytes((arch+unit).encode());expected['target/wine/'+name]=path.read_bytes()
        args.wine_archive.write_bytes(b'x'*512)
        with mock.patch.object(retention,'MAX_TOTAL',sum(map(len,expected.values()))):
            result=retention.collect(args)
        self.assertEqual(set(result['files']),set(expected))
        for name,value in expected.items():self.assertEqual((args.out/name).read_bytes(),value)
        self.assertTrue(result['omissions']);self.assertFalse(result['accepted'])

    def test_links_and_path_escape_refused(self):
        source=self.root/'source';source.mkdir();other=self.root/'private';other.write_bytes(b'private')
        (source/'alias').symlink_to(other)
        c=retention.Collector(self.root/'out');c.copy(source/'alias',source,'target')
        self.assertFalse(c.files);self.assertEqual(c.omissions[0]['reason'],'symlink input')
        for name in ('../escape','/absolute','a/../b'):
            with self.assertRaises(ValueError):c.put(name,b'x')

    def test_user_objects_and_compilers_precede_large_evidence(self):
        names=('repo','title_foundation','foundation','wine_work','tls_work','title_build')
        args=argparse.Namespace(**{name:self.root/name for name in names},wine_archive=self.root/'wine.tar.gz',
                                sdk_source_archive=self.root/'sdk.tar.gz',out=self.root/'retained-user')
        for name in names:getattr(args,name).mkdir()
        expected={}
        for name in ('build/dlls/win32u/ps5drv.o','build/dlls/win32u/window.o',
                     'build/dlls/win32u/winstation.o','build/dlls/win32u/syscall.o','service-translation-units.log',
                     'user-driver-compiler','user-driver-sdk-compiler'):
            path=args.wine_work/name;path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(('inert '+name).encode());expected['target/wine/'+name]=path.read_bytes()
        args.wine_archive.write_bytes(b'x'*4096)
        with mock.patch.object(retention,'MAX_TOTAL',sum(map(len,expected.values()))):
            result=retention.collect(args)
        self.assertEqual(set(result['files']),set(expected))
        for name,value in expected.items():self.assertEqual((args.out/name).read_bytes(),value)
        self.assertTrue(result['omissions']);self.assertFalse(result['accepted'])

    def test_bound_is_explicit_and_completed_evidence_remains(self):
        c=retention.Collector(self.root/'out');c.put('small',b'a')
        with mock.patch.object(retention,'MAX_TOTAL',2):c.put('too-large',b'bb')
        result=c.finish({});self.assertEqual(set(result['files']),{'small'});self.assertEqual(len(result['omissions']),1)
        self.assertEqual((self.root/'out/small').read_bytes(),b'a')

    def test_real_collection_excludes_prefix_home_and_registry(self):
        names=('repo','title_foundation','foundation','wine_work','tls_work','title_build')
        args=argparse.Namespace(**{name:self.root/name for name in names},wine_archive=self.root/'wine.tar.gz',
                                sdk_source_archive=self.root/'sdk.tar.gz',out=self.root/'retained')
        for name in names:getattr(args,name).mkdir()
        (args.wine_work/'prx').mkdir();(args.wine_work/'prx/ntdll.shared.elf').write_bytes(b'linked')
        (args.title_build/'wine-child').mkdir();(args.title_build/'wine-child/native-wine-child.self').write_bytes(b'child')
        inspection=args.title_build.with_name(args.title_build.name+'-wine-child-title-inspection')/'inspection'
        inspection.mkdir(parents=True);(inspection/'001-tool.log').write_bytes(b'analyzer output')
        for name in ('prefix/system.reg','home/secret'):
            path=self.root/name;path.parent.mkdir();path.write_bytes(b'do not retain')
        result=retention.collect(args)
        self.assertEqual(set(result['files']),{'target/wine/prx/ntdll.shared.elf','target/child/native-wine-child.self',
                                             'target/title-inspection/inspection/001-tool.log'})
        self.assertFalse(result['raw_prefix_or_registry_retained'])

    def test_failed_child_build_retains_exact_module_provider_inputs(self):
        names=('repo','title_foundation','foundation','wine_work','tls_work','title_build')
        args=argparse.Namespace(**{name:self.root/name for name in names},wine_archive=self.root/'wine.tar.gz',
                                sdk_source_archive=self.root/'sdk.tar.gz',out=self.root/'retained')
        for name in names:getattr(args,name).mkdir()
        sdk=args.title_foundation/'.deps/native/ps5-payload-sdk/target/lib';sdk.mkdir(parents=True)
        for name in ('libSceSysmodule.so','libSceNet.so','unrelated-private.so'):
            (sdk/name).write_bytes(('inert '+name).encode())
        result=retention.collect(args)
        self.assertEqual(set(result['files']),{'providers/sdk/target/lib/libSceSysmodule.so',
                                             'providers/sdk/target/lib/libSceNet.so'})
        for leaf in ('libSceSysmodule.so','libSceNet.so'):
            self.assertEqual((args.out/'providers/sdk/target/lib'/leaf).read_bytes(),(sdk/leaf).read_bytes())
        self.assertFalse(result['accepted']);self.assertFalse(result['raw_prefix_or_registry_retained'])

    def test_inspection_log_selection_links_and_bounds(self):
        build=self.root/'title';build.mkdir()
        sibling=self.root/'title-wine-child-title-inspection';inspection=sibling/'inspection'
        inspection.mkdir(parents=True)
        (inspection/'001-tool.log').write_bytes(b'ok')
        (inspection/'1000-tool.log').write_bytes(b'ok')
        (inspection/'002-tool.log').write_bytes(b'oversize')
        private=self.root/'private';private.write_bytes(b'not a tool log')
        (inspection/'003-tool.log').symlink_to(private)
        for name in ('system.reg','other.log','private-tool.log'):(inspection/name).write_bytes(b'not retained')
        (sibling/'prefix').mkdir();(sibling/'prefix/004-tool.log').write_bytes(b'not retained')
        c=retention.Collector(self.root/'logs')
        with mock.patch.object(retention,'MAX_FILE',2):retention.collect_title_inspection(c,build)
        self.assertEqual(set(c.files),{'target/title-inspection/inspection/001-tool.log',
                                      'target/title-inspection/inspection/1000-tool.log'})
        self.assertEqual({row['reason'] for row in c.omissions},{'file retention limit','symlink input'})
        alias=self.root/'alias-wine-child-title-inspection';alias.symlink_to(sibling,target_is_directory=True)
        c=retention.Collector(self.root/'alias-logs');retention.collect_title_inspection(c,self.root/'alias')
        self.assertFalse(c.files)

    def preview_paths(self):
        build=self.root/'preview-source/build/native-windows-child-fixture'
        check=self.root/'preview-title-inspection'
        paths=[(build/'wine-child','target/child'),
               (build.with_name(build.name+'-wine-child-title-inspection'),'target/title-inspection'),
               (check,'target/title-check')]
        for base,label in paths:(base/'inspection').mkdir(parents=True)
        return build,check,paths

    def test_preview_keeps_exact_numbered_logs_from_all_three_routes_only(self):
        build,check,paths=self.preview_paths();expected={}
        for index,(base,label) in enumerate(paths):
            data=b'argv: compiler\nstdout: output\nstderr: failed compilation\xff'+bytes([index])
            path=base/'inspection/001-tool.log';path.write_bytes(data);path.chmod(0o755)
            expected[label+'/inspection/001-tool.log']=data
            for name in ('system.reg','source.tar.gz','other.log','private-tool.log','01-tool.log'):
                (base/'inspection'/name).write_bytes(b'not retained')
            (base/'prefix').mkdir();(base/'prefix/002-tool.log').write_bytes(b'not retained')
            (base/'worker.elf').write_bytes(b'not retained')
        out=self.root/'preview-evidence/compiler-inspection'
        with mock.patch.object(retention,'archive_git',side_effect=AssertionError('no source archive')):
            result=retention.collect_preview_inspection(build,check,out)
        self.assertEqual(set(result['files']),set(expected))
        for name,data in expected.items():
            self.assertEqual((out/name).read_bytes(),data)
            self.assertEqual(result['files'][name]['sha256'],retention.sha(data))
            self.assertEqual(result['files'][name]['original_mode'],0o755)
            self.assertEqual((out/name).stat().st_mode & 0o777,0o644)
        self.assertFalse(result['accepted']);self.assertFalse(result['runtime_validated'])
        self.assertFalse(result['raw_prefix_or_registry_retained'])
        self.assertTrue(result['inputs']['preview_inspection_only'])
        self.assertEqual(json.loads((out/'UNACCEPTED-BUILD.json').read_text()),result)

    def test_preview_rejects_symlinks_fifos_and_directories(self):
        build,check,paths=self.preview_paths();inspection=paths[0][0]/'inspection'
        secret=self.root/'private';secret.write_bytes(b'not retained')
        (inspection/'001-tool.log').symlink_to(secret)
        os.mkfifo(inspection/'002-tool.log')
        (inspection/'003-tool.log').mkdir()
        (inspection/'1000-tool.log').write_bytes(b'compiler log')
        result=retention.collect_preview_inspection(build,check,self.root/'out')
        self.assertEqual(set(result['files']),{'target/child/inspection/1000-tool.log'})
        self.assertEqual([item['reason'] for item in result['omissions']],
                         ['symlink input','nonregular input','nonregular input'])

    def test_preview_rejects_symlink_roots_and_ancestors(self):
        real=self.root/'real';(real/'nested/inspection').mkdir(parents=True)
        (real/'nested/inspection/001-tool.log').write_bytes(b'not retained through alias')
        alias=self.root/'alias';alias.symlink_to(real,target_is_directory=True)
        for name,base in [('ancestor',alias/'nested'),('root',self.root/'root-alias'),
                          ('inspection',self.root/'inspection-alias')]:
            with self.subTest(name=name):
                if name=='root':base.symlink_to(real/'nested',target_is_directory=True)
                if name=='inspection':
                    base.mkdir();(base/'inspection').symlink_to(real/'nested/inspection',target_is_directory=True)
                c=retention.Collector(self.root/(name+'-out'))
                retention.collect_numbered_inspection(c,base,'target/child')
                self.assertFalse(c.files)

    def test_preview_file_total_and_count_limits_are_independent(self):
        self.assertEqual(retention.PREVIEW_LOG_LIMITS,(4*1024*1024,16*1024*1024,256))
        build,check,paths=self.preview_paths();inspection=paths[0][0]/'inspection'
        for name,data in [('001-tool.log',b'aa'),('002-tool.log',b'bb'),('003-tool.log',b'oversize')]:
            (inspection/name).write_bytes(data)
        for kind,limits,expected in [('file',(2,100,10),2),('total',(10,3,10),1),('count',(10,100,1),1)]:
            with self.subTest(kind=kind),mock.patch.object(retention,'PREVIEW_LOG_LIMITS',limits):
                result=retention.collect_preview_inspection(build,check,self.root/kind)
                self.assertEqual(len(result['files']),expected)
                self.assertEqual(len(result['omissions']),3-expected)
                self.assertLessEqual(result['bytes'],limits[1])
                self.assertTrue(all(record['bytes']<=limits[0] for record in result['files'].values()))
        c=retention.Collector(self.root/'no-read',limits=(1,1,1))
        with mock.patch.object(Path,'read_bytes',side_effect=AssertionError('oversize input read')):
            c.copy(inspection/'003-tool.log',paths[0][0],'target/child')
        self.assertEqual(c.omissions[0]['reason'],'file retention limit')

    def test_missing_preview_is_reported_without_reusing_output(self):
        out=self.root/'out'
        result=retention.collect_preview_inspection(self.root/'missing',self.root/'missing-check',out)
        self.assertFalse(result['files']);self.assertFalse(result['accepted'])
        with self.assertRaises(ValueError):
            retention.collect_preview_inspection(self.root/'missing',self.root/'missing-check',out)
        alias=self.root/'output-alias';alias.symlink_to(out,target_is_directory=True)
        with self.assertRaises(ValueError):
            retention.collect_preview_inspection(self.root/'missing',self.root/'missing-check',alias/'new')

if __name__=='__main__':unittest.main(verbosity=2)
