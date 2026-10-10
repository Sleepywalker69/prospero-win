#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Original filesystem-only evidence-retention controls."""
import argparse
import json
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

    def test_links_and_path_escape_refused(self):
        source=self.root/'source';source.mkdir();other=self.root/'private';other.write_bytes(b'private')
        (source/'alias').symlink_to(other)
        c=retention.Collector(self.root/'out');c.copy(source/'alias',source,'target')
        self.assertFalse(c.files);self.assertEqual(c.omissions[0]['reason'],'symlink input')
        for name in ('../escape','/absolute','a/../b'):
            with self.assertRaises(ValueError):c.put(name,b'x')

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

if __name__=='__main__':unittest.main(verbosity=2)
