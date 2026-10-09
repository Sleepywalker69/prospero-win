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
        for name in ('prefix/system.reg','home/secret'):
            path=self.root/name;path.parent.mkdir();path.write_bytes(b'do not retain')
        result=retention.collect(args)
        self.assertEqual(set(result['files']),{'target/wine/prx/ntdll.shared.elf','target/child/native-wine-child.self'})
        self.assertFalse(result['raw_prefix_or_registry_retained'])

if __name__=='__main__':unittest.main(verbosity=2)
