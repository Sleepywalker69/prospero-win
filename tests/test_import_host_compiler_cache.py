# SPDX-License-Identifier: LGPL-2.1-or-later
import hashlib
import copy
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile
sys.path.insert(0, str(Path(__file__).parents[1] / 'tools'))
import import_host_compiler_cache as m

class ImportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def record(self, data=b'object'):
        return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}

    def tar(self, items):
        path = self.root / 'cache.tar.gz'
        with tarfile.open(path, 'w:gz') as archive:
            for name, data, kind in items:
                item = tarfile.TarInfo(name)
                item.mode = 0o644
                item.type = kind
                if kind == tarfile.REGTYPE:
                    item.size = len(data)
                else:
                    item.linkname = 'outside'
                archive.addfile(item, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
        return path

    def test_manifest_aliases_types_and_bounds(self):
        self.assertEqual(m.manifest({'a/object': self.record()}), 6)
        cases = ({'../x': self.record()}, {'/x': self.record()}, {'a//x': self.record()},
                 {'a': self.record(), 'a/x': self.record()},
                 {'A/x': self.record(), 'a/y': self.record()},
                 {'x': {'bytes': True, 'sha256': 'a' * 64}},
                 {'x': {'bytes': 0, 'sha256': 'a' * 64}}, {})
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ValueError):
                m.manifest(value)
        with patch.object(m, 'FILE_LIMIT', 1), self.assertRaises(ValueError):
            m.manifest({'x': self.record()})
        with patch.object(m, 'COUNT_LIMIT', 0), self.assertRaises(ValueError):
            m.manifest({'x': self.record()})
        with patch.object(m, 'TOTAL_LIMIT', 1), self.assertRaises(ValueError):
            m.manifest({'x': self.record()})

    def test_tar_two_pass_valid_and_unsafe(self):
        expected = {'a/object': self.record()}
        path = self.tar([('a/object', b'object', tarfile.REGTYPE)])
        m.scan_cache(path, expected)
        out = self.root / 'out'; out.mkdir()
        m.scan_cache(path, expected, out)
        self.assertEqual((out / 'a/object').read_bytes(), b'object')
        for entries in ([('a/object', b'changed', tarfile.REGTYPE)],
                        [('a/object', b'object', tarfile.REGTYPE)] * 2,
                        [('a/object', b'', tarfile.SYMTYPE)],
                        [('a/object', b'', tarfile.LNKTYPE)],
                        [('a/object', b'', tarfile.FIFOTYPE)],
                        [('missing', b'object', tarfile.REGTYPE)]):
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                m.scan_cache(self.tar(entries), expected)

    def test_fresh_directory_rejects_alias_and_existing(self):
        out = self.root / 'out'
        m.fresh_directory(out)
        with self.assertRaises(ValueError): m.fresh_directory(out)
        link = self.root / 'link'; link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError): m.fresh_directory(link / 'other')

    def zip(self, duplicate=False, special=False):
        path = self.root / 'export.zip'
        with zipfile.ZipFile(path, 'w') as archive:
            for name in sorted(m.MEMBERS):
                item = zipfile.ZipInfo(name)
                item.external_attr = (0o020600 if special else 0o100644) << 16
                archive.writestr(item, b'x')
            if duplicate:
                archive.writestr('inventory.json', b'x')
        return path

    def test_zip_exact_members_preflight_before_write(self):
        path = self.zip()
        pins = m.ARTIFACT | {'size_in_bytes': path.stat().st_size,
                             'digest': 'sha256:' + m.cache.sha(path)}
        with patch.object(m, 'ARTIFACT', pins):
            m.unpack_export(path, self.root / 'ok')
        self.assertEqual(len([p for p in (self.root / 'ok').rglob('*') if p.is_file()]), 8)
        for variant in ('duplicate', 'special'):
            path = self.zip(**{variant: True})
            pins = m.ARTIFACT | {'size_in_bytes': path.stat().st_size,
                                 'digest': 'sha256:' + m.cache.sha(path)}
            out = self.root / variant
            with patch.object(m, 'ARTIFACT', pins), self.assertRaises(ValueError):
                m.unpack_export(path, out)
            self.assertFalse(out.exists())

    def identities(self):
        old, fresh = self.root / 'old', self.root / 'fresh'
        (old / 'receipts').mkdir(parents=True)
        fresh.mkdir()
        identity = {'schema': m.cache.SCHEMA, 'phase': 'host', 'recipe': {'source': 'a' * 64},
                    'flags': {'CFLAGS': ''}, 'headers': {'h': 'b' * 64}}
        def write(directory, value):
            (directory / 'compatibility.json').write_bytes(m.canonical(value))
            (directory / 'partition.json').write_bytes(m.canonical(m.cache.cache_partition(value)))
            partition, prefix, key = m.cache.cache_keys(value)
            state = dict(phase='host', cache_dir=str(self.root / 'objects'),
                         key=key, partition_key=partition, restore_prefix=prefix,
                         partition_sha256=m.cache.sha(directory / 'partition.json'),
                         compatibility_sha256=m.cache.sha(directory / 'compatibility.json'))
            (directory / 'state.json').write_bytes(m.canonical(state))
            return state
        state = write(old / 'receipts', identity)
        write(fresh, identity)
        return old, fresh, identity, state, write

    def test_fresh_partition_and_recipe_are_independently_checked(self):
        old, fresh, identity, state, write = self.identities()
        with patch.object(m.exporter, 'PARTITION', state['partition_sha256']):
            self.assertEqual(m.bind_fresh_identity(old, fresh)['key'], state['key'])
            for changed in (identity | {'recipe': {'source': 'c' * 64}},
                            identity | {'flags': {'CFLAGS': '-O0'}},
                            identity | {'headers': {'h': 'd' * 64}}):
                write(fresh, changed)
                with self.assertRaises(ValueError): m.bind_fresh_identity(old, fresh)

    def test_complete_scan_before_cache_destination_exists(self):
        out = self.root / 'input'; out.mkdir()
        expected = {'a/object': self.record()}
        (out / 'inventory.json').write_bytes(m.canonical(expected))
        self.tar([('a/object', b'wrong!', tarfile.REGTYPE)]).rename(out / 'compiler-cache.tar.gz')
        destination = self.root / 'cache'
        with patch.object(m, 'read_receipt', return_value={'cache': {}}), \
             patch.object(m, 'bind_fresh_identity', return_value={'cache_dir': str(destination)}), \
             self.assertRaises(ValueError):
            m.import_cache(out, self.root / 'fresh')
        self.assertFalse(destination.exists())

    def test_successful_import_uses_new_regular_files(self):
        out = self.root / 'input'; out.mkdir()
        expected = {'a/object': self.record()}
        (out / 'inventory.json').write_bytes(m.canonical(expected))
        self.tar([('a/object', b'object', tarfile.REGTYPE)]).rename(out / 'compiler-cache.tar.gz')
        destination = self.root / 'cache'
        with patch.object(m, 'read_receipt', return_value={'cache': {}}), \
             patch.object(m, 'bind_fresh_identity', return_value={
                 'cache_dir': str(destination), 'partition_sha256': 'a' * 64}), patch('builtins.print'):
            result = m.import_cache(out, self.root / 'fresh')
        self.assertEqual(result['files'], 1)
        self.assertEqual((destination / 'a/object').read_bytes(), b'object')
        self.assertFalse(result['compilation_performed'])
        self.assertEqual((destination / 'a/object').stat().st_nlink, 1)

    def test_export_run_attempt_and_artifact_pins(self):
        run = dict(id=m.RUN, run_attempt=1, head_sha=m.HEAD, status='completed', conclusion='success',
                   repository={'full_name': m.exporter.REPO}, head_repository={'full_name': m.exporter.REPO},
                   path='.github/workflows/export-host-compiler-cache.yml', event='pull_request')
        job = dict(id=m.JOB, run_id=m.RUN, run_attempt=1, head_sha=m.HEAD, name='export',
                   status='completed', conclusion='success',
                   steps=[{'number': n, 'conclusion': 'success'} for n in (5, 6, 7, 8, 9)])
        artifact = m.ARTIFACT | {'expired': False, 'workflow_run': {'id': m.RUN, 'head_sha': m.HEAD}}
        self.assertEqual(m.artifact_admission(run, [job], [artifact])['id'], m.ARTIFACT['id'])
        for field, value in (('run_attempt', 2), ('head_sha', '0' * 40), ('conclusion', 'failure'),
                             ('status', 'in_progress'), ('event', 'workflow_dispatch')):
            with self.subTest(field=field), self.assertRaises(ValueError):
                m.artifact_admission(run | {field: value}, [job], [artifact])
        for field, value in (('expired', True), ('digest', 'sha256:' + '0' * 64), ('size_in_bytes', 1)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                m.artifact_admission(run, [job], [artifact | {field: value}])
        with self.assertRaises(ValueError):
            m.artifact_admission(run, [job | {'run_attempt': 2}], [artifact])

    def test_receipt_producer_and_payload_tampering(self):
        out = self.root / 'receipt'; out.mkdir()
        (out / 'host.zip').write_bytes(b'host source')
        (out / 'compiler-cache.tar.gz').write_bytes(b'opaque cache')
        (out / 'inventory.json').write_bytes(b'{}')
        proof = m.strict_json(m.exporter.PROOF.read_bytes())
        proof['artifacts']['host'] = {'size_in_bytes': (out / 'host.zip').stat().st_size,
                                     'digest': 'sha256:' + m.cache.sha(out / 'host.zip')}
        proof_path = self.root / 'proof.json'; proof_path.write_bytes(m.canonical(proof))
        archive = {'bytes': (out / 'compiler-cache.tar.gz').stat().st_size,
                   'sha256': m.cache.sha(out / 'compiler-cache.tar.gz')}
        value = {'schema': 'pw-host-compiler-cache-export/1', 'host_component_accepted': True,
                 'runtime_distribution_accepted': False, 'compilation_performed': False,
                 'consumer_partition_verification_required': True, 'archive': archive,
                 'exporter': {'GITHUB_RUN_ID': str(m.RUN), 'GITHUB_RUN_ATTEMPT': '1',
                              'GITHUB_SHA': m.MERGE, 'GITHUB_REF': m.exporter.REF,
                              'GITHUB_HEAD_REF': 'review/child-net-targets-host-reuse-20261012'},
                 'proof': proof, 'identity': {'verified': 'receipts'},
                 'cache': {'id': 123, 'key': proof['key'], 'ref': m.exporter.REF, 'version': 'a' * 64,
                           'created_at': '2026-10-12T12:16:18Z', 'size_in_bytes': 100},
                 'inventory_sha256': m.cache.sha(out / 'inventory.json')}
        def write(record):
            (out / 'EXPORT-RECEIPT.json').write_bytes(m.canonical(record))
        with patch.object(m.exporter, 'PROOF', proof_path), patch.object(m, 'ARCHIVE', archive), \
             patch.object(m.exporter, 'receipts', return_value={'verified': 'receipts'}):
            write(value)
            self.assertEqual(m.read_receipt(out), value)
            for key, wrong in (('GITHUB_RUN_ID', '1'), ('GITHUB_RUN_ATTEMPT', '2'),
                               ('GITHUB_SHA', m.HEAD), ('GITHUB_REF', 'refs/heads/main')):
                bad = copy.deepcopy(value); bad['exporter'][key] = wrong; write(bad)
                with self.subTest(key=key), self.assertRaises(ValueError): m.read_receipt(out)
            for key, wrong in (('archive', {}), ('inventory_sha256', '0' * 64),
                               ('identity', {}), ('runtime_distribution_accepted', True)):
                write(value | {key: wrong})
                with self.subTest(key=key), self.assertRaises(ValueError): m.read_receipt(out)
            write(value)
            for filename in ('host.zip', 'compiler-cache.tar.gz', 'inventory.json'):
                path = out / filename; original = path.read_bytes(); path.write_bytes(b'tampered')
                with self.subTest(filename=filename), self.assertRaises(ValueError): m.read_receipt(out)
                path.write_bytes(original)

if __name__ == '__main__':
    unittest.main()
