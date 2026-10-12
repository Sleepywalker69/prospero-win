# SPDX-License-Identifier: LGPL-2.1-or-later
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import tarfile
import unittest
from unittest.mock import patch
import zipfile

spec = importlib.util.spec_from_file_location('reader', Path(__file__).parents[1] / 'tools/inspect_matched_artifact.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class ArchiveEvidence(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def zip(self, names=('windows-child-fixture.tar.gz',), data=b'bounded'):
        source = self.root / 'source.zip'
        with zipfile.ZipFile(source, 'w') as z:
            for name in names:
                z.writestr(name, data)
        return source, dict(outer_size=source.stat().st_size,
                           outer_sha=hashlib.sha256(source.read_bytes()).hexdigest(),
                           inner_size=len(data), inner_sha=hashlib.sha256(data).hexdigest())

    def test_zip_identity_and_new_destination(self):
        source, pins = self.zip()
        target = self.root / 'new.tar.gz'
        m.zip_to_new_tar(source, target, **pins)
        self.assertEqual(target.read_bytes(), b'bounded')
        with self.assertRaises(ValueError):
            m.zip_to_new_tar(source, target, **pins)

    def test_wrong_outer_and_inner_hash(self):
        source, pins = self.zip()
        for key in ('outer_sha', 'inner_sha'):
            with self.subTest(key=key), self.assertRaises(ValueError):
                m.zip_to_new_tar(source, self.root / key, **(pins | {key: '0' * 64}))

    def test_wrong_zip_name_and_multiple_members(self):
        for names in (('../windows-child-fixture.tar.gz',), ('first', 'second')):
            source, pins = self.zip(names)
            with self.assertRaises(ValueError):
                m.zip_to_new_tar(source, self.root / 'out', **pins)

    def tar(self, entries):
        path = self.root / 'test.tar.gz'
        with tarfile.open(path, 'w:gz') as archive:
            for name, kind, data in entries:
                item = tarfile.TarInfo(name)
                item.mode = 0o755 if kind == 'directory' else 0o644
                if kind == 'directory':
                    item.type = tarfile.DIRTYPE
                elif kind == 'link':
                    item.type = tarfile.SYMTYPE
                    item.linkname = 'outside'
                else:
                    item.size = len(data)
                archive.addfile(item, io.BytesIO(data) if kind == 'file' else None)
        return path

    def test_bounded_regular_selected_file(self):
        path = self.tar([('proof.json', 'file', b'{}')])
        values, contents = m.scan_tar(path, ('proof.json',))
        self.assertEqual(contents, {'proof.json': b'{}'})
        self.assertEqual(values['proof.json']['sha256'], hashlib.sha256(b'{}').hexdigest())
        with patch.object(m, 'MAX_JSON', 1), self.assertRaises(ValueError):
            m.scan_tar(path, ('proof.json',))

    def test_unsafe_duplicate_link_and_missing_parent(self):
        cases = [[('../proof.json', 'file', b'{}')],
                 [('proof.json', 'file', b'{}'), ('PROOF.json', 'file', b'{}')],
                 [('proof.json', 'link', b'')],
                 [('missing/proof.json', 'file', b'{}')]]
        for entries in cases:
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                m.scan_tar(self.tar(entries), ('proof.json',))

    def test_manifest_missing_and_checksum_mismatch(self):
        with self.assertRaises(ValueError):
            m.scan_tar(self.tar([('other', 'file', b'{}')]), ('proof.json',))
        with self.assertRaises(ValueError):
            m.scan_tar(self.tar([('SHA256SUMS', 'file', b'wrong')]), ('SHA256SUMS',))

    def test_strict_json(self):
        for data in (b'{"a":1,"a":2}', b'{"a":NaN}', b'\xff', b'{'):
            with self.subTest(data=data), self.assertRaises((ValueError, UnicodeDecodeError)):
                m.strict_json(data)
        self.assertEqual(m.strict_json(b'{"safe":"\\n::error::"}'), {'safe': '\n::error::'})

    def inventory(self):
        values = {m.BATTLE: {'type': 'directory'}, m.BATTLE_PROFILE: {'type': 'file', 'bytes': 1}}
        pe = (('parent.exe', 'child.exe'), ('user-parent.exe', 'user-child.exe'), ('net-parent.exe', 'net-child.exe'))
        leaf = ('windows-child-fixture', 'windows-child-user', 'windows-child-net')
        for slug, programs, directory in zip(m.FIXTURES, pe, leaf):
            root = 'console/data/prospero-win/prefixes/' + slug
            for name in ('system.reg', 'user.reg', 'userdef.reg', *('drive_c/' + directory + '/' + n for n in programs)):
                values[root + '/' + name] = {'type': 'file', 'bytes': 1, 'sha256': 'a' * 64}
            values['console/data/prospero-win/profiles/' + slug + '.profile'] = {'type': 'file', 'bytes': 1}
        return values

    def test_exact_exclusions_and_fixture_presence(self):
        values = self.inventory()
        result, included, omitted = m.deployment_inventory(values)
        self.assertTrue(result['partial_deployment'])
        self.assertFalse(result['battle_launch_allowed'])
        self.assertEqual(set(omitted), {m.BATTLE, m.BATTLE_PROFILE})
        self.assertEqual(len(included), 18)
        for name in ('PPSA99995/battlenet-experimental-v1', 'PPSA99995/BATTLENET-EXPERIMENTAL-V1.PROFILE'):
            bad = copy.deepcopy(values)
            bad[name] = {'type': 'file', 'bytes': 1}
            with self.assertRaises(ValueError):
                m.deployment_inventory(bad)
        del values['console/data/prospero-win/profiles/windows-child-net-v1.profile']
        with self.assertRaises(ValueError):
            m.deployment_inventory(values)

    def test_pins_are_the_matched113_package(self):
        self.assertEqual((m.ARTIFACT, m.RUN, m.ZIP_BYTES, m.TAR_BYTES),
                         (11747362547, 38241186538, 754378842, 758102289))
        self.assertEqual(m.ZIP_SHA, '542e980e3ac21d3064481daf22a5817c666aa35a194e55a22cf3bd7dfd88a6d8')
        self.assertEqual(m.TAR_SHA, 'd8f35234b740af9c5517a4c5ef441aa9574aa0518c563b3e9969c1bf172a67e8')
        self.assertNotEqual(m.CANDIDATE, m.COMPILED)

if __name__ == '__main__':
    unittest.main()
