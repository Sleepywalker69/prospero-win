# SPDX-License-Identifier: LGPL-2.1-or-later
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('splitter', Path(__file__).parents[1] / 'tools/split_verified_artifact.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class SplitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.data = bytes(range(256)) * 3 + b'last'
        self.source = self.root / 'source.zip'
        self.source.write_bytes(self.data)
        self.out = self.root / 'parts'
        self.sha = hashlib.sha256(self.data).hexdigest()

    def run_split(self, **kw):
        args = dict(size=len(self.data), digest=self.sha, part_bytes=200)
        args.update(kw)
        return m.split_verified(self.source, self.out, **args)

    def test_exact_roundtrip(self):
        report = self.run_split()
        self.assertEqual([x['bytes'] for x in report['parts']], [200, 200, 200, 172])
        self.assertEqual(b''.join((self.out / x['name']).read_bytes() for x in report['parts']), self.data)
        for x in report['parts']:
            self.assertEqual(hashlib.sha256((self.out / x['name']).read_bytes()).hexdigest(), x['sha256'])

    def test_wrong_size(self):
        with self.assertRaises(ValueError): self.run_split(size=2)
        self.assertFalse(self.out.exists())

    def test_wrong_hash_retains_unadmitted_parts(self):
        with self.assertRaises(ValueError): self.run_split(digest='0' * 64)
        self.assertTrue(list(self.out.glob('*.part*')))
        self.assertFalse((self.out / 'MANIFEST.json').exists())

    def test_existing_destination(self):
        self.out.mkdir()
        with self.assertRaises(ValueError): self.run_split()

    def test_symlink_source(self):
        link = self.root / 'link'
        link.symlink_to(self.source)
        self.source = link
        with self.assertRaises(ValueError): self.run_split()

    def test_invalid_part_bounds(self):
        for size in (0, -1, m.PART_BYTES + 1):
            with self.assertRaises(ValueError): self.run_split(part_bytes=size)


if __name__ == '__main__':
    unittest.main()
