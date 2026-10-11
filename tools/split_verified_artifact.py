# SPDX-License-Identifier: LGPL-2.1-or-later
"""Split already downloaded bytes; never extract or execute the archive."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

EXPECTED_BYTES = 630656649
EXPECTED_SHA256 = '81cccfdf9300789eaf707ee544e6059682ca147853394a53efba3df4bf281e20'
PART_BYTES = 200 * 1024 * 1024


def split_verified(source, destination, size, digest, part_bytes=PART_BYTES):
    source, destination = Path(source), Path(destination)
    if size <= 0 or part_bytes <= 0 or part_bytes > PART_BYTES:
        raise ValueError('invalid size or part bound')
    before = source.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size != size:
        raise ValueError('input must be an exact-size regular file')
    if destination.exists() or destination.is_symlink():
        raise ValueError('destination already exists')
    destination.mkdir()
    parts = []
    whole = hashlib.sha256()
    with source.open('rb') as handle:
        opened = os.fstat(handle.fileno())
        if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
                before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns):
            raise ValueError('input changed before read')
        remaining = size
        while remaining:
            name = 'runtime.zip.part%02d' % (len(parts) + 1)
            amount = min(remaining, part_bytes)
            hashed = hashlib.sha256()
            with (destination / name).open('xb') as output:
                pending = amount
                while pending:
                    data = handle.read(min(pending, 1024 * 1024))
                    if not data:
                        raise ValueError('input shortened during read')
                    output.write(data)
                    whole.update(data)
                    hashed.update(data)
                    pending -= len(data)
            parts.append({'name': name, 'bytes': amount, 'sha256': hashed.hexdigest()})
            remaining -= amount
        after = os.fstat(handle.fileno())
        if handle.read(1) or (after.st_size, after.st_mtime_ns) != (before.st_size, before.st_mtime_ns):
            raise ValueError('input changed during read')
    if whole.hexdigest() != digest:
        raise ValueError('whole archive SHA256 mismatch; retained parts are not admitted')
    report = {'schema': 'exact-archive-byte-parts/1', 'source_artifact_id': 11695207767,
              'source_run_id': 38120712135, 'source_run_attempt': 1,
              'source_candidate_commit': '4b802bea97f4a4414c632eb5a017218b712f7122',
              'source_compiled_commit': 'f3b51781edb94d630dd682af430309f6c5ba59a8',
              'transport': {'run_id': os.environ.get('GITHUB_RUN_ID'),
                            'run_attempt': os.environ.get('GITHUB_RUN_ATTEMPT'),
                            'commit': os.environ.get('GITHUB_SHA')},
              'bytes': size, 'sha256': digest, 'parts': parts,
              'scope': 'byte-preserving transport only; no new build or runtime validation'}
    pending_manifest = destination / 'MANIFEST.json.pending'
    pending_manifest.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    pending_manifest.replace(destination / 'MANIFEST.json')
    return report


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit('usage: split_verified_artifact.py INPUT.zip NEW_OUTPUT_DIRECTORY')
    print(json.dumps(split_verified(sys.argv[1], sys.argv[2], EXPECTED_BYTES, EXPECTED_SHA256), indent=2))
