#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Archive identity, malformed inputs, and bounded opt-in producer contracts."""
from pathlib import Path
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
import yaml

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import package_radv_archive as radv


def object_file(machine=62, kind=2, defined=3):
    names = [''] + sorted(radv.REQUIRED)
    strings = b''; offsets = []
    for name in names:
        offsets.append(len(strings)); strings += name.encode() + b'\0'
    start = 64 + 4 * 64; symbols = start + len(strings); text = symbols + len(names) * 24
    value = bytearray(text + 1); value[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHIQQQIHHHHHH', value, 16, 1, machine, 1, 0, 0, 64, 0, 64, 0, 0, 64, 4, 0)
    struct.pack_into('<IIQQQQIIQQ', value, 128, 0, 3, 0, 0, start, len(strings), 0, 0, 1, 0)
    struct.pack_into('<IIQQQQIIQQ', value, 192, 0, 2, 0, 0, symbols, len(names) * 24, 1, 1, 8, 24)
    struct.pack_into('<IIQQQQIIQQ', value, 256, 0, 1, 6, 0, text, 1, 0, 0, 1, 0)
    value[start:symbols] = strings; value[text] = 0xc3
    for index in range(1, len(names)):
        struct.pack_into('<IBBHQQ', value, symbols + index * 24, offsets[index], 16 | kind, 0, defined, 0, 1)
    return value


def member(name, value):
    header = f'{name:<16}{0:<12}{0:<6}{0:<6}{100644:<8}{len(value):<10}`\n'.encode()
    return header + value + (b'\n' if len(value) & 1 else b'')


class ArchiveTests(unittest.TestCase):
    def inspect(self, value):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'lib.a'; path.write_bytes(value)
            return radv.inspect_archive(path)

    def test_actual_member_machine_and_function_definitions(self):
        result = self.inspect(b'!<arch>\n' + member('test.o/', object_file()))
        self.assertEqual(result['members'], 1)
        self.assertEqual(result['required_defined_functions'], sorted(radv.REQUIRED))
        self.assertEqual(result['global_function_count'], 5)

    def test_gnu_and_bsd_long_names(self):
        obj = object_file(); longname = b'long_file_name_for_radv.o'
        gnu = member('//', longname + b'/\n') + member('/0', obj)
        bsd = member('#1/' + str(len(longname)), longname + obj)
        self.assertEqual(self.inspect(b'!<arch>\n' + gnu)['members'], 1)
        self.assertEqual(self.inspect(b'!<arch>\n' + bsd)['members'], 1)

    def test_reject_malformed_or_wrong_archive_members(self):
        good = b'!<arch>\n' + member('test.o/', object_file())
        cases = [b'!<thin>\n' + good[8:], good[:-3], b'!<arch>\n',
                 b'!<arch>\n' + member('../escape/', object_file()),
                 b'!<arch>\n' + member('/999', object_file()),
                 b'!<arch>\n' + member('wrong.o/', object_file(machine=183)),
                 b'!<arch>\n' + member('data.o/', object_file(kind=1)),
                 b'!<arch>\n' + member('undefined.o/', object_file(defined=0)),
                 b'!<arch>\n' + member('bitcode.o/', b'BC\xc0\xde'),
                 good + b'bad header']
        for value in cases:
            with self.subTest(size=len(value)), self.assertRaises((ValueError, UnicodeError)):
                self.inspect(value)

    def test_reject_corrupt_elf_tables(self):
        for offset, fmt, bad in ((40, '<Q', 0xffffffffffffffff), (58, '<H', 1),
                                 (192 + 56, '<Q', 0), (192 + 40, '<I', 400)):
            value = object_file(); struct.pack_into(fmt, value, offset, bad)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                self.inspect(b'!<arch>\n' + member('bad.o/', value))

    def test_licences_cannot_copy_private_host_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source = root / 'source'; source.mkdir()
            notice = source / 'COPYING'; notice.write_text('owned notice')
            self.assertEqual(radv.licence_path(source, notice), notice)
            outside = root / 'outside'; outside.write_text('not an artifact')
            notice.unlink(); notice.symlink_to(outside)
            with self.assertRaisesRegex(ValueError, 'symlink leaves'):
                radv.licence_path(source, notice)

    def test_readable_upstream_scripts_run_through_bash_and_keep_guards(self):
        workflow = yaml.load((ROOT / '.github/workflows/radv-archive.yml').read_text(), Loader=yaml.BaseLoader)
        step = next(s for s in workflow['jobs']['radv-archive']['steps']
                    if s.get('name', '').startswith('Build the pinned'))
        lines = [line.strip() for line in step['run'].splitlines()
                 if line.strip().startswith(('PS5_PAYLOAD_SDK_FORK=', 'PS5_MESA_FORK='))]
        self.assertEqual(len(lines), 2)
        self.assertIn('bash tools/setup-native-dependencies.sh', lines[0])
        self.assertIn('bash tools/build-radv.sh release', lines[1])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source = root / 'upstream source'; tools = source / 'tools'; tools.mkdir(parents=True)
            setup = tools / 'setup-native-dependencies.sh'; build = tools / 'build-radv.sh'
            setup.write_text('#!/usr/bin/env bash\nset -euo pipefail\n'
                             '[[ $PS5_PAYLOAD_SDK_FORK == "$INPUTS/payload" && $BUILD_JOBS == 4 ]]\n'
                             'if [[ ${FIXTURE_FAIL:-0} == 1 ]]; then echo "fixture guard failure" >&2; exit 37; fi\n'
                             'printf "setup\\n" >> "$TRACE"\n')
            build.write_text('#!/usr/bin/env bash\nset -euo pipefail\n'
                             '[[ $1 == release && $PS5_MESA_FORK == "$INPUTS/mesa" ]]\n'
                             '[[ $MESON == "$VENV/bin/meson" && $NINJA == "$RUNNER_TEMP/ninja-bounded" ]]\n'
                             'printf "build\\n" >> "$TRACE"\n')
            setup.chmod(0o644); build.chmod(0o644)
            trace = root / 'trace'
            env = dict(os.environ, INPUTS=str(root), VENV=str(root / 'venv'), RUNNER_TEMP=str(root), TRACE=str(trace))
            def run(commands, fail=False):
                return subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', '\n'.join(commands)],
                                      cwd=source, env=dict(env, FIXTURE_FAIL='1' if fail else '0'),
                                      capture_output=True, text=True)
            before = run([line.replace(' bash tools/', ' tools/') for line in lines])
            self.assertEqual(before.returncode, 126)
            self.assertIn('Permission denied', before.stderr)
            self.assertFalse(trace.exists())
            result = run(lines)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(trace.read_text(), 'setup\nbuild\n')
            trace.unlink()
            guarded = run(lines, fail=True)
            self.assertEqual(guarded.returncode, 37)
            self.assertIn('fixture guard failure', guarded.stderr)
            self.assertFalse(trace.exists())
            self.assertEqual(setup.stat().st_mode & 0o777, 0o644)
            self.assertEqual(build.stat().st_mode & 0o777, 0o644)

    def test_workflow_keeps_explicit_boundaries(self):
        workflow = yaml.load((ROOT / '.github/workflows/radv-archive.yml').read_text(), Loader=yaml.BaseLoader)
        self.assertEqual(workflow['permissions'], {'contents': 'read'})
        self.assertNotIn('pull_request_target', workflow['on'])
        job = workflow['jobs']['radv-archive']
        self.assertEqual(job['runs-on'], 'ubuntu-24.04')
        self.assertEqual(job['timeout-minutes'], '180')
        self.assertIn('head.repo.full_name == github.repository', job['if'])
        self.assertIn('build-radv-archive', job['if'])
        runs = '\n'.join(s.get('run', '') for s in job['steps'])
        for expected in ('tools/build-radv.sh release', 'tools/setup-native-dependencies.sh',
                         'package_radv_archive.py sources', 'package_radv_archive.py archive',
                         'ninja -j4', '--atleast-version=2024.1 SPIRV-Tools'):
            self.assertIn(expected, runs)
        for forbidden in ('--radv ', 'package_release.sh', 'wineboot', 'continue-on-error'):
            self.assertNotIn(forbidden, runs)
        before = next(i for i,s in enumerate(job['steps']) if s.get('name','').startswith('Retain verified source'))
        build = next(i for i,s in enumerate(job['steps']) if s.get('name','').startswith('Build the pinned'))
        self.assertLess(before, build)
        for step in job['steps']:
            self.assertNotIn('continue-on-error', step)
            if 'uses' in step:
                self.assertRegex(step['uses'], r'^actions/[a-z-]+@[0-9a-f]{40}$')
        for url, pin in radv.PINS.values():
            self.assertTrue(url.startswith('https://github.com/'))
            self.assertRegex(pin, '^[0-9a-f]{40}$')
        for url, digest in radv.DOWNLOADS.values():
            self.assertTrue(url.startswith('https://'))
            self.assertRegex(digest, '^[0-9a-f]{64}$')


if __name__ == '__main__':
    unittest.main()
