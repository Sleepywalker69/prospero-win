#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Compile and execute pure byte validators from the actual distributed patches."""
import os
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def added_header(patch, name):
    section = patch.read_text().split('+++ b/' + name + '\n', 1)[1]
    section = section.split('\ndiff --git ', 1)[0].split('\n--- ', 1)[0]
    lines = [line[1:] for line in section.splitlines()
             if line.startswith('+') and not line.startswith('+++')]
    if not lines or not lines[0].startswith('/* SPDX-'):
        raise ValueError('missing complete added header')
    return '\n'.join(lines) + '\n'


class PrivateDispatchWow64Contract(unittest.TestCase):
    def test_actual_added_header_and_original_pure_controls(self):
        compiler = os.environ.get('CC', 'cc')
        self.assertIsNotNone(shutil.which(compiler), 'host C compiler required')
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            include = directory / 'include/wine'
            include.mkdir(parents=True)
            for patch, name in [
                ('0910-ntdll-private-dispatcher-abi-proposal.patch', 'pw_private_dispatch.h'),
                ('0914-ntdll-private-dispatcher-wow64.patch', 'pw_private_dispatch_i386.h')]:
                (include / name).write_text(added_header(ROOT / 'wine/patches' / patch, 'include/wine/' + name))
            executable = directory / 'private-dispatch-i386'
            subprocess.run([compiler, '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-I' + str(include.parent), str(ROOT / 'tests/fixtures/private_dispatch_i386.c'),
                            '-o', str(executable)], check=True)
            subprocess.run([str(executable)], check=True)


    def test_actual_build_flag_selection(self):
        source = (ROOT / 'tools/build_wine_ps5.sh').read_text()
        block = source[source.index('case " ${CFLAGS:-}'):source.index('# Reconfigure whenever')]
        program = 'set -eu\nfail() { exit 73; }\nps5opengl_sdk=\n' + block + \
            "\nexport opengl_cflags\npython3 -c 'import os,json; print(json.dumps({k:os.environ.get(k) for k in [\"opengl_cflags\",\"x86_64_CFLAGS\",\"i386_CFLAGS\"]}))'\n"
        for mode in ('0', '1'):
            env = {k: v for k, v in os.environ.items()
                   if k not in ('CFLAGS', 'CPPFLAGS', 'CROSSCFLAGS', 'x86_64_CFLAGS', 'i386_CFLAGS')}
            env.update(PW_WINE_PRIVATE_DISPATCH=mode, x86_64_CFLAGS='-O1', i386_CFLAGS='-O3')
            result = subprocess.run(['sh'], input=program, env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            flags = json.loads(result.stdout)
            for name, original in [('x86_64_CFLAGS', '-O1'), ('i386_CFLAGS', '-O3')]:
                self.assertEqual(flags[name], original + (' -DWINE_PS5_PRIVATE_DISPATCH=1' if mode == '1' else ''))
            self.assertEqual('WINE_PS5_PRIVATE_DISPATCH' in flags['opengl_cflags'], mode == '1')
        for name in ('CFLAGS', 'CPPFLAGS', 'CROSSCFLAGS', 'x86_64_CFLAGS', 'i386_CFLAGS'):
            env = dict(os.environ, PW_WINE_PRIVATE_DISPATCH='0')
            env[name] = '-DWINE_PS5_PRIVATE_DISPATCH=0'
            result = subprocess.run(['sh'], input=program, env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 73)


if __name__ == '__main__':
    unittest.main()
