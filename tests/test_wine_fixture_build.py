#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Execute the experimental selector and stream-pipe wrapper without native I/O."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class WineFixtureBuild(unittest.TestCase):
    def test_real_translation_unit_gate_routing_and_failure(self):
        for selector in ('0', 'invalid'):
            refused = subprocess.run(['sh', str(ROOT/'tools/build_wine_ps5.sh'), '--compile-check'],
                env=dict(os.environ, PW_WINE_SERVICE_FIXTURE=selector), capture_output=True, text=True)
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn('--compile-check requires PW_WINE_SERVICE_FIXTURE=1', refused.stderr)
        source = (ROOT / 'tools/build_wine_ps5.sh').read_text()
        block = source.split('# Compile complete experimental units', 1)[1].split("# The SDK's libc", 1)[0]
        block = block.split("\n", 1)[1]
        objects = ['dlls/ntdll/unix/' + n + '.o' for n in ('loader','process','server','signal_x86_64','thread','virtual')]
        objects += ['dlls/wow64/x86_64-windows/syscall.o']
        objects += ['server/' + n + '.o' for n in ('process','ptrace','request','thread')]
        with tempfile.TemporaryDirectory(prefix='real gate routing ') as temporary:
            root = Path(temporary); sdk = root / 'sdk'; (sdk / 'bin').mkdir(parents=True)
            compiler = sdk / 'bin/prospero-clang'
            compiler.write_text('#!/usr/bin/env python3\nimport os,sys,json\n'
                'with open(os.environ["CALLS"],"a") as f: f.write(json.dumps(sys.argv[1:])+"\\n")\n'
                'raise SystemExit(9 if os.environ.get("FAIL_ADAPTER","") in sys.argv[-1] and os.environ.get("FAIL_ADAPTER") else 0)\n')
            compiler.chmod(0o755)
            for name, service, partial, fail_make, fail_adapter in [
                ('off',0,0,0,''), ('partial',1,1,0,''), ('full',1,0,0,''),
                ('make-error',1,1,1,''), ('adapter-error',1,1,0,'pw_wine_fixture_socket'),
                ('child-data-error',1,1,0,'pw_wine_child_data')]:
                work = root / name; work.mkdir(); calls = work / 'calls'
                env = dict(os.environ, SDK=str(sdk), WORK=str(work), CALLS=str(calls),
                           SERVICE=str(service), PARTIAL=str(partial), FAIL_MAKE=str(fail_make), FAIL_ADAPTER=fail_adapter)
                setup = ('set -eu\nsdk=$SDK\nwork=$WORK\nbuild=$work/build\ntree=$work/source\nroot=$work/repo\n'
                         'jobs=2\nservice_cflags=-DPW_WINE_SERVICE_FIXTURE=1\nservice_fixture=$SERVICE\n'
                         'compile_check_only=$PARTIAL\nfail() { exit 73; }\n'
                         'make() { printf "%s\\n" "$@" > "$work/make-args"; [ "$FAIL_MAKE" = 0 ]; }\n')
                result = subprocess.run(['sh'], input=setup+block+'\necho FULL_CONTINUATION\n', env=env,
                                        text=True, capture_output=True)
                failed = bool(fail_make or fail_adapter)
                self.assertEqual(result.returncode, 73 if failed else 0, result.stderr)
                if not service:
                    self.assertFalse((work/'make-args').exists()); self.assertFalse(calls.exists())
                    self.assertIn('FULL_CONTINUATION', result.stdout); continue
                args = (work/'make-args').read_text().splitlines()
                self.assertEqual(args[-11:], objects)
                self.assertEqual(args.count('-W'), 11)
                expected_sources = [str(work/'source'/name.replace('x86_64-windows/', '')).removesuffix('.o') + '.c' for name in objects]
                self.assertEqual([args[i+1] for i, arg in enumerate(args) if arg == '-W'], expected_sources)
                self.assertIn('-k', args)
                compiled = [json.loads(row) for row in calls.read_text().splitlines()] if calls.exists() else []
                self.assertEqual(len(compiled), 0 if fail_make else 2 if fail_adapter == 'pw_wine_fixture_socket' else 4)
                adapter_names = ['pw_wine_fixture_provider.c', 'pw_wine_fixture_socket.c', 'pw_wine_compat.c', 'pw_wine_child_data.c']
                self.assertEqual([Path(argv[-1]).name for argv in compiled], adapter_names[:len(compiled)])
                if len(compiled) == 4:
                    self.assertEqual(compiled[-1][-1], str(work/'repo/native/pw_wine_child_data.c'))
                for argv in compiled:
                    self.assertIn('-fsyntax-only', argv)
                    self.assertIn('-DPW_WINE_SERVICE_FIXTURE=1', argv)
                    self.assertNotIn('-c', argv)
                self.assertFalse((work/'report.json').exists())
                self.assertFalse((work/'prx').exists())
                if partial and not failed:
                    self.assertFalse(json.loads((work/'compile-check-only.json').read_text())['complete_runtime'])
                    self.assertNotIn('FULL_CONTINUATION', result.stdout)
                else:
                    self.assertFalse((work/'compile-check-only.json').exists())
                    self.assertEqual('FULL_CONTINUATION' in result.stdout, not failed)

    def test_host_tools_only_stops_before_full_build_and_install(self):
        source = (ROOT / 'tools/build_host_wine.sh').read_text()
        block = source.split('# Configure once,', 1)[1].split('make -C "$build" -j"$jobs" > "$work/make.log"', 1)[0]
        block = block.split("\n", 1)[1]
        with tempfile.TemporaryDirectory() as temporary:
            for mode, failure in [(0,0),(1,0),(1,1)]:
                work = Path(temporary)/('%d-%d' % (mode,failure)); work.mkdir()
                setup = ('set -eu\nwork=$WORK\nbuild=$work/build\njobs=2\ntools_only=$MODE\n'
                         'fail() { exit 73; }\nmake() { printf "%s\\n" "$@" > "$work/args"; [ "$FAIL" = 0 ]; }\n')
                result = subprocess.run(['sh'], input=setup+block+'\necho FULL_CONTINUATION\n',
                    env=dict(os.environ, WORK=str(work), MODE=str(mode), FAIL=str(failure)), text=True, capture_output=True)
                self.assertEqual(result.returncode, 73 if failure else 0)
                self.assertEqual('FULL_CONTINUATION' in result.stdout, mode == 0)
                self.assertFalse((work/'install').exists())
                if mode:
                    self.assertEqual((work/'args').read_text().splitlines()[-1], '__tooldeps__')
                if mode and not failure:
                    self.assertFalse(json.loads((work/'tools-only.json').read_text())['complete_runtime'])
                else:
                    self.assertFalse((work/'tools-only.json').exists())

    def test_selector_preserves_both_architectures_and_refuses_manual_flags(self):
        source = (ROOT / 'tools/build_wine_ps5.sh').read_text()
        block = source[source.index('case " ${CFLAGS:-}'):source.index('# Reconfigure whenever')]
        program = 'set -eu\nfail() { exit 73; }\nps5opengl_sdk=\ncompile_check_only=0\n' + block + \
            '\nexport opengl_cflags service_fixture\npython3 -c \'import os,json; print(json.dumps(dict(os.environ)))\'\n'
        clean = {k: v for k, v in os.environ.items() if k not in (
            'CFLAGS', 'CPPFLAGS', 'CROSSCFLAGS', 'x86_64_CFLAGS', 'i386_CFLAGS',
            'PW_WINE_PRIVATE_DISPATCH', 'PW_WINE_SERVICE_FIXTURE')}
        for private, service, status in [('0', '0', 0), ('1', '0', 0), ('1', '1', 0),
                                         ('0', '1', 73), ('1', '2', 73)]:
            env = dict(clean, PW_WINE_PRIVATE_DISPATCH=private, PW_WINE_SERVICE_FIXTURE=service)
            result = subprocess.run(['sh'], input=program, env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, status, result.stderr)
            if not status:
                values = json.loads(result.stdout)
                self.assertEqual('PW_WINE_SERVICE_FIXTURE=1' in values['opengl_cflags'], service == '1')
                for arch in ('x86_64_CFLAGS', 'i386_CFLAGS'):
                    self.assertEqual('WINE_PS5_PRIVATE_DISPATCH=1' in values.get(arch, ''), private == '1')
                    self.assertNotIn('PW_WINE_SERVICE_FIXTURE', values.get(arch, ''))
        for key in ('CFLAGS', 'CPPFLAGS', 'CROSSCFLAGS', 'x86_64_CFLAGS', 'i386_CFLAGS'):
            result = subprocess.run(['sh'], input=program,
                                    env=dict(clean, **{key: '-DPW_WINE_SERVICE_FIXTURE=0'}),
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 73)

    def test_actual_owned_pipe_wrapper_and_unchanged_default(self):
        source = (ROOT / 'wine/ps5/pw_wine_compat.c').read_text()
        body = source[source.index('int pw_compat_pipe('):source.index('static struct timeval')]
        program = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/socket.h>
#include "pw_wine_fixture_socket.h"
static int setup_calls, close_calls, fcntl_calls, fail_at, pair_fail;
static unsigned wanted;
static int fake_pair(int a,int b,int c,int f[2])
{ assert(a==AF_UNIX&&b==SOCK_STREAM&&c==0); if(pair_fail){errno=EACCES;return -1;} f[0]=20;f[1]=21;return 0; }
static int fake_shutdown(int fd,int how) { assert(fd==20||fd==21);(void)how;return 0; }
static int fake_close(int fd) { assert(fd==20||fd==21);++close_calls;errno=EBADF;return 0; }
static int fake_flags(int fd,int op,...)
{ assert(fd==20||fd==21);++fcntl_calls; if(op==F_GETFL)return 0x40;
  va_list ap;va_start(ap,op);int value=va_arg(ap,int);va_end(ap);
  assert((op==F_SETFD&&value==FD_CLOEXEC)||(op==F_SETFL&&value==(0x40|O_NONBLOCK)));return 0; }
int pw_wine_fixture_socket(int fd,unsigned flags)
{ assert(fd==20+setup_calls);assert(flags==wanted);++setup_calls;
  if(setup_calls==fail_at){errno=EACCES;return -1;}return 0; }
#define socketpair fake_pair
#define shutdown fake_shutdown
#define close fake_close
#define fcntl fake_flags
''' + body + r'''
int main(void)
{
 int f[2]={-9,-8};wanted=PW_WF_SOCKET_CLOEXEC|PW_WF_SOCKET_NONBLOCK;
 assert(!pw_compat_pipe2(f,O_CLOEXEC|O_NONBLOCK));assert(f[0]==20&&f[1]==21&&close_calls==0);
#ifdef PW_WINE_SERVICE_FIXTURE
 assert(setup_calls==2&&fcntl_calls==0);
 for(int i=1;i<=2;i++){setup_calls=close_calls=0;fail_at=i;f[0]=-9;f[1]=-8;
  assert(pw_compat_pipe2(f,O_CLOEXEC|O_NONBLOCK)==-1&&errno==EACCES);
  assert(close_calls==2&&setup_calls==i&&f[0]==-9&&f[1]==-8);}
#else
 assert(setup_calls==0&&fcntl_calls==6);
#endif
 setup_calls=close_calls=fcntl_calls=0;pair_fail=1;
 assert(pw_compat_pipe2(f,0)==-1&&errno==EACCES);
 assert(!setup_calls&&!close_calls&&!fcntl_calls);
 assert(pw_compat_pipe2(f,0x40000000)==-1&&errno==EINVAL);
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            (path / 'test.c').write_text(program)
            for mode in (0, 1):
                subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                                '-Wno-unused-function', '-I' + str(ROOT / 'wine/ps5'),
                                *(['-DPW_WINE_SERVICE_FIXTURE=1'] if mode else []),
                                str(path / 'test.c'), '-o', str(path / 'test')], check=True)
                subprocess.run([str(path / 'test')], check=True)


if __name__ == '__main__':
    unittest.main()
