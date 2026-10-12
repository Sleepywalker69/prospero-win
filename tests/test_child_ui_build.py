#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Host syntax/cohort controls; does not build or run a PS5 binary."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
class ChildUiBuild(unittest.TestCase):
 def test_default_off_invalid_and_mismatched_cohorts(self):
  compiler=shlex.split(os.environ.get('CC','cc'))
  with tempfile.TemporaryDirectory(prefix='pw-ui-syntax-') as tmp:
   config=Path(tmp)/'wine-child-title-config.h'
   config.write_text('#define PW_WINE_FIXTURE_CHILD_SHA256 "'+'0'*64+'"\n#define PW_WINE_USER_PROFILE_ENABLED 0\n')
   common=[*compiler,'-std=c11','-D_DEFAULT_SOURCE','-O2','-Wall','-Wextra','-Werror','-Wno-enum-compare',
           '-pthread','-fsyntax-only','-DPW_WINE64_SECONDS=1','-DPW_WINE_CHILD_FIXTURE_MODE=1',
           '-I'+tmp,'-iquote',str(ROOT/'tests/wine_child_fixture'),'-iquote',str(ROOT/'tests/wine_child_title_fixture')]
   for enabled,cohort,good in [(0,0,True),(1,1,True),(1,0,False),(0,1,False),(2,2,False)]:
    for source in ['native/pw_wine_child_main.c','native/pw_wine_child_title.c']:
     with self.subTest(enabled=enabled,cohort=cohort,source=source):
      result=subprocess.run([*common,'-DPW_WINE_CHILD_UI_ENABLED='+str(enabled),'-DPW_WINE_CHILD_UI_COHORT='+str(cohort),str(ROOT/source)],capture_output=True,text=True,timeout=30)
      self.assertEqual(result.returncode==0,good,result.stderr)
   for enabled in [0,1]:
    result=subprocess.run([*common,'-DPW_WINE_CHILD_UI_ENABLED='+str(enabled),str(ROOT/'native/wine64_main.c')],capture_output=True,text=True,timeout=30)
    self.assertEqual(result.returncode,0,result.stderr)
 def test_worker_target_preview_preserves_sdk_extension_visibility(self):
  # Compile the actual pre-header feature selection, without host libc headers
  # masking the target distinction. Retained-SDK probes separately check MAP_ANON.
  source=(ROOT/'native/pw_wine_child_main.c').read_text()
  preamble=source.split('#include',1)[0]
  compiler=shlex.split(os.environ.get('CC','cc'))
  for target in [False,True]:
   for enabled in [None,0,1]:
    with self.subTest(target=target,enabled=enabled):
     flags=(['-D__PROSPERO__=1'] if target else [])
     if enabled is not None:flags+=['-DPW_WINE_CHILD_UI_ENABLED='+str(enabled)]
     result=subprocess.run([*compiler,'-std=c11','-Werror','-E','-dM','-x','c',*flags,'-'],
                           input=preamble,capture_output=True,text=True,timeout=10)
     self.assertEqual(result.returncode,0,result.stderr)
     macros=dict(line.removeprefix('#define ').split(' ',1) for line in result.stdout.splitlines()
                 if line.startswith('#define ') and ' ' in line.removeprefix('#define '))
     if target and enabled==1:self.assertNotIn('_POSIX_C_SOURCE',macros)
     else:self.assertEqual(macros.get('_POSIX_C_SOURCE'),'200809L')
     self.assertNotIn('__BSD_VISIBLE',macros) # Do not override SDK-owned internals.
 def test_shell_flag_reaches_both_worker_and_title_inspection(self):
  source=(ROOT/'tools/build_native.sh').read_text()
  self.assertIn('wine_child_ui=${PW_WINE_CHILD_UI_ENABLED:-0}',source)
  self.assertIn('child_ui_args+=(--child-ui)',source)
  self.assertIn('-DPW_WINE_CHILD_UI_ENABLED="$wine_child_ui"',source)
  self.assertIn('--out "$build/wine-child" --llvm-bindir "$llvm_bindir" "${child_ui_args[@]}"',source)
  self.assertIn('--out "$build-wine-child-title-inspection" "${child_ui_args[@]}"',source)
  for value in ['2','yes','1']:
   env=dict(os.environ,PW_WINE_CHILD_UI_ENABLED=value,PW_WINE_CHILD_FIXTURE_MODE='0')
   run=subprocess.run(['bash',str(ROOT/'tools/build_native.sh')],env=env,capture_output=True,text=True,timeout=10)
   self.assertEqual(run.returncode,2,run.stderr)
   self.assertIn('PW_WINE_CHILD_UI_ENABLED',run.stderr)
if __name__=='__main__':unittest.main()
