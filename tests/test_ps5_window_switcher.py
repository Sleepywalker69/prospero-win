#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Compose real PS5 driver patches; execute its exact window/input/clip bodies.

Boundary USER calls are inert models. This proves host contracts, not PS5 or
Wine runtime behavior. Requires headers from the pinned Wine source checkout.
"""
import argparse, hashlib, json, pathlib, re, subprocess
from test_ps5_extended_keys import function

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--wine-source',required=True,type=pathlib.Path)
    p.add_argument('--out',required=True,type=pathlib.Path)
    p.add_argument('--cc',default='cc')
    p.add_argument('--ubsan',action='store_true')
    a=p.parse_args();root=pathlib.Path(__file__).resolve().parent.parent
    a.out.mkdir(parents=True,exist_ok=False)
    composed=a.out/'composed';composed.mkdir()
    # Makefile output lives below this checkout. Give the scratch composition
    # its own repository so git apply cannot inherit the parent's path prefix
    # and silently skip every driver hunk as outside its current directory.
    subprocess.run(['git','init','--quiet',str(composed)],check=True)
    for patch in sorted((root/'wine/patches').glob('*.patch')):
        if '+++ b/dlls/win32u/ps5drv.c' in patch.read_text():
            subprocess.run(['git','apply','--include=dlls/win32u/ps5drv.c',str(patch)],cwd=composed,check=True)
    driver=(composed/'dlls/win32u/ps5drv.c').read_text()
    supplied=a.wine_source/'dlls/win32u/ps5drv.c'
    if supplied.exists() and supplied.read_text()!=driver:
        raise RuntimeError('supplied composed PS5 driver differs from this repository patch chain')
    declarations='\n'.join(re.search(r'struct '+name+r'\n\{.*?\n\};',driver,re.S).group() for name in ['ps5_input','ps5_window','ps5_surface','ps5_window_choice'])
    names=['find_window','ps5_surface_set_clip','ps5_surface_flush','ps5_surface_destroy','ps5_WindowPosChanged','ps5_DestroyWindow','last_shown_window','send_mouse','is_extended_key','window_choice_live','cycle_window','window_input_generation','release_window_input','ps5_ProcessEvents']
    bodies='\n'.join(function(driver,re.search(r'^static [^\n]+\b'+name+r'\(',driver,re.M).group()) for name in names)
    fixture=root/'tests/fixtures/ps5_window_switcher.c'
    generated=a.out/'control.c';generated.write_text(fixture.read_text().replace('/* ACTUAL_DECLARATIONS */',declarations).replace('/* ACTUAL_FUNCTIONS */',bodies))
    binary=a.out/'control'
    flags=['-std=gnu11','-D_GNU_SOURCE','-D__WINESRC__','-fshort-wchar','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-I'+str(a.wine_source.resolve()/'include'),'-I'+str(root),'-pthread']
    if a.ubsan:flags+=['-fsanitize=undefined','-fno-sanitize-recover=all']
    commands=[]
    for name,argv in [('compile',[a.cc,*flags,str(generated),str(root/'wine/ps5/pw_wine_sink.c'),'-o',str(binary)]),('run',[str(binary)])]:
        result=subprocess.run(argv,capture_output=True,text=True,timeout=60)
        (a.out/(name+'.log')).write_text(result.stdout+result.stderr)
        commands.append({'name':name,'argv':argv,'exit':result.returncode})
        print(result.stdout+result.stderr,end='')
        if result.returncode:break
    sha=lambda b:hashlib.sha256(b).hexdigest()
    (a.out/'RESULT.json').write_text(json.dumps({'scope':'Exact composed PS5 driver bodies with real Wine headers and real input sink; USER boundary mocks; no Wine/PS5 execution','source_sha256':sha(driver.encode()),'functions_sha256':sha(bodies.encode()),'fixture_sha256':sha(fixture.read_bytes()),'commands':commands},indent=2)+'\n')
    return result.returncode
if __name__=='__main__':raise SystemExit(main())
