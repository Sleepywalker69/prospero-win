#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Explicit compile-only protocol963 source cohort. Never grants a permit."""
import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path
import re
import subprocess
import sys
sys.dont_write_bytecode = True
WINE_COMMIT = '490f6d5dcbb2a5047345b8af88d114bbcaad69a8'
OPTIONAL = ('0001-server-adapter.patch', '0002-server-requests.patch', '0003-neutral-cohort.patch')
ACCEPTED = ('5b4f6fb8d06b5878669ad2ac7ad784ac1e9b37b2596f9e21b51f24325a51cde6',
            '8d3924c4539a064f311d3638e34de3f773d2f5e64a69b8d5ba86beeb2e2f7894')
MARKERS = {'__wine_ps5_focus_abi': 1, '__wine_ps5_focus_protocol': 963, '__wine_ps5_focus_mode': 1}

def need(value, message):
    if not value: raise ValueError(message)

def sha(data): return hashlib.sha256(data).hexdigest()

def contract(root):
    root = Path(root).resolve(strict=True)
    inputs = sorted(set(p for pattern in ('wine/patches/*.patch', 'wine/focus-neutral/*.patch',
        'wine/ps5/*.c', 'wine/ps5/*.h', 'native/*.c', 'native/*.h',
        'tools/*focus*.py', 'tools/build_wine_ps5.sh', 'tools/build_native.sh',
        'tools/build_wine_service_child.py', 'tools/wine_creation_abi.py',
        'tools/check_private_dispatch_abi.py', 'tools/package_windows_child_fixture.py')
        for p in root.glob(pattern)))
    need(tuple(p.name for p in (root/'wine/focus-neutral').glob('*.patch')) == OPTIONAL or
         tuple(sorted(p.name for p in (root/'wine/focus-neutral').glob('*.patch'))) == OPTIONAL,
         'optional patch inventory differs')
    for name, digest in zip(OPTIONAL, ACCEPTED):
        need(sha((root/'wine/focus-neutral'/name).read_bytes()) == digest, 'accepted focus source changed')
    records = {}
    for p in inputs:
        need(p.is_file() and not p.is_symlink(), 'linked/missing cohort source')
        records[str(p.relative_to(root))] = sha(p.read_bytes())
    identity = sha(json.dumps({'wine_commit':WINE_COMMIT,'sources':records},sort_keys=True,separators=(',',':')).encode())
    return {'schema':'pw-focus-neutral/1','abi':1,'protocol':963,'mode':1,'source_sha256':identity,
            'input_enabled':False,'provider_enabled':False,'native_entry_enabled':False,
            'package_enabled':False,'runtime_validated':False,'wine_commit':WINE_COMMIT,'sources':records}

def checked(value):
    need(isinstance(value,dict) and re.fullmatch('[0-9a-f]{64}',str(value.get('source_sha256',''))), 'bad focus source identity')
    for k,v in {'schema':'pw-focus-neutral/1','abi':1,'protocol':963,'mode':1,'input_enabled':False,
                'provider_enabled':False,'native_entry_enabled':False,'package_enabled':False,'runtime_validated':False,
                'wine_commit':WINE_COMMIT}.items():
        need(type(value.get(k)) is type(v) and value[k]==v,'focus contract differs: '+k)
    need(set(value)=={'schema','abi','protocol','mode','source_sha256','input_enabled','provider_enabled','native_entry_enabled','package_enabled','runtime_validated','wine_commit','sources'}, 'unexpected focus contract fields')
    need(isinstance(value.get('sources'),dict) and value['sources'],'missing focus sources')
    need(all(isinstance(k,str) and not Path(k).is_absolute() and '..' not in Path(k).parts and isinstance(v,str) and re.fullmatch('[0-9a-f]{64}',v) for k,v in value['sources'].items()), 'malformed focus source record')
    need(value['source_sha256']==sha(json.dumps({'wine_commit':WINE_COMMIT,'sources':value['sources']},sort_keys=True,separators=(',',':')).encode()),'focus source digest differs')
    return value

def header(value):
    value=checked(value); digest=value['source_sha256']
    return ('/* Generated, source-bound, compile-only neutral cohort. */\n#ifndef PW_FOCUS_BUILD_H\n#define PW_FOCUS_BUILD_H\n'
            '#define PW_FOCUS_BUILD_MODE 1\n#define PW_FOCUS_BUILD_PROTOCOL 963\n'
            '#define PW_FOCUS_BUILD_SOURCE_SHA256 "'+digest+'"\n'+
            ''.join('#define PW_FOCUS_SOURCE_WORD_'+str(i)+' 0x'+digest[i*8:i*8+8]+'u\n' for i in range(8))+'#endif\n')

def markers(value):
    return {**MARKERS, **{'__wine_ps5_focus_source_'+str(i):int(checked(value)['source_sha256'][i*8:i*8+8],16) for i in range(8)}}

def verify_default_source(root, source):
    """Replay the pinned default index without changing the caller's index/tree."""
    root,source=Path(root).resolve(strict=True),Path(source).resolve(strict=True)
    need(subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip()==WINE_COMMIT,
         'focus staging requires pinned Wine Git HEAD')
    need(not subprocess.check_output(['git','-C',str(source),'diff','--name-only'],text=True).strip(),
         'focus staging source differs from its index')
    need(not subprocess.check_output(['git','-C',str(source),'ls-files','--others'],text=True).strip(),
         'focus staging source contains untracked inputs')
    actual=subprocess.check_output(['git','-C',str(source),'write-tree'],text=True).strip()
    with tempfile.TemporaryDirectory(prefix='pw-focus-index-') as d:
        env=dict(os.environ,GIT_INDEX_FILE=str(Path(d)/'index'))
        subprocess.run(['git','-C',str(source),'read-tree',WINE_COMMIT],env=env,check=True)
        for patch in sorted((Path(root)/'wine/patches').glob('*.patch')):
            subprocess.run(['git','-C',str(source),'apply','--cached',str(patch)],env=env,check=True)
        expected=subprocess.check_output(['git','-C',str(source),'write-tree'],env=env,text=True).strip()
    need(actual==expected,'focus staging default patch index differs')


def stage(root, source, output):
    raw_output=Path(output).absolute()
    need(not any(p.is_symlink() for p in (raw_output,*raw_output.parents)), 'linked focus receipt path')
    root,source,output=(Path(p).resolve() for p in (root,source,raw_output)); value=contract(root)
    verify_default_source(root, source)
    need(not output.exists() and not output.is_symlink(),'focus receipt already exists')
    need('#define SERVER_PROTOCOL_VERSION 962' in (source/'include/wine/server_protocol.h').read_text(),'focus stage requires exact default protocol962 source')
    need(not (source/'include/wine/pw_focus_build.h').exists(),'focus build header already exists')
    for name in OPTIONAL:
        subprocess.run(['git','-C',str(source),'apply','--index',str(root/'wine/focus-neutral'/name)],check=True)
    need('#define SERVER_PROTOCOL_VERSION 963' in (source/'include/wine/server_protocol.h').read_text(),'focus patch protocol differs')
    (source/'include/wine/pw_focus_build.h').write_text(header(value))
    output.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
    return value

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--repo',type=Path,required=True);p.add_argument('--source',type=Path);p.add_argument('--output',type=Path);a=p.parse_args()
    need((a.source is None)==(a.output is None),'stage needs both source and output')
    value=stage(a.repo,a.source,a.output) if a.source else contract(a.repo)
    print(json.dumps(value,sort_keys=True))
if __name__=='__main__':main()
