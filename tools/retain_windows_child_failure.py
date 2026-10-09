#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Retain bounded unaccepted build bytes and matching public sources on failure.

Never consumes a prefix, registry, home directory or installer. This is diagnostic
retention, not a release manifest or a claim that an incomplete build passed.
"""
from __future__ import annotations
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import os
import re
import stat
import subprocess

MAX_FILE=256*1024*1024
MAX_TOTAL=2*1024*1024*1024
MAX_FILES=10000


def sha(data):return hashlib.sha256(data).hexdigest()


class Collector:
    def __init__(self,out):
        self.out=Path(out).absolute()
        if self.out.exists() or self.out.is_symlink():raise ValueError('retention output must be fresh')
        for parent in self.out.parents:
            if parent.is_symlink():raise ValueError('retention output has symlink parent')
        self.out.mkdir(parents=True)
        self.files={};self.omissions=[];self.total=0

    def put(self,name,data,mode=0o644):
        if not name or Path(name).is_absolute() or any(p in ('','..','.') for p in name.split('/')):
            raise ValueError('unsafe retained path')
        if name in self.files:raise ValueError('duplicate retained path')
        if len(data)>MAX_FILE or self.total+len(data)>MAX_TOTAL or len(self.files)>=MAX_FILES:
            self.omissions.append({'path':name,'reason':'bounded retention limit','bytes':len(data)});return
        destination=self.out/name;destination.parent.mkdir(parents=True,exist_ok=True)
        destination.write_bytes(data);destination.chmod(0o644)
        self.files[name]={'bytes':len(data),'sha256':sha(data),'original_mode':mode,'retained_mode':0o644}
        self.total+=len(data)

    def copy(self,path,base,label):
        path,base=Path(path),Path(base)
        name=label+'/'+path.relative_to(base).as_posix()
        if not path.exists() and not path.is_symlink():return
        if not path.is_relative_to(base) or any(p.is_symlink() for p in (path,*path.parents) if p==base or p.is_relative_to(base)):
            self.omissions.append({'path':name,'reason':'symlink input'});return
        info=path.lstat()
        if not stat.S_ISREG(info.st_mode):
            self.omissions.append({'path':name,'reason':'nonregular input'});return
        if info.st_size>MAX_FILE:
            self.omissions.append({'path':name,'reason':'file retention limit','bytes':info.st_size});return
        self.put(name,path.read_bytes(),stat.S_IMODE(info.st_mode))

    def tree(self,base,label,suffixes=None):
        base=Path(base)
        if not base.is_dir() or base.is_symlink():return
        for path in sorted(base.rglob('*')):
            if path.is_dir() and not path.is_symlink():continue
            if suffixes is None or path.suffix in suffixes:self.copy(path,base,label)

    def finish(self,inputs):
        value={'schema':'pw-windows-child-unaccepted-build-evidence/1','accepted':False,
               'runtime_validated':False,'inputs':inputs,'files':self.files,'omissions':self.omissions,
               'bytes':self.total,'raw_prefix_or_registry_retained':False,
               'scope':'partial diagnostic artifacts only; source archives and original file modes retained separately'}
        (self.out/'UNACCEPTED-BUILD.json').write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
        return value


def archive_git(collector,root,name):
    root=Path(root)
    if not (root/'.git').exists():return {'available':False}
    def run(*args):return subprocess.run(['git','-C',str(root),*args],check=True,capture_output=True,timeout=120).stdout
    commit=run('rev-parse','HEAD').decode().strip();tree=run('rev-parse','HEAD^{tree}').decode().strip()
    payload=run('archive',commit)
    collector.put('sources/'+name+'.tar.gz',gzip.compress(payload,mtime=0))
    return {'commit':commit,'tree':tree,'archive_uncompressed_sha256':sha(payload),
            'tracked_source_clean':not run('diff','HEAD','--name-only').strip()}


def collect_title_inspection(collector,title_build):
    sibling=title_build.with_name(title_build.name+'-wine-child-title-inspection')
    inspection=sibling/'inspection'
    if not sibling.is_dir() or sibling.is_symlink() or not inspection.is_dir() or inspection.is_symlink():return
    for path in sorted(inspection.glob('*-tool.log')):
        if re.fullmatch(r'[0-9]{3,}-tool\.log',path.name):
            collector.copy(path,sibling,'target/title-inspection')


def collect(args):
    c=Collector(args.out);identities={}
    # Preserve source first, even if later large diagnostics hit their bound.
    for name,root in [('project',args.repo),('title-foundation',args.title_foundation),('prx-foundation',args.foundation)]:
        try:identities[name]=archive_git(c,root,name)
        except (OSError,subprocess.SubprocessError) as error:
            identities[name]={'available':False,'error':type(error).__name__}
    for path in (args.wine_archive,args.sdk_source_archive):c.copy(path,path.parent,'sources')
    c.tree(args.repo/'LICENSES','notices/project/LICENSES')
    for name in ('LICENSE','NOTICE.md','LICENSING.md','THIRD_PARTY.md'):c.copy(args.repo/name,args.repo,'notices/project')
    for label,base in [('title-foundation',args.title_foundation),('prx-foundation',args.foundation)]:
        for pattern in ('LICENSE*','COPYING*','NOTICE*'):
            for path in sorted(base.glob(pattern)):
                if path.is_file():c.copy(path,base,'notices/'+label)
    for label,base in [('tls',args.tls_work),('freetype',args.wine_work/'freetype'),('zlib',args.foundation/'.deps/native/zlib')]:
        if base.is_dir():
            for path in sorted(base.rglob('*')):
                if path.name.endswith(('.tar.gz','.tar.xz','.tar.bz2','.tgz')) or path.name.startswith(('LICENSE','COPYING','NOTICE')):
                    if path.is_file():c.copy(path,base,'dependency-sources/'+label)
    c.tree(args.wine_work/'prx','target/wine/prx')
    c.tree(args.wine_work/'pe','target/wine/pe')
    for name in ('report.json','private-dispatch-pe.json'):
        c.copy(args.wine_work/name,args.wine_work,'target/wine')
    for name in ('ntdll','win32u','winevulkan','opengl32','ws2_32','crypt32','dwrite','secur32'):
        path=args.wine_work/'build/dlls'/name/(name+'.so')
        c.copy(path,args.wine_work,'target/wine')
    c.tree(args.title_build/'wine-child','target/child')
    collect_title_inspection(c,args.title_build)
    for path in sorted(args.title_build.glob('*')):
        if path.is_file() and (path.suffix in ('.elf','.o','.json','.h','.c') or path.name=='eboot.bin'):
            c.copy(path,args.title_build,'target/title')
    c.tree(args.title_build/'import-stubs','target/title/import-stubs')
    app=args.repo/'dist/PPSA99995-windows-child-fixture'
    for name in ('eboot.bin','native-wine-child.self','native-wine-child-build.json','sce_module/libc.prx','lapy.elf'):
        c.copy(app/name,app,'target/app')
    # Only actual SDK providers and wrapper bytes, not a blanket SDK/tool upload.
    sdk=args.title_foundation/'.deps/native/ps5-payload-sdk'
    for name in ('libkernel.so','libSceLibcInternal.so','libSceSystemService.so'):
        c.copy(sdk/'target/lib'/name,sdk,'providers/sdk')
    c.copy(sdk/'bin/prospero-clang',sdk,'providers/sdk')
    return c.finish(identities)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('repo','title-foundation','foundation','wine-work','tls-work','title-build','wine-archive','sdk-source-archive','out'):
        p.add_argument('--'+name,type=Path,required=True)
    result=collect(p.parse_args())
    print('Retained',len(result['files']),'unaccepted diagnostic files;',len(result['omissions']),'bounded omissions.')

if __name__=='__main__':main()
