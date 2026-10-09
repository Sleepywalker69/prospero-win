#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Static translated-I386 capability evidence for the experimental Wine cohort.

The only executed helper is an original host byte-reader using Wine's exact
pure validator header. PE/PRX instructions are never mapped or executed.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
from native_probe_elf import Elf, extract_self, require

EXPORT = '__wine_ps5_private_dispatch_wow64_abi'
BACKEND_MESSAGE = b'wow64: private dispatcher ABI1 uses matched wowprospero.dll translator\n\0'
LIMIT = 32 * 1024 * 1024
RUNNER = r'''#include <stdio.h>
#include <stdlib.h>
#include "wine/pw_private_dispatch_i386.h"
int main(int argc, char **argv) {
    unsigned char length[4], *bytes;
    unsigned long size;
    int valid;
    if (argc != 3 || fread(length,1,4,stdin) != 4) return 2;
    size = length[0] | (unsigned long)length[1]<<8 | (unsigned long)length[2]<<16 | (unsigned long)length[3]<<24;
    if (!size || size > 32UL*1024*1024 || !(bytes=malloc(size))) return 2;
    if (fread(bytes,1,size,stdin) != size || fgetc(stdin) != EOF) { free(bytes); return 2; }
    valid=pw_private_dispatch_i386_image_valid(bytes,size,argv[1],argv[2]);
    free(bytes);
    return valid ? 0 : 1;
}
'''


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= LIMIT,
            'missing, linked or oversized capability artifact: ' + str(path))
    return path.read_bytes()


def mapped_pe(data, machine=0x14c):
    """Map raw sections into a bounded ordinary bytearray, never OS memory."""
    def field(fmt, at):
        require(0 <= at <= len(data)-struct.calcsize(fmt), 'truncated capability PE')
        return struct.unpack_from(fmt, data, at)
    require(64 <= len(data) <= LIMIT and data[:2] == b'MZ', 'invalid capability PE')
    pe, = field('<I', 60)
    require(pe <= 4096-24 and data[pe:pe+4] == b'PE\0\0', 'invalid PE signature')
    kind, count, _, _, _, optional_size, _ = field('<HHIIIHH', pe+4)
    optional = pe+24
    magic = 0x10b if machine == 0x14c else 0x20b
    require(kind == machine and field('<H',optional)[0] == magic and 0<count<=96,
            'wrong capability PE architecture')
    minimum = 144 if machine == 0x14c else 160
    require(optional_size >= minimum and optional+optional_size+count*40<=4096, 'invalid PE optional header')
    image_size, headers = field('<II', optional+56)
    require(0<headers<=min(len(data),4096) and headers<=image_size<=LIMIT and
            optional+optional_size+count*40<=headers, 'invalid bounded PE extent')
    result=bytearray(image_size); result[:headers]=data[:headers]
    occupied=[(0,headers)]; raw_ranges=[(0,headers)]
    for index in range(count):
        span,rva,raw_size,raw = field('<IIII',optional+optional_size+index*40+8)
        extent=max(span,raw_size)
        require(rva+extent<=image_size and raw+raw_size<=len(data), 'PE section exceeds bounded image')
        if extent:
            require(all(rva+extent<=a or b<=rva for a,b in occupied), 'overlapping PE virtual sections')
            occupied.append((rva,rva+extent))
        if raw_size:
            require(all(raw+raw_size<=a or b<=raw for a,b in raw_ranges), 'overlapping PE raw sections')
            raw_ranges.append((raw,raw+raw_size)); result[rva:rva+raw_size]=data[raw:raw+raw_size]
    return bytes(result)


def build_reader(source, directory, compiler):
    source, directory, compiler = Path(source), Path(directory), Path(compiler).resolve(strict=True)
    headers={name: digest(read(source/'include/wine'/name)) for name in
             ('pw_private_dispatch.h','pw_private_dispatch_i386.h')}
    path=directory/'reader.c'; path.write_text(RUNNER)
    output=directory/'reader'
    flags=['-std=c11','-O2','-Wall','-Wextra','-Werror']
    subprocess.run([str(compiler),*flags,'-I'+str(source/'include'),str(path),'-o',str(output)],
                   check=True,capture_output=True,timeout=60)
    return output, {'source_sha256':digest(RUNNER.encode()),'headers':headers,
                    'compiler':{'path':str(compiler),'sha256':digest(compiler.read_bytes()),'flags':flags},
                    'host_reader_sha256':digest(read(output)),
                    'scope':'ordinary allocated byte buffer only; no PE execution or OS image mapping'}


def check_i386(data, anchor, dispatcher, reader):
    mapped=mapped_pe(data)
    run=subprocess.run([str(reader),anchor,dispatcher],input=struct.pack('<I',len(mapped))+mapped,
                       capture_output=True,timeout=30)
    require(run.returncode == 0 and not run.stdout and not run.stderr,
            'actual I386 module-local thunk/dispatcher/relocation contract failed: '+anchor)
    return {'sha256':digest(data),'machine':'I386','anchor':anchor,'dispatcher_export':dispatcher,
            'preferred_base_mapping_sha256':digest(mapped),'contract':'module-local HIGHLOW-relocated thunk and zero dispatcher slot',
            'executed':False}


def function(elf, name):
    symbols=[s for s in elf.symbols if s['name']==name]
    require(len(symbols)==1, 'capability function absent or ambiguous: '+name)
    symbol=symbols[0]
    require(symbol['type']==2 and symbol['binding']==1 and symbol['visibility']==0 and
            symbol['section'] and 0<symbol['size']<=64, 'capability export is not a visible bounded FUNC')
    code=elf.data[elf.offset(symbol['value'],symbol['size'],1):][:symbol['size']]
    return symbol, code


def returns_one(code):
    # The actual compiler may retain an ordinary frame or CET landing pad.
    if code.startswith(bytes.fromhex('f30f1efa')): code=code[4:]
    require(code in (bytes.fromhex('b801000000c3'),bytes.fromhex('554889e5b8010000005dc3')),
            'capability FUNC does not contain the checked return-1 implementation')


def pointer(elf,address):
    elf.offset(address,8,4)
    hits=[r for r in elf.relocations if r['address']<address+8 and address<r['address']+8]
    require(len(hits)==1 and hits[0]['address']==address, 'descriptor pointer has missing/overlapping relocations')
    rel=hits[0]
    if rel['type']==8:
        require(rel['symbol']==0, 'relative descriptor pointer has symbol')
        value=rel['addend']
    else:
        require(rel['type']==1, 'unsupported descriptor pointer relocation')
        sym=elf.symbols[rel['symbol']]
        require(sym['section'], 'descriptor pointer refers to undefined symbol')
        value=sym['value']+rel['addend']
    require(0<value<2**64, 'invalid resolved descriptor pointer')
    return value


def descriptor(elf,name):
    tables=[]
    for p in elf.programs:
        if p[0]!=1 or not p[1]&4: continue
        start=p[2]; end=start+p[5]
        at=elf.data.find(b'PRXDESC1',start,end)
        while at>=0:
            address=p[3]+at-start
            if address%16==0:
                offset=elf.offset(address,16,4)
                version,count=struct.unpack_from('<II',elf.data,offset+8)
                require(version==1 and 0<count<=4096,'invalid PRXDESC1 candidate')
                elf.offset(address,16+16*count,4)
                names={}
                for i in range(count):
                    entry=address+16+16*i
                    text_address=pointer(elf,entry); raw=bytearray()
                    for j in range(256):
                        char=elf.data[elf.offset(text_address+j,1,4)]
                        if not char: break
                        raw.append(char)
                    else: raise ValueError('unterminated PRX descriptor name')
                    text=raw.decode('ascii'); require(text and text not in names,'duplicate/empty PRX descriptor name')
                    names[text]=pointer(elf,entry+8)
                tables.append((address,names))
            at=elf.data.find(b'PRXDESC1',at+1,end)
    require(len(tables)==1 and name in tables[0][1], 'missing/ambiguous actual PRX descriptor capability')
    address= tables[0][1][name]
    return {'descriptor_address':hex(tables[0][0]),'function_address':hex(address)}, address


def module_bytes(work, name):
    require(name in ('ntdll', 'wowprospero'), 'unexpected capability module')
    return read(Path(work) / 'prx/sce_module' / (name + '.prx'))


def native_capability(work):
    paths={'native':work/'build/dlls/ntdll/ntdll.so','shared':work/'prx/ntdll.shared.elf',
           'converted':work/'prx/ntdll.elf'}
    images={key:read(path) for key,path in paths.items()}
    images['self']=module_bytes(work,'ntdll')
    images['recovered']=extract_self(images['self'],module=True)
    result={key:{'bytes':len(value),'sha256':digest(value)} for key,value in images.items()}
    for key in ('native','shared'):
        elf=Elf(images[key],module=True); sym,code=function(elf,EXPORT); returns_one(code)
        result[key].update(function_address=hex(sym['value']),code_sha256=digest(code))
        if key=='shared':
            _,expected=descriptor(elf,EXPORT)
            require(expected==sym['value'],'descriptor capability differs from exported function')
            shared_address,shared_code=expected,code
    for key in ('converted','recovered'):
        elf=Elf(images[key],module=True); table,address=descriptor(elf,EXPORT)
        require(address==shared_address,'conversion moved the capability descriptor target')
        actual=elf.data[elf.offset(address,len(shared_code),1):][:len(shared_code)]
        require(actual==shared_code,'conversion changed actual capability function bytes')
        result[key].update(table,code_sha256=digest(actual))
    converted=Elf(images['converted'],module=True); recovered=Elf(images['recovered'],module=True)
    require(converted.programs==recovered.programs,'SELF changed module program metadata')
    require(all(images['converted'][p[2]:p[2]+p[5]]==images['recovered'][p[2]:p[2]+p[5]]
                for p in converted.programs if p[0]==1), 'SELF changed module LOAD bytes')
    return result


def check_backend(data):
    mapped_pe(data,0x8664)
    require(data.count(BACKEND_MESSAGE)==1 and '\\wowprospero.dll\0'.encode('utf-16le') in data,
            'wow64.dll lacks actual private translator selection marker/path')
    require(b'WINE_PS5_WOW64_CPU\0' not in data and 'WINE_PS5_WOW64_CPU\0'.encode('utf-16le') not in data,
            'wow64.dll retains environment-selected backend fallback')
    return {'sha256':digest(data),'machine':'AMD64','backend':'wowprospero.dll',
            'selection_evidence':'compiled private-only diagnostic/path and absent environment fallback; source and flags also bound',
            'runtime_validated':False}


def check_runtime(work, report, compiler):
    work=Path(work)
    declaration=report.get('private_dispatcher',{})
    require(declaration.get('wow64_abi')==1 and declaration.get('native_wow64_abi_export')==EXPORT,
            'older ABI1-only runtime lacks declared translated-I386 capability')
    with tempfile.TemporaryDirectory(prefix='pw-static-i386-') as directory:
        reader,validator=build_reader(work/'source',Path(directory),compiler)
        modules={name:check_i386(read(work/'pe/i386-windows'/(name+'.dll')),anchor,dispatcher,reader)
                 for name,anchor,dispatcher in [('ntdll','NtClose','__wine_syscall_dispatcher'),
                                                ('win32u','NtUserGetThreadState','Wow64Transition')]}
    backend=check_backend(read(work/'pe/x86_64-windows/wow64.dll'))
    require(report.get('pe',{}).get('x86_64-windows/wow64.dll')==backend['sha256'] and
            all(report.get('pe',{}).get('i386-windows/'+name+'.dll')==value['sha256'] for name,value in modules.items()),
            'WoW64 PE bytes differ from actual build report')
    native=native_capability(work)
    translator=module_bytes(work,'wowprospero')
    require(report.get('prx',{}).get('modules',{}).get('wowprospero',{}).get('sha256')==digest(translator),
            'translator PRX differs from actual build report')
    return {'schema':'pw-private-dispatch-wow64-build/1','abi':1,'native_export':EXPORT,
            'i386_modules':modules,'backend':backend,'native':native,'validator':validator,
            'translator_prx':{'bytes':len(translator),'sha256':digest(translator)},
            'cpu_pe_required_separately':True,'runtime_validated':False,'executed':False}
