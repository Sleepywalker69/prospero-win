#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Explicit native-only derivative of one immutable matched donor; never executes targets."""
from __future__ import annotations
import argparse, gzip, hashlib, json, os, re, shutil, stat, subprocess, tarfile, zipfile
from pathlib import Path
import package_windows_child_fixture as pkg

DONOR = {'project': {'commit':'7acf08abea63640a737c7cec0cae4c0da61b82f5',
                    'tree':'e28679c3d6c1a8735b9069509062c4114c166c47'},
         'run':'38241186538','attempt':'1','artifact':11747362547,
         'zip':{'bytes':754378842,'sha256':'542e980e3ac21d3064481daf22a5817c666aa35a194e55a22cf3bd7dfd88a6d8'},
         'tar':{'bytes':758102289,'sha256':'d8f35234b740af9c5517a4c5ef441aa9574aa0518c563b3e9969c1bf172a67e8'},
         'evidence_artifact':11747637406,
         'evidence':{'bytes':192181819,'sha256':'d795a5dedf06c42c51b9a0db15376c4777e5ac582969bd8559257e2cde67e85e'}}
REPLACED = ('PPSA99995/eboot.bin','PPSA99995/native-wine-child.self',
            'PPSA99995/native-wine-child-build.json','PPSA99995/lapy.elf')
# No Wine, PE producer, prefix, ABI or helper source change is admitted.
ALLOWED_SOURCE_CHANGES = {
 'native/pw_wine_child_data.c','native/pw_wine_child_data.h',
 'native/pw_wine_child_wire.c','native/pw_wine_child_wire.h',
 'native/pw_wine_child_main.c','native/pw_wine_fixture_owner.c','native/pw_wine_child_title.c',
 'tools/build_wine_service_child.py','tools/build_native.sh',
 'tools/derived_native_package.py','tests/test_derived_native_package.py',
 '.github/workflows/derived-native-child.yml','Makefile','PUBLICATION_ALLOWLIST.txt',
 'tests/test_pw_wine_child_wire.c','tests/test_pw_wine_fixture_owner.c',
 'tests/test_wine_service_child_build.py',
 'tests/test_wine_child_data.c','tests/test_wine_child_progress_failure.c','tests/test_pw_wine_child_title.c',
 '.github/workflows/export-host-compiler-cache.yml','docs/host-cache-113-save.json',
 'tests/test_export_host_compiler_cache.py','tools/export_host_compiler_cache.py',
 'tests/test_wine_net_wire.c','tests/test_wine_user_wire.c'}
MANIFEST = 'provenance/derived-native.json'
require = pkg.require

def producer(environment):
    require(environment.get('GITHUB_REPOSITORY')=='Sleepywalker69/prospero-win','wrong native producer repository')
    run,attempt=environment.get('GITHUB_RUN_ID'),environment.get('GITHUB_RUN_ATTEMPT')
    require(isinstance(run,str) and re.fullmatch('[1-9][0-9]*',run) and
            isinstance(attempt,str) and re.fullmatch('[1-9][0-9]*',attempt),'invalid native producer run/attempt')
    return {'native_run_url':'https://github.com/Sleepywalker69/prospero-win/actions/runs/'+run,
            'native_run_attempt':attempt}

def verify_producer(record):
    url,attempt=record.get('native_run_url'),record.get('native_run_attempt')
    require(isinstance(url,str) and
            re.fullmatch(r'https://github\.com/Sleepywalker69/prospero-win/actions/runs/[1-9][0-9]*',url) and
            isinstance(attempt,str) and re.fullmatch('[1-9][0-9]*',attempt),
            'invalid native producer receipt')
    return {'native_run_url':url,'native_run_attempt':attempt}

def git(root,*args):
    return subprocess.run(['git','-C',str(root),*args],check=True,capture_output=True,timeout=120).stdout

def project(root):
    require(not git(root,'status','--porcelain','--untracked-files=no').strip(),'dirty tracked source')
    return {'commit':git(root,'rev-parse','HEAD').decode().strip(),
            'tree':git(root,'rev-parse','HEAD^{tree}').decode().strip()}

def fresh(path):
    path=Path(path).absolute()
    require(not path.exists() and not path.is_symlink(),'output already exists')
    require(not any(p.is_symlink() for p in path.parents),'symlink output parent')
    path.mkdir(parents=True)
    return path

def write(root,name,data,mode=0o644):
    target=root/pkg.safe_name(name)
    target.parent.mkdir(parents=True,exist_ok=True)
    with target.open('xb') as f:f.write(data)
    target.chmod(mode)

def copy(root,name,source,mode=None):
    source=Path(source)
    pkg.prefix.ordinary(source)
    target=root/pkg.safe_name(name);target.parent.mkdir(parents=True,exist_ok=True)
    with source.open('rb') as a,target.open('xb') as b:shutil.copyfileobj(a,b,1<<20)
    target.chmod(mode if mode is not None else stat.S_IMODE(source.stat().st_mode))
    require(pkg.record(target)==pkg.record(source),'copy changed bytes')

def unpack_zip(path,out,expected):
    require(pkg.record(path)==expected,'original ZIP pin differs')
    out=fresh(out);names=set();total=0
    with zipfile.ZipFile(path) as z:
        require(len(z.infolist())<=20000,'too many ZIP members')
        for item in z.infolist():
            name=pkg.safe_name(item.filename.rstrip('/') if item.is_dir() else item.filename)
            require(name.casefold() not in names,'ZIP collision')
            names.add(name.casefold())
            kind=(item.external_attr>>16)&0o170000
            require(kind in (0,stat.S_IFREG,stat.S_IFDIR) and not item.flag_bits&1,'ZIP link/special/encryption')
            require(item.file_size<=2<<30,'ZIP member exceeds bound')
            total+=item.file_size;require(total<=4<<30,'ZIP exceeds bound')
            if item.is_dir():(out/name).mkdir(parents=True,exist_ok=True);continue
            target=out/name;target.parent.mkdir(parents=True,exist_ok=True)
            with z.open(item) as a,target.open('xb') as b:
                used=0
                while chunk:=a.read(1<<20):
                    used+=len(chunk);require(used<=item.file_size,'ZIP expansion differs');b.write(chunk)
                require(used==item.file_size,'ZIP length differs')
            target.chmod(0o644)
    return out

def unpack_donor(path,out):
    require(pkg.record(path)==DONOR['tar'],'original TAR pin differs')
    pkg.verify_archive(path)
    out=fresh(out)
    with tarfile.open(path,'r:gz') as t:
        for item in t:
            name=pkg.safe_name(item.name.rstrip('/') if item.isdir() else item.name)
            require(item.isdir() or item.isreg(),'TAR special member')
            if item.isdir():(out/name).mkdir(parents=True,exist_ok=True)
            else:
                target=out/name;target.parent.mkdir(parents=True,exist_ok=True)
                with t.extractfile(item) as a,target.open('xb') as b:shutil.copyfileobj(a,b,1<<20)
            (out/name).chmod(item.mode)
    pkg.verify_directory(out)
    return out

def compatible_sources(root):
    identity=project(root)
    require(git(root,'rev-parse',DONOR['project']['commit']+'^{tree}').decode().strip()==DONOR['project']['tree'],
            'donor Git tree differs')
    names=git(root,'diff','--name-only',DONOR['project']['commit'],identity['commit']).decode().splitlines()
    require(set(names)<=ALLOWED_SOURCE_CHANGES,'unreviewed donor source delta: '+str(sorted(set(names)-ALLOWED_SOURCE_CHANGES)))
    records={}
    for name in sorted(names):
        require((root/name).is_file() and not (root/name).is_symlink(),'source deletion/link refused')
        records[name]={**pkg.record(root/name),'mode':stat.S_IMODE((root/name).stat().st_mode)}
    return {'donor_project':DONOR['project'],'native_project':identity,'changed_sources':records,
            'protected_source_tree_unchanged':True}

def donor_state(contract):
    value=pkg.read_json(Path(contract))
    require(value.get('schema')=='pw-derived-native-donor/1' and value.get('donor')==DONOR,'unrecognized donor contract')
    root=Path(value['package']).resolve(strict=True)
    require(pkg.record(root/pkg.MANIFEST)=={'bytes':2459343,'sha256':'d07daa128a72e8ca522fded71d951014743014d47c2bc2cfd77cde27180e0b09'},'original manifest pin differs')
    require(pkg.record(root/'SHA256SUMS')=={'bytes':1430772,'sha256':'b9e911835c615bcb25db40c3b409cda547f9e6e929ad622dd34edacea747d0c0'},'original checksum pin differs')
    manifest=pkg.verify_directory(root)
    require(manifest['project']==DONOR['project'] and str(manifest.get('run_attempt'))==DONOR['attempt'] and
            manifest['run_url'].endswith('/'+DONOR['run']),'donor package identity differs')
    require(pkg.inventory(root)==value['inventory'],'donor package changed')
    return value,root

def restore_runtime(evidence,out,package):
    base=evidence/'unaccepted-build-inputs'
    meta=pkg.read_json(base/'UNACCEPTED-BUILD.json')
    require(meta.get('schema')=='pw-windows-child-unaccepted-build-evidence/1','missing original evidence index')
    target=base/'target/wine'
    out=fresh(out)
    records={}
    for name,row in meta['files'].items():
        if not name.startswith('target/wine/'):continue
        source=base/name
        require(pkg.record(source)=={k:row[k] for k in ('bytes','sha256')},'retained runtime bytes differ')
        relative=name[len('target/wine/'):]
        copy(out,relative,source,row['original_mode'])
        records[relative]={**pkg.record(source),'mode':row['original_mode']}
    require(records,'retained runtime absent')
    for branch,dest in [('prx/sce_module','PPSA99995/win/wine/lib/wine/x86_64-unix'),
                        ('pe','PPSA99995/win/wine/lib/wine')]:
        for path in (out/branch).rglob('*'):
            if path.is_file():
                relative=path.relative_to(out/branch)
                require(pkg.record(path)==pkg.record(package/dest/relative),'donor runtime package/evidence mismatch')
    require(pkg.record(out/'report.json')==pkg.record(package/'provenance/wine-build.json'),'Wine report differs')
    for name in ('build/dlls/ntdll/ntdll.so','prx/ntdll.shared.elf','private-dispatch-pe.json'):
        require(name in records,'required ABI input omitted: '+name)
    return records

def prepare(root,package_zip,evidence_zip,out):
    out=fresh(out)
    outer=unpack_zip(package_zip,out/'outer',DONOR['zip'])
    members=[p for p in outer.rglob('*') if p.is_file()]
    require(len(members)==1 and members[0].name=='windows-child-fixture.tar.gz','unexpected original package wrapper')
    package=unpack_donor(members[0],out/'package')
    evidence=unpack_zip(evidence_zip,out/'evidence',DONOR['evidence'])
    runtime=out/'runtime';records=restore_runtime(evidence,runtime,package)
    fixtures=out/'fixtures';fixtures.mkdir()
    original=fixtures/'original';original.mkdir()
    copy(original,'fixture-source.json',package/'provenance/fixture-source.json')
    for name in ('parent.exe','child.exe'):
        copy(original,name,package/'console/data/prospero-win/prefixes/windows-child-fixture-v1/drive_c/windows-child-fixture'/name)
    import windows_child_user_package as user
    import windows_child_network_package as net
    for label,module in [('user',user),('network',net)]:
        destination=fixtures/label;destination.mkdir()
        for path in (package/module.REFERENCE_ROOT).iterdir():
            require(path.is_file() and not path.is_symlink(),'nonflat original reference')
            copy(destination,path.name,path)
        # REFERENCE_ROOT is the complete original flat producer directory,
        # including role images, copied source/recipe, dependency logs and receipts.
        for name in module.IMAGES:
            source=package/('console/data/prospero-win/prefixes/'+module.SLUG+'/drive_c/'+
                            ('windows-child-user' if label=='user' else 'windows-child-net'))/name
            if not (destination/name).exists():copy(destination,name,source)
    value={'schema':'pw-derived-native-donor/1','donor':DONOR,'package':str(package),
           'runtime':str(runtime),'evidence_zip':str(Path(evidence_zip).resolve()),'runtime_records':records,'inventory':pkg.inventory(package),
           'source_compatibility':compatible_sources(root)}
    write(out,'donor-contract.json',pkg.json_bytes(value))
    return out/'donor-contract.json'

def admit_runtime(root,runtime,abi,contract):
    value,package=donor_state(contract)
    require(Path(runtime).resolve()==Path(value['runtime']).resolve(),'wrong donor runtime directory')
    evidence=Path(value['evidence_zip'])
    require(pkg.record(evidence)==DONOR['evidence'],'original evidence ZIP changed')
    with zipfile.ZipFile(evidence) as z:
        matches=[i for i in z.infolist() if i.filename=='unaccepted-build-inputs/UNACCEPTED-BUILD.json']
        require(len(matches)==1 and matches[0].file_size<=16<<20,'ambiguous evidence index')
        index=pkg.decode_json(z.read(matches[0]))
    expected={n[len('target/wine/'):]:{k:row[k] for k in ('bytes','sha256')}|{'mode':row['original_mode']}
              for n,row in index['files'].items() if n.startswith('target/wine/')}
    require(value['runtime_records']==expected,'donor runtime index differs')
    for name,row in expected.items():
        path=Path(runtime)/pkg.safe_name(name)
        require({**pkg.record(path),'mode':stat.S_IMODE(path.stat().st_mode)}==row,'restored runtime changed')
        package_name=('PPSA99995/win/wine/lib/wine/x86_64-unix/'+name[len('prx/sce_module/'):]
                      if name.startswith('prx/sce_module/') else
                      'PPSA99995/win/wine/lib/wine/'+name[len('pe/'):] if name.startswith('pe/') else None)
        if package_name:require(pkg.record(path)==pkg.record(package/package_name),'runtime overlap differs')
    for name in ('report.json','private-dispatch-pe.json','build/dlls/ntdll/ntdll.so','prx/ntdll.shared.elf'):
        require(name in expected,'required donor ABI input missing')
    require(abi==pkg.read_json(package/'provenance/private-dispatch-abi.json'),'new native runtime ABI differs from donor')
    compatibility=compatible_sources(Path(root))
    require(compatibility==value['source_compatibility'],'source compatibility changed')
    return {'schema':'pw-derived-native-admission/1','donor':DONOR,'source_compatibility':compatibility,
            'abi_sha256':pkg.record(package/'provenance/private-dispatch-abi.json')['sha256'],
            'wine_build_sha256':pkg.record(package/'provenance/wine-build.json')['sha256'],
            'runtime_inventory_sha256':hashlib.sha256(pkg.json_bytes(value['runtime_records'])).hexdigest(),
            'reference_results':'inherited; not rerun','console_execution_verified':False}

def title_inputs(root,service_work,fixture,user_fixture,run_id,run_attempt,network_fixture,contract):
    from build_wine_service_child import title_profiles_input_contract
    value,package=donor_state(contract)
    compatibility=compatible_sources(Path(root))
    require(compatibility==value['source_compatibility'],'title source compatibility changed')
    new=pkg.read_json(Path(service_work)/'native-wine-child-build.json')
    require(new['project']==compatibility['native_project'] and new.get('derived_donor',{}).get('donor')==DONOR,
            'new native lacks donor admission')
    result,header,pair,user,net=title_profiles_input_contract(Path(root),package/'PPSA99995',fixture,user_fixture,
                                              DONOR['run'],DONOR['attempt'],network_fixture)
    result.update(project=new['project'],service_manifest_sha256=pkg.record(Path(service_work)/'native-wine-child-build.json')['sha256'],
                  donor_reference={'project':DONOR['project'],'run_id':DONOR['run'],'run_attempt':DONOR['attempt'],
                                   'reference_results':'inherited; not rerun'})
    return result,header,pair,user,net

def inherited_name(name):
    pkg.safe_name(name)
    if name=='provenance':return 'provenance/donor113'
    if name=='sources':return 'sources/donor113'
    if name in REPLACED:return 'provenance/donor113/original-native/'+name.split('/',1)[1]
    if name.startswith('provenance/'):return 'provenance/donor113/'+name[len('provenance/'):]
    if name.startswith('sources/'):return 'sources/donor113/'+name[len('sources/'):]
    if name in ('BUILD-INFO.txt','SHA256SUMS'):return 'provenance/donor113/'+name
    return name

def verify_payload(donor,actual):
    expected={inherited_name(n):v for n,v in donor.items()}
    for name,row in expected.items():require(actual.get(name)==row,'inherited file changed: '+name)
    for name,row in actual.items():
        if row['type']!='file' or name in expected:continue
        require(name in REPLACED or name in ('BUILD-INFO.txt','SHA256SUMS',MANIFEST) or
                name.startswith(('provenance/native/','sources/native/')),'unapproved derived addition: '+name)

def check_native(package,app,title):
    worker=pkg.read_json(app/'native-wine-child-build.json')
    require(worker['project']==title['project'] and worker['worker']==
            {**pkg.record(app/'native-wine-child.self'),'build_id':worker['worker']['build_id']},
            'native SELF/project binding differs')
    require(title['service_manifest_sha256']==pkg.record(app/'native-wine-child-build.json')['sha256'],
            'title/child manifest differs')
    require({k:title['embedded_child'][k] for k in ('bytes','sha256')}==pkg.record(app/'native-wine-child.self'),
            'embedded child differs')
    require(type(title['embedded_child']['address']) is int and title['embedded_child']['address']>0,'invalid embedded address')
    require({k:title['files']['eboot.bin'][k] for k in ('bytes','sha256')}==pkg.record(app/'eboot.bin'),
            'title bytes differ')
    require(title['helper']==worker['helper'] and worker['helper']['elf']==pkg.record(app/'lapy.elf') and worker['helper']['project']==worker['project'],
            'current helper binding differs')
    old=pkg.read_json(package/'PPSA99995/native-wine-child-build.json')
    require(worker['runtime']==old['runtime'],'native ABI/runtime cohort changed')
    require(worker.get('derived_donor',{}).get('donor')==DONOR,'donor declaration absent')
    obs=worker.get('net_target_observation',{})
    slot_names={'sceNetSocket','sceNetConnect','sceNetSend','sceNetRecv','sceNetSetsockopt',
                'sceNetSocketClose','sceNetErrnoLoc','sceKernelLoadStartModule'}
    require(obs.get('schema')=='pw-wine-child-net-target-observation/2' and
            obs.get('wire_version')==3 and obs.get('wire_bytes')==136 and obs.get('stages')==[4,5] and
            obs.get('guard_slot_order')==['sceNetSocket','sceNetConnect','sceNetSend','sceNetRecv','sceNetSetsockopt',
                                         'sceNetSocketClose','sceNetErrnoLoc','sceKernelLoadStartModule'] and
            obs.get('load_path')=='/system/common/lib/libSceNet.sprx' and
            set(obs.get('got_slots',{}))==slot_names and set(obs.get('guard_instructions',{}))==slot_names and
            all(type(v) is int and v>0 for v in obs['got_slots'].values()) and
            len(set(obs['got_slots'].values()))==8 and
            all(isinstance(v,list) and len(v)==1 and type(v[0]) is int and v[0]>0 for v in obs['guard_instructions'].values()) and
            obs.get('target_executed') is False and obs.get('runtime_validated') is False,
            'native Net diagnostic proof absent or wrong version')
    require(worker['console_execution_verified'] is False and worker['windows_process_support'] is False and
            worker['platform_authentication_verified'] is False and title['console_execution_verified'] is False,
            'unsupported runtime claim')
    from native_probe_elf import Elf, extract_self
    from check_native_suite import compiled_identity, embedded_image
    image=Elf(extract_self((app/'eboot.bin').read_bytes()))
    child=Elf(extract_self((app/'native-wine-child.self').read_bytes()))
    require(compiled_identity(image,worker['project']['commit'])==title['title_compiled_identity'],'title compiled identity differs')
    require(compiled_identity(image,worker['helper']['elf']['sha256'])==title['helper_compiled_identity'],'title helper literal differs')
    require(embedded_image(image,(app/'native-wine-child.self').read_bytes())==title['embedded_child'],'actual embedded image differs')
    compiled_identity(child,worker['worker']['build_id'])
    compiled_identity(child,worker['helper']['elf']['sha256'])
    return worker

def assemble(root,contract,app,build,title_path,out,archive):
    native_producer=producer(os.environ)
    value,package=donor_state(contract)
    compatibility=compatible_sources(root)
    require(compatibility==value['source_compatibility'],'source changed before packaging')
    title=pkg.read_json(title_path);worker=check_native(package,app,title)
    require(title['project']==project(root),'title not built from current source')
    require(title['title_compile_receipt']==pkg.record(build/'wine-child-title-compile.json'),'title compile receipt differs')
    out=fresh(out)
    for name,row in value['inventory'].items():
        if row['type']=='directory':
            target=out/inherited_name(name);target.mkdir(parents=True,exist_ok=True);target.chmod(row['mode'])
        else:copy(out,inherited_name(name),package/name,row['mode'])
    for name in REPLACED:copy(out,name,app/name.split('/',1)[1],pkg.normal_mode(name))
    # Refuse unnoticed extra changes in the newly built app (icons, libc etc).
    for path in app.rglob('*'):
        if not path.is_file():continue
        name='PPSA99995/'+path.relative_to(app).as_posix()
        require(name in REPLACED or (name in value['inventory'] and pkg.record(path)==
                {k:value['inventory'][name][k] for k in ('bytes','sha256')}),'unexpected new title output: '+name)
    copy(out,'provenance/native/title.json',title_path)
    for path in build.rglob('*'):
        require(not path.is_symlink(),'linked native evidence')
        if path.is_file():copy(out,'provenance/native/build/'+path.relative_to(build).as_posix(),path,0o644)
    write(out,'sources/native/project.tar.gz',gzip.compress(git(root,'archive',title['project']['commit']),mtime=0))
    write(out,'sources/native/project.commit',git(root,'cat-file','commit',title['project']['commit']))
    write(out,'BUILD-INFO.txt',('Mode: derived-native-child\nNative commit: '+title['project']['commit']+
          '\nDonor commit: '+DONOR['project']['commit']+'\nDonor run: '+DONOR['run']+
          '\nWindows reference: inherited, not rerun\nConsole validated: false\n').encode())
    pkg.normalize_directories(out)
    inventory=pkg.inventory(out)
    verify_payload(value['inventory'],inventory)
    report={'schema':'pw-derived-native-package/1','donor':DONOR,**native_producer,'native_project':title['project'],
            'native_worker_build_id':worker['worker']['build_id'],'source_compatibility':compatibility,
            'replaced':{n:inventory[n] for n in REPLACED},'inherited_inventory':value['inventory'],
            'native_title_receipt':pkg.record(title_path),'native_compile_receipt':title['title_compile_receipt'],
            'files':inventory,'reference_results':'inherited; not rerun',
            'console_execution_verified':False,'new_checks':'native build, static decoder, host tests only'}
    write(out,MANIFEST,pkg.json_bytes(report))
    write(out,'SHA256SUMS',pkg.checksums(pkg.inventory(out)))
    verify(out)
    pkg.write_archive(out,archive)
    return report

def archive_tree(path,with_files=False):
    nodes={};files={};count=0;total=0
    def obj(kind,value):
        return hashlib.sha1(kind.encode()+b' '+str(len(value)).encode()+b'\0'+value).hexdigest()
    with tarfile.open(path,'r:gz') as archive:
        names=set()
        for member in archive:
            name=pkg.safe_name(member.name.rstrip('/') if member.isdir() else member.name)
            require(name not in names,'duplicate source archive member');names.add(name)
            if member.isdir():continue
            require(member.isreg() or member.issym(),'unsupported source archive member')
            count+=1;total+=member.size
            require(count<=20000 and total<=256<<20 and member.size<=32<<20,'source archive bounds')
            value=archive.extractfile(member).read() if member.isreg() else member.linkname.encode()
            mode='120000' if member.issym() else '100755' if member.mode&0o111 else '100644'
            node=nodes
            for part in name.split('/')[:-1]:
                require(not isinstance(node.get(part),tuple),'source file/directory collision')
                node=node.setdefault(part,{})
            leaf=name.split('/')[-1];require(leaf not in node,'source collision')
            node[leaf]=(mode,obj('blob',value))
            files[name]={'bytes':len(value),'sha256':hashlib.sha256(value).hexdigest(),
                         'mode':0o120000 if member.issym() else 0o755 if member.mode&0o111 else 0o644}
    def tree(node):
        entries=[]
        for name,value in node.items():
            mode,digest=('40000',tree(value)) if isinstance(value,dict) else value
            entries.append((name.encode()+(b'/' if mode=='40000' else b''),
                            mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(digest)))
        return obj('tree',b''.join(v for _,v in sorted(entries)))
    require(nodes,'empty source archive')
    digest=tree(nodes)
    return (digest,files) if with_files else digest

def source_delta(old,new,claimed):
    changes={n:new.get(n) for n in set(new)|set(old) if new.get(n)!=old.get(n)}
    require(set(changes)<=ALLOWED_SOURCE_CHANGES and all(v is not None and v['mode'] in (0o644,0o755) for v in changes.values()),
            'unreviewed/deleted/link native source delta')
    require(changes==claimed,'claimed source delta differs')
    return changes

def retained_donor(root):
    path=root/'provenance/donor113/windows-child-fixture.json'
    require(pkg.record(path)=={'bytes':2459343,'sha256':'d07daa128a72e8ca522fded71d951014743014d47c2bc2cfd77cde27180e0b09'},
            'retained accepted donor manifest pin differs')
    manifest=pkg.read_json(path);values=dict(manifest['inventory'])
    values[pkg.MANIFEST]={'type':'file','mode':0o644,**pkg.record(path)}
    sums=root/'provenance/donor113/SHA256SUMS'
    require(pkg.record(sums)=={'bytes':1430772,'sha256':'b9e911835c615bcb25db40c3b409cda547f9e6e929ad622dd34edacea747d0c0'},
            'retained donor checksum pin differs')
    values['SHA256SUMS']={'type':'file','mode':0o644,**pkg.record(sums)}
    read=lambda n:(root/inherited_name(n)).read_bytes()
    require(read('SHA256SUMS')==pkg.checksums(values),'donor checksums differ')
    pkg.validate_manifest(manifest,values,read)
    require(manifest['project']==DONOR['project'] and str(manifest.get('run_attempt'))==DONOR['attempt'] and
            manifest['run_url'].endswith('/'+DONOR['run']),'retained donor identity differs')
    return values

def verify(root):
    report=pkg.read_json(root/MANIFEST);actual=pkg.inventory(root)
    require(report['schema']=='pw-derived-native-package/1' and report['donor']==DONOR,'derived identity differs')
    verify_producer(report)
    require(report['console_execution_verified'] is False and report['reference_results']=='inherited; not rerun',
            'derived execution claim')
    require({n:v for n,v in actual.items() if n not in (MANIFEST,'SHA256SUMS')}==report['files'],
            'derived inventory differs')
    require((root/'SHA256SUMS').read_bytes()==pkg.checksums(actual),'derived checksum set differs')
    donor=retained_donor(root)
    require(report['inherited_inventory']==donor,'claimed donor inventory differs from pinned proof')
    verify_payload(donor,actual)
    require(report['replaced']=={n:actual[n] for n in REPLACED},'replacement inventory differs')
    title_path=root/'provenance/native/title.json';title=pkg.read_json(title_path)
    require(report['native_project']==title['project'] and report['native_title_receipt']==pkg.record(title_path),
            'new native project/title differs')
    # check_native expects only the original child manifest beneath its donor root.
    class DonorView:
        def __truediv__(self,name):
            require(name=='PPSA99995/native-wine-child-build.json','unexpected donor lookup')
            return root/inherited_name(name)
    worker=check_native(DonorView(),root/'PPSA99995',title)
    require(report['native_worker_build_id']==worker['worker']['build_id'],'new worker identity differs')
    compile_path=root/'provenance/native/build/wine-child-title-compile.json'
    require(report['native_compile_receipt']==title['title_compile_receipt']==pkg.record(compile_path),
            'new compiler receipt differs')
    compile_record=pkg.read_json(compile_path)
    require(compile_record['project']==title['project'],'compiler project differs')
    commit=(root/'sources/native/project.commit').read_bytes()
    require(len(commit)<=1<<20 and hashlib.sha1(b'commit '+str(len(commit)).encode()+b'\0'+commit).hexdigest()==title['project']['commit'],
            'native commit object differs')
    require(commit.split(b'\n',1)[0]==b'tree '+title['project']['tree'].encode(),'native commit/tree association differs')
    new_tree,new_files=archive_tree(root/'sources/native/project.tar.gz',True)
    old_tree,old_files=archive_tree(root/'sources/donor113/project.tar.gz',True)
    require(new_tree==title['project']['tree'] and old_tree==DONOR['project']['tree'],'retained source tree differs')
    source_delta(old_files,new_files,report['source_compatibility']['changed_sources'])
    with tarfile.open(root/'sources/native/project.tar.gz','r:gz') as archive:
        sources={m.name:archive.extractfile(m).read() for m in archive if m.isreg() and m.name in compile_record['sources']}
    for name,row in compile_record['sources'].items():
        require(name in sources and {'bytes':len(sources[name]),'sha256':hashlib.sha256(sources[name]).hexdigest()}==row['source'],
                'compiler source differs from native archive')
        require(pkg.record(root/'provenance/native/build'/pkg.safe_name(row['object_path']))==row['object'],
                'compiler object differs from retained native build')
    require(report['source_compatibility']==worker['derived_donor']['source_compatibility'],
            'native admission source compatibility differs')
    require(report['source_compatibility']['donor_project']==DONOR['project'] and
            report['source_compatibility']['native_project']==title['project'],
            'source compatibility project differs')
    return report

def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='command',required=True)
    q=sub.add_parser('prepare')
    for name in ('repo','package-zip','evidence-zip','out'):q.add_argument('--'+name,type=Path,required=True)
    q=sub.add_parser('assemble')
    for name in ('repo','contract','app','build','title','out','archive'):q.add_argument('--'+name,type=Path,required=True)
    q=sub.add_parser('verify');q.add_argument('root',type=Path)
    a=p.parse_args()
    if a.command=='prepare':print(prepare(a.repo,a.package_zip,a.evidence_zip,a.out))
    elif a.command=='assemble':
        r=assemble(a.repo,a.contract,a.app,a.build,a.title,a.out,a.archive)
        print(json.dumps({'schema':r['schema'],'native_project':r['native_project'],'donor':DONOR['project'],
                          'archive':pkg.record(a.archive),**verify_producer(r),'console_execution_verified':False},sort_keys=True))
    else:verify(a.root);print('Derived package verified; no target execution.')
if __name__=='__main__':main()
