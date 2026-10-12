#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Host-only derived-package contract controls; no SDK, target or network execution."""
import copy, hashlib, io, json, sys, tarfile, tempfile, unittest, zipfile
from pathlib import Path
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import derived_native_package as d

ROW={'type':'file','mode':0o644,'bytes':3,'sha256':'a'*64}
class DerivedTests(unittest.TestCase):
    def test_donor_fixed_two_identities(self):
        self.assertEqual(d.DONOR['run'],'38241186538')
        self.assertEqual(d.DONOR['project']['commit'],'7acf08abea63640a737c7cec0cae4c0da61b82f5')
        self.assertEqual(len(d.REPLACED),4)
        self.assertNotIn('PPSA99995/win/wine/lib/wine/x86_64-unix/ntdll.prx',d.REPLACED)

    def test_metadata_relocation_and_original_native_preservation(self):
        names={'PPSA99995/eboot.bin':'provenance/donor113/original-native/eboot.bin',
               'provenance/title.json':'provenance/donor113/title.json',
               'sources/project.tar.gz':'sources/donor113/project.tar.gz',
               'BUILD-INFO.txt':'provenance/donor113/BUILD-INFO.txt',
               'SHA256SUMS':'provenance/donor113/SHA256SUMS',
               'console/data/prospero-win/prefixes/battlenet-experimental-v1/user.reg':
               'console/data/prospero-win/prefixes/battlenet-experimental-v1/user.reg'}
        for name,want in names.items():self.assertEqual(d.inherited_name(name),want)
        for name in ('../outside','a/../b','/absolute','a//b'):
            with self.assertRaises(ValueError):d.inherited_name(name)

    def test_inherited_payload_is_exact_including_empty_directories(self):
        donor={'console/empty':{'type':'directory','mode':0o755},
               'console/user.reg':ROW,'PPSA99995/eboot.bin':ROW,'provenance/title.json':ROW}
        actual={d.inherited_name(k):copy.deepcopy(v) for k,v in donor.items()}
        actual['PPSA99995/eboot.bin']={**ROW,'sha256':'b'*64}
        d.verify_payload(donor,actual)
        for name in ('console/user.reg','console/empty','provenance/donor113/title.json',
                     'provenance/donor113/original-native/eboot.bin'):
            bad=copy.deepcopy(actual);del bad[name]
            with self.assertRaises(ValueError):d.verify_payload(donor,bad)
        for key,value in [('mode',0o755),('bytes',4),('sha256','c'*64)]:
            bad=copy.deepcopy(actual);bad['console/user.reg'][key]=value
            with self.assertRaises(ValueError):d.verify_payload(donor,bad)

    def test_extra_payload_changes_refused(self):
        for name in ('console/extra','PPSA99995/extra.prx','random.txt'):
            with self.assertRaises(ValueError):d.verify_payload({}, {name:ROW})
        d.verify_payload({}, {'sources/native/project.tar.gz':ROW,'provenance/native/title.json':ROW})

    def test_protected_source_delta(self):
        native={'commit':'b'*40,'tree':'c'*40}
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'native').mkdir();(root/'native/pw_wine_child_data.c').write_text('new')
            def fake_git(root,*args):
                if args[0]=='rev-parse':return (d.DONOR['project']['tree']+'\n').encode()
                return b'native/pw_wine_child_data.c\n'
            with patch.object(d,'project',return_value=native),patch.object(d,'git',side_effect=fake_git):
                got=d.compatible_sources(root)
                self.assertEqual(got['donor_project'],d.DONOR['project'])
                self.assertEqual(got['native_project'],native)
                self.assertEqual(set(got['changed_sources']),{'native/pw_wine_child_data.c'})
            def wrong(root,*args):
                return ((d.DONOR['project']['tree']+'\n').encode() if args[0]=='rev-parse'
                        else b'wine/ps5/pw_wine_fixture_provider.c\n')
            with patch.object(d,'project',return_value=native),patch.object(d,'git',side_effect=wrong):
                with self.assertRaisesRegex(ValueError,'unreviewed'):d.compatible_sources(root)
        self.assertNotIn('tools/build_wine_ps5.sh',d.ALLOWED_SOURCE_CHANGES)
        self.assertNotIn('native/lapy_elevation_protocol.h',d.ALLOWED_SOURCE_CHANGES)

    def test_zip_pin_traversal_duplicate_link_and_encryption(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for i,mode in enumerate(('valid','traversal','duplicate','link')):
                z=root/(mode+'.zip')
                with zipfile.ZipFile(z,'w') as archive:
                    if mode=='traversal':archive.writestr('../escape','x')
                    elif mode=='duplicate':
                        archive.writestr('A','x');archive.writestr('a','y')
                    elif mode=='link':
                        item=zipfile.ZipInfo('link');item.create_system=3;item.external_attr=0o120777<<16
                        archive.writestr(item,'target')
                    else:archive.writestr('dir/file','x')
                if mode=='valid':
                    out=d.unpack_zip(z,root/('out'+str(i)),d.pkg.record(z))
                    self.assertEqual((out/'dir/file').read_text(),'x')
                    with self.assertRaisesRegex(ValueError,'pin'):d.unpack_zip(z,root/'wrongpin',{'bytes':0,'sha256':'0'*64})
                else:
                    with self.assertRaises(ValueError):d.unpack_zip(z,root/('out'+str(i)),d.pkg.record(z))

    def test_copy_refuses_existing_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=root/'source';source.write_bytes(b'abc');source.chmod(0o644)
            out=d.fresh(root/'out');d.copy(out,'file',source)
            with self.assertRaises(FileExistsError):d.copy(out,'file',source)
            self.assertEqual((out/'file').read_bytes(),b'abc')

    def test_native_bindings_and_claims(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);app=root/'app';app.mkdir();donor=root/'donor';(donor/'PPSA99995').mkdir(parents=True)
            for name in ('eboot.bin','native-wine-child.self','lapy.elf'):(app/name).write_bytes(name.encode())
            project={'commit':'b'*40,'tree':'c'*40};runtime={'creation_protocol':962}
            worker={'schema':'pw-wine-service-child/2','project':project,'runtime':runtime,
                    'worker':{**d.pkg.record(app/'native-wine-child.self'),'build_id':'d'*40},
                    'helper':{'elf':d.pkg.record(app/'lapy.elf'),'project':project},
                    'derived_donor':{'donor':d.DONOR},'net_target_observation':{'schema':'pw-wine-child-net-target-observation/2',
                    'stages':[4,5],'wire_version':3,'wire_bytes':136,
                    'guard_slot_order':['sceNetSocket','sceNetConnect','sceNetSend','sceNetRecv','sceNetSetsockopt','sceNetSocketClose','sceNetErrnoLoc','sceKernelLoadStartModule'],'load_path':'/system/common/lib/libSceNet.sprx',
                    'got_slots':dict(zip(('sceNetSocket','sceNetConnect','sceNetSend','sceNetRecv','sceNetSetsockopt','sceNetSocketClose','sceNetErrnoLoc','sceKernelLoadStartModule'),range(1,9))),
                    'guard_instructions':{n:[v+10] for n,v in zip(('sceNetSocket','sceNetConnect','sceNetSend','sceNetRecv','sceNetSetsockopt','sceNetSocketClose','sceNetErrnoLoc','sceKernelLoadStartModule'),range(1,9))},
                    'target_executed':False,'runtime_validated':False},'console_execution_verified':False,
                    'windows_process_support':False,'platform_authentication_verified':False}
            (donor/'PPSA99995/native-wine-child-build.json').write_text(json.dumps({'runtime':runtime}))
            def title():
                (app/'native-wine-child-build.json').write_text(json.dumps(worker))
                return {'project':project,'service_manifest_sha256':d.pkg.record(app/'native-wine-child-build.json')['sha256'],
                        'embedded_child':{**d.pkg.record(app/'native-wine-child.self'),'address':0x1000},
                        'files':{'eboot.bin':d.pkg.record(app/'eboot.bin')},'helper':worker['helper'],
                        'title_compiled_identity':{},'helper_compiled_identity':{},'console_execution_verified':False}
            good=title()
            for target,value in [('native_probe_elf.Elf',object()),('native_probe_elf.extract_self',b''),
                                 ('check_native_suite.compiled_identity',{}),('check_native_suite.embedded_image',good['embedded_child'])]:
                mocked=patch(target,return_value=value);mocked.start();self.addCleanup(mocked.stop)
            d.check_native(donor,app,good)
            for key,value in [('schema','old'),('wire_version',2),('stages',[5]),('load_path','/other'),('runtime_validated',True)]:
                original=worker['net_target_observation'][key];worker['net_target_observation'][key]=value
                with self.assertRaises(ValueError):d.check_native(donor,app,title())
                worker['net_target_observation'][key]=original
            for field in ('console_execution_verified','windows_process_support','platform_authentication_verified'):
                worker[field]=True
                with self.assertRaises(ValueError):d.check_native(donor,app,title())
                worker[field]=False
            bad=title();bad['embedded_child']['sha256']='e'*64
            with self.assertRaises(ValueError):d.check_native(donor,app,bad)
            bad=title();bad['embedded_child']['address']=False
            with self.assertRaises(ValueError):d.check_native(donor,app,bad)
            worker['helper']['project']=d.DONOR['project']
            with self.assertRaises(ValueError):d.check_native(donor,app,title())


    def test_recompute_protected_source_delta(self):
        row={'bytes':3,'sha256':'a'*64,'mode':0o644}
        old={'native/pw_wine_child_data.c':dict(row),'tools/build_wine_ps5.sh':dict(row)}
        new=copy.deepcopy(old);new['native/pw_wine_child_data.c']['sha256']='b'*64
        claimed={'native/pw_wine_child_data.c':new['native/pw_wine_child_data.c']}
        self.assertEqual(d.source_delta(old,new,claimed),claimed)
        with self.assertRaises(ValueError):d.source_delta(old,new,{})
        bad=copy.deepcopy(new);bad['tools/build_wine_ps5.sh']['sha256']='c'*64
        with self.assertRaises(ValueError):d.source_delta(old,bad,claimed)
        bad=copy.deepcopy(new);del bad['native/pw_wine_child_data.c']
        with self.assertRaises(ValueError):d.source_delta(old,bad,{})
        bad=copy.deepcopy(new);bad['native/pw_wine_child_data.c']['mode']=0o120000
        with self.assertRaises(ValueError):d.source_delta(old,bad,bad)
        mode=copy.deepcopy(new);mode['native/pw_wine_child_data.c']['mode']=0o755
        with self.assertRaises(ValueError):d.source_delta(old,mode,claimed)

    def test_source_archive_actual_git_tree_and_modes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'source.tar.gz'
            with tarfile.open(path,'w:gz') as archive:
                member=tarfile.TarInfo('a');member.size=3;member.mode=0o644
                archive.addfile(member,io.BytesIO(b'abc'))
            digest,files=d.archive_tree(path,True)
            blob=hashlib.sha1(b'blob 3\0abc').digest()
            entry=b'100644 a\0'+blob
            self.assertEqual(digest,hashlib.sha1(b'tree '+str(len(entry)).encode()+b'\0'+entry).hexdigest())
            self.assertEqual(files['a'],{'bytes':3,'sha256':hashlib.sha256(b'abc').hexdigest(),'mode':0o644})
            with tarfile.open(path,'w:gz') as archive:
                for _ in range(2):
                    member=tarfile.TarInfo('a');member.size=3;member.mode=0o644
                    archive.addfile(member,io.BytesIO(b'abc'))
            with self.assertRaises(ValueError):d.archive_tree(path)


    def test_verify_rejects_self_consistent_identity_relabel(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            inherited={'console/data/file':dict(ROW)}
            inherited.update({n:dict(ROW) for n in d.REPLACED})
            actual={d.inherited_name(n):dict(v) for n,v in inherited.items()}
            actual.update({n:dict(ROW) for n in d.REPLACED})
            actual[d.MANIFEST]=dict(ROW);actual['SHA256SUMS']=dict(ROW)
            receipt={'bytes':3,'sha256':'a'*64}
            native={'commit':'b'*40,'tree':'c'*40}
            report={'schema':'pw-derived-native-package/1','donor':d.DONOR,
                    'native_run_url':'https://github.com/Sleepywalker69/prospero-win/actions/runs/123','native_run_attempt':'1',
                    'console_execution_verified':False,'reference_results':'inherited; not rerun',
                    'files':{n:v for n,v in actual.items() if n not in (d.MANIFEST,'SHA256SUMS')},
                    'inherited_inventory':copy.deepcopy(inherited),
                    'replaced':{n:actual[n] for n in d.REPLACED},
                    'native_project':dict(native),'native_title_receipt':receipt}
            # Both checksums and declared inventory are self-consistent. The
            # independent retained donor/native receipts remain authoritative.
            (root/'SHA256SUMS').write_bytes(d.pkg.checksums(actual))
            def read(path):
                return report if path==root/d.MANIFEST else {'project':native}
            with patch.object(d.pkg,'inventory',return_value=actual),patch.object(d.pkg,'read_json',side_effect=read), \
                 patch.object(d,'retained_donor',return_value=inherited),patch.object(d.pkg,'record',return_value=receipt):
                report['inherited_inventory']['console/data/file']['sha256']='e'*64
                with self.assertRaisesRegex(ValueError,'claimed donor inventory'):d.verify(root)
                report['inherited_inventory']=copy.deepcopy(inherited)
                report['native_project']={'commit':'f'*40,'tree':'c'*40}
                with self.assertRaisesRegex(ValueError,'native project/title'):d.verify(root)


    def test_native_producer_identity_is_new_and_bounded(self):
        env={'GITHUB_REPOSITORY':'Sleepywalker69/prospero-win','GITHUB_RUN_ID':'987','GITHUB_RUN_ATTEMPT':'2'}
        got=d.producer(env)
        self.assertEqual(got,{'native_run_url':'https://github.com/Sleepywalker69/prospero-win/actions/runs/987',
                              'native_run_attempt':'2'})
        self.assertEqual(d.verify_producer(got),got)
        self.assertNotEqual(got['native_run_url'].rsplit('/',1)[-1],d.DONOR['run'])
        for key,values in [('GITHUB_REPOSITORY',('fork/prospero-win','Sleepywalker69/other',None)),
                           ('GITHUB_RUN_ID',('0','01','-1','1/2','1'+chr(10),1,None)),
                           ('GITHUB_RUN_ATTEMPT',('0','01','x','1'+chr(10),1,None))]:
            for value in values:
                bad=dict(env);bad[key]=value
                with self.assertRaises(ValueError):d.producer(bad)
        for key,values in [('native_run_url',('https://github.com/fork/prospero-win/actions/runs/987',
                         got['native_run_url']+'/jobs','https://githubXcom/Sleepywalker69/prospero-win/actions/runs/987',None)),
                           ('native_run_attempt',('0','01',1,None))]:
            for value in values:
                bad=dict(got);bad[key]=value
                with self.assertRaises(ValueError):d.verify_producer(bad)


    def test_restore_runtime_report_uses_exact_package_serialization(self):
        raw = b'{"z": [1, 2], "a": {"y": 2, "b": 1}}\n'
        report = json.loads(raw)
        canonical = d.pkg.json_bytes(report)
        changed = copy.deepcopy(report); changed['a']['y'] = 3
        extra = copy.deepcopy(report); extra['extra'] = 0
        missing = copy.deepcopy(report); del missing['a']['b']
        reordered = copy.deepcopy(report); reordered['z'].reverse()
        boolean = copy.deepcopy(report); boolean['a']['b'] = True
        floating = copy.deepcopy(report); floating['a']['y'] = 2.0
        cases = [
            ('canonical', raw, canonical, False, None),
            ('nested-value', raw, d.pkg.json_bytes(changed), False, 'Wine report differs'),
            ('extra-field', raw, d.pkg.json_bytes(extra), False, 'Wine report differs'),
            ('missing-field', raw, d.pkg.json_bytes(missing), False, 'Wine report differs'),
            ('list-order', raw, d.pkg.json_bytes(reordered), False, 'Wine report differs'),
            ('boolean-number', raw, d.pkg.json_bytes(boolean), False, 'Wine report differs'),
            ('float-number', raw, d.pkg.json_bytes(floating), False, 'Wine report differs'),
            ('malformed-json', b'{broken', canonical, False, None),
            ('duplicate-key', b'{"z": [1, 2], "a": 1, "a": {"y": 2, "b": 1}}',
             canonical, False, 'duplicate JSON key'),
            ('noncanonical-package', raw, raw, False, 'Wine report differs'),
            ('tampered-evidence', raw, canonical, 'report', 'retained runtime bytes differ'),
            ('tampered-abi', raw, canonical, 'abi', 'retained runtime bytes differ'),
            ('mismatched-binary', raw, canonical, 'binary', 'donor runtime package/evidence mismatch'),
            ('missing-abi', raw, canonical, 'missing-abi', 'required ABI input omitted'),
        ]
        for name, evidence_bytes, package_bytes, tamper, error in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); evidence = root/'evidence'; package = root/'package'
                base = evidence/'unaccepted-build-inputs'; base.mkdir(parents=True)
                (package/'provenance').mkdir(parents=True)
                (package/'provenance/wine-build.json').write_bytes(package_bytes)
                files = {
                    'report.json': evidence_bytes,
                    'build/dlls/ntdll/ntdll.so': b'ntdll-so',
                    'prx/ntdll.shared.elf': b'ntdll-elf',
                    'private-dispatch-pe.json': b'{}',
                    'prx/sce_module/ntdll.prx': b'ntdll-prx',
                    'pe/x86_64-windows/ntdll.dll': b'ntdll-pe',
                }
                inventory = {}
                for relative, data in files.items():
                    path = base/'target/wine'/relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(data)
                    inventory['target/wine/'+relative] = {
                        **d.pkg.record(path), 'original_mode': 0o644}
                for source, target in (
                    ('prx/sce_module/ntdll.prx', 'PPSA99995/win/wine/lib/wine/x86_64-unix/ntdll.prx'),
                    ('pe/x86_64-windows/ntdll.dll', 'PPSA99995/win/wine/lib/wine/x86_64-windows/ntdll.dll')):
                    path = package/target; path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(files[source])
                if tamper == 'missing-abi':
                    del inventory['target/wine/private-dispatch-pe.json']
                (base/'UNACCEPTED-BUILD.json').write_bytes(d.pkg.json_bytes({
                    'schema': 'pw-windows-child-unaccepted-build-evidence/1',
                    'files': inventory}))
                if tamper == 'report':
                    (base/'target/wine/report.json').write_bytes(evidence_bytes+b' ')
                elif tamper == 'abi':
                    (base/'target/wine/private-dispatch-pe.json').write_bytes(b'{"changed": true}')
                elif tamper == 'binary':
                    (package/'PPSA99995/win/wine/lib/wine/x86_64-unix/ntdll.prx').write_bytes(b'changed')
                out = root/'runtime'
                if name == 'malformed-json':
                    with self.assertRaises(json.JSONDecodeError):
                        d.restore_runtime(evidence, out, package)
                elif error is not None:
                    with self.assertRaisesRegex(ValueError, error):
                        d.restore_runtime(evidence, out, package)
                else:
                    restored = d.restore_runtime(evidence, out, package)
                    self.assertEqual((out/'report.json').read_bytes(), evidence_bytes)
                    self.assertEqual(restored['report.json'], {
                        **d.pkg.record(out/'report.json'), 'mode': 0o644})
                    self.assertNotEqual(d.pkg.record(out/'report.json'),
                                        d.pkg.record(package/'provenance/wine-build.json'))


    def test_workflow_fetches_exact_donor_without_changing_checkout(self):
        import yaml
        workflow = yaml.safe_load((Path(__file__).resolve().parents[1]/
                                  '.github/workflows/derived-native-child.yml').read_text())
        steps = workflow['jobs']['native-only']['steps']
        names = [step.get('name') for step in steps]
        fetch = names.index('Fetch and verify exact donor source object')
        self.assertLess(names.index('Run derived admission controls before downloads'), fetch)
        self.assertLess(fetch, names.index('Download exact accepted same-repository donor artifacts'))
        self.assertEqual(steps[fetch]['run'], """set -euo pipefail
head_before=$(git rev-parse HEAD)
git fetch --no-tags origin 7acf08abea63640a737c7cec0cae4c0da61b82f5:refs/pw-derived/donor113
[[ $(git rev-parse 'refs/pw-derived/donor113^{commit}') == 7acf08abea63640a737c7cec0cae4c0da61b82f5 ]]
[[ $(git rev-parse 'refs/pw-derived/donor113^{tree}') == e28679c3d6c1a8735b9069509062c4114c166c47 ]]
[[ $(git rev-parse HEAD) == "$head_before" ]]
""")
        self.assertNotIn('--depth', steps[fetch]['run'])


    def test_restore_validator_headers_from_exact_donor_source(self):
        import subprocess
        cases = ('valid', 'tree', 'missing-patch', 'nonregular-patch', 'duplicate-patch',
                 'malformed-patch', 'non-new-patch', 'header-hash', 'missing-hash',
                 'extra-hash', 'invalid-hash', 'existing-source', 'extra-output', 'linked-output')
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);package=root/'package';runtime=root/'runtime'
                (package/'sources').mkdir(parents=True)
                (package/'provenance').mkdir();runtime.mkdir()
                expected={};members=[]
                for index,(header,name) in enumerate(d.VALIDATOR_PATCHES.items()):
                    content=('#define PW_RESTORED_'+str(index)+' 1\n').encode()
                    expected[header]=hashlib.sha256(content).hexdigest()
                    patch_bytes=(b'--- /dev/null\n+++ b/include/wine/'+header.encode()+
                                 b'\n@@ -0,0 +1 @@\n+'+content)
                    kind='file'
                    if index==0:
                        if case=='missing-patch':continue
                        if case=='nonregular-patch':kind='link'
                        if case=='malformed-patch':patch_bytes=b'not a patch\n'
                        if case=='non-new-patch':
                            patch_bytes=(b'--- a/include/wine/'+header.encode()+
                                         b'\n+++ b/include/wine/'+header.encode()+
                                         b'\n@@ -1 +1 @@\n-old\n+'+content)
                    members.append((name,patch_bytes,kind))
                    if case=='duplicate-patch' and index==0:members.append((name,patch_bytes,kind))
                archive_path=package/'sources/project.tar.gz'
                with tarfile.open(archive_path,'w:gz') as archive:
                    for name,data,kind in members:
                        member=tarfile.TarInfo(name);member.mode=0o644
                        if kind=='link':
                            member.type=tarfile.SYMTYPE;member.linkname='elsewhere'
                            archive.addfile(member)
                        else:
                            member.size=len(data);archive.addfile(member,io.BytesIO(data))
                donor=copy.deepcopy(d.DONOR)
                donor['project']['tree']=('0'*40 if case in ('tree','duplicate-patch')
                                           else d.archive_tree(archive_path))
                if case=='header-hash':expected['pw_private_dispatch.h']='0'*64
                if case=='missing-hash':del expected['pw_private_dispatch.h']
                if case=='extra-hash':expected['other.h']='a'*64
                if case=='invalid-hash':expected['pw_private_dispatch.h']='not-a-digest'
                (package/'provenance/private-dispatch-abi.json').write_bytes(
                    d.pkg.json_bytes({'wow64':{'validator':{'headers':expected}}}))
                if case=='existing-source':
                    (runtime/'source').mkdir();(runtime/'source/keep').write_bytes(b'keep')
                real_run=d.subprocess.run
                def apply(*args,**kwargs):
                    result=real_run(*args,**kwargs)
                    extra=Path(kwargs['cwd'])/'unexpected'
                    if case=='extra-output':extra.write_bytes(b'not a header')
                    elif case=='linked-output' and not extra.is_symlink():extra.symlink_to(root/'outside')
                    return result
                with patch.object(d,'DONOR',donor),patch.object(d.subprocess,'run',side_effect=apply):
                    if case=='valid':
                        self.assertEqual(d.restore_validator_headers(package,runtime),expected)
                        self.assertEqual({p.relative_to(runtime/'source').as_posix()
                                          for p in (runtime/'source').rglob('*') if p.is_file()},
                                         {'include/wine/'+name for name in d.VALIDATOR_PATCHES})
                        for header,digest in expected.items():
                            self.assertEqual(d.pkg.record(runtime/'source/include/wine'/header)['sha256'],digest)
                    else:
                        with self.assertRaises((ValueError,subprocess.CalledProcessError)):
                            d.restore_validator_headers(package,runtime)
                if case=='existing-source':
                    self.assertEqual((runtime/'source/keep').read_bytes(),b'keep')

if __name__=='__main__':unittest.main()
