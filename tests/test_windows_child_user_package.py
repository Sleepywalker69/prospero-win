#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Inert real-file package controls; no compiler, Wine, PE or target execution."""
import copy
import configparser
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import package_windows_child_fixture as package
import prepare_windows_child_prefix as prefix
import windows_child_user_package as user
import test_package_windows_child_fixture as original

PROFILE = b'''[application]
name=Original USER control
id=windows-child-user-v1
prefix=windows-child-user-v1
executable=C:\\windows-child-user\\user-parent.exe
working_directory=C:\\windows-child-user
runtime=wine-wow64
architecture=pe64
graphics=auto
[display]
desktop=800x600
view=desktop
show_fps=false
'''


def source_archive(copies, duplicate=None):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w:gz') as archive:
        for name, data in list(copies.items()) + ([duplicate] if duplicate else []):
            entry = tarfile.TarInfo(name); entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))
    return out.getvalue()


class PureControls(unittest.TestCase):
    def test_optional_off_original_directory_and_archive(self):
        for battle in (False, True):
            with self.subTest(battle=battle):
                fixture = original.ArchiveControls(); fixture.setUp()
                try:
                    manifest = fixture.prepared_battle() if battle else fixture.prepared()
                    result = package.verify_directory(fixture.root)
                    self.assertEqual(result, manifest)
                    self.assertNotIn('user_enabled', result)
                    self.assertFalse(any('windows-child-user' in x for x in result['inventory']))
                    archive = fixture.temp / 'off.tar.gz'
                    package.write_archive(fixture.root, archive)
                    self.assertEqual(package.verify_archive(archive), result)
                finally: fixture.doCleanups()

    def test_optional_off_rejects_payload_or_roles(self):
        combined = {'.': {'type': 'directory', 'mode': 0o755}}
        for name in (user.PROFILE, user.PREFIX, user.APP + '/user-child.exe', user.REFERENCE):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'disabled USER'):
                package.validate_user({}, {name: {'type': 'file'}}, None, None, None, None, None, combined)
        for enabled in (None, 0, 1, 'false'):
            with self.subTest(enabled=enabled), self.assertRaises(ValueError):
                package.validate_user({'user_enabled': enabled}, {}, None, None, None, None, None, combined)
        with self.assertRaisesRegex(ValueError, 'optional consumer roles'):
            package.validate_user({'optional_roles': user.ROLES}, {}, None, None, None, None, None, combined)
        self.assertIs(package.validate_user({}, {}, None, None, None, None, None, combined), combined)

    def test_profile_exact_fields(self):
        parsed = user.profile_fields(PROFILE)
        self.assertEqual((parsed['cpu'], parsed['architecture'], parsed['args']), ('default', 'pe64', []))
        self.assertEqual((parsed['desktop'], parsed['view'], parsed['show_fps']), ('800x600', 'desktop', False))
        for before, after in ((b'architecture=pe64', b'architecture=pe32'),
            (b'800x600', b'1920x1080'), (b'show_fps=false', b'show_fps=true'),
            (b'view=desktop', b'view=window'), (b'user-parent.exe', b'child.exe'),
            (b'runtime=wine-wow64', b'runtime=native'), (b'graphics=auto', b'graphics=dxvk'),
            (b'prefix=windows-child-user-v1', b'prefix=windows-child-fixture-v1'),
            (b'graphics=auto', b'graphics=auto\ncpu=box64'),
            (b'graphics=auto', b'graphics=auto\narguments=--child')):
            with self.subTest(after=after), self.assertRaises(ValueError): user.profile_fields(PROFILE.replace(before, after))
        for data in (PROFILE + b'\n[other]\nx=1\n', b'[DEFAULT]\nx=y\n' + PROFILE,
                     PROFILE.replace(b'graphics=auto', b'graphics=auto\ngraphics=auto'), b'', b'x' * 16385):
            with self.assertRaises((ValueError, configparser.Error)): user.profile_fields(data)

    def test_original_recipes_unchanged_and_third_recipe_exact(self):
        # Complete original recipe values are preserved, including the no-DXVK choice.
        for battle,slug,name,exe,cwd in [(False,'windows-child-fixture-v1','Original Windows child-process fixture','drive_c/windows-child-fixture/parent.exe','$GAMEDIR/drive_c/windows-child-fixture'),
                                       (True,'battlenet-experimental-v1','Battle.net experimental installer','drive_c/installer/Battle.net-Setup.exe','$GAMEDIR/drive_c/installer')]:
            self.assertEqual(prefix.recipe(battle),{'name':name,'game_slug':slug,'runner':'wine',
                'prospero':{'graphics':'auto'},'script':{'game':{'exe':exe,'working_dir':cwd},'wine':{'dxvk':False}}})
        new = prefix.recipe(user=True)
        self.assertEqual(new['game_slug'], user.SLUG)
        self.assertEqual(new['prospero']['display'], {'desktop': '800x600', 'view': 'desktop', 'show_fps': False})
        self.assertEqual(new['script']['game']['exe'], 'drive_c/windows-child-user/user-parent.exe')
        self.assertIs(new['script']['wine']['dxvk'], False)
        with self.assertRaises(ValueError): prefix.recipe(True, True)

    def test_third_prefix_fresh_output_no_overwrite_or_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); original = root / 'original'; original.mkdir()
            sentinel = original / 'sentinel'; sentinel.write_bytes(b'old-data')
            fresh = root / 'third'
            self.assertEqual(prefix.absent(fresh, (original,)), fresh)
            self.assertFalse(fresh.exists())
            for target in (original, original / 'nested', sentinel):
                with self.subTest(target=target), self.assertRaises(ValueError): prefix.absent(target, (original,))
            link = root / 'link'; link.symlink_to(original, target_is_directory=True)
            for target in (link, link / 'fresh'):
                with self.assertRaises(ValueError): prefix.absent(target, (original,))
            self.assertEqual(sentinel.read_bytes(), b'old-data')

    def test_inventory_scopes_collision_and_casefold(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); console = root / 'console'; console.mkdir()
            for name in user.IMAGES:
                path = console / user.APP.removeprefix('console/') / name
                path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(name.encode())
            p = console / user.PROFILE.removeprefix('console/'); p.parent.mkdir(parents=True); p.write_bytes(PROFILE)
            extra = prefix.inventory(console); baseline = {'.': extra['.']}
            merged = user.merge_inventory(baseline, extra); self.assertEqual(merged, extra)
            with self.assertRaisesRegex(ValueError, 'overwrites'): user.merge_inventory(extra, extra)
            for name in ('../escape', '/abs', 'data\\escape', 'data//escape',
                         'data/prospero-win/prefixes/windows-child-fixture-v1/evil',
                         'data/prospero-win/profiles/other.profile'):
                mutated = copy.deepcopy(extra); mutated[name] = {'type':'file','sha256':'a'*64,'bytes':0}
                with self.subTest(name=name), self.assertRaises(ValueError): user.merge_inventory(baseline, mutated)
            same = console / user.APP.removeprefix('console/') / 'USER-CHILD.EXE'; same.write_bytes(b'alias')
            with self.assertRaisesRegex(ValueError, 'case-colliding'): prefix.inventory(console)

    def test_capability_exact_bytes_and_conservative_claims(self):
        project = {'commit':'a'*40,'tree':'b'*40}; result = user.capability(project, PROFILE, b'prefix', b'ref', 'c'*40, 'd'*64)
        self.assertEqual(result['profile']['sha256'], hashlib.sha256(PROFILE).hexdigest())
        self.assertEqual(result['child']['maximum_direct_generations'], 1)
        self.assertEqual((result['native_child_budget_ms'],result['attempt_budget_ms']), (120000,180000))
        for key in ('runtime_validated','console_validated','child_presentation','child_input','descendant_admission'):
            self.assertIs(result[key], False)
        self.assertNotEqual(result, user.capability(project, PROFILE, b'prefix ', b'ref', 'c'*40, 'd'*64))
        for worker, child in (('c'*39,'d'*64), ('c'*40,'d'*63)):
            with self.assertRaises(ValueError): user.capability(project,PROFILE,b'p',b'r',worker,child)

    def test_source_copies_exact_retained_bytes(self):
        copies = {name: ('inert '+name).encode() for name in user.SOURCE_FILES.values()}
        archive = source_archive(copies)
        expected = {key:hashlib.sha256(copies[path]).hexdigest() for key,path in user.SOURCE_FILES.items()}
        self.assertEqual(user.source_copies(archive,copies), expected)
        for name in copies:
            wrong = dict(copies); wrong[name] += b'changed'
            with self.subTest(name=name), self.assertRaises(ValueError): user.source_copies(archive, wrong)
        with self.assertRaisesRegex(ValueError,'duplicate'):
            user.source_copies(source_archive(copies,next(iter(copies.items()))), copies)
        with self.assertRaisesRegex(ValueError,'missing'):
            user.source_copies(source_archive(dict(list(copies.items())[1:])), copies)


class EnabledPackageControls(unittest.TestCase):
    def setUp(self):
        # This helper manufactures inert PE headers and synthetic MSVC/log receipts.
        # The production validator still parses every byte; no validator is mocked.
        from test_windows_child_user_contract import make_bundle
        self.files, self.reference, self.project, self.source_hashes, self.validator = make_bundle()
        self.fixture = original.ArchiveControls(); self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.project = self.project
        self.battle = False

    def get(self, name): return package.read_json(self.fixture.root / name)
    def put_json(self, name, value): self.fixture.json(name, value)
    def put(self, name, value): self.fixture.put(name, value)

    def prepare(self, battle=False):
        self.battle = battle
        f = self.fixture
        f.prepared_battle() if battle else f.prepared()
        for name, data in self.files.items(): self.put(user.REFERENCE_ROOT + '/' + name, data)
        copies = {user.SOURCE_FILES['source_sha256']: self.files['windows_child_user.c'],
                  user.SOURCE_FILES['recipe_sha256']: self.files['build_windows_child_user.ps1'],
                  user.SOURCE_FILES['validator_sha256']: self.validator}
        for name, data in copies.items(): self.put(user.SOURCE_ROOT + '/' + name, data)
        self.put('sources/project.tar.gz', source_archive(copies))
        sources = self.get('provenance/retained-sources.json')
        sources['roles']['project'] = {'path': 'project.tar.gz', 'revision': self.project['commit']}
        sources['inventory'] = prefix.inventory(f.root / 'sources')
        self.put_json('provenance/retained-sources.json', sources)
        # Retain the original two profiles exactly; create only the dedicated third scope.
        for p in (f.root / package.CONSOLE_PREFIX).rglob('*'):
            rel = p.relative_to(f.root / package.CONSOLE_PREFIX).as_posix()
            if p.is_file() and rel.startswith('drive_c/windows/'):
                self.put(user.PREFIX + '/' + rel, p.read_bytes())
        for name in user.IMAGES: self.put(user.APP + '/' + name, self.files[name])
        self.put(user.PROFILE, PROFILE)
        all_console = prefix.inventory(f.root / 'console')
        path = user.PREFIX.removeprefix('console/')
        ancestors = {'.', 'data', 'data/prospero-win', 'data/prospero-win/prefixes', 'data/prospero-win/profiles'}
        self.extra = {n:v for n,v in all_console.items() if n in ancestors or n == path or
                      n.startswith(path + '/') or n == user.PROFILE.removeprefix('console/')}
        baseline = self.get('provenance/prefix.json')
        self.prepared = {'schema':'pw-windows-child-user-prefix/1', 'project':self.project,
            'wine_commit':prefix.WINE, 'patches':{}, 'private_dispatcher':self.get(package.ABI_REPORT),
            'cpu':baseline['cpu'], 'fixture':self.reference, 'inventory':self.extra,
            'patched_pe_delta':baseline['patched_pe_delta'], 'fixture_executed':False,
            'console_execution_verified':False, 'child_presentation':False, 'child_input':False}
        self.put_json(user.REPORT, self.prepared)
        worker = self.get('PPSA99995/native-wine-child-build.json')
        worker['worker']['build_id'] = 'f'*40
        worker['candidate_capabilities'] = [
            {'mode':1,'prefix':package.SLUG,'guest_machine':'AMD64','backend':'native-amd64','runtime_validated':False},
            {'mode':2,'prefix':package.BATTLE_SLUG,'guest_machine':'I386','backend':'wowprospero','runtime_validated':False},
            {'mode':3,'prefix':user.SLUG,'guest_machine':'AMD64','backend':'native-amd64','runtime_validated':False},
            {'mode':4,'prefix':'windows-child-net-v1','guest_machine':'AMD64','backend':'native-amd64','runtime_validated':False}]
        self.put_json('PPSA99995/native-wine-child-build.json', worker)
        self.put_json(user.CAPABILITY, user.capability(self.project,PROFILE,
            (f.root/user.REPORT).read_bytes(),self.files['user-source.json'],worker['worker']['build_id'],
            self.reference['files']['user-child.exe']['sha256']))
        title = self.get('provenance/title.json')
        compile_receipt=b'{"scope":"synthetic compile receipt, no compiler execution"}\n'
        self.put('provenance/title-compile.json',compile_receipt)
        title['title_compile_receipt']={'bytes':len(compile_receipt),'sha256':hashlib.sha256(compile_receipt).hexdigest()}
        title.update(user_enabled=True,user_child_sha256=self.reference['files']['user-child.exe']['sha256'],
                     user_reference_sha256=hashlib.sha256(self.files['user-source.json']).hexdigest())
        self.put_json('provenance/title.json',title)
        self.finish()

    def finish(self):
        manifest = self.fixture.finish(self.battle)
        manifest.update(user_enabled=True,run_attempt='1',
            user_reference_inventory=prefix.inventory(self.fixture.root / user.REFERENCE_ROOT))
        manifest.setdefault('optional_roles',{}).update(user.ROLES)
        self.put_json(package.MANIFEST,manifest)
        self.put(package.SUMS,package.checksums(package.inventory(self.fixture.root)))
        return manifest

    def verify(self): return package.verify_directory(self.fixture.root)
    def reject(self, pattern=None):
        self.finish()
        with self.assertRaisesRegex(ValueError,pattern or '.'):
            self.verify()

    def test_enabled_real_directory_and_archive(self):
        self.prepare()
        manifest = self.verify()
        self.assertTrue(manifest['user_enabled'])
        self.assertEqual(manifest['optional_roles'],user.ROLES)
        archive = self.fixture.temp/'enabled.tar.gz';package.write_archive(self.fixture.root,archive)
        self.assertEqual(package.verify_archive(archive),manifest)
        self.assertEqual(len(self.get(user.REPORT)['patched_pe_delta']),24)
        self.assertEqual((self.fixture.root/user.APP/'user-child.exe').read_bytes(),self.files['user-child.exe'])

    def test_third_profile_with_battle_keeps_original_scopes(self):
        self.prepare(True)
        manifest = self.verify()
        self.assertEqual(set(manifest['optional_roles']),{'user_profile','user_capability','battlenet_profile','battlenet_capability'})
        self.assertEqual((self.fixture.root/package.FIXTURE/'parent.exe').read_bytes(),b'original same fixture image')
        self.assertTrue((self.fixture.root/package.BATTLE_PROFILE).is_file())

    def test_disabled_selection_refuses_enabled_payload(self):
        self.prepare();manifest=self.finish();manifest['user_enabled']=False;manifest['optional_roles']={}
        self.put_json(package.MANIFEST,manifest);self.put(package.SUMS,package.checksums(package.inventory(self.fixture.root)))
        with self.assertRaisesRegex(ValueError,'disabled USER'):self.verify()

    def test_exact_source_copies_must_match_retained_archive(self):
        self.prepare();self.put(user.SOURCE_ROOT+'/'+user.SOURCE_FILES['source_sha256'],b'other source')
        self.reject('source copy differs')

    def test_missing_retained_source_refused(self):
        self.prepare();copies={user.SOURCE_FILES['source_sha256']:self.files['windows_child_user.c'],
            user.SOURCE_FILES['recipe_sha256']:self.files['build_windows_child_user.ps1']}
        self.put('sources/project.tar.gz',source_archive(copies));self.reject('source missing')

    def test_original_reference_run_attempt_and_project_bound(self):
        self.prepare()
        for key,value in (('run_id','124'),('run_attempt','2'),('project',{'commit':'d'*40,'tree':'e'*40})):
            meta=copy.deepcopy(self.reference);meta[key]=value
            self.put_json(user.REFERENCE,meta);self.finish()
            with self.subTest(key=key),self.assertRaises(ValueError):self.verify()
            self.put(user.REFERENCE,self.files['user-source.json'])

    def test_original_pe_machine_and_role_bytes_bound(self):
        self.prepare();data=bytearray(self.files['user-child.exe']);data[0x84:0x86]=b'\x4c\x01'
        # Rehash the synthetic reference: the actual PE parser must still reject it.
        self.put(user.REFERENCE_ROOT+'/user-child.exe',bytes(data));meta=copy.deepcopy(self.reference)
        meta['files']['user-child.exe'].update(bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
        self.put_json(user.REFERENCE,meta);self.reject()

    def test_packaged_child_bytes_must_equal_reference(self):
        self.prepare();self.put(user.APP+'/user-child.exe',b'wrong role image');self.reject('packaged role image differs')

    def test_all_24_pe_bytes_and_overlay_records_required(self):
        self.prepare();name=user.PREFIX+'/drive_c/windows/syswow64/dnsapi.dll'
        data=(self.fixture.root/name).read_bytes();self.put(name,data+b'changed');self.reject('matched PE overlay')
        self.put(name,data);report=self.get(user.REPORT);report['patched_pe_delta'].pop('drive_c/windows/syswow64/dnsapi.dll')
        self.put_json(user.REPORT,report);self.reject('matched PE overlay|complete PE overlay')

    def test_cpu_and_abi_exact_binding(self):
        self.prepare();name=user.PREFIX+'/drive_c/windows/system32/wowprospero.dll'
        self.put(name,b'changed translator');self.reject('CPU PE differs')

    def test_prepared_abi_and_worker_binding(self):
        self.prepare();report=self.get(user.REPORT);report['private_dispatcher']['mode']=0
        self.put_json(user.REPORT,report);self.reject('prefix/source/ABI/reference differs')

    def test_worker_generation_and_title_digest_bound(self):
        self.prepare();worker=self.get('PPSA99995/native-wine-child-build.json');worker['worker']['build_id']='e'*40
        self.put_json('PPSA99995/native-wine-child-build.json',worker);self.reject('capability differs')
        worker['worker']['build_id']='f'*40;self.put_json('PPSA99995/native-wine-child-build.json',worker)
        title=self.get('provenance/title.json');title['user_child_sha256']='e'*64
        self.put_json('provenance/title.json',title);self.reject('title original USER child/reference differs')

    def test_capability_cannot_claim_execution_input_or_descendants(self):
        self.prepare();baseline=self.get(user.CAPABILITY)
        for key in ('console_validated','runtime_validated','child_presentation','child_input','descendant_admission'):
            changed=copy.deepcopy(baseline);changed[key]=True;self.put_json(user.CAPABILITY,changed)
            with self.subTest(key=key): self.reject('capability differs')
        self.put_json(user.CAPABILITY,baseline)

    def test_profile_escape_cannot_be_rehashed_into_package(self):
        self.prepare();self.put(user.PROFILE,PROFILE.replace(b'prefix=windows-child-user-v1',b'prefix=windows-child-fixture-v1'))
        self.reject('application configuration differs')

    def test_reference_inventory_extra_file_refused_by_real_core(self):
        self.prepare();self.put(user.REFERENCE_ROOT+'/unclaimed.exe',b'inert');self.reject()

    def test_prefix_input_admission_uses_real_reference_and_inventory(self):
        self.prepare()
        root = self.fixture.temp / 'admission'; root.mkdir()
        repo = root / 'repo'; exported = root / 'exported'
        copies = {user.SOURCE_FILES['source_sha256']: self.files['windows_child_user.c'],
                  user.SOURCE_FILES['recipe_sha256']: self.files['build_windows_child_user.ps1'],
                  user.SOURCE_FILES['validator_sha256']: self.validator}
        for name, data in copies.items():
            target = repo/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
        for name, entry in self.extra.items():
            target=exported/name
            if entry['type']=='directory':target.mkdir(parents=True,exist_ok=True);target.chmod(entry['mode'])
            else:target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((self.fixture.root/'console'/name).read_bytes());target.chmod(entry['mode'])
        prepared = copy.deepcopy(self.prepared);prepared['host_stamp']='exact-host-stamp'
        report=root/'report.json';report.write_bytes(package.json_bytes(prepared))
        paths={'repo':repo,'user_fixture':self.fixture.root/user.REFERENCE_ROOT,
               'user_prefix':exported,'user_prefix_report':report}
        old=self.get('provenance/prefix.json');abi=self.get(package.ABI_REPORT)
        env=mock.patch.dict(os.environ,GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='1');env.start();self.addCleanup(env.stop)
        admitted=package.check_user_inputs(paths,self.project,old,abi,'exact-host-stamp')
        self.assertEqual(admitted['pair'],self.reference)
        self.assertEqual(admitted['profile'],PROFILE)
        for key,value in [('GITHUB_RUN_ID','124'),('GITHUB_RUN_ATTEMPT','2')]:
            with mock.patch.dict(os.environ,{key:value}),self.assertRaises(ValueError):
                package.check_user_inputs(paths,self.project,old,abi,'exact-host-stamp')
        with self.assertRaisesRegex(ValueError,'source/reference'):
            package.check_user_inputs(paths,self.project,old,abi,'other-host-stamp')
        (exported/user.APP.removeprefix('console/')/'user-child.exe').write_bytes(b'modified')
        with self.assertRaisesRegex(ValueError,'prefix bytes changed'):
            package.check_user_inputs(paths,self.project,old,abi,'exact-host-stamp')

    def test_retained_project_role_cannot_redirect(self):
        self.prepare();sources=self.get('provenance/retained-sources.json')
        sources['roles']['project']['path']='other.tar.gz';self.put_json('provenance/retained-sources.json',sources)
        self.reject('project source archive path')

    def test_archive_rejects_oversized_new_inspection_header_before_read(self):
        # A real truncated tar header is sufficient: refusal must happen before attempting its body.
        archive=self.fixture.temp/'oversized.tar.gz'
        with tarfile.open(archive,'w:gz') as stream:
            item=tarfile.TarInfo(user.SOURCE_ROOT+'/tests/fixtures/windows_child_user.c')
            item.mode=0o644;item.size=package.MAX_JSON+1;stream.addfile(item)
        with self.assertRaisesRegex(ValueError,'oversized inspection input'):
            package.verify_archive(archive)

    def test_title_compile_raw_receipt_is_mandatory_and_byte_bound(self):
        self.prepare();path=self.fixture.root/'provenance/title-compile.json';saved=path.read_bytes()
        path.unlink();self.reject('USER raw title compiler receipt differs')
        self.put('provenance/title-compile.json',saved+b'changed');self.reject('USER raw title compiler receipt differs')
        self.put('provenance/title-compile.json',saved)
        self.finish();self.verify()

    def test_exact_four_worker_capabilities_no_claim_inflation(self):
        self.prepare();baseline=self.get('PPSA99995/native-wine-child-build.json')
        mutations=[]
        for count in (0,2,3):
            x=copy.deepcopy(baseline);x['candidate_capabilities']=x['candidate_capabilities'][:count];mutations.append(x)
        x=copy.deepcopy(baseline);x['candidate_capabilities'].append(dict(x['candidate_capabilities'][-1]));mutations.append(x)
        for field,value in [('guest_machine','I386'),('backend','wowprospero'),('prefix',package.SLUG),('mode',5),('runtime_validated',True)]:
            for index in (2,3):
                x=copy.deepcopy(baseline);x['candidate_capabilities'][index][field]=value;mutations.append(x)
        for x in mutations:
            with self.subTest(capabilities=x['candidate_capabilities']):
                self.put_json('PPSA99995/native-wine-child-build.json',x);self.reject('worker capability cohort differs')

    def test_optional_title_must_be_enabled(self):
        self.prepare();title=self.get('provenance/title.json');title['user_enabled']=False
        self.put_json('provenance/title.json',title);self.reject('title USER admission')

    def test_user_prefix_cannot_overwrite_original_inventory(self):
        self.prepare();report=self.get(user.REPORT)
        report['inventory']['data/prospero-win/prefixes/windows-child-fixture-v1/drive_c/windows-child-fixture/parent.exe']={
            'type':'file','bytes':1,'sha256':'e'*64,'mode':0o644}
        self.put_json(user.REPORT,report);self.reject('escapes its dedicated')


if __name__ == '__main__': unittest.main(verbosity=2)
