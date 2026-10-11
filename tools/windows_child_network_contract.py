#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Read-only inspection of the separately built original AMD64 network pair.

This does not execute, map or load PE instructions. A trusted hosted artifact
and externally supplied project/run identities remain the evidence anchors.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import ntpath
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
sys.dont_write_bytecode = True
from windows_child_user_contract import inspect_pe, require, digest, regular, decode, record, windows_path

NAMES = ('net-parent.exe', 'net-child.exe')
RECEIPT = 'network-source.json'
SOURCE = 'tests/fixtures/windows_child_network.c'
RECIPE = 'tools/build_windows_child_network.ps1'
VALIDATOR = 'tools/windows_child_network_contract.py'
HEADER = 'tests/fixtures/windows_child_network_contract.h'
MAX_PE = 16 << 20


REQUIRED = {
    'parent': {'kernel32.dll': {'CreateProcessW', 'WaitForSingleObject', 'GetExitCodeProcess',
                               'CloseHandle', 'CreateFileA', 'WriteFile'}},
    'child': {'kernel32.dll': {'CreateThread', 'GetExitCodeThread', 'CloseHandle', 'CreateFileA',
                              'WriteFile', 'GetSystemDirectoryW', 'LoadLibraryW',
                              'GetProcAddress', 'FreeLibrary'}}}


def inspect_role(data, role):
    report = inspect_pe(data)
    require(set(report['imports']) == set(REQUIRED[role]), 'unexpected original role DLL imports')
    for dll, symbols in REQUIRED[role].items():
        require(symbols <= set(report['imports'][dll]), 'required original role imports missing')
    return report


def parse_log(data, role):
    require(type(data) is bytes and 0 < len(data) <= 65536, 'bounded role log required')
    rows = []
    for line in data.decode('ascii').splitlines():
        parts = line.split()
        require(parts and parts[0] == 'PW_CHILD_NET', 'foreign role log line')
        row = {}
        for part in parts[1:]:
            require(part.count('=') == 1, 'malformed role field')
            key, value = part.split('=')
            require(key and value and key not in row, 'empty/duplicate role field')
            row[key] = value
        require(row.get('role') == role and all(re.fullmatch('[1-9][0-9]*', row.get(k, '')) and
                int(row[k]) <= 0xffffffff for k in ('pid', 'tid')), 'role process/thread identity invalid')
        require(row.get('result') != 'failed' and row.get('stage') != 'self_exit', 'failed reference log')
        rows.append(row)
    require(1 <= len(rows) <= 64, 'bounded stage count required')
    return rows


def inspect_logs(parent_data, child_data):
    parent, child = parse_log(parent_data, 'parent'), parse_log(child_data, 'child')
    require([x.get('stage') for x in parent] == ['start', 'create_process', 'create_process', 'child_exit', 'finish'],
            'parent reference stage order differs')
    pid, main = child[0]['pid'], child[0]['tid']
    require(pid != parent[0]['pid'] and
            all(x['pid'] == pid and x['tid'] == main for x in child) and
            all(x['pid'] == parent[0]['pid'] and x['tid'] == parent[0]['tid'] for x in parent),
            'reference process/main-thread identity changed')
    common = {'role','stage','pid','tid'}
    def fields(row, expected, variable=()):
        require(set(row) == common | set(expected) | set(variable), 'unexpected/missing role fields: '+str(row.get('stage')))
        require(all(row.get(k) == str(v) for k,v in expected.items()), 'reference observation differs: '+row['stage'])
    def number(row, key, minimum=0, maximum=0xffffffff):
        value = row.get(key,'')
        require(re.fullmatch(r'0|-?[1-9][0-9]*',value) and minimum <= int(value) <= maximum,
                'invalid bounded numeric observation: '+key)
        return int(value)
    start = {'mode':'original_network_control','network_success':'unverified',
             'child_presentation':'unverified','child_input':'unverified'}
    finish = {'prior_status':0,'diagnostic_cleanup':'completed','final_log_close':'pending','native_settlement':'unverified'}
    fields(parent[0],start)
    fields(parent[1],{'result':'attempt','child':'net-child.exe','inherited_handles':0,'arguments':'none'})
    fields(parent[2],{'result':'returned_success','child_pid':pid,'child_tid':main,'initialized':'unverified'})
    fields(parent[3],{'query_ok':1,'observed_code':37,'expected':37,'matches':1,'native_settlement':'unverified'})
    fields(parent[4],{'planned_exit':0,**finish})
    position = 0
    def take(stage):
        nonlocal position
        require(position < len(child) and child[position].get('stage') == stage,
                'child reference stage order differs: '+stage)
        row = child[position]; position += 1
        return row
    fields(take('start'),start)
    fields(take('winsock_module'),{'result':'loaded','error':0})
    row=take('wsa_startup');fields(row,{'domain':'winsock','code':0,'version':514},('high_version',))
    number(row,'high_version',0,65535)
    def resolver(case, optional, flags, kind):
        fields(take('resolve_attempt'),{'case':case,'optional':optional,'family':'AF_INET','service':80,'flags':flags})
        row=take('resolve_result')
        fields(row,{'case':case,'domain':'winsock','shape_valid':1,'optional':optional},
               ('code','count','success','elapsed_ms'))
        code=number(row,'code',-(1<<31),(1<<31)-1);count=number(row,'count',0,64)
        success=number(row,'success',0,1);elapsed=number(row,'elapsed_ms',0,44999)
        if kind=='numeric': require(code==0 and 1<=count<=64 and success==1,'mandatory numeric resolution failed')
        elif kind=='refusal': require(code in (11001,11004) and count==0 and success==0,'unexpected numeric-only refusal')
        else: require((code==0 and count>=1 and success==1) or (code!=0 and count==0 and success==0),
                      'optional FQDN result is contradictory')
        return {'code':code,'count':count,'success':bool(success),'elapsed_ms':elapsed}
    resolver('127.0.0.1',0,4,'numeric')
    refusal=resolver('not-numeric.invalid',0,4,'refusal')
    fields(take('socket_create'),{'domain':'winsock','created':1,'code':0,'remote_traffic':0})
    fields(take('socket_close'),{'domain':'winsock','result':0,'code':0})
    module=take('dnsapi_module');dns={'module_available':False,'exports_available':False,
                                   'numeric':None,'server_config':None}
    if module.get('result')=='unavailable':
        if 'operation' in module:
            fields(module,{'result':'unavailable','operation':'system_directory','capacity':260},('returned_length','error'))
            length=number(module,'returned_length');number(module,'error')
            require(length==0 or length>=249,'system-directory refusal contradicts fixed path bounds')
        else:
            fields(module,{'result':'unavailable'},('error',));number(module,'error')
    else:
        fields(module,{'result':'loaded','error':0});dns['module_available']=True
        require(position<len(child),'missing optional DNS observations')
        if child[position].get('stage')=='export':
            row=take('export');fields(row,{'result':'unavailable'},('name','error'))
            require(row['name'] in ('DnsQuery_W','DnsQueryConfig','DnsRecordListFree'),'unrelated export refusal')
            number(row,'error');dns['missing_export']=row['name']
        else:
            dns['exports_available']=True
            row=take('dnsapi_numeric');fields(row,{'domain':'dns_status','shape_valid':1,'optional':1},('code','record_present'))
            code=number(row,'code');present=number(row,'record_present',0,1)
            require(present==int(code==0),'optional numeric DNS record contradiction')
            dns['numeric']={'code':code,'success':code==0}
            row=take('dnsapi_config')
            fields(row,{'domain':'dns_status','capacity':260,'shape_valid':1,'optional':1},
                   ('code','returned_bytes','count','untouched','server_config_available'))
            code=number(row,'code');length=number(row,'returned_bytes');count=number(row,'count',0,64)
            untouched=number(row,'untouched',0,1);available=number(row,'server_config_available',0,1)
            if code==0:
                require(4<=length<=260 and count<=(length-4)//4 and available==1 and untouched==0,
                        'malformed successful DNS configuration')
            else:
                require(count==0 and available==0 and (not untouched or length==260),
                        'contradictory unavailable DNS configuration')
            dns['server_config']={'code':code,'available':bool(available),'returned_bytes':length,
                                  'count':count,'untouched':bool(untouched)}
        fields(take('dnsapi_unload'),{'result':1,'error':0,'prior_status':0})
    fqdn=resolver('example.com.',1,0,'optional')
    fields(take('wsa_cleanup'),{'domain':'winsock','result':0,'code':0})
    fields(take('winsock_unload'),{'result':1,'error':0,'prior_status':0})
    fields(take('network_cleanup'),{'status':0,'local_contract_complete':1,
                                  'fqdn_success_is_separate':1,'native_settlement':'unverified'})
    fields(take('finish'),{'planned_exit':37,**finish})
    require(position==len(child),'extra or repeated diagnostic operation')
    return {'parent_pid':parent[0]['pid'],'child_pid':pid,'main_tid':main,'observed_child_exit':37,
            'local_contract_complete':True,'numeric_refusal_code':refusal['code'],'dnsapi':dns,'fqdn':fqdn,
            'tcp_tested':False,'tls_tested':False,'native_settlement':'unverified'}


def inspect_commands(commands, headers, data_file):
    require(isinstance(commands,dict) and set(commands)=={'parent','child'}, 'both exact role commands required')
    path=r'([A-Za-z]:\\[^"\r\n%!]+)'
    pattern=(r'call "'+path+r'" > nul && "'+path+r'" /nologo /std:c11 /W4 /WX /O2 /MT '
             r'/D_CRT_SECURE_NO_WARNINGS /DPW_NET_CHILD=([01]) /sourceDependencies "'+path+r'" "'+path+
             r'" /Fe:"'+path+r'" /Fo:"'+path+
             r'" /link /DYNAMICBASE /FIXED:NO /NXCOMPAT /INCREMENTAL:NO')
    normalized_headers={}
    for name,record_ in headers.items():
        key=windows_path(name)
        require(key not in normalized_headers,'ambiguous header path aliases')
        normalized_headers[key]=record_
    shared=None; consumed=set(); result={}
    for selector,role in enumerate(('parent','child')):
        command=commands[role]
        require(isinstance(command,str) and len(command)<=32768,'bounded compile command required')
        match=re.fullmatch(pattern,command)
        require(match is not None,'compile flags/arguments differ from the original recipe')
        vcvars,compiler,actual_selector,deps,source,exe,obj=match.groups()
        vcvars,compiler,deps,source,exe,obj=map(windows_path,(vcvars,compiler,deps,source,exe,obj))
        require(actual_selector==str(selector) and vcvars.endswith(r'\vc\auxiliary\build\vcvars64.bat') and
                compiler.endswith(r'\bin\hostx64\x64\cl.exe') and
                source.endswith(r'\tests\fixtures\windows_child_network.c'),'role/compiler/source path differs')
        parent=ntpath.dirname(exe)
        require(ntpath.basename(exe)=='net-'+role+'.exe' and ntpath.dirname(obj)==parent and
                ntpath.basename(obj)=='net-'+role+'.obj' and ntpath.dirname(deps)==parent and
                ntpath.basename(deps)=='dependencies-'+role+'.json','role output paths differ')
        identity=(vcvars,compiler,source,parent)
        require(shared is None or shared==identity,'role compile providers/source/output differ')
        shared=identity
        dependency=decode(data_file('dependencies-'+role+'.json',4<<20,1))
        require(dependency.get('Version') in ('1.1','1.2') and isinstance(dependency.get('Data'),dict),
                'compiler source dependency schema differs')
        dep=dependency['Data']; includes=dep.get('Includes')
        require(windows_path(dep.get('Source'))==source and isinstance(includes,list) and 0<len(includes)<=512,
                'compiler dependency source/includes differ')
        require(dep.get('ProvidedModule') in (None,'') and dep.get('ImportedModules') in (None,[]) and
                dep.get('ImportedHeaderUnits') in (None,[]),'unexpected module inputs in C fixture')
        for name in includes:
            key=windows_path(name)
            require(key in normalized_headers,'consumed compiler header lacks receipt')
            consumed.add(key)
        result[role]={'selector':selector,'command_sha256':digest(command.encode()),
                      'dependency_sha256':digest(data_file('dependencies-'+role+'.json',4<<20,1)),
                      'header_count':len(set(map(windows_path,includes)))}
        if role=='child':
            contract_path=ntpath.join(ntpath.dirname(source),'windows_child_network_contract.h')
            selected=[name for name in includes if windows_path(name)==contract_path]
            require(len(selected)==1, 'child did not consume exact fixture contract header')
            result[role]['contract_header']=next(name for name in headers if windows_path(name)==contract_path)
    require(consumed==set(normalized_headers),'unconsumed header receipt or missing dependency')
    return result

def verify_pair_copy(directory, metadata):
    for name in NAMES:
        data = regular(Path(directory) / name, MAX_PE, 256)
        require(record(data) == {k: metadata['files'][name][k] for k in ('bytes', 'sha256')},
                'network exported image differs')


def validate_contents(read, names, expected_project, expected_run, expected_attempt, source_hashes, details=None):
    """Validate already bounded archive bytes; no extraction or code execution."""
    require(isinstance(names, (set, frozenset)) and 1 <= len(names) <= 64, 'bounded file-name set required')
    require(all(isinstance(n,str) and re.fullmatch('[A-Za-z0-9_.-]+',n) and n not in ('.','..')
                for n in names) and len({n.casefold() for n in names}) == len(names), 'unsafe/duplicate artifact names')
    allowed = {RECEIPT, *NAMES, 'windows_child_network.c','build_windows_child_network.ps1','windows_child_network_contract.h','windows_child_network_contract.py',
               'net-parent.obj','net-child.obj','build-parent.log','build-child.log',
               'inspect-parent.log','inspect-child.log','dependencies-parent.json','dependencies-child.json',
               'reference.stdout.log','reference.stderr.log','network-inspection.json','SHA256SUMS'}
    require(all(n in allowed or re.fullmatch(r'net-(parent|child)-[1-9][0-9]*-(0|[1-9][0-9]*)\.log',n)
                for n in names), 'unexpected original artifact file or role image')
    def data_file(name, maximum, minimum=0):
        require(name in names, 'missing original input: '+name)
        data=read(name)
        require(type(data) is bytes and minimum <= len(data) <= maximum, 'unbounded/nonbyte original input')
        return data
    require(isinstance(expected_project,dict) and set(expected_project)=={'commit','tree'} and
            all(isinstance(v,str) and re.fullmatch('[0-9a-f]{40}',v) for v in expected_project.values()),
            'external project identity required')
    require(isinstance(source_hashes,dict) and set(source_hashes)=={'source_sha256','recipe_sha256','validator_sha256','header_sha256'} and
            all(isinstance(v,str) and re.fullmatch('[0-9a-f]{64}',v) for v in source_hashes.values()),
            'independently bound current source hashes required')
    run, attempt = expected_run, expected_attempt
    require(isinstance(run, str) and re.fullmatch('[1-9][0-9]*', run) and
            isinstance(attempt, str) and re.fullmatch('[1-9][0-9]*', attempt), 'external run/attempt required')
    meta = decode(data_file(RECEIPT, 8 << 20, 1))
    require(meta.get('schema') == 'pw-original-windows-child-network-msvc/1' and
            meta.get('project') == expected_project and meta.get('architecture') == 'x64' and
            meta.get('run_id') == run and meta.get('run_attempt') == attempt, 'network producer identity differs')
    for key, expected in source_hashes.items():
        require(meta.get(key) == expected, 'network source/recipe/validator differs')
    for name,key in [('windows_child_network.c','source_sha256'),('build_windows_child_network.ps1','recipe_sha256'),('windows_child_network_contract.h','header_sha256'),('windows_child_network_contract.py','validator_sha256')]:
        require(digest(data_file(name,4<<20,1))==source_hashes[key], 'copied original source/recipe differs')
    require(meta.get('runtime_validated') is False and meta.get('network_validated') is False and
            meta.get('independent_log_validation') is False and meta.get('child_presentation') is False and
            meta.get('child_input') is False and meta.get('import_policy_verified') is False and
            meta.get('relocation_entries_verified') is False, 'network producer overstates its evidence')
    compiler = meta.get('compiler', {})
    require(compiler.get('name') == 'MSVC cl.exe' and isinstance(compiler.get('file_version'), str) and
            compiler['file_version'] and re.fullmatch('[0-9a-f]{64}', compiler.get('sha256', '')),
            'exact MSVC compiler identity required')
    require(meta.get('inspector', {}).get('name') == 'MSVC dumpbin.exe' and
            re.fullmatch('[0-9a-f]{64}', meta['inspector'].get('sha256', '')), 'inspector identity required')
    headers = meta.get('headers')
    require(isinstance(headers, dict) and 0 < len(headers) <= 1024, 'consumed header receipts missing')
    for name, value in headers.items():
        require(isinstance(name, str) and 0 < len(name) <= 4096 and isinstance(value, dict) and
                type(value.get('bytes')) is int and 0 < value['bytes'] <= 16 << 20 and
                re.fullmatch('[0-9a-f]{64}', value.get('sha256', '')), 'invalid consumed header receipt')
    commands = inspect_commands(meta.get('compile_commands'), headers, data_file)
    contract_header=record(data_file('windows_child_network_contract.h',4<<20,1))
    require(commands['child'].get('contract_header') in headers and
            headers[commands['child']['contract_header']]==contract_header, 'consumed original contract header differs')
    require(isinstance(meta.get('files'), dict) and set(meta['files']) == set(NAMES), 'network role images differ')
    images, inspected = {}, {}
    for selector, (name, role) in enumerate(zip(NAMES, ('parent', 'child'))):
        images[name] = data_file(name, MAX_PE, 256)
        require(type(meta['files'][name].get('selector')) is int and meta['files'][name] == {**record(images[name]), 'machine': 'AMD64', 'selector': selector},
                'network role image binding differs')
        inspected[role] = inspect_role(images[name], role)
    require(images[NAMES[0]] != images[NAMES[1]], 'distinct compiled role images required')
    reference = meta.get('reference', {})
    require(reference.get('executed') is True and type(reference.get('exit')) is int and
            reference['exit'] == 0 and reference.get('deadline_seconds') == 105, 'fresh Windows reference required')
    for role in ('stdout', 'stderr'):
        data = data_file('reference.' + role + '.log', 128 << 10)
        require(reference.get(role) == record(data), 'reference stream differs')
        if role == 'stderr':
            require(not data, 'unexpected reference stderr')
    logs = reference.get('role_logs')
    require(isinstance(logs, dict) and len(logs) == 2, 'exactly two role logs required')
    role_data, role_names = {}, {}
    for name, expected in logs.items():
        match = re.fullmatch(r'net-(parent|child)-([1-9][0-9]*)-([0-9]+)\.log', name)
        require(match and match[1] not in role_data and int(match[2]) <= 0xffffffff and
                int(match[3]) <= (1 << 64)-1, 'ambiguous/unsafe role log')
        data = data_file(name, 65536, 1)
        require(record(data) == expected, 'role log bytes differ')
        rows = parse_log(data, match[1])
        require(all(row['pid'] == match[2] for row in rows), 'role log filename PID differs')
        role_data[match[1]], role_names[match[1]] = data, name
    require(set(role_data) == {'parent', 'child'}, 'missing role log')
    observed = inspect_logs(role_data['parent'], role_data['child'])
    require({n for n in names if n.startswith('net-') and n.endswith('.log')} == set(logs), 'extra ambiguous role logs')
    if details is not None:
        details.update(schema='pw-original-windows-child-network-inspection/1', project=expected_project,
                       run_id=run, run_attempt=attempt, receipt_sha256=digest(data_file(RECEIPT, 8 << 20, 1)),
                       images=inspected, observed=observed, role_logs=role_names, compile_commands=commands,
                       import_policy_verified=True, relocation_entries_verified=True,
                       independent_log_validation=True, dynamic_provider_closure_verified=False, network_validated=False,
                       runtime_validated=False, console_validated=False)
    return meta


def validate_pair(directory, expected_project, root, expected_run=None, expected_attempt=None, *, details=None):
    directory, root = Path(directory), Path(root)
    names=set()
    for path in directory.iterdir():
        # The original producer creates a flat fresh directory. Do not follow
        # links or accept hidden alternate role images from an unlisted tree.
        regular(path,MAX_PE)
        names.add(path.name)
    hashes={key:digest(regular(root/relative,4<<20,1)) for key,relative in
            [('source_sha256',SOURCE),('recipe_sha256',RECIPE),('validator_sha256',VALIDATOR),('header_sha256',HEADER)]}
    return validate_contents(lambda name:regular(directory/name,MAX_PE), names, expected_project,
        expected_run if expected_run is not None else os.environ.get('GITHUB_RUN_ID'),
        expected_attempt if expected_attempt is not None else os.environ.get('GITHUB_RUN_ATTEMPT'),
        hashes, details)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--run')
    parser.add_argument('--attempt')
    args = parser.parse_args()
    def git(*parts):
        return subprocess.run(['git', '-C', str(args.repo), *parts], check=True,
                              capture_output=True, text=True, timeout=60).stdout.strip()
    require(not git('status', '--porcelain', '--untracked-files=no'), 'tracked project inputs are dirty')
    project = {'commit': git('rev-parse', 'HEAD'), 'tree': git('rev-parse', 'HEAD^{tree}')}
    result = {}
    validate_pair(args.directory, project, args.repo, args.run, args.attempt, details=result)
    with args.report.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write('\n')


if __name__ == '__main__':
    main()
