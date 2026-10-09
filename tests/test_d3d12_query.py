#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Source-routing control only. Does not load or run the Windows fixture."""
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'tests/fixtures/d3d12_capability_query.c').read_text()

class QuerySource(unittest.TestCase):
    def test_pure_result_cleanup_and_absolute_deadline_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'query-contract'
            subprocess.run([shutil.which('cc'), '-std=c11', '-Wall', '-Wextra', '-Werror', '-pedantic',
                            '-I', str(ROOT / 'tests/fixtures'),
                            str(ROOT / 'tests/fixtures/d3d12_query_contract_test.c'), '-o', str(binary)], check=True)
            subprocess.run([str(binary)], check=True)

    def test_reports_queries_instead_of_requesting_a_higher_minimum(self):
        self.assertIn('(D3D_FEATURE_LEVEL)0xc200', SOURCE)
        self.assertNotIn('D3D_FEATURE_LEVEL_12_2', SOURCE)
        self.assertRegex(SOURCE, r'D3D12CreateDevice\(\(IUnknown \*\)adapter, D3D_FEATURE_LEVEL_11_0,')
        self.assertIn('D3D12_FEATURE_FEATURE_LEVELS', SOURCE)
        self.assertIn('D3D12_FEATURE_D3D12_OPTIONS', SOURCE)
        self.assertIn('desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE', SOURCE)
        for forbidden in ['EnumWarpAdapter(', 'D3D12GetInterface(', 'CreateCommandQueue(',
                          'CreateSwapChain', 'ExecuteCommandLists(', 'SetEnvironmentVariable']:
            self.assertNotIn(forbidden, SOURCE)

    def test_exact_environment_guard_with_original_api_mocks(self):
        first = SOURCE.index('static int configuration_is_unforced(void)')
        last = SOURCE.index('static DWORD WINAPI query_worker', first)
        body = SOURCE[first:last]
        prologue = r'''#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t DWORD;
#define ERROR_SUCCESS 0u
#define ERROR_ENVVAR_NOT_FOUND 203u
static DWORD lengths[2], errors[2], last_error;
static unsigned calls;
static void SetLastError(DWORD value) { last_error=value; }
static DWORD GetLastError(void) { return last_error; }
static DWORD GetEnvironmentVariableA(const char *name, char *buffer, DWORD size) {
    unsigned index;
    assert(buffer==NULL && size==0);
    if(!strcmp(name,"VKD3D_FEATURE_LEVEL")) index=0;
    else { assert(!strcmp(name,"VKD3D_SHADER_MODEL")); index=1; }
    ++calls;last_error=errors[index];return lengths[index];
}
'''
        main = r'''int main(void) {
    errors[0]=errors[1]=ERROR_ENVVAR_NOT_FOUND;
    assert(configuration_is_unforced() && calls==2); /* missing */
    calls=0;errors[0]=errors[1]=ERROR_SUCCESS;
    assert(configuration_is_unforced() && calls==2); /* empty */
    calls=0;lengths[0]=5;
    assert(!configuration_is_unforced() && calls==1);
    calls=0;lengths[0]=0;lengths[1]=4;
    assert(!configuration_is_unforced() && calls==2);
    calls=0;lengths[1]=0;errors[0]=5; /* unreadable is not absent */
    assert(!configuration_is_unforced() && calls==1);
    calls=0;errors[0]=ERROR_ENVVAR_NOT_FOUND;errors[1]=87;
    assert(!configuration_is_unforced() && calls==2);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            d=Path(directory); source=d/'environment.c'; binary=d/'environment'
            source.write_text(prologue+body+main)
            subprocess.run([shutil.which('cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                            str(source), '-o', str(binary)], check=True, capture_output=True, text=True)
            subprocess.run([str(binary)], check=True, capture_output=True, text=True)

    def test_override_refusal_and_deadline_before_completion(self):
        self.assertIn('"VKD3D_FEATURE_LEVEL", "VKD3D_SHADER_MODEL"', SOURCE)
        main = SOURCE[SOURCE.index('int main('):]
        self.assertLess(main.index('configuration_is_unforced()'), main.index('CreateThread('))
        self.assertLess(main.index('started = GetTickCount64()'), main.index('CreateThread('))
        self.assertIn('WaitForSingleObject(worker, remaining)', main)
        self.assertEqual(main.count('pw_d3d12_query_remaining(started, &last_observed, now, &remaining)'), 3)
        self.assertIn('wait_error = wait_result == WAIT_FAILED ? GetLastError() : 0;', main)
        self.assertRegex(main, r'if \(!budget\) budget = pw_d3d12_query_remaining')
        self.assertGreater(main.rindex('pw_d3d12_query_remaining'), main.index('CloseHandle(worker)'))
        self.assertLess(main.rindex('pw_d3d12_query_remaining'), main.index('? "COMPLETE"'))
        self.assertNotIn('INFINITE', main)
        self.assertIn('static struct query_result result;', main)
        self.assertIn('GetExitCodeThread(worker, &thread_exit)', main)
        self.assertIn('worker_finished == 1, exit_query_ok != FALSE', main)
        self.assertLess(SOURCE.index('if (factory) IDXGIFactory1_Release(factory);'),
                        SOURCE.index('InterlockedExchange(&result->finished, 1)'))
        self.assertIn('ExitProcess((UINT)status);', main)

if __name__ == '__main__':
    unittest.main()
