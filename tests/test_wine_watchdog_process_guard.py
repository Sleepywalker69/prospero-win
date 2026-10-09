#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Pure extracted-predicate and source-order controls; never runs Wine/server."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / 'wine/patches/0911-server-watchdog-local-address-space.patch'


def patch_sides():
    text = PATCH.read_text()
    hunks = text[text.index('@@ '):].splitlines()
    before, after = [], []
    for line in hunks:
        if line.startswith('@@ '):
            continue
        if line.startswith((' ', '-')):
            before.append(line[1:])
        if line.startswith((' ', '+')):
            after.append(line[1:])
    return text, '\n'.join(before), '\n'.join(after)


def condition(source):
    # The patch includes one outer eligibility condition before the first
    # pointer dereference. Retain its exact C spelling and nested getpid().
    start = source.index('if (') + len('if (')
    depth = 1
    for end in range(start, len(source)):
        depth += (source[end] == '(') - (source[end] == ')')
        if not depth:
            return source[start:end], start, end
    raise ValueError('unclosed eligibility condition')


class WatchdogProcessGuard(unittest.TestCase):
    def test_real_before_condition_admits_foreign_identity_after_rejects_it(self):
        _, before, after = patch_sides()
        old, _, _ = condition(before)
        new, _, _ = condition(after)
        # All addresses are numeric local data, never dereferenced. getpid()
        # is a mock integer. This TU contains no Wine/platform code or calls.
        source = r'''
#include <assert.h>
#include <stdint.h>
struct process { int unix_pid; };
struct thread { int unix_pid; struct process *process; int wait; uintptr_t teb; int64_t ps5_last_req_time; };
static int mock_host_pid;
static int64_t monotonic_time;
#define TICKS_PER_SEC INT64_C(10000000)
#define getpid() mock_host_pid
static int before(struct thread *thread) { return OLD; }
static int after(struct thread *thread) { return NEW; }
int main(void) {
    struct process p = { 101 };
    struct thread t = { 101, &p, 0, UINT64_C(0x12345000), 0 };
    const int ids[] = { -2, -1, 0, 101, 202 };
    unsigned i,j,k;
    mock_host_pid=101; monotonic_time=2*TICKS_PER_SEC;
    assert(before(&t) && after(&t));
    t.unix_pid=p.unix_pid=202; /* actual defect: a known live foreign client */
    assert(before(&t) && !after(&t));
    t.unix_pid=p.unix_pid=-1; /* not registered, or cleared after ESRCH */
    assert(before(&t) && !after(&t));
    t.unix_pid=p.unix_pid=0;
    assert(before(&t) && !after(&t));
    for(i=0;i<sizeof(ids)/sizeof(ids[0]);i++)
        for(j=0;j<sizeof(ids)/sizeof(ids[0]);j++)
            for(k=0;k<sizeof(ids)/sizeof(ids[0]);k++) {
                t.unix_pid=ids[i];p.unix_pid=ids[j];mock_host_pid=ids[k];
                assert(after(&t)==(ids[i]>0 && ids[i]==ids[j] && ids[i]==ids[k]));
            }
    t.unix_pid=p.unix_pid=mock_host_pid=101;
    t.wait=1;assert(!before(&t) && !after(&t));t.wait=0;
    t.teb=0;assert(!before(&t) && !after(&t));t.teb=UINT64_C(0x12345000);
    monotonic_time=TICKS_PER_SEC;assert(!before(&t) && !after(&t));
    monotonic_time=TICKS_PER_SEC+1;assert(before(&t) && after(&t));
    return 0;
}
'''.replace('OLD', old).replace('NEW', new)
        cc = os.environ.get('CC') or shutil.which('cc')
        self.assertTrue(cc, 'a host C compiler is required for the pure predicate control')
        with tempfile.TemporaryDirectory() as directory:
            d=Path(directory); (d/'predicate.c').write_text(source)
            subprocess.run([cc, '-std=c11', '-Wall', '-Wextra', '-Werror',
                            str(d/'predicate.c'), '-o', str(d/'predicate')],
                           check=True, capture_output=True, text=True)
            subprocess.run([str(d/'predicate')], check=True, capture_output=True, text=True)

    def test_guard_precedes_unchanged_guest_read_block(self):
        text,before,after=patch_sides()
        self.assertEqual(re.findall(r'^--- a/(.+)$',text,re.M),['server/thread.c'])
        self.assertEqual(len(re.findall(r'^@@ ',text,re.M)),1)
        old,old_start,old_end=condition(before)
        new,new_start,new_end=condition(after)
        self.assertEqual(before[old_end+1:],after[new_end+1:])
        self.assertIn('thread->unix_pid > 0',new)
        self.assertIn('thread->process->unix_pid == thread->unix_pid',new)
        self.assertIn('thread->unix_pid == getpid()',new)
        for legacy in ['!thread->wait','thread->teb','monotonic_time - thread->ps5_last_req_time > TICKS_PER_SEC']:
            self.assertIn(legacy,old)
            self.assertIn(legacy,new)
        first_read='*(unsigned char * const *)(ULONG_PTR)(thread->teb + 0x1480 + 8)'
        self.assertGreater(after.index(first_read),new_end)
        self.assertNotIn('ps5_peek(',new)
        self.assertNotIn('WINE_PS5_WAIT_WATCHDOG',text)
        # No new remote memory/control fallback, changed callback, or altered
        # inner diagnostic statement is hidden among the additions.
        additions='\n'.join(x[1:] for x in text.splitlines() if x.startswith('+') and not x.startswith('+++'))
        self.assertNotRegex(additions,r'\b(ptrace|mmap|socket|sendmsg|recvmsg|read|write|kill)\s*\(')


if __name__=='__main__':
    unittest.main()
