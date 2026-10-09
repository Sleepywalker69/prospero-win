#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Compile exact composed Wine consumer bodies with pure boundary mocks.

Requires an already composed Wine source tree. Does not download, execute Wine,
or implement a replacement process provider. Generated excerpts are retained.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess


def function(text, signature):
    matches = list(re.finditer(re.escape(signature) + r"\s*\{", text))
    assert len(matches) == 1, signature
    begin = matches[0].start()
    brace = text.index("{", begin)
    depth = 1
    for end in range(brace + 1, len(text)):
        if text[end] == "{":
            depth += 1
        elif text[end] == "}":
            depth -= 1
            if not depth:
                return text[begin:end + 1] + "\n"
    raise AssertionError(signature)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--wine-source", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--cc", default="cc")
    p.add_argument("--cflags", default="-std=c11 -Wall -Wextra -Werror")
    p.add_argument("--mutate-remove-final-budget", action="store_true")
    args = p.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    paths = ["dlls/ntdll/unix/process.c", "dlls/ntdll/unix/server.c", "server/process.c", "server/ptrace.c", "dlls/ntdll/unix/thread.c", "include/wine/pw_wine_fixture_provider.h"]
    source = {n: (args.wine_source/n).read_text() for n in paths}
    (out/"source-hashes.json").write_text(json.dumps({n: hashlib.sha256((args.wine_source/n).read_bytes()).hexdigest() for n in paths}, indent=2)+"\n")
    (out/"pw_wine_fixture_provider.h").write_text(source[paths[-1]])
    proc = source[paths[0]]
    begin = proc.index("    /* wait for the new process info to be ready */")
    end = proc.index("    /* update output attributes */", begin)
    startup = proc[begin:end]
    assert "if (status != STATUS_WAIT_0)" in startup
    if args.mutate_remove_final_budget:
        guard = "#ifdef PW_WINE_SERVICE_FIXTURE\n    if (!fixture->startup_remaining_ms( fixture->context, fixture_generation ))\n    { success = FALSE; status = STATUS_IO_TIMEOUT; goto done; }\n#endif\n"
        assert startup.count(guard) == 1
        startup = startup.replace(guard, "/* DELIBERATE MUTATION: final budget check removed. */\n")
    (out/"startup.inc").write_text(startup)
    done = proc.index("done:\n", end)
    footer_end = proc.index("    if (file_handle)", done)
    (out/"startup-result.inc").write_text(proc[done:footer_end])
    server = source[paths[1]]
    local = function(server, "int pw_wine_fixture_local_threads( int (*add)(long,pthread_t), void (*remove)(long) )")
    local += function(server, "static void register_inprocess_thread( int tid )")
    (out/"local-threads.inc").write_text(local)
    start = server.index("    server_pid = -1;", server.index("size_t server_init_process(void)"))
    stop = server.index("    /* setup the signal mask */", start)
    (out/"inherited-server.inc").write_text(server[start:stop])
    adapter = "pw_wine_fixture_socket( fd_socket, PW_WF_SOCKET_CLOEXEC )" in server[start:stop]
    (out/"socket-adapter.inc").write_text("#define PW_TEST_SOCKET_ADAPTER %d\n" % adapter)
    (out/"signal.inc").write_text(function(source[paths[3]], "int send_thread_signal( struct thread *thread, int sig )"))
    timers = function(source[paths[2]], "static void process_sigkill( void *private )")
    timers += function(source[paths[2]], "static void start_sigkill_timer( struct process *process )")
    (out/"timers.inc").write_text(timers)
    thread = source["dlls/ntdll/unix/thread.c"]
    root_exit = function(server, "void pw_wine_fixture_root_exit( unsigned int windows_status )")
    root_exit += function(server, "void process_exit_wrapper( int status )")
    root_exit += function(thread, "static inline int get_unix_exit_code( NTSTATUS status )")
    root_exit += function(thread, "void exit_process( int status )")
    (out/"root-exit.inc").write_text(root_exit)
    test = Path(__file__).resolve().parents[1]/"tests/fixtures/wine_fixture_consumers.c"
    commands = [shlex.split(args.cc) + shlex.split(args.cflags) + ["-I", str(out), str(test.resolve()), "-o", str(out/"test")], [str(out/"test")]]
    results = []
    for cmd in commands:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        results.append({"command": cmd, "exit_status": result.returncode, "output": result.stdout})
        if result.returncode:
            break
    (out/"result.json").write_text(json.dumps({"deliberate_mutation":args.mutate_remove_final_budget,"commands":results},indent=2)+"\n")
    print(json.dumps(results,indent=2))
    raise SystemExit(0 if len(results)==2 and not results[-1]["exit_status"] else 1)


if __name__ == "__main__":
    main()
