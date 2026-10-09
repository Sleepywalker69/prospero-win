/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Original, bounded Win32 process diagnostic. Build once, copy the image to
 * parent.exe and child.exe. No game data, networking, or custom memory maps. */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define INITIAL_MARKER ((DWORD)0x13579bdf)
#define NORMAL_EXIT ((DWORD)0x0051002a)
#define EARLY_EXIT ((DWORD)0x00510031)
#define STOP_EXIT ((DWORD)0x00510040)
#define CHILD_ERROR ((DWORD)0x005100ee)
#define WAIT_MS ((DWORD)5000)
#define HOLD_MS ((DWORD)120000)
#define MAGIC ((DWORD)0x50574331)
static volatile DWORD private_marker = INITIAL_MARKER;
static unsigned owned_handles;
static DWORD last_launch_error;

struct hello {
    DWORD magic, bytes, version, pid, parent_claim, nonce, initial, value;
    uint64_t address;
};
struct child {
    PROCESS_INFORMATION process;
    HANDLE read_pipe, release_event;
};

static int close_owned(HANDLE *handle)
{
    if (!*handle) return 1;
    if (!CloseHandle(*handle)) {
        printf("PW_CHILD_FIXTURE role=parent stage=close result=fail error=%lu\n", GetLastError());
        return 0;
    }
    *handle = NULL;
    --owned_handles;
    return 1;
}
static int decimal(const wchar_t *text, uint64_t maximum, uint64_t *value)
{
    wchar_t *end;
    if (!text[0] || text[0] < L'0' || text[0] > L'9') return 0;
    errno = 0;
    *value = wcstoull(text, &end, 10);
    return !errno && !*end && *value <= maximum;
}
static int child_main(int argc, wchar_t **argv)
{
    struct hello message;
    uint64_t parent, nonce, pipe_value, event_value;
    HANDLE pipe, release_event;
    DWORD written, wait;
    int hold;
    if (argc != 7 || !decimal(argv[3], UINT32_MAX, &parent) ||
        !decimal(argv[4], UINT32_MAX, &nonce) || !decimal(argv[5], UINTPTR_MAX, &pipe_value) ||
        !decimal(argv[6], UINTPTR_MAX, &event_value)) return (int)CHILD_ERROR;
    hold = !wcscmp(argv[2], L"hold");
    pipe = (HANDLE)(uintptr_t)pipe_value;
    release_event = (HANDLE)(uintptr_t)event_value;
    if (!wcscmp(argv[2], L"early")) {
        CloseHandle(pipe); CloseHandle(release_event);
        return (int)EARLY_EXIT; /* Deliberate exit before the READY record. */
    }
    if (!hold && wcscmp(argv[2], L"normal")) return (int)CHILD_ERROR;
    memset(&message, 0, sizeof(message));
    message.magic = MAGIC; message.bytes = (DWORD)sizeof(message); message.version = 1;
    message.pid = GetCurrentProcessId(); message.parent_claim = (DWORD)parent;
    message.nonce = (DWORD)nonce; message.initial = private_marker;
    private_marker = (DWORD)nonce ^ 0x53594e54u;
    message.value = private_marker; message.address = (uint64_t)(uintptr_t)&private_marker;
    printf("PW_CHILD_FIXTURE role=child stage=ready pid=%lu parent_claim=%lu nonce=%lu va=%llu initial=%lu value=%lu\n",
           message.pid, message.parent_claim, message.nonce, (unsigned long long)message.address,
           message.initial, message.value);
    fflush(stdout);
    if (!WriteFile(pipe, &message, sizeof(message), &written, NULL) || written != sizeof(message)) {
        CloseHandle(pipe); CloseHandle(release_event);
        return (int)CHILD_ERROR;
    }
    CloseHandle(pipe);
    /* The event keeps this child alive while the parent checks both states.
     * A finite deadline also bounds a failed external Stop experiment. */
    wait = WaitForSingleObject(release_event, hold ? HOLD_MS : 2 * WAIT_MS);
    CloseHandle(release_event);
    if (wait != WAIT_OBJECT_0 || private_marker != message.value) return (int)CHILD_ERROR;
    return (int)NORMAL_EXIT;
}
static int sibling(wchar_t path[MAX_PATH], const wchar_t *leaf)
{
    DWORD length = GetModuleFileNameW(NULL, path, MAX_PATH);
    wchar_t *last;
    size_t prefix, suffix = wcslen(leaf);
    if (!length || length >= MAX_PATH || !(last = wcsrchr(path, L'\\'))) return 0;
    prefix = (size_t)(last + 1 - path);
    if (prefix + suffix >= MAX_PATH) return 0;
    memcpy(path + prefix, leaf, (suffix + 1) * sizeof(*path));
    return 1;
}
static int start_child(const wchar_t *path, const wchar_t *mode, DWORD nonce, struct child *child)
{
    SECURITY_ATTRIBUTES attributes = {(DWORD)sizeof(attributes), NULL, TRUE};
    STARTUPINFOW startup;
    HANDLE write_pipe = NULL;
    wchar_t command[1024];
    int length;
    DWORD error;
    memset(child, 0, sizeof(*child)); memset(&startup, 0, sizeof(startup)); startup.cb = (DWORD)sizeof(startup);
    if (!CreatePipe(&child->read_pipe, &write_pipe, &attributes, 0)) {
        /* CreatePipe documents indeterminate output handles on failure. */
        child->read_pipe = write_pipe = NULL;
        goto setup_failed;
    }
    owned_handles += 2;
    if (!SetHandleInformation(child->read_pipe, HANDLE_FLAG_INHERIT, 0)) goto setup_failed;
    child->release_event = CreateEventW(&attributes, TRUE, FALSE, NULL);
    if (!child->release_event) goto setup_failed;
    ++owned_handles;
    length = swprintf(command, sizeof(command) / sizeof(command[0]),
                      L"\"%ls\" --child %ls %lu %lu %llu %llu", path, mode,
                      GetCurrentProcessId(), nonce, (unsigned long long)(uintptr_t)write_pipe,
                      (unsigned long long)(uintptr_t)child->release_event);
    if (length < 0 || (size_t)length >= sizeof(command) / sizeof(command[0])) goto setup_failed;
    printf("PW_CHILD_FIXTURE role=parent stage=CreateProcess result=attempt nonce=%lu\n", nonce);
    fflush(stdout);
    last_launch_error = 0;
    if (!CreateProcessW(path, command, NULL, NULL, TRUE, 0, NULL, NULL, &startup, &child->process)) {
        error = last_launch_error = GetLastError();
        /* Failed-call output handles do not establish fixture ownership. */
        memset(&child->process, 0, sizeof(child->process));
        printf("PW_CHILD_FIXTURE role=parent stage=CreateProcess result=not_created error=%lu nonce=%lu\n", error, nonce);
        close_owned(&write_pipe); close_owned(&child->read_pipe); close_owned(&child->release_event);
        return 0;
    }
    owned_handles += 2;
    printf("PW_CHILD_FIXTURE role=parent stage=CreateProcess result=created parent_pid=%lu child_pid=%lu thread_id=%lu nonce=%lu\n",
           GetCurrentProcessId(), child->process.dwProcessId, child->process.dwThreadId, nonce);
    if (!close_owned(&write_pipe) || !close_owned(&child->process.hThread)) return -1;
    return 1;
setup_failed:
    printf("PW_CHILD_FIXTURE role=parent stage=fixture_setup result=fail error=%lu\n", GetLastError());
    close_owned(&write_pipe); close_owned(&child->read_pipe); close_owned(&child->release_event);
    return -1;
}
static int ready(struct child *child, DWORD nonce, struct hello *message)
{
    DWORD start = GetTickCount(), available, got;
    while (GetTickCount() - start < WAIT_MS) {
        available = 0;
        if (PeekNamedPipe(child->read_pipe, NULL, 0, NULL, &available, NULL) && available >= sizeof(*message)) {
            if (available != sizeof(*message) || !ReadFile(child->read_pipe, message, sizeof(*message), &got, NULL) ||
                got != sizeof(*message)) return 0;
            return message->magic == MAGIC && message->bytes == sizeof(*message) && message->version == 1 &&
                   message->pid == child->process.dwProcessId && message->pid == GetProcessId(child->process.hProcess) &&
                   message->pid != GetCurrentProcessId() && message->parent_claim == GetCurrentProcessId() &&
                   message->nonce == nonce && message->initial == INITIAL_MARKER &&
                   message->value == (nonce ^ 0x53594e54u);
        }
        if (WaitForSingleObject(child->process.hProcess, 0) != WAIT_TIMEOUT) break;
        Sleep(10);
    }
    printf("PW_CHILD_FIXTURE role=parent stage=ready result=fail nonce=%lu\n", nonce);
    return 0;
}
static int wait_code(struct child *child, DWORD expected)
{
    DWORD wait = WaitForSingleObject(child->process.hProcess, WAIT_MS), code = STILL_ACTIVE;
    int ok = wait == WAIT_OBJECT_0 && GetExitCodeProcess(child->process.hProcess, &code) && code == expected;
    printf("PW_CHILD_FIXTURE role=parent stage=wait result=%s wait=%lu exit=%lu expected=%lu\n",
           ok ? "pass" : "fail", wait, code, expected);
    return ok;
}
static int cleanup(struct child *child)
{
    int ok = 1;
    if (child->process.hProcess && WaitForSingleObject(child->process.hProcess, 0) != WAIT_OBJECT_0) {
        ok = TerminateProcess(child->process.hProcess, STOP_EXIT) &&
             WaitForSingleObject(child->process.hProcess, WAIT_MS) == WAIT_OBJECT_0;
        printf("PW_CHILD_FIXTURE role=parent stage=owned_child_cleanup result=%s pid=%lu\n",
               ok ? "terminated_and_waited" : "unverified", child->process.dwProcessId);
    }
    ok &= close_owned(&child->process.hThread);
    ok &= close_owned(&child->process.hProcess);
    ok &= close_owned(&child->read_pipe);
    ok &= close_owned(&child->release_event);
    return ok;
}
static int rejected_image(DWORD nonce)
{
    wchar_t path[MAX_PATH], leaf[80];
    STARTUPINFOW startup;
    PROCESS_INFORMATION process;
    DWORD error;
    swprintf(leaf, sizeof(leaf) / sizeof(leaf[0]), L"pw-fixture-missing-%lu.exe", nonce);
    if (!sibling(path, leaf) || GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES) return 0;
    memset(&startup, 0, sizeof(startup)); startup.cb = (DWORD)sizeof(startup); memset(&process, 0, sizeof(process));
    if (CreateProcessW(path, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &process)) {
        /* Only this fixture-created process is eligible for cleanup. */
        int cleaned = TerminateProcess(process.hProcess, STOP_EXIT) &&
                      WaitForSingleObject(process.hProcess, WAIT_MS) == WAIT_OBJECT_0;
        printf("PW_CHILD_FIXTURE role=parent stage=unexpected_missing_image_child result=fail cleanup=%s\n",
               cleaned ? "terminated_and_waited" : "unverified");
        CloseHandle(process.hThread); CloseHandle(process.hProcess);
        return 0;
    }
    error = GetLastError();
    printf("PW_CHILD_FIXTURE role=parent stage=missing_image result=%s error=%lu\n",
           error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND ? "pass" : "fail", error);
    return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
}
int wmain(int argc, wchar_t **argv)
{
    struct child child;
    struct hello message;
    wchar_t path[MAX_PATH];
    DWORD nonce = GetTickCount() ^ GetCurrentProcessId() ^ 0x514357u, parent_value, code;
    int started, ok, isolation, observe = argc == 2 && !wcscmp(argv[1], L"--stop-observe");
    if (argc > 1 && !wcscmp(argv[1], L"--child")) return child_main(argc, argv);
    if (argc != 1 && !observe) return 2;
    if (!sibling(path, L"child.exe") || GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) return 2;
    parent_value = nonce ^ 0x2468ace0u; private_marker = parent_value;
    started = start_child(path, observe ? L"hold" : L"normal", nonce, &child);
    if (started <= 0) {
        int cleaned = cleanup(&child);
        return cleaned && !started && (last_launch_error == ERROR_NOT_SUPPORTED ||
               last_launch_error == ERROR_CALL_NOT_IMPLEMENTED) ? 77 : 1;
    }
    ok = ready(&child, nonce, &message) && private_marker == parent_value &&
         WaitForSingleObject(child.process.hProcess, 0) == WAIT_TIMEOUT;
    isolation = ok && message.address == (uint64_t)(uintptr_t)&private_marker;
    printf("PW_CHILD_FIXTURE role=parent stage=private_state result=%s parent_va=%llu child_va=%llu nonce=%lu\n",
           isolation ? "same_va_independent_values" : "not_established",
           (unsigned long long)(uintptr_t)&private_marker, ok ? (unsigned long long)message.address : 0, nonce);
    if (observe && ok) {
        DWORD began = GetTickCount();
        printf("PW_CHILD_FIXTURE role=parent stage=STOP_OBSERVE_READY parent_pid=%lu child_pid=%lu nonce=%lu budget_ms=%lu\n",
               GetCurrentProcessId(), child.process.dwProcessId, nonce, HOLD_MS);
        fflush(stdout);
        while (GetTickCount() - began < HOLD_MS - WAIT_MS &&
               WaitForSingleObject(child.process.hProcess, 0) == WAIT_TIMEOUT && private_marker == parent_value) {
            printf("PW_CHILD_FIXTURE role=parent stage=heartbeat nonce=%lu\n", nonce); fflush(stdout); Sleep(1000);
        }
        /* No Stop was externally proved. Clean up this test and stay inconclusive. */
        cleanup(&child); return 77;
    }
    if (ok) ok = SetEvent(child.release_event) && wait_code(&child, NORMAL_EXIT);
    ok &= cleanup(&child);
    if (!ok) return 1;
    if (!rejected_image(nonce + 1)) return 1;
    started = start_child(path, L"early", nonce + 2, &child);
    ok = started == 1 && wait_code(&child, EARLY_EXIT);
    if (ok) {
        DWORD available = 0;
        ok = !PeekNamedPipe(child.read_pipe, NULL, 0, NULL, &available, NULL)
             ? GetLastError() == ERROR_BROKEN_PIPE : available == 0;
    }
    ok &= cleanup(&child);
    if (!ok) return 1;
    started = start_child(path, L"hold", nonce + 3, &child);
    ok = started == 1 && ready(&child, nonce + 3, &message) &&
         WaitForSingleObject(child.process.hProcess, 0) == WAIT_TIMEOUT &&
         TerminateProcess(child.process.hProcess, STOP_EXIT) && wait_code(&child, STOP_EXIT);
    ok &= cleanup(&child);
    code = private_marker;
    printf("PW_CHILD_FIXTURE role=parent stage=summary result=%s owned_handles=%u stop_cleanup=external_unverified\n",
           ok && isolation && !owned_handles && code == parent_value ? "automated_pass" : "not_pass", owned_handles);
    fflush(stdout);
    return !ok || owned_handles || code != parent_value ? 1 : isolation ? 0 : 77;
}
