/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Owned-process data-memory reference. No executable memory or vendor input. */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define WAIT_MS 5000
#define MAGIC 0x50574d31u
#define INITIAL 0x13579bdfu
#define REPLACEMENT 0x2468ace0u
struct message {
    uint32_t magic, kind, pid, nonce, value, reserved;
    uint64_t address;
};
struct child {
    PROCESS_INFORMATION pi;
    HANDLE pipe_read, pipe_write, event;
};

static int number(const wchar_t *s, uint64_t *v)
{
    wchar_t *end;
    if (*s < L'0' || *s > L'9') return 0;
    errno = 0;
    *v = wcstoull(s, &end, 10);
    return !errno && !*end;
}
static int close_handle(HANDLE *h)
{
    if (!*h) return 1;
    if (!CloseHandle(*h)) {
        printf("PW_MEMORY stage=close result=fail error=%lu\n", GetLastError());
        return 0;
    }
    *h = NULL;
    return 1;
}
static int send_message(HANDLE pipe, struct message *m)
{
    DWORD n = 0;
    return WriteFile(pipe, m, (DWORD)sizeof(*m), &n, NULL) && n == sizeof(*m);
}
static int child_main(int argc, wchar_t **argv)
{
    uint64_t p, e, nonce;
    HANDLE pipe, event;
    struct message m;
    volatile DWORD *page;
    DWORD wait;
    int ok;
    if (argc != 5 || !number(argv[2], &p) || p > UINTPTR_MAX ||
        !number(argv[3], &e) || e > UINTPTR_MAX ||
        !number(argv[4], &nonce) || nonce > UINT32_MAX) return 2;
    pipe = (HANDLE)(uintptr_t)p;
    event = (HANDLE)(uintptr_t)e;
    if (!wcscmp(argv[1], L"--suspended-child")) {
        ok = SetEvent(event) != 0;
        if (!close_handle(&event)) ok = 0;
        return ok ? 0 : 3;
    }
    page = (volatile DWORD *)VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!page) return 4;
    *page = INITIAL;
    memset(&m, 0, sizeof(m));
    m.magic = MAGIC; m.kind = 1; m.pid = GetCurrentProcessId();
    m.nonce = (uint32_t)nonce; m.value = *page;
    m.address = (uint64_t)(uintptr_t)page;
    ok = send_message(pipe, &m);
    wait = ok ? WaitForSingleObject(event, WAIT_MS) : WAIT_FAILED;
    ok = ok && wait == WAIT_OBJECT_0;
    if (ok) {
        m.kind = 2;
        m.value = *page;
        ok = send_message(pipe, &m) && m.value == REPLACEMENT;
    }
    if (!VirtualFree((void *)page, 0, MEM_RELEASE)) ok = 0;
    if (!close_handle(&pipe)) ok = 0;
    if (!close_handle(&event)) ok = 0;
    return ok ? 0 : 5;
}
static int cleanup(struct child *c)
{
    int ok = 1;
    DWORD wait;
    if (c->pi.hProcess) {
        wait = WaitForSingleObject(c->pi.hProcess, 0);
        if (wait == WAIT_TIMEOUT) {
            if (!TerminateProcess(c->pi.hProcess, 90)) ok = 0;
            wait = WaitForSingleObject(c->pi.hProcess, WAIT_MS);
        }
        if (wait != WAIT_OBJECT_0) ok = 0;
    }
    if (!close_handle(&c->pi.hThread)) ok = 0;
    if (!close_handle(&c->pi.hProcess)) ok = 0;
    if (!close_handle(&c->pipe_read)) ok = 0;
    if (!close_handle(&c->pipe_write)) ok = 0;
    if (!close_handle(&c->event)) ok = 0;
    printf("PW_MEMORY stage=cleanup result=%s\n", ok ? "pass" : "fail");
    return ok;
}
static int launch(struct child *c, int suspended, DWORD nonce)
{
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    STARTUPINFOW si;
    wchar_t image[32768], command[33000];
    DWORD n, error;
    BOOL ok;
    memset(c, 0, sizeof(*c));
    memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
    c->event = CreateEventW(&sa, TRUE, FALSE, NULL);
    if (!c->event) return 0;
    if (!suspended) {
        if (!CreatePipe(&c->pipe_read, &c->pipe_write, &sa, 4096) ||
            !SetHandleInformation(c->pipe_read, HANDLE_FLAG_INHERIT, 0)) return 0;
    }
    n = GetModuleFileNameW(NULL, image, (DWORD)(sizeof(image) / sizeof(image[0])));
    if (!n || n >= sizeof(image) / sizeof(image[0])) return 0;
    if (swprintf(command, sizeof(command) / sizeof(command[0]),
                 L"\"%ls\" %ls %llu %llu %lu", image,
                 suspended ? L"--suspended-child" : L"--memory-child",
                 (unsigned long long)(uintptr_t)c->pipe_write,
                 (unsigned long long)(uintptr_t)c->event, nonce) < 0) return 0;
    SetLastError(0);
    ok = CreateProcessW(image, command, NULL, NULL, TRUE,
                       suspended ? CREATE_SUSPENDED : 0, NULL, NULL, &si, &c->pi);
    error = GetLastError();
    printf("PW_MEMORY stage=create suspended=%d ok=%d error=%lu pid=%lu\n",
           suspended, ok != 0, error, c->pi.dwProcessId);
    if (!ok) return 0;
    if (!close_handle(&c->pipe_write)) return 0;
    return c->pi.dwProcessId != GetCurrentProcessId() &&
           GetProcessId(c->pi.hProcess) == c->pi.dwProcessId;
}
static int receive(struct child *c, struct message *m, DWORD kind, DWORD nonce)
{
    ULONGLONG start = GetTickCount64();
    DWORD available = 0, n = 0;
    do {
        if (!PeekNamedPipe(c->pipe_read, NULL, 0, NULL, &available, NULL)) return 0;
        if (available >= sizeof(*m)) {
            if (!ReadFile(c->pipe_read, m, (DWORD)sizeof(*m), &n, NULL)) return 0;
            return n == sizeof(*m) && m->magic == MAGIC && m->kind == kind &&
                   m->pid == c->pi.dwProcessId && m->nonce == nonce && !m->reserved;
        }
        /* Read queued final data before inspecting child exit. */
        if (WaitForSingleObject(c->pi.hProcess, 0) != WAIT_TIMEOUT) return 0;
        Sleep(10);
    } while (GetTickCount64() - start < WAIT_MS);
    return 0;
}
static int exited(struct child *c)
{
    DWORD code = STILL_ACTIVE;
    DWORD wait = WaitForSingleObject(c->pi.hProcess, WAIT_MS);
    BOOL ok = GetExitCodeProcess(c->pi.hProcess, &code);
    printf("PW_MEMORY stage=exit wait=%lu query=%d code=%lu\n", wait, ok != 0, code);
    return wait == WAIT_OBJECT_0 && ok && code == 0;
}
static int memory_case(void)
{
    struct child c;
    struct message hello, done;
    DWORD value = 0, replacement = REPLACEMENT, error;
    DWORD nonce = GetCurrentProcessId() ^ (DWORD)GetTickCount64();
    SIZE_T n = 0;
    BOOL api;
    int ok = 0;
    if (!launch(&c, 0, nonce)) goto out;
    if (!receive(&c, &hello, 1, nonce) || hello.value != INITIAL ||
        !hello.address || hello.address > UINTPTR_MAX ||
        hello.address > UINTPTR_MAX - sizeof(value)) goto out;
    SetLastError(0);
    api = ReadProcessMemory(c.pi.hProcess, (const void *)(uintptr_t)hello.address,
                           &value, sizeof(value), &n);
    error = GetLastError();
    printf("PW_MEMORY stage=read ok=%d error=%lu bytes=%llu value=%08lx address=%llu\n",
           api != 0, error, (unsigned long long)n, value, (unsigned long long)hello.address);
    if (!api || n != sizeof(value) || value != INITIAL) goto out;
    n = 0; SetLastError(0);
    api = WriteProcessMemory(c.pi.hProcess, (void *)(uintptr_t)hello.address,
                            &replacement, sizeof(replacement), &n);
    error = GetLastError();
    printf("PW_MEMORY stage=write ok=%d error=%lu bytes=%llu value=%08lx\n",
           api != 0, error, (unsigned long long)n, replacement);
    if (!api || n != sizeof(replacement) || !SetEvent(c.event)) goto out;
    if (!receive(&c, &done, 2, nonce) || done.value != REPLACEMENT ||
        done.address != hello.address || !exited(&c)) goto out;
    ok = 1;
out:
    if (!cleanup(&c)) ok = 0;
    printf("PW_MEMORY case=data result=%s nonce=%lu\n", ok ? "pass" : "fail", nonce);
    return ok;
}
static int suspended_case(void)
{
    struct child c;
    DWORD nonce = GetCurrentProcessId() ^ (DWORD)GetTickCount64();
    DWORD before, resumed;
    int ok = 0;
    if (!launch(&c, 1, nonce)) goto out;
    before = WaitForSingleObject(c.event, 250);
    printf("PW_MEMORY stage=before_resume event_wait=%lu\n", before);
    if (before != WAIT_TIMEOUT || WaitForSingleObject(c.pi.hProcess, 0) != WAIT_TIMEOUT) goto out;
    SetLastError(0);
    resumed = ResumeThread(c.pi.hThread);
    printf("PW_MEMORY stage=resume previous=%lu error=%lu\n", resumed, GetLastError());
    if (resumed != 1 || WaitForSingleObject(c.event, WAIT_MS) != WAIT_OBJECT_0 ||
        !exited(&c)) goto out;
    ok = 1;
out:
    if (!cleanup(&c)) ok = 0;
    printf("PW_MEMORY case=suspended result=%s\n", ok ? "pass" : "fail");
    return ok;
}
int wmain(int argc, wchar_t **argv)
{
    int memory_ok, suspended_ok;
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc > 1 && (!wcscmp(argv[1], L"--memory-child") ||
                     !wcscmp(argv[1], L"--suspended-child"))) return child_main(argc, argv);
    if (argc != 1) return 2;
    printf("PW_MEMORY version=1 pointer_bits=%u parent_pid=%lu\n",
           (unsigned)(sizeof(void *) * 8), GetCurrentProcessId());
    memory_ok = memory_case();
    suspended_ok = suspended_case();
    printf("PW_MEMORY result=%s\n", memory_ok && suspended_ok ? "pass" : "fail");
    return memory_ok && suspended_ok ? 0 : 1;
}
