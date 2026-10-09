/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Original, single-process WinHTTP DNS/TLS diagnostic. No default endpoint.
 * Build-only proposal: running this program makes one caller-selected request.
 */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <stdio.h>
#include <wchar.h>

#define PROBE_IO_MS 5000
#define PROBE_TOTAL_MS 25000
#define PROBE_UA L"prospero-win-original-https-probe/1"

enum { EXIT_PASS = 0, EXIT_FAIL = 1, EXIT_USAGE = 2, EXIT_SETUP = 3,
       EXIT_INCONCLUSIVE = 4, EXIT_DEADLINE = 5 };
enum { EXPECT_OK, EXPECT_NAME, EXPECT_DATE, EXPECT_CA };
enum { ST_OPEN = 1, ST_OPTIONS, ST_CONNECT, ST_REQUEST, ST_SEND,
       ST_RECEIVE, ST_CERT, ST_CLOSE, ST_DONE };
enum { OBS_RESOLVE = 1, OBS_RESOLVED = 2, OBS_CONNECT = 4, OBS_CONNECTED = 8,
       OBS_SENT = 16, OBS_RESPONSE = 32 };

struct probe {
    const WCHAR *host;
    INTERNET_PORT port;
    int expectation;
    volatile LONG stage;
    volatile LONG observed;
    volatile LONG secure_flags;
    DWORD error;
    DWORD error_stage;
    DWORD http_status;
    DWORD key_bits;
    DWORD result;
    FILETIME cert_before;
    FILETIME cert_after;
};

static struct probe state;

static BOOL valid_host(const WCHAR *host)
{
    size_t length = wcslen(host), label = 0, dots = 0;
    BOOL has_alpha = FALSE;
    size_t i;
    if (!length || length > 253) return FALSE;
    for (i = 0; i < length; ++i) {
        WCHAR c = host[i];
        if (c == L'.') {
            if (!label || label > 63 || host[i - 1] == L'-') return FALSE;
            label = 0;
            ++dots;
        } else {
            BOOL alpha = (c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z');
            if (!alpha && !(c >= L'0' && c <= L'9') && c != L'-') return FALSE;
            if (!label && c == L'-') return FALSE;
            if (alpha) has_alpha = TRUE;
            if (++label > 63) return FALSE;
        }
    }
    /* A dotted DNS name is deliberate: no IP-literal or single-label bypass. */
    return dots && has_alpha && label && host[length - 1] != L'-';
}

static BOOL parse_port(const WCHAR *text, INTERNET_PORT *port)
{
    DWORD value = 0;
    if (!*text) return FALSE;
    while (*text) {
        if (*text < L'0' || *text > L'9') return FALSE;
        value = value * 10 + (DWORD)(*text++ - L'0');
        if (value > 65535) return FALSE;
    }
    if (!value) return FALSE;
    *port = (INTERNET_PORT)value;
    return TRUE;
}

static void CALLBACK status_callback(HINTERNET handle, DWORD_PTR context,
                                    DWORD status, void *info, DWORD size)
{
    LONG observed = 0;
    (void)handle;
    (void)context;
    switch (status) {
    case WINHTTP_CALLBACK_STATUS_RESOLVING_NAME: observed = OBS_RESOLVE; break;
    case WINHTTP_CALLBACK_STATUS_NAME_RESOLVED: observed = OBS_RESOLVED; break;
    case WINHTTP_CALLBACK_STATUS_CONNECTING_TO_SERVER: observed = OBS_CONNECT; break;
    case WINHTTP_CALLBACK_STATUS_CONNECTED_TO_SERVER: observed = OBS_CONNECTED; break;
    case WINHTTP_CALLBACK_STATUS_REQUEST_SENT: observed = OBS_SENT; break;
    case WINHTTP_CALLBACK_STATUS_RESPONSE_RECEIVED: observed = OBS_RESPONSE; break;
    case WINHTTP_CALLBACK_STATUS_SECURE_FAILURE:
        if (info && size == sizeof(DWORD))
            InterlockedOr(&state.secure_flags, (LONG)*(const DWORD *)info);
        break;
    default: break;
    }
    if (observed) InterlockedOr(&state.observed, observed);
    /* Never print server-provided bytes or call WinHTTP from this callback. */
}

static BOOL option(HINTERNET handle, DWORD name, DWORD value)
{
    return WinHttpSetOption(handle, name, &value, sizeof(value));
}

static DWORD classify_rejection(const struct probe *p)
{
    DWORD expected_error = 0, expected_flag = 0;
    DWORD flags = (DWORD)InterlockedCompareExchange((volatile LONG *)&p->secure_flags, 0, 0);
    switch (p->expectation) {
    case EXPECT_NAME:
        expected_error = ERROR_WINHTTP_SECURE_CERT_CN_INVALID;
        expected_flag = WINHTTP_CALLBACK_STATUS_FLAG_CERT_CN_INVALID;
        break;
    case EXPECT_DATE:
        expected_error = ERROR_WINHTTP_SECURE_CERT_DATE_INVALID;
        expected_flag = WINHTTP_CALLBACK_STATUS_FLAG_CERT_DATE_INVALID;
        break;
    case EXPECT_CA:
        expected_error = ERROR_WINHTTP_SECURE_INVALID_CA;
        expected_flag = WINHTTP_CALLBACK_STATUS_FLAG_INVALID_CA;
        break;
    default: return EXIT_INCONCLUSIVE;
    }
    if (p->error == expected_error)
        return !flags || flags == expected_flag ? EXIT_PASS : EXIT_INCONCLUSIVE;
    if ((p->error == ERROR_WINHTTP_SECURE_FAILURE ||
         p->error == ERROR_WINHTTP_SECURE_CHANNEL_ERROR) && flags == expected_flag)
        return EXIT_PASS;
    /* Pinned Wine loses the certificate-specific reason in this path. */
    if (p->error == ERROR_WINHTTP_SECURE_CHANNEL_ERROR ||
        p->error == ERROR_WINHTTP_SECURE_FAILURE ||
        p->error == ERROR_WINHTTP_TIMEOUT ||
        p->error == ERROR_WINHTTP_NAME_NOT_RESOLVED ||
        p->error == ERROR_WINHTTP_CANNOT_CONNECT ||
        p->error == ERROR_WINHTTP_CONNECTION_ERROR)
        return EXIT_INCONCLUSIVE;
    return EXIT_FAIL;
}

static DWORD WINAPI run_probe(void *unused)
{
    HINTERNET session = NULL, connect = NULL, request = NULL;
    PCCERT_CONTEXT cert = NULL;
    DWORD bytes, security_flags = 0;
    DWORD ignore_mask = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                        SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                        SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                        SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
    BOOL request_failed = FALSE;
    DWORD callback_flags = WINHTTP_CALLBACK_FLAG_RESOLVE_NAME |
                           WINHTTP_CALLBACK_FLAG_CONNECT_TO_SERVER |
                           WINHTTP_CALLBACK_FLAG_SEND_REQUEST |
                           WINHTTP_CALLBACK_FLAG_RECEIVE_RESPONSE |
                           WINHTTP_CALLBACK_FLAG_SECURE_FAILURE;
    (void)unused;
    state.result = EXIT_SETUP;
    InterlockedExchange(&state.stage, ST_OPEN);
    session = WinHttpOpen(PROBE_UA, WINHTTP_ACCESS_TYPE_NO_PROXY,
                          WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) goto error;
    InterlockedExchange(&state.stage, ST_OPTIONS);
    if (!WinHttpSetTimeouts(session, PROBE_IO_MS, PROBE_IO_MS, PROBE_IO_MS, PROBE_IO_MS) ||
        !option(session, WINHTTP_OPTION_RECEIVE_RESPONSE_TIMEOUT, PROBE_IO_MS) ||
        !option(session, WINHTTP_OPTION_SECURE_PROTOCOLS, WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2))
        goto error;
    InterlockedExchange(&state.stage, ST_CONNECT);
    connect = WinHttpConnect(session, state.host, state.port, 0);
    if (!connect) goto error;
    InterlockedExchange(&state.stage, ST_REQUEST);
    request = WinHttpOpenRequest(connect, L"HEAD", L"/", NULL, WINHTTP_NO_REFERER,
                                 WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!request) goto error;
    if (!option(request, WINHTTP_OPTION_DISABLE_FEATURE,
                WINHTTP_DISABLE_REDIRECTS | WINHTTP_DISABLE_COOKIES |
                WINHTTP_DISABLE_AUTHENTICATION | WINHTTP_DISABLE_KEEP_ALIVE) ||
        !option(request, WINHTTP_OPTION_AUTOLOGON_POLICY, WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH) ||
        !option(request, WINHTTP_OPTION_RECEIVE_RESPONSE_TIMEOUT, PROBE_IO_MS) ||
        !WinHttpSetTimeouts(request, PROBE_IO_MS, PROBE_IO_MS, PROBE_IO_MS, PROBE_IO_MS))
        goto error;
    if (WinHttpSetStatusCallback(request, status_callback, callback_flags, 0) ==
        WINHTTP_INVALID_STATUS_CALLBACK) goto error;
    InterlockedExchange(&state.stage, ST_SEND);
    if (!WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        request_failed = TRUE;
        goto error;
    }
    InterlockedExchange(&state.stage, ST_RECEIVE);
    if (!WinHttpReceiveResponse(request, NULL)) {
        request_failed = TRUE;
        goto error;
    }
    bytes = sizeof(state.http_status);
    if (!WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX, &state.http_status, &bytes,
                             WINHTTP_NO_HEADER_INDEX)) goto error;
    InterlockedExchange(&state.stage, ST_CERT);
    bytes = sizeof(security_flags);
    if (!WinHttpQueryOption(request, WINHTTP_OPTION_SECURITY_FLAGS, &security_flags, &bytes)) goto error;
    if (!(security_flags & SECURITY_FLAG_SECURE) || (security_flags & ignore_mask)) {
        state.error = ERROR_INVALID_DATA;
        state.result = EXIT_FAIL;
        goto done;
    }
    bytes = sizeof(cert);
    if (!WinHttpQueryOption(request, WINHTTP_OPTION_SERVER_CERT_CONTEXT, &cert, &bytes) || !cert)
        goto error;
    state.cert_before = cert->pCertInfo->NotBefore;
    state.cert_after = cert->pCertInfo->NotAfter;
    bytes = sizeof(state.key_bits);
    if (!WinHttpQueryOption(request, WINHTTP_OPTION_SECURITY_KEY_BITNESS, &state.key_bits, &bytes))
        goto error;
    state.result = state.expectation == EXPECT_OK && state.http_status >= 100 &&
                   state.http_status <= 599 && state.key_bits ? EXIT_PASS : EXIT_FAIL;
    goto done;
error:
    state.error = GetLastError();
    state.error_stage = (DWORD)InterlockedCompareExchange(&state.stage, 0, 0);
    if (request_failed)
        state.result = state.expectation == EXPECT_OK ? EXIT_INCONCLUSIVE : classify_rejection(&state);
done:
    /* The total deadline includes close/cleanup, not just the handshake. */
    InterlockedExchange(&state.stage, ST_CLOSE);
    if (cert) CertFreeCertificateContext(cert);
    if (request) WinHttpCloseHandle(request);
    if (connect) WinHttpCloseHandle(connect);
    if (session) WinHttpCloseHandle(session);
    InterlockedExchange(&state.stage, ST_DONE);
    return state.result;
}

int wmain(int argc, WCHAR **argv)
{
    HANDLE worker;
    SYSTEMTIME utc;
    ULONGLONG started, elapsed;
    DWORD wait, result;
    const char *result_name;
    setvbuf(stdout, NULL, _IONBF, 0);
    state.port = 443;
    if (argc < 3 || argc > 4 || !valid_host(argv[2]) ||
        (argc == 4 && !parse_port(argv[3], &state.port))) goto usage;
    if (!wcscmp(argv[1], L"ok")) state.expectation = EXPECT_OK;
    else if (!wcscmp(argv[1], L"cert-name")) state.expectation = EXPECT_NAME;
    else if (!wcscmp(argv[1], L"cert-date")) state.expectation = EXPECT_DATE;
    else if (!wcscmp(argv[1], L"cert-ca")) state.expectation = EXPECT_CA;
    else goto usage;
    state.host = argv[2];
    GetSystemTime(&utc);
    printf("PW_HTTPS/1 begin pid=%lu expectation=%d port=%u tls=1.2 proxy=none "
           "redirects=off auth=off cookies=off request=HEAD-root total_ms=%u "
           "utc=%04u-%02u-%02uT%02u:%02u:%02uZ\n",
           GetCurrentProcessId(), state.expectation, (unsigned)state.port, PROBE_TOTAL_MS,
           utc.wYear, utc.wMonth, utc.wDay, utc.wHour, utc.wMinute, utc.wSecond);
    started = GetTickCount64();
    worker = CreateThread(NULL, 0, run_probe, NULL, 0, NULL);
    if (!worker) {
        printf("PW_HTTPS/1 result=SETUP_ERROR stage=thread error=%lu\n", GetLastError());
        return EXIT_SETUP;
    }
    elapsed = GetTickCount64() - started;
    wait = elapsed >= PROBE_TOTAL_MS ? WAIT_TIMEOUT :
           WaitForSingleObject(worker, (DWORD)(PROBE_TOTAL_MS - elapsed));
    if (wait != WAIT_OBJECT_0) {
        printf("PW_HTTPS/1 result=DEADLINE_OR_WAIT_ERROR wait=%lu error=%lu stage=%ld "
               "observed=0x%lx elapsed_ms=%llu; terminating this diagnostic process\n",
               wait, wait == WAIT_FAILED ? GetLastError() : 0,
               InterlockedCompareExchange(&state.stage, 0, 0),
               (unsigned long)InterlockedCompareExchange(&state.observed, 0, 0),
               (unsigned long long)(GetTickCount64() - started));
        /* Deliberately no TerminateThread, DLL-unload race or worker reuse. */
        TerminateProcess(GetCurrentProcess(), EXIT_DEADLINE);
        return EXIT_DEADLINE;
    }
    elapsed = GetTickCount64() - started;
    if (elapsed >= PROBE_TOTAL_MS) {
        CloseHandle(worker);
        printf("PW_HTTPS/1 result=DEADLINE exit=%u worker_finished=yes elapsed_ms=%llu\n",
               EXIT_DEADLINE, (unsigned long long)elapsed);
        return EXIT_DEADLINE;
    }
    if (!GetExitCodeThread(worker, &result)) result = EXIT_SETUP;
    CloseHandle(worker);
    elapsed = GetTickCount64() - started;
    if (elapsed >= PROBE_TOTAL_MS) result = EXIT_DEADLINE;
    result_name = result == EXIT_PASS ? "PASS" : result == EXIT_INCONCLUSIVE ? "INCONCLUSIVE" :
                  result == EXIT_SETUP ? "SETUP_ERROR" : result == EXIT_DEADLINE ? "DEADLINE" : "FAIL";
    printf("PW_HTTPS/1 result=%s exit=%lu error=%lu error_stage=%lu http=%lu key_bits=%lu "
           "observed=0x%lx secure_failure_flags=0x%lx elapsed_ms=%llu "
           "cert_before=%08lx:%08lx cert_after=%08lx:%08lx\n",
           result_name, result, state.error, state.error_stage, state.http_status, state.key_bits,
           (unsigned long)state.observed, (unsigned long)state.secure_flags,
           (unsigned long long)elapsed,
           state.cert_before.dwHighDateTime, state.cert_before.dwLowDateTime,
           state.cert_after.dwHighDateTime, state.cert_after.dwLowDateTime);
    return (int)result;
usage:
    fputs("Usage: windows-https-probe.exe <ok|cert-name|cert-date|cert-ca> <DNS-FQDN> [port]\n"
          "No default endpoint. One TLS1.2 HEAD /, no redirects/auth/cookies.\n"
          "Use only a public or authorized test endpoint; no credentials or secret URLs.\n", stderr);
    return EXIT_USAGE;
}
