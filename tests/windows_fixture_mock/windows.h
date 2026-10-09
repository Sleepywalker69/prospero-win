/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Portable decision-path model only; no Windows calls or ABI execution. */
#ifndef PW_FIXTURE_MOCK_WINDOWS_H
#define PW_FIXTURE_MOCK_WINDOWS_H
#include <stdint.h>
#include <stddef.h>
#include <wchar.h>
typedef uint32_t DWORD;
typedef int BOOL;
typedef void *HANDLE;
typedef struct { DWORD nLength; void *lpSecurityDescriptor; BOOL bInheritHandle; } SECURITY_ATTRIBUTES;
typedef struct { DWORD cb; } STARTUPINFOW;
typedef struct { HANDLE hProcess, hThread; DWORD dwProcessId, dwThreadId; } PROCESS_INFORMATION;
#define TRUE 1
#define FALSE 0
#define MAX_PATH 260
#define HANDLE_FLAG_INHERIT 1
#define WAIT_OBJECT_0 0u
#define WAIT_TIMEOUT 258u
#define WAIT_FAILED 0xffffffffu
#define STILL_ACTIVE 259u
#define INVALID_FILE_ATTRIBUTES 0xffffffffu
#define ERROR_FILE_NOT_FOUND 2u
#define ERROR_PATH_NOT_FOUND 3u
#define ERROR_BROKEN_PIPE 109u
#define ERROR_NOT_SUPPORTED 50u
#define ERROR_CALL_NOT_IMPLEMENTED 120u
BOOL CloseHandle(HANDLE);
DWORD GetLastError(void);
DWORD GetCurrentProcessId(void);
DWORD GetProcessId(HANDLE);
DWORD GetTickCount(void);
BOOL WriteFile(HANDLE,const void *,DWORD,DWORD *,void *);
BOOL ReadFile(HANDLE,void *,DWORD,DWORD *,void *);
DWORD WaitForSingleObject(HANDLE,DWORD);
DWORD GetModuleFileNameW(HANDLE,wchar_t *,DWORD);
BOOL CreatePipe(HANDLE *,HANDLE *,SECURITY_ATTRIBUTES *,DWORD);
BOOL SetHandleInformation(HANDLE,DWORD,DWORD);
HANDLE CreateEventW(SECURITY_ATTRIBUTES *,BOOL,BOOL,const wchar_t *);
BOOL CreateProcessW(const wchar_t *,wchar_t *,void *,void *,BOOL,DWORD,void *,void *,STARTUPINFOW *,PROCESS_INFORMATION *);
BOOL PeekNamedPipe(HANDLE,void *,DWORD,DWORD *,DWORD *,DWORD *);
BOOL GetExitCodeProcess(HANDLE,DWORD *);
BOOL TerminateProcess(HANDLE,unsigned);
BOOL SetEvent(HANDLE);
DWORD GetFileAttributesW(const wchar_t *);
void Sleep(DWORD);
#endif
