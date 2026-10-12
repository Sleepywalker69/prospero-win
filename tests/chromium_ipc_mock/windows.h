/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Portable decision-path declarations, NOT Windows ABI definitions. */
#ifndef PW_CHROMIUM_IPC_MOCK_WINDOWS_H
#define PW_CHROMIUM_IPC_MOCK_WINDOWS_H
#include "../windows_fixture_mock/windows.h"
typedef uint32_t ULONG;
typedef int32_t LONG;
typedef uintptr_t ULONG_PTR;
typedef uint64_t ULONGLONG;
typedef size_t SIZE_T;
typedef HANDLE HMODULE;
typedef void (*FARPROC)(void);
typedef void *LPPROC_THREAD_ATTRIBUTE_LIST;
typedef struct { int64_t QuadPart; } LARGE_INTEGER;
typedef struct { STARTUPINFOW StartupInfo; LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList; } STARTUPINFOEXW;
typedef struct { uintptr_t Internal,InternalHigh; DWORD Offset,OffsetHigh; HANDLE hEvent; } OVERLAPPED;
typedef struct { char unused[64]; } SECURITY_DESCRIPTOR;
typedef struct { char unused[8]; } ACL;
typedef struct { void *BaseAddress,*AllocationBase; DWORD AllocationProtect; SIZE_T RegionSize; DWORD State,Protect,Type; } MEMORY_BASIC_INFORMATION;
#define NTAPI
#define WINAPI
#define INVALID_HANDLE_VALUE ((HANDLE)(intptr_t)-1)
#define GENERIC_WRITE 0x40000000u
#define GENERIC_READ 0x80000000u
#define FILE_SHARE_READ 1u
#define CREATE_NEW 1u
#define OPEN_EXISTING 3u
#define FILE_ATTRIBUTE_NORMAL 0x80u
#define FILE_FLAG_OVERLAPPED 0x40000000u
#define FILE_FLAG_FIRST_PIPE_INSTANCE 0x00080000u
#define PROCESS_VM_READ 0x10u
#define PROCESS_VM_WRITE 0x20u
#define PROCESS_VM_OPERATION 8u
#define PROCESS_QUERY_INFORMATION 0x400u
#define ERROR_INSUFFICIENT_BUFFER 122u
#define ERROR_ACCESS_DENIED 5u
#define ERROR_INVALID_HANDLE 6u
#define ERROR_IO_PENDING 997u
#define ERROR_NOT_FOUND 1168u
#define ERROR_OPERATION_ABORTED 995u
#define ERROR_PIPE_CONNECTED 535u
#define PROC_THREAD_ATTRIBUTE_HANDLE_LIST 0x20002u
#define EXTENDED_STARTUPINFO_PRESENT 0x80000u
#define CREATE_SUSPENDED 4u
#define PAGE_READWRITE 4
#define PAGE_READONLY 2
#define FILE_MAP_READ 4u
#define FILE_MAP_WRITE 2u
#define SEC_IMAGE 0x01000000u
#define SECURITY_DESCRIPTOR_REVISION 1u
#define ACL_REVISION 2u
#define DUPLICATE_CLOSE_SOURCE 1u
#define DUPLICATE_SAME_ACCESS 2u
#define ERROR_NOT_SAME_OBJECT 1656u
#define PIPE_ACCESS_DUPLEX 3u
#define PIPE_TYPE_BYTE 0u
#define PIPE_READMODE_BYTE 0u
#define PIPE_WAIT 0u
#define PIPE_REJECT_REMOTE_CLIENTS 8u
#define MEM_RESERVE 0x2000u
#define MEM_COMMIT 0x1000u
#define MEM_DECOMMIT 0x4000u
#define MEM_RELEASE 0x8000u
ULONGLONG GetTickCount64(void);
HANDLE GetCurrentProcess(void);
HANDLE GetProcessHeap(void);
HANDLE OpenProcess(DWORD,BOOL,DWORD);
HANDLE CreateFileW(const wchar_t *,DWORD,DWORD,SECURITY_ATTRIBUTES *,DWORD,DWORD,HANDLE);
HANDLE CreateFileMappingW(HANDLE,SECURITY_ATTRIBUTES *,DWORD,DWORD,DWORD,const wchar_t *);
HANDLE CreateNamedPipeW(const wchar_t *,DWORD,DWORD,DWORD,DWORD,DWORD,DWORD,SECURITY_ATTRIBUTES *);
HANDLE CreateIoCompletionPort(HANDLE,HANDLE,ULONG_PTR,DWORD);
BOOL InitializeProcThreadAttributeList(LPPROC_THREAD_ATTRIBUTE_LIST,DWORD,DWORD,SIZE_T *);
BOOL UpdateProcThreadAttribute(LPPROC_THREAD_ATTRIBUTE_LIST,DWORD,uintptr_t,void *,SIZE_T,void *,SIZE_T *);
void DeleteProcThreadAttributeList(LPPROC_THREAD_ATTRIBUTE_LIST);
void *HeapAlloc(HANDLE,DWORD,SIZE_T);
BOOL HeapFree(HANDLE,DWORD,void *);
DWORD ResumeThread(HANDLE);
HMODULE GetModuleHandleW(const wchar_t *);
FARPROC GetProcAddress(HMODULE,const char *);
BOOL ReadProcessMemory(HANDLE,const void *,void *,SIZE_T,SIZE_T *);
BOOL WriteProcessMemory(HANDLE,void *,const void *,SIZE_T,SIZE_T *);
BOOL InitializeSecurityDescriptor(SECURITY_DESCRIPTOR *,DWORD);
BOOL InitializeAcl(ACL *,DWORD,DWORD);
BOOL SetSecurityDescriptorDacl(SECURITY_DESCRIPTOR *,BOOL,ACL *,BOOL);
BOOL DuplicateHandle(HANDLE,HANDLE,HANDLE,HANDLE *,DWORD,BOOL,DWORD);
BOOL GetHandleInformation(HANDLE,DWORD *);
BOOL ConnectNamedPipe(HANDLE,OVERLAPPED *);
BOOL CancelIoEx(HANDLE,OVERLAPPED *);
BOOL GetQueuedCompletionStatus(HANDLE,DWORD *,ULONG_PTR *,OVERLAPPED **,DWORD);
void *MapViewOfFile(HANDLE,DWORD,DWORD,DWORD,SIZE_T);
BOOL UnmapViewOfFile(const void *);
LONG InterlockedExchange(volatile LONG *,LONG);
void *VirtualAlloc(void *,SIZE_T,DWORD,DWORD);
BOOL VirtualProtect(void *,SIZE_T,DWORD,DWORD *);
SIZE_T VirtualQuery(const void *,MEMORY_BASIC_INFORMATION *,SIZE_T);
BOOL VirtualFree(void *,SIZE_T,DWORD);
#endif
