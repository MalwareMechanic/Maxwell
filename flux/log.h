#pragma once

#include <Windows.h>
#include <msgpack.h>

namespace MaxLog
{ 

#define MAXWELL_PIPE_NAME L"\\\\.\\PIPE\\Maxwell"
#define MAXWELL_PLUGIN_NAME "flux"

// s -> (char *) -> zero-terminated string
// S -> (char *, int) -> string with length
// u -> (wchar_t *) -> zero-terminated unicode string
// U -> (wchar_t *, int) -> unicode string with length
// i -> (int) -> signed integer
// l -> (unsigned long) -> unsigned long
// q -> (unsigned long long) -> 64 bit unsigned int
// o -> (UNICODE_STRING *) -> unicode string
// p -> (DWORD_PTR) -> pointer converted to hex string
// x -> (DWORD) -> DWORD converted to hex string
// b -> (void*, int) -> raw data with size


// Examples:
// Log("s", "key", "value");
//
// Log("sui", "key1", "strVal", "key2", L"wideStrVal", "key3", 100);
//

DWORD InitLog();
void Log(const char * fmt, ...);
void LogWithMeta(const char * fmt, ...);
void ModuleThread(wchar_t * module);
bool AddressToModule(DWORD_PTR Addr, wchar_t * modName, unsigned int size);

#define LOG(fmt, ...) MaxLog::LogWithMeta(fmt, &__FUNCTION__[4], ##__VA_ARGS__)

typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation,
    MemoryWorkingSetList,
    MemorySectionName
} MEMORY_INFORMATION_CLASS;

typedef NTSTATUS(WINAPI * _NtQueryVirtualMemory)(
    _In_      HANDLE                   ProcessHandle,
    _In_opt_  PVOID                    BaseAddress,
    _In_      MEMORY_INFORMATION_CLASS MemoryInformationClass,
    _Out_     PVOID                    MemoryInformation,
    _In_      SIZE_T                   MemoryInformationLength,
    _Out_opt_ PSIZE_T                  ReturnLength
    );

typedef NTSTATUS(WINAPI* _NtQueryInformationThread)(
    _In_       HANDLE ThreadHandle,
    _In_       int ThreadInformationClass,
    _Inout_    PVOID ThreadInformation,
    _In_       ULONG ThreadInformationLength,
    _Out_opt_  PULONG ReturnLength
    );

typedef struct _LSA_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

extern const char *g_baseExe;

#define STATUS_SUCCESS                    ((NTSTATUS)0x00000000)

}