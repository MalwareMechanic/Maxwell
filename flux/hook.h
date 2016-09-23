#pragma once
#include "ntapi.h"


typedef struct _hook_t {
    const wchar_t *libraryName;
    const char *funcName;

    void *new_func;

    void **old_func;

    bool is_hooked;

} hook_t;

void InstallHook(_hook_t * hook);

#define HOOKDEF(return_value, calling_convention, apiname, ...) \
	return_value(calling_convention *Old_##apiname)(__VA_ARGS__); \
	return_value calling_convention New_##apiname(__VA_ARGS__)

/* Inject */
extern HOOKDEF(NTSTATUS, WINAPI, NtProtectVirtualMemory,
    IN HANDLE               ProcessHandle,
    IN OUT PVOID            *BaseAddress,
    IN OUT PULONG           NumberOfBytesToProtect,
    IN ULONG                NewAccessProtection,
    OUT PULONG              OldAccessProtection
    );

extern HOOKDEF(NTSTATUS, WINAPI, NtWriteVirtualMemory,
    _In_	HANDLE ProcessHandle,
    _In_	PVOID BaseAddress,
    _In_	PVOID Buffer,
    _In_	ULONG NumberOfBytesToWrite,
    OUT		PULONG NumberOfBytesWritten
    );

extern HOOKDEF(NTSTATUS, WINAPI, NtAllocateVirtualMemory,
    _In_     HANDLE ProcessHandle,
    _Inout_  PVOID *BaseAddress,
    _In_     ULONG_PTR ZeroBits,
    _Inout_  PSIZE_T RegionSize,
    _In_     ULONG AllocationType,
    _In_     ULONG Protect
    );

extern HOOKDEF(NTSTATUS, WINAPI, NtCreateSection,
    _Out_     PHANDLE SectionHandle,
    _In_      ACCESS_MASK DesiredAccess,
    _In_opt_  POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_  PLARGE_INTEGER MaximumSize,
    _In_      ULONG SectionPageProtection,
    _In_      ULONG AllocationAttributes,
    _In_opt_  HANDLE FileHandle
    );

extern HOOKDEF(NTSTATUS, WINAPI, NtSuspendProcess,
    __in        HANDLE ProcessHandle
    );

extern HOOKDEF(BOOL, WINAPI, VirtualProtectEx,
    _In_   HANDLE hProcess,
    _In_   LPVOID lpAddress,
    _In_   SIZE_T dwSize,
    _In_   DWORD flNewProtect,
    _Out_  PDWORD lpflOldProtect
    );

extern HOOKDEF(BOOL, WINAPI, VirtualProtect,
    _In_   LPVOID lpAddress,
    _In_   SIZE_T dwSize,
    _In_   DWORD flNewProtect,
    _Out_  PDWORD lpflOldProtect
    );

extern HOOKDEF(NTSTATUS, WINAPI, NtFreeVirtualMemory,
    _In_    HANDLE  ProcessHandle,
    _Inout_ PVOID   *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_    ULONG   FreeType
    );

/* File */
extern HOOKDEF(NTSTATUS, WINAPI, NtWriteFile,
    _In_      HANDLE FileHandle,
    _In_opt_  HANDLE Event,
    _In_opt_  PIO_APC_ROUTINE ApcRoutine,
    _In_opt_  PVOID ApcContext,
    _Out_     PIO_STATUS_BLOCK IoStatusBlock,
    _In_      PVOID Buffer,
    _In_      ULONG Length,
    _In_opt_  PLARGE_INTEGER ByteOffset,
    _In_opt_  PULONG Key
    );

extern HOOKDEF(NTSTATUS, WINAPI, NtCreateFile,
    _Out_     PHANDLE FileHandle,
    _In_      ACCESS_MASK DesiredAccess,
    _In_      POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_     PIO_STATUS_BLOCK IoStatusBlock,
    _In_opt_  PLARGE_INTEGER AllocationSize,
    _In_      ULONG FileAttributes,
    _In_      ULONG ShareAccess,
    _In_      ULONG CreateDisposition,
    _In_      ULONG CreateOptions,
    _In_      PVOID EaBuffer,
    _In_      ULONG EaLength
    );

extern HOOKDEF(NTSTATUS, WINAPI, NtQueryAttributesFile,
    _In_  POBJECT_ATTRIBUTES      ObjectAttributes,
    _Out_ PFILE_BASIC_INFORMATION FileInformation
    );

/*Registry*/
extern HOOKDEF(NTSTATUS, WINAPI, NtSetValueKey,
    _In_      HANDLE KeyHandle,
    _In_      PUNICODE_STRING ValueName,
    _In_opt_  ULONG TitleIndex,
    _In_      ULONG Type,
    _In_opt_  PVOID Data,
    _In_      ULONG DataSize
    );

extern HOOKDEF(NTSTATUS, WINAPI, NtOpenKeyEx,
    _Out_ PHANDLE            KeyHandle,
    _In_  ACCESS_MASK        DesiredAccess,
    _In_  POBJECT_ATTRIBUTES ObjectAttributes,
    _In_  ULONG              OpenOptions
    );


/*Process*/
extern HOOKDEF(BOOL, WINAPI, CreateProcessInternalW,
    __in_opt    LPVOID lpUnknown1,
    __in_opt    LPWSTR lpApplicationName,
    __inout_opt LPWSTR lpCommandLine,
    __in_opt    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    __in_opt    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    __in        BOOL bInheritHandles,
    __in        DWORD dwCreationFlags,
    __in_opt    LPVOID lpEnvironment,
    __in_opt    LPWSTR lpCurrentDirectory,
    __in        LPSTARTUPINFO lpStartupInfo,
    __out       LPPROCESS_INFORMATION lpProcessInformation,
    __in_opt    LPVOID lpUnknown2
    );

extern HOOKDEF(NTSTATUS, NTAPI, NtCreateUserProcess,
    PHANDLE ProcessHandle,
    PHANDLE ThreadHandle,
    ACCESS_MASK ProcessDesiredAccess,
    ACCESS_MASK ThreadDesiredAccess,
    POBJECT_ATTRIBUTES ProcessObjectAttributes,
    POBJECT_ATTRIBUTES ThreadObjectAttributes,
    ULONG ProcessFlags,
    ULONG ThreadFlags,
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    //PPROCESS_CREATE_INFO CreateInfo,
    //PPROCESS_ATTRIBUTE_LIST AttributeList
    void * CreateInfo,
    void * AttributeList
    );

extern HOOKDEF(NTSTATUS, WINAPI, NtCreateProcess,
    __out       PHANDLE ProcessHandle,
    __in        ACCESS_MASK DesiredAccess,
    __in_opt    POBJECT_ATTRIBUTES ObjectAttributes,
    __in        HANDLE ParentProcess,
    __in        BOOLEAN InheritObjectTable,
    __in_opt    HANDLE SectionHandle,
    __in_opt    HANDLE DebugPort,
    __in_opt    HANDLE ExceptionPort
    );

extern HOOKDEF(NTSTATUS, WINAPI, NtCreateProcessEx,
    __out       PHANDLE ProcessHandle,
    __in        ACCESS_MASK DesiredAccess,
    __in_opt    POBJECT_ATTRIBUTES ObjectAttributes,
    __in        HANDLE ParentProcess,
    __in        ULONG Flags,
    __in_opt    HANDLE SectionHandle,
    __in_opt    HANDLE DebugPort,
    __in_opt    HANDLE ExceptionPort,
    __in        BOOLEAN InJob
    );

/*Misc*/
extern HOOKDEF(NTSTATUS, WINAPI, NtDelayExecution,
    __in    BOOLEAN Alertable,
    __in    PLARGE_INTEGER DelayInterval
    );


