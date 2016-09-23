#include "hook.h"
#include "log.h"

HOOKDEF(BOOL, WINAPI, CreateProcessInternalW,
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
	) 
{
	BOOL ret = Old_CreateProcessInternalW(lpUnknown1, lpApplicationName,
		lpCommandLine, lpProcessAttributes, lpThreadAttributes,
		bInheritHandles, dwCreationFlags, lpEnvironment,
		lpCurrentDirectory, lpStartupInfo, lpProcessInformation, lpUnknown2);

	LOG("uu", "ApplicationName", lpApplicationName, "CommandLine", lpCommandLine);
	return ret;
}

HOOKDEF(NTSTATUS, NTAPI, NtCreateUserProcess,
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
	)
{
	NTSTATUS ret = Old_NtCreateUserProcess(ProcessHandle, ThreadHandle, ProcessDesiredAccess, ThreadDesiredAccess, ProcessObjectAttributes, ThreadObjectAttributes, ProcessFlags, ThreadFlags, ProcessParameters, CreateInfo, AttributeList);

	LOG("uu", "ImagePathName", ProcessParameters->ImagePathName.Buffer, "CommandLine", ProcessParameters->CommandLine.Buffer);

	return ret;
}


HOOKDEF(NTSTATUS, WINAPI, NtCreateProcess,
	__out       PHANDLE ProcessHandle,
	__in        ACCESS_MASK DesiredAccess,
	__in_opt    POBJECT_ATTRIBUTES ObjectAttributes,
	__in        HANDLE ParentProcess,
	__in        BOOLEAN InheritObjectTable,
	__in_opt    HANDLE SectionHandle,
	__in_opt    HANDLE DebugPort,
	__in_opt    HANDLE ExceptionPort
	) 
{
	NTSTATUS ret = Old_NtCreateProcess(ProcessHandle, DesiredAccess,
		ObjectAttributes, ParentProcess, InheritObjectTable, SectionHandle,
		DebugPort, ExceptionPort);
	LOG("o", "FileName", ObjectAttributes->ObjectName->Buffer);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtCreateProcessEx,
	__out       PHANDLE ProcessHandle,
	ACCESS_MASK DesiredAccess,
	__in_opt    POBJECT_ATTRIBUTES ObjectAttributes,
	__in        HANDLE ParentProcess,
	__in        ULONG Flags,
	__in_opt    HANDLE SectionHandle,
	__in_opt    HANDLE DebugPort,
	__in_opt    HANDLE ExceptionPort,
	__in        BOOLEAN InJob
	) 
{
	NTSTATUS ret = Old_NtCreateProcessEx(ProcessHandle, DesiredAccess,
		ObjectAttributes, ParentProcess, Flags, SectionHandle, DebugPort,
		ExceptionPort, InJob);
	LOG("o", "FileName", ObjectAttributes->ObjectName->Buffer);
	
	return ret;
}


