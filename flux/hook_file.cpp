#include <stdio.h>
#include <Shlobj.h>
#include "hook.h"
#include "ntapi.h"
#include "log.h"
#include "whitelist.h"

typedef NTSTATUS(NTAPI * pNtQueryInformationFile)(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass);

typedef NTSTATUS(NTAPI * pNtCreateFile)(
	_Out_     PHANDLE FileHandle,
	_In_      ACCESS_MASK DesiredAccess,
	_In_      POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_     PIO_STATUS_BLOCK IoStatusBlock,
	_In_opt_  PLARGE_INTEGER AllocationSize,
	_In_      ULONG FileAttributes,
	_In_      ULONG ShareAccess,
	_In_      ULONG CreateDisposition,
	_In_      ULONG CreateOptions,
	_In_opt_  PVOID EaBuffer,
	_In_      ULONG EaLength
	);

/*typedef struct _FILE_NAME_INFORMATION {
ULONG FileNameLength;
WCHAR FileName[1];
} FILE_NAME_INFORMATION, *PFILE_NAME_INFORMATION;
*/

bool HandleToFilePath(HANDLE FileHandle, char * filePath,wchar_t * widefilePath, int size)
{
	IO_STATUS_BLOCK iosb;
    char buffer[MAX_PATH * 2];

	FILE_NAME_INFORMATION * fileNameInfo = (FILE_NAME_INFORMATION *)buffer;
	ZeroMemory(fileNameInfo, MAX_PATH * 2);
	// FileNameInformation = 9
	pNtQueryInformationFile  NtQueryInformationFile = (pNtQueryInformationFile)GetProcAddress(GetModuleHandle(L"ntdll"), "NtQueryInformationFile");
	if (NtQueryInformationFile)
	{

		NTSTATUS status = NtQueryInformationFile(FileHandle, &iosb, fileNameInfo, MAX_PATH * 2, FileNameInformation);
		if (status == STATUS_SUCCESS)
		{
			size_t ReturnValue;
			int retVal = wcstombs_s(&ReturnValue, filePath, size, fileNameInfo->FileName,size);
			wcscpy_s(widefilePath, 512, fileNameInfo->FileName);
			if (ReturnValue > 0 && retVal == 0)
				return true;
			else
				return false;
		}
	}

	return false;


}


/* ToDo:
Walk callstack for things outside loaded modules, should be able to detect shellcode dropping files. 
*/
HOOKDEF(NTSTATUS, WINAPI, NtWriteFile,
	_In_      HANDLE FileHandle,
	_In_opt_  HANDLE Event,
	_In_opt_  PIO_APC_ROUTINE ApcRoutine,
	_In_opt_  PVOID ApcContext,
	_Out_     PIO_STATUS_BLOCK IoStatusBlock,
	_In_      PVOID Buffer,
	_In_      ULONG Length,
	_In_opt_  PLARGE_INTEGER ByteOffset,
	_In_opt_  PULONG Key
	)
{
	try
	{
		NTSTATUS retVal = Old_NtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
		if (retVal == STATUS_SUCCESS && Length > 0)
		{
			char filePath[512];
			wchar_t widefilePath[512];
			if (HandleToFilePath(FileHandle, filePath, widefilePath, 512))
			{
				if (!is_ignored_file_unicode(widefilePath, wcslen(widefilePath)))
				{
                    LOG("slb", "FileName", filePath, "Length", Length, "FileData", Buffer, Length);
				}
			}
		}
		return retVal;
	}
	catch (...)
	{
		LOG("s", "Exception", "NtWriteFile");
		return -1;
	}
}

bool MemSearch(void * needle, SIZE_T needleSize, void * haystack, SIZE_T haystackSize)
{
	if (needleSize > haystackSize)
		return false;

	for (SIZE_T i = 0; i <= haystackSize - needleSize; i++)
	{
		if (memcmp((char*)haystack + i, needle, needleSize) == 0)
			return true;
	}

	return false;

}

const wchar_t * VMDetect[] =
{
    L"TPAutoConnSvc"
    L"Bitdefender Agent",
    L"ESET NOD32 Antivirus",
    L"\\FFDec\\"
    L"Wireshark",
    L"Fiddler",
    //L"VMware Tools", possible whiteops FP
    //L"VirtualBox Guest Additions", possible whiteops FP

};

HOOKDEF(NTSTATUS, WINAPI, NtCreateFile,
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
	)
{
	try
	{
		if (ObjectAttributes)
		{
			if (ObjectAttributes->ObjectName)
			{
				if (ObjectAttributes->ObjectName->Buffer)
				{
                    for (int i = 0; i < ARRAYSIZE(VMDetect); i++)
                    {
                        if (MemSearch((void*)VMDetect[i], wcslen(VMDetect[i]) * 2, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length))
                        {
                            LOG("o", "VMDetect", ObjectAttributes->ObjectName);
                        }
                    }
				}
			}
		}
		NTSTATUS retVal = Old_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);

		
		return retVal;
	}
	catch (...)
	{
		LOG("s", "Exception", "NtCreateFile");
		return -1;
	}
}

HOOKDEF(NTSTATUS, WINAPI, NtQueryAttributesFile,
	_In_  POBJECT_ATTRIBUTES      ObjectAttributes,
	_Out_ PFILE_BASIC_INFORMATION FileInformation
	)
{

	try
	{
		if (ObjectAttributes)
		{
			if (ObjectAttributes->ObjectName)
			{
				if (ObjectAttributes->ObjectName->Buffer)
				{
                    for (int i = 0; i < ARRAYSIZE(VMDetect); i++)
                    {
                        if (MemSearch((void*)VMDetect[i], wcslen(VMDetect[i]) * 2, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length))
                        {
                            LOG("o", "VMDetect", ObjectAttributes->ObjectName);
                        }
                    }
				}
			}
		}
		NTSTATUS retVal = Old_NtQueryAttributesFile(ObjectAttributes, FileInformation);

		return retVal;
	}
	catch (...)
	{
		LOG("s", "Exception", "NtQueryAttributesFile");
		return -1;
	}

}