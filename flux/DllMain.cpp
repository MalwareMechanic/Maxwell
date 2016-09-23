#include <Windows.h>

#include "log.h"
#include "hook.h"
#include "whitelist.h"
#include "MemGuard.h"

#pragma comment(lib, "Ws2_32.lib")

#define HOOK(library, funcname) {L#library, #funcname, \
	&New_##funcname, (void **)&Old_##funcname, false}

CRITICAL_SECTION cs;

extern LONG CALLBACK VectoredHandler(
    _In_ PEXCEPTION_POINTERS ExceptionInfo
    );

static hook_t g_hooks[] =
{
    /*File*/
    HOOK(ntdll, NtWriteFile),
    HOOK(ntdll, NtCreateFile),
    HOOK(ntdll, NtQueryAttributesFile),

    /*Registry*/
    HOOK(ntdll, NtSetValueKey),
    HOOK(ntdll, NtOpenKeyEx),

    /*Process*/
    HOOK(ntdll, NtCreateUserProcess),
    HOOK(ntdll, NtCreateProcess),
    HOOK(ntdll, NtCreateProcessEx),
	
    /*Misc*/
    HOOK(ntdll, NtDelayExecution),
    HOOK(ntdll, NtFreeVirtualMemory),
    HOOK(ntdll, NtSuspendProcess),

};


void FluxMain()
{
    if (ProcessWhitelist())
        return;

    HANDLE hThread = INVALID_HANDLE_VALUE;
    //hThread = CreateThread(0, 0, WorkThread, 0, 0, 0);

    DWORD retVal = MaxLog::InitLog();
    if (retVal)
    {
        //printf("InitLog error: %d\n", retVal);
    }
    
    if (strcmp(MaxLog::g_baseExe, "WerFault.exe") == 0)
    {
        LOG("s", "WerFault", "Application Crash"); 
    }

    if (hThread != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hThread);
    }

    InitializeCriticalSection(&cs);

    for (int i = 0; i < ARRAYSIZE(g_hooks); i++)
    {
        InstallHook(&g_hooks[i]);
    }

    InitEAF();
}

BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD     fdwReason,
	_In_ LPVOID    lpvReserved
	)
{

    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        FluxMain();
        break;
    case DLL_PROCESS_DETACH:
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    }
    return true;

}