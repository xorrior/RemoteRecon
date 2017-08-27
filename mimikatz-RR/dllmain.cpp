// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include "ReflectiveLoader.h"
#include <stdio.h>
#include <Windows.h>

HINSTANCE hAppInstance;
extern "C" __declspec(dllexport) wchar_t * powershell_reflective_mimikatz(LPCWSTR input);

#ifdef WIN_X86
#pragma comment(lib, "..\\Win32\\mimikatz.lib")
#pragma comment(lib, "..\\lib\\Win32\\ntdll.min.lib")
#pragma comment(lib, "..\\lib\\Win32\\samlib.lib")
#pragma comment(lib, "..\\lib\\Win32\\cryptdll.lib")
#pragma comment(lib, "..\\lib\\Win32\\advapi32.hash.lib")
#endif

#ifdef WIN_X64
#pragma comment(lib, "..\\x64\\mimikatz.lib")
#pragma comment(lib, "..\\lib\\x64\\ntdll.min.lib")
#pragma comment(lib, "..\\lib\\x64\\samlib.lib")
#pragma comment(lib, "..\\lib\\x64\\cryptdll.lib")
#pragma comment(lib, "..\\lib\\x64\\advapi32.hash.lib")
#pragma comment(lib, "Ntdsapi.lib")
#endif

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Secur32.lib")

BOOL WINAPI DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	BOOL bReturnValue = TRUE;
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

