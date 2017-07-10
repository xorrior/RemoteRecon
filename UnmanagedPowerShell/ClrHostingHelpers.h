#ifndef CLRHOSTINGHELPERS_H_
#define CLRHOSTINGHELPERS_H_

#include <Windows.h>
#include <mscoree.h>

#define CountOf(x) sizeof(x)/sizeof(*x)

// Constants for known .NET Framework versions used with the GetRequestedRuntimeInfo API
#define NETFX_10_VERSION_STRING "v1.0.3705"
#define NETFX_11_VERSION_STRING "v1.1.4322"
#define NETFX_20_VERSION_STRING "v2.0.50727"
#define NETFX_40_VERSION_STRING "v4.0.30319"

DWORD GetProcessorArchitectureFlag();
bool CheckNetfxVersionUsingMscoree(const TCHAR *pszNetfxVersionToCheck, HMODULE& hMscoree);

#endif // CLRHOSTINGHELPERS_H_