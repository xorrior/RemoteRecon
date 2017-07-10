#ifndef UNMANAGEDPOWERSHELL_H_
#define UNMANAGEDPOWERSHELL_H_

#include <metahost.h>

#pragma comment(lib, "mscoree.lib")





// Import mscorlib.tlb (Microsoft Common Language Runtime Class Library).
#import "mscorlib.tlb" raw_interfaces_only				\
    high_property_prefixes("_get","_put","_putref")		\
    rename("ReportEvent", "InteropServices_ReportEvent")
using namespace mscorlib;

typedef HRESULT(WINAPI *funcCLRCreateInstance)(
	REFCLSID  clsid,
	REFIID     riid,
	LPVOID  * ppInterface
	);

typedef HRESULT(WINAPI *funcCorBindToRuntime)(
	LPCWSTR  pwszVersion,
	LPCWSTR  pwszBuildFlavor,
	REFCLSID rclsid,
	REFIID   riid,
	LPVOID*  ppv);

bool CheckNetfxVersionUsingMscoree(const TCHAR *pszNetfxVersionToCheck, HMODULE& hMscoree);
bool createHost(ICorRuntimeHost** ppCorRuntimeHost);
bool createDotNetFourHost(LPCWSTR pwzVersion, ICorRuntimeHost** ppCorRuntimeHost, HMODULE& hMscoree);
bool createDotNetTwoHost(LPCWSTR pwzVersion, HMODULE& hMscoree, ICorRuntimeHost** ppCorRuntimeHost);
DWORD GetProcessorArchitectureFlag();
bool CheckNetfxVersionUsingMscoree(const TCHAR *pszNetfxVersionToCheck, HMODULE& hMscoree);
void InvokeMethod(_TypePtr spType, wchar_t* method, wchar_t* command);
HRESULT SetupPSRuntime(_Type** PsRuntime);

#endif