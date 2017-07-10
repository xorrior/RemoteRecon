#include "stdafx.h"
#include "Clr.h"
#include <string.h>

/******************************************************************
Function Name:  GetProcessorArchitectureFlag
Description:    Determine the processor architecture of the
system (x86, x64, ia64)
Inputs:         NONE
Results:        DWORD processor architecture flag

Code take from https://blogs.msdn.microsoft.com/astebner/2006/08/03/updated-sample-net-framework-detection-code-that-does-more-in-depth-checking/
******************************************************************/
DWORD GetProcessorArchitectureFlag()
{
	HMODULE hmodKernel32 = NULL;
	typedef void (WINAPI *PFnGetNativeSystemInfo) (LPSYSTEM_INFO);
	PFnGetNativeSystemInfo pfnGetNativeSystemInfo;

	SYSTEM_INFO sSystemInfo;
	memset(&sSystemInfo, 0, sizeof(sSystemInfo));

	bool bRetrievedSystemInfo = false;

	// Attempt to load kernel32.dll
	hmodKernel32 = LoadLibrary("Kernel32.dll");
	if (NULL != hmodKernel32)
	{
		// If the DLL loaded correctly, get the proc address for GetNativeSystemInfo
		pfnGetNativeSystemInfo = (PFnGetNativeSystemInfo)GetProcAddress(hmodKernel32, "GetNativeSystemInfo");
		if (NULL != pfnGetNativeSystemInfo)
		{
			// Call GetNativeSystemInfo if it exists
			(*pfnGetNativeSystemInfo)(&sSystemInfo);
			bRetrievedSystemInfo = true;
		}
		FreeLibrary(hmodKernel32);
	}

	if (!bRetrievedSystemInfo)
	{
		// Fallback to calling GetSystemInfo if the above failed
		GetSystemInfo(&sSystemInfo);
		bRetrievedSystemInfo = true;
	}

	if (bRetrievedSystemInfo)
	{
		switch (sSystemInfo.wProcessorArchitecture)
		{
		case PROCESSOR_ARCHITECTURE_INTEL:
			return RUNTIME_INFO_REQUEST_X86;
		case PROCESSOR_ARCHITECTURE_IA64:
			return RUNTIME_INFO_REQUEST_IA64;
		case PROCESSOR_ARCHITECTURE_AMD64:
			return RUNTIME_INFO_REQUEST_AMD64;
		default:
			return 0;
		}
	}

	return 0;
}


/******************************************************************
Function Name:  CheckNetfxVersionUsingMscoree
Description:    Uses the logic described in the sample code at
http://msdn2.microsoft.com/library/ydh6b3yb.aspx
to load mscoree.dll and call its APIs to determine
whether or not a specific version of the .NET
Framework is installed on the system
Inputs:         pszNetfxVersionToCheck - version to look for
Results:        true if the requested version is installed
false otherwise

Code taken from https://blogs.msdn.microsoft.com/astebner/2006/08/03/updated-sample-net-framework-detection-code-that-does-more-in-depth-checking/
******************************************************************/
bool CheckNetfxVersionUsingMscoree(const TCHAR *pszNetfxVersionToCheck, HMODULE& hMscoree)
{
	bool bFoundRequestedNetfxVersion = false;
	HRESULT hr = S_OK;

	// Check input parameter
	if (NULL == pszNetfxVersionToCheck)
	{
		return false;
	}

	if (NULL != hMscoree)
	{
		typedef HRESULT(STDAPICALLTYPE *GETCORVERSION)(LPWSTR szBuffer, DWORD cchBuffer, DWORD* dwLength);
		GETCORVERSION pfnGETCORVERSION = (GETCORVERSION)GetProcAddress(hMscoree, "GetCORVersion");

		// Some OSs shipped with a placeholder copy of mscoree.dll. The existence of mscoree.dll
		// therefore does NOT mean that a version of the .NET Framework is installed.
		// If this copy of mscoree.dll does not have an exported function named GetCORVersion
		// then we know it is a placeholder DLL.
		if (NULL == pfnGETCORVERSION)
			goto Finish;

		typedef HRESULT(STDAPICALLTYPE *CORBINDTORUNTIME)(LPCWSTR pwszVersion, LPCWSTR pwszBuildFlavor, REFCLSID rclsid, REFIID riid, LPVOID FAR *ppv);
		CORBINDTORUNTIME pfnCORBINDTORUNTIME = (CORBINDTORUNTIME)GetProcAddress(hMscoree, "CorBindToRuntime");

		typedef HRESULT(STDAPICALLTYPE *GETREQUESTEDRUNTIMEINFO)(LPCWSTR pExe, LPCWSTR pwszVersion, LPCWSTR pConfigurationFile, DWORD startupFlags, DWORD runtimeInfoFlags, LPWSTR pDirectory, DWORD dwDirectory, DWORD *dwDirectoryLength, LPWSTR pVersion, DWORD cchBuffer, DWORD* dwlength);
		GETREQUESTEDRUNTIMEINFO pfnGETREQUESTEDRUNTIMEINFO = (GETREQUESTEDRUNTIMEINFO)GetProcAddress(hMscoree, "GetRequestedRuntimeInfo");

		if (NULL != pfnCORBINDTORUNTIME)
		{
			TCHAR szRetrievedVersion[50];
			DWORD dwLength = CountOf(szRetrievedVersion);

			if (NULL == pfnGETREQUESTEDRUNTIMEINFO)
			{
				// Having CorBindToRuntimeHost but not having GetRequestedRuntimeInfo means that
				// this machine contains no higher than .NET Framework 1.0, but the only way to
				// 100% guarantee that the .NET Framework 1.0 is installed is to call a function
				// to exercise its functionality
				if (0 == strcmp(pszNetfxVersionToCheck, NETFX_10_VERSION_STRING))
				{
					hr = pfnGETCORVERSION((LPWSTR)szRetrievedVersion, dwLength, &dwLength);

					if (SUCCEEDED(hr))
					{
						if (0 == strcmp(szRetrievedVersion, NETFX_10_VERSION_STRING))
							bFoundRequestedNetfxVersion = true;
					}

					goto Finish;
				}
			}

			// Set error mode to prevent the .NET Framework from displaying
			// unfriendly error dialogs
			UINT uOldErrorMode = SetErrorMode(SEM_FAILCRITICALERRORS);

			TCHAR szDirectory[MAX_PATH];
			DWORD dwDirectoryLength = 0;
			DWORD dwRuntimeInfoFlags = RUNTIME_INFO_DONT_RETURN_DIRECTORY | GetProcessorArchitectureFlag();

			// Check for the requested .NET Framework version
			hr = pfnGETREQUESTEDRUNTIMEINFO(NULL, (LPCWSTR)pszNetfxVersionToCheck, NULL, STARTUP_LOADER_OPTIMIZATION_MULTI_DOMAIN_HOST, NULL, (LPWSTR)szDirectory, CountOf(szDirectory), &dwDirectoryLength, (LPWSTR)szRetrievedVersion, CountOf(szRetrievedVersion), &dwLength);

			if (SUCCEEDED(hr))
				bFoundRequestedNetfxVersion = true;

			// Restore the previous error mode
			SetErrorMode(uOldErrorMode);
		}
	}

Finish:

	return bFoundRequestedNetfxVersion;
}