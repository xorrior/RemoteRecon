//===============================================================================================//
// This is a stub for the actuall functionality of the DLL.
//===============================================================================================//
#include "stdafx.h"
#include "ReflectiveLoader.h"
#include "RemoteReconKS_dll.h"
#include "RemoteReconHost.h"

// Note: REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR and REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN are
// defined in the project properties (Properties->C++->Preprocessor) so as we can specify our own 
// DllMain and use the LoadRemoteLibraryR() API to inject this DLL.

// You can use this value as a pseudo hinstDLL value (defined and set via ReflectiveLoader.c)
extern HINSTANCE hAppInstance;


void DoStuff(LPVOID lpParam)
{
	CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

	_Type* RnRRuntime = NULL;
	HRESULT hr = NULL;
	wchar_t* argument = L"THIS DOES NOTHING";

	hr = SetupRuntime(&RnRRuntime);
	if (SUCCEEDED(hr) && RnRRuntime != NULL) {
		InvokeMethod(RnRRuntime, L"Run", argument);
		CoUninitialize();
		//return 0;
	}
	else {
		//return -1;
	}

}

// Currently called by Invoke-ReflectivePEInjection. 
extern "C" __declspec(dllexport) void VoidFunc()
{
	DoStuff(NULL);
}

//===============================================================================================//
BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved )
{
    BOOL bReturnValue = TRUE;
	switch( dwReason ) 
    { 
		case DLL_QUERY_HMODULE:
			if( lpReserved != NULL )
				*(HMODULE *)lpReserved = hAppInstance;
			break;
		case DLL_PROCESS_ATTACH:
			hAppInstance = hinstDLL;
			
			//DoStuff(NULL);

			break;
		case DLL_PROCESS_DETACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
            break;
    }
	return bReturnValue;
}