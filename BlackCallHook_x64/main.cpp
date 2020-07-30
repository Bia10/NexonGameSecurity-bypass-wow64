#ifdef UNICODE
#undef UNICODE
#endif

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <Windows.h>
#include <Winternl.h>
#include <Psapi.h>

#include <intrin.h>
#include <iostream>

#define STATUS_SUCCESS			((NTSTATUS)0x00000000)
#define STATUS_ACCESS_DENIED	((NTSTATUS)0xC0000022)

typedef enum _MEMORY_INFORMATION_CLASS
{
	MemoryBasicInformation,				// MEMORY_BASIC_INFORMATION
	MemoryWorkingSetInformation,		// MEMORY_WORKING_SET_INFORMATION
	MemoryMappedFilenameInformation,	// UNICODE_STRING
	MemoryRegionInformation,			// MEMORY_REGION_INFORMATION
	MemoryWorkingSetExInformation,		// MEMORY_WORKING_SET_EX_INFORMATION
	MemorySharedCommitInformation,		// MEMORY_SHARED_COMMIT_INFORMATION
	MemoryImageInformation,				// MEMORY_IMAGE_INFORMATION
	MemoryRegionInformationEx,
	MemoryPrivilegedBasicInformation,
	MemoryEnclaveImageInformation,		// since REDSTONE3
	MemoryBasicInformationCapped
} MEMORY_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESS_INFO
{
	ULONG                   NextEntryOffset;
	ULONG                   NumberOfThreads;
	LARGE_INTEGER           Reserved[3];
	LARGE_INTEGER           CreateTime;
	LARGE_INTEGER           UserTime;
	LARGE_INTEGER           KernelTime;
	UNICODE_STRING          ImageName;
	ULONG                   BasePriority;
	HANDLE                  UniqueProcessId;
	HANDLE                  InheritedFromProcessId;
	ULONG					HandleCount;
} SYSTEM_PROCESS_INFO, *PSYSTEM_PROCESS_INFO;

#include "VMProtectSDK.h"

#ifndef _VIRTUALIZE_
#define _VIRTUALIZE_
#endif

#ifndef _PRINTDEBUG
#define _PRINTDEBUG
#endif

#ifdef _PRINTDEBUG
//FILE* f = nullptr;
#endif

namespace blackcall {

#pragma optimize("g", off)
	
typedef NTSTATUS(NTAPI* NtOpenProcess_t)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, CLIENT_ID* ClientId);
NtOpenProcess_t _NtOpenProcess = nullptr;

NTSTATUS NtOpenProcess_hook(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, CLIENT_ID* ClientId)
{
#ifdef _VIRTUALIZE_
	VMProtectBeginVirtualization("NtOpenProcess_hook");
#endif
	HMODULE hModule = NULL;

	//if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<LPCSTR>(_ReturnAddress()), &hModule) && hModule == GetModuleHandle("BlackCall.aes"))
	//{
#ifdef _PRINTDEBUG
	FILE* f = fopen("C:\\blackcall.txt", "a+");
	fprintf(f, "[NtOpenProcess] %016I64x -> %I64d\n", _ReturnAddress(), ClientId->UniqueProcess);
	fclose(f);
#endif
	//}

	return _NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
#ifdef _VIRTUALIZE_
	VMProtectEnd();
#endif
}

typedef NTSTATUS (NTAPI* NtQueryVirtualMemory_t)(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);
NtQueryVirtualMemory_t _NtQueryVirtualMemory = nullptr;

NTSTATUS NtQueryVirtualMemory_hook(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength)
{
#ifdef _VIRTUALIZE_
	VMProtectBeginVirtualization("NtQueryVirtualMemory_hook");
#endif
	HMODULE hModule = NULL;

	//if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<LPCSTR>(_ReturnAddress()), &hModule) && hModule == GetModuleHandle("BlackCall.aes"))
	//{
		// Called once for each of the following: NGClient.aes, BlackCall.aes and BlackCipher.aes

#ifdef _PRINTDEBUG
	FILE* f = fopen("C:\\blackcall.txt", "a+");
	fprintf(f, "[NtQueryVirtualMemory] %016I64x -> %I64x (%x)\n", _ReturnAddress(), ProcessHandle, MemoryInformationClass);
	fclose(f);
#endif
	//}

	return _NtQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
#ifdef _VIRTUALIZE_
	VMProtectEnd();
#endif
}

typedef NTSTATUS (NTAPI* NtReadVirtualMemory_t)(HANDLE ProcessHandle, LPBYTE BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesReaded);
NtReadVirtualMemory_t _NtReadVirtualMemory = nullptr;

NTSTATUS NtReadVirtualMemory_hook(HANDLE ProcessHandle, LPBYTE BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesReaded)
{
#ifdef _VIRTUALIZE_
	VMProtectBeginVirtualization("NtReadVirtualMemory_hook");
#endif
	HMODULE hModule = NULL;

	if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<LPCSTR>(_ReturnAddress()), &hModule))
	{
#ifdef _PRINTDEBUG
		FILE* f = fopen("C:\\blackcall.txt", "a+");
		fprintf(f, "[NtReadVirtualMemory ix] %016I64x -> %I64x (%I64x -> %I64x)\n", _ReturnAddress(), ProcessHandle, BaseAddress, NumberOfBytesToRead);
		fclose(f);
#endif
		if (hModule == GetModuleHandle("BlackCall.aes"))
		{
		}

		// CurrentProcess: Used to traverse the 64-bit PEB for the x64 emulation library
		// BlackCipher.aes: Repeatedly reads the BlackCipher.aes memory (Since we use API hooks, this doesn't need to be prevented)

	}
	else
	{
#ifdef _PRINTDEBUG
		FILE* f = fopen("C:\\blackcall.txt", "a+");
		fprintf(f, "[NtReadVirtualMemory ex] %016I64x %d -> %I64x (%I64x -> %I64x)\n", _ReturnAddress(), GetLastError(), ProcessHandle, BaseAddress, NumberOfBytesToRead);
		fclose(f);
#endif
	}

	return _NtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesReaded);
#ifdef _VIRTUALIZE_
	VMProtectEnd();
#endif
}

typedef NTSTATUS (NTAPI* NtQuerySystemInformation_t)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, ULONG* ReturnLength);
NtQuerySystemInformation_t _NtQuerySystemInformation = nullptr;

NTSTATUS NtQuerySystemInformation_hook(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, ULONG* ReturnLength)
{
	if (SystemInformationClass == SYSTEM_INFORMATION_CLASS::SystemProcessInformation)
	{
#ifdef _PRINTDEBUG
		FILE* f = fopen("C:\\blackcall.txt", "a+");
		fprintf(f, "[NtQuerySystemInformation] %016I64x -> %x\n", _ReturnAddress(), SystemInformationClass);
		fclose(f);
#endif

		//NTSTATUS result = _NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

		//if (NT_SUCCESS(result))
		//{
		//	for (SYSTEM_PROCESS_INFO* info = reinterpret_cast<SYSTEM_PROCESS_INFO*>(SystemInformation); info != nullptr;
		//		info = reinterpret_cast<SYSTEM_PROCESS_INFO*>(reinterpret_cast<uint8_t*>(info) + info->NextEntryOffset))
		//	{
		//		if (reinterpret_cast<DWORD>(info->UniqueProcessId) != GetCurrentProcessId())
		//		{
		//			memset(&info->ImageName.Buffer, 0, info->ImageName.MaximumLength);
		//			memset(&info->ImageName, 0, sizeof(UNICODE_STRING));

		//			info->UniqueProcessId = 0;
		//			info->InheritedFromProcessId = 0;

		//			info->NumberOfThreads = 0;
		//			info->HandleCount = 0;
		//		}

		//		if (info->NextEntryOffset == 0)
		//			break;
		//	}
		//}

		//return result;
	}

	return _NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}

#pragma optimize("g", on)

} // namespace blackcall

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
#ifdef _PRINTDEBUG
	//if (dwReason == DLL_PROCESS_ATTACH)
	//	fopen_s(&f, "C:\\blackcall.txt", "a+");
	//else if (dwReason == DLL_PROCESS_DETACH)
	//	fclose(f);
#endif

	return TRUE;
}