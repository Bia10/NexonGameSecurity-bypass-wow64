#ifdef UNICODE
#undef UNICODE
#endif

#include <Windows.h>
#include <Winternl.h>
#include <Psapi.h>
#include <TlHelp32.h>

#include <intrin.h>

#include <string>
#include <utility>
#include <vector>

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

//#ifndef _PRINTDEBUG
//#define _PRINTDEBUG
//#endif

#pragma optimize("g", off)

#ifdef _PRINTDEBUG
FILE* f = nullptr;
#endif

namespace blackcipher {

DWORD parent_process_id = 0;

std::pair<BYTE*, DWORD> parent_module;
std::vector<BYTE> parent_module_copy;

namespace detail {

bool GetParentBaseModule(DWORD ProcessId)
{
#ifdef _VIRTUALIZE_
	VMProtectBeginVirtualization("GetParentBaseModule");
#endif
	if (HANDLE hParent = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId))
	{
		std::vector<char> temp(MAX_PATH);

		if (GetModuleBaseName(hParent, NULL, &temp[0], static_cast<DWORD>(temp.size())))
		{
			HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, ProcessId);
			
			if (hSnapshot != INVALID_HANDLE_VALUE)
			{
				MODULEENTRY32 module_entry;
				memset(&module_entry, 0, sizeof(MODULEENTRY32));

				module_entry.dwSize = sizeof(MODULEENTRY32);

				if (Module32First(hSnapshot, &module_entry))
				{
					do
					{
						if (!strcmp(module_entry.szModule, &temp[0]))
						{
							parent_module = std::make_pair(module_entry.modBaseAddr, module_entry.modBaseSize);
							parent_module_copy.resize(parent_module.second);

							SIZE_T number_of_bytes = 0;

							if (ReadProcessMemory(hParent, parent_module.first, &parent_module_copy[0], parent_module_copy.size(), &number_of_bytes))
								return (number_of_bytes == static_cast<SIZE_T>(parent_module_copy.size()));
						}
					}
					while (Module32Next(hSnapshot, &module_entry));
				}

				CloseHandle(hSnapshot);
			}
		}

		CloseHandle(hParent);
	}

	return false;
#ifdef _VIRTUALIZE_
	VMProtectEnd();
#endif
}

} // namespace detail

typedef NTSTATUS (NTAPI* NtOpenProcess_t)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, CLIENT_ID* ClientId);
NtOpenProcess_t _NtOpenProcess = nullptr;

NTSTATUS NtOpenProcess_hook(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, CLIENT_ID* ClientId)
{
#ifdef _VIRTUALIZE_
	VMProtectBeginVirtualization("NtOpenProcess_hook");
#endif
	HMODULE hModule = NULL;

	if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<LPCSTR>(_ReturnAddress()), &hModule) && hModule == GetModuleHandle(NULL))
	{
#ifdef _PRINTDEBUG
		fprintf(f, "[NtOpenProcess] %016I64x -> %I64d\n", _ReturnAddress(), ClientId->UniqueProcess);
		fflush(f);
#endif

		if (reinterpret_cast<DWORD64>(ClientId->UniqueProcess) != parent_process_id)
		{
			if (ProcessHandle)
				*ProcessHandle = NULL;

			return STATUS_ACCESS_DENIED;
		}
	}

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

	if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<LPCSTR>(_ReturnAddress()), &hModule) && hModule == GetModuleHandle(NULL))
	{
#ifdef _PRINTDEBUG
		fprintf(f, "[NtQueryVirtualMemory] %016I64x -> %I64x (%x)\n", _ReturnAddress(), ProcessHandle, MemoryInformationClass);
		fflush(f);
#endif

		if (ProcessHandle == GetCurrentProcess() && MemoryInformationClass == MemoryBasicInformation)
		{
			BYTE* module_base = reinterpret_cast<BYTE*>(GetModuleHandle(NULL));

			IMAGE_DOS_HEADER* dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(module_base);
			IMAGE_NT_HEADERS* nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(module_base + dos_header->e_lfanew);

			if (BaseAddress < module_base)
				BaseAddress = module_base;
			else if (BaseAddress > (module_base + nt_headers->OptionalHeader.SizeOfImage))
			{
				memset(MemoryInformation, 0, MemoryInformationLength);

				if (ReturnLength != NULL)
					*ReturnLength = 0;

				return STATUS_INVALID_PARAMETER;
			}
		}
		else
		{
			memset(MemoryInformation, 0, MemoryInformationLength);

			if (ReturnLength != NULL)
				*ReturnLength = 0;

			return STATUS_ACCESS_DENIED;
		}
	}

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

	if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<LPCSTR>(_ReturnAddress()), &hModule) && hModule == GetModuleHandle(NULL))
	{
#ifdef _PRINTDEBUG
		fprintf(f, "[NtReadVirtualMemory] %016I64x -> %I64x (%I64x -> %I64x)\n", _ReturnAddress(), ProcessHandle, BaseAddress, NumberOfBytesToRead);
		fflush(f);
#endif

		if (ProcessHandle != GetCurrentProcess())
		{
			MEMORY_BASIC_INFORMATION mbi;
			memset(&mbi, 0, sizeof(MEMORY_BASIC_INFORMATION));

			if (VirtualQueryEx(ProcessHandle, BaseAddress, &mbi, sizeof(mbi)) == sizeof(mbi))
			{
				if (mbi.AllocationBase == parent_module.first)
				{
					std::size_t offset = BaseAddress - parent_module.first;

					if (offset + NumberOfBytesToRead <= parent_module.second)
					{
						memcpy(Buffer, &parent_module_copy[offset], NumberOfBytesToRead);

						if (NumberOfBytesReaded)
							*NumberOfBytesReaded = NumberOfBytesToRead;

						return STATUS_SUCCESS;
					}
				}
				else if (mbi.Type == MEM_IMAGE)
				{
					std::vector<char> temp(MAX_PATH);

					if (GetModuleBaseName(ProcessHandle, reinterpret_cast<HMODULE>(mbi.AllocationBase), &temp[0], static_cast<DWORD>(temp.size())))
					{
						if (_strcmpi(&temp[0], "NGClient.aes") && _strcmpi(&temp[0], "BlackCall.aes"))
							return STATUS_ACCESS_DENIED;
					}
				}
			}
		}
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
		fprintf(f, "[NtQuerySystemInformation] %016I64x -> %x\n", _ReturnAddress(), SystemInformationClass);
		fflush(f);
#endif

		NTSTATUS result = _NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

		if (NT_SUCCESS(result))
		{
			for (SYSTEM_PROCESS_INFO* info = reinterpret_cast<SYSTEM_PROCESS_INFO*>(SystemInformation); info != nullptr;
				info = reinterpret_cast<SYSTEM_PROCESS_INFO*>(reinterpret_cast<uint8_t*>(info) + info->NextEntryOffset))
			{
				if (reinterpret_cast<DWORD>(info->UniqueProcessId) != parent_process_id &&
					reinterpret_cast<DWORD>(info->UniqueProcessId) != GetCurrentProcessId())
				{
					memset(&info->ImageName.Buffer, 0, info->ImageName.MaximumLength);
					memset(&info->ImageName, 0, sizeof(UNICODE_STRING));

					info->UniqueProcessId = 0;
					info->InheritedFromProcessId = 0;

					info->NumberOfThreads = 0;
					info->HandleCount = 0;
				}

				if (info->NextEntryOffset == 0)
					break;
			}
		}

		return result;
	}

	return _NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}

} // namespace blackcipher

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
#ifdef _VIRTUALIZE_
	VMProtectBeginVirtualization("DllMain");
#endif
	if (dwReason == DLL_PROCESS_ATTACH)
	{
#ifdef _PRINTDEBUG
		fopen_s(&f, "C:\\blackcipher.txt", "a+");
#endif

		blackcipher::detail::GetParentBaseModule(blackcipher::parent_process_id = std::stoul(std::wstring(wcsrchr(GetCommandLineW(), ' ') + 1), 0, 8));
	}
#ifdef _PRINTDEBUG
	else if (dwReason == DLL_PROCESS_DETACH)
		fclose(f);
#endif

	return TRUE;
#ifdef _VIRTUALIZE_
	VMProtectEnd();
#endif
}

#pragma optimize("g", on)