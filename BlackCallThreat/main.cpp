#include "exports.hpp"

#include "detour.hpp"
#include "utility.hpp"

#include "x64_intrinsic.hpp"
#include "x64_structures.hpp"

#include <vector>

#include <VMProtectSDK.h>

#pragma optimize("g", off)

#ifndef _VIRTUALIZE_
#define _VIRTUALIZE_
#endif

namespace blackcall {

bool hook_CopyFileW()
{
#ifdef _VIRTUALIZE_
	VMProtectBeginVirtualization("hook_CopyFileW");
#endif
	static decltype(&CopyFileW) _CopyFileW = reinterpret_cast<decltype(&CopyFileW)>(GetProcAddress(GetModuleHandleA("KERNELBASE"), "CopyFileW"));

	decltype(&CopyFileW) CopyFileW_hook = [](LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName, BOOL bFailIfExists) -> BOOL
	{
#ifdef _VIRTUALIZE_
		VMProtectBeginVirtualization("CopyFileW_hook");
#endif
		if (lpExistingFileName)
		{
			if (black::utility::CompareModuleNameW(lpExistingFileName, L"ntdll.dll") || black::utility::CompareModuleNameW(lpExistingFileName, L"kernelbase.dll"))
			{
				SetLastError(ERROR_ACCESS_DENIED);
				return FALSE;
			}
		}

		return _CopyFileW(lpExistingFileName, lpNewFileName, bFailIfExists);
#ifdef _VIRTUALIZE_
		VMProtectEnd();
#endif
	};

	return black::detours::redirect(true, reinterpret_cast<void**>(&_CopyFileW), CopyFileW_hook);
#ifdef _VIRTUALIZE_
	VMProtectEnd();
#endif
}

bool hook_CreateFileW()
{
#ifdef _VIRTUALIZE_
	VMProtectBeginVirtualization("hook_CreateFileW");
#endif
	static decltype(&CreateFileW) _CreateFileW = reinterpret_cast<decltype(&CreateFileW)>(GetProcAddress(GetModuleHandleA("KERNELBASE"), "CreateFileW"));

	decltype(&CreateFileW) CreateFileW_hook = [](LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) -> HANDLE
	{
#ifdef _VIRTUALIZE_
		VMProtectBeginVirtualization("CreateFileW_hook");
#endif
		if (lpFileName)
		{
			if (black::utility::CompareSubstringW(lpFileName, L"\\\\.\\pipe\\BlackCipher\\"))
				wcscpy_s(const_cast<wchar_t*>(wcsrchr(lpFileName, '\\') + 1), 256, std::to_wstring(GetCurrentProcessId()).c_str());
		}

		return _CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
#ifdef _VIRTUALIZE_
		VMProtectEnd();
#endif
	};

	return black::detours::redirect(true, reinterpret_cast<void**>(&_CreateFileW), CreateFileW_hook);
#ifdef _VIRTUALIZE_
	VMProtectEnd();
#endif
}

bool initialize(HMODULE hModule, std::wstring const& module_name)
{
#ifdef _VIRTUALIZE_
	VMProtectBeginVirtualization("initialize");
#endif
	uint8_t* module_base = reinterpret_cast<uint8_t*>(GetModuleHandle(NULL));

	IMAGE_DOS_HEADER* dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(module_base);
	IMAGE_NT_HEADERS* nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(module_base + dos_header->e_lfanew);

	DWORD dwOldProtect = 0;
	VirtualProtect(&nt_headers->FileHeader.Characteristics, sizeof(WORD), PAGE_EXECUTE_READWRITE, &dwOldProtect);
	
	nt_headers->FileHeader.Characteristics &= ~IMAGE_FILE_LARGE_ADDRESS_AWARE;

	VirtualProtect(&nt_headers->FileHeader.Characteristics, sizeof(WORD), dwOldProtect, &dwOldProtect);

	if (!black::detours::redirect_x64(black::utility::ModifyModulePath(module_name, 1, L"\\common.dll"), { "NtOpenProcess", "NtQueryVirtualMemory", "NtReadVirtualMemory", "NtQuerySystemInformation" }))
		return false;

	return (hook_CopyFileW() && hook_CreateFileW());
#ifdef _VIRTUALIZE_
	VMProtectEnd();
#endif
}

} // namespace blackcall

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
#ifdef _VIRTUALIZE_
	VMProtectBeginVirtualization("DllMain");
#endif
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		if (exports::setup(hModule))
		{
			std::vector<wchar_t> module_name_buffer(MAX_PATH);
			GetModuleFileNameW(GetModuleHandle(NULL), &module_name_buffer[0], module_name_buffer.size());

			blackcall::initialize(hModule, std::wstring(&module_name_buffer[0]));
		}

		DisableThreadLibraryCalls(hModule);
	}

	return TRUE;
#ifdef _VIRTUALIZE_
	VMProtectEnd();
#endif
}

#pragma optimize("g", on)