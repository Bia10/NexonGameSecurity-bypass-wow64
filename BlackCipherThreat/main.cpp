#include "dbgcore.hpp"

#include "detour.hpp"
#include "utility.hpp"

#include "x64_intrinsic.hpp"
#include "x64_structures.hpp"

#include <vector>
#pragma comment(lib, "ntdll")

#include "VMProtectSDK.h"

#ifndef _VIRTUALIZE_
#define _VIRTUALIZE_
#endif

#pragma optimize("g", off)

namespace blackcipher {

void unlink_modules()
{
#ifdef _VIRTUALIZE_
	VMProtectBeginVirtualization("unlink_modules");
#endif
	PEB_LDR_DATA32* head = reinterpret_cast<PEB_LDR_DATA32*>(NtCurrentTeb()->ProcessEnvironmentBlock->Ldr);
	LDR_DATA_TABLE_ENTRY32* executable = reinterpret_cast<LDR_DATA_TABLE_ENTRY32*>(head->InLoadOrderModuleList.Flink);

	executable->InLoadOrderLinks.Flink = reinterpret_cast<DWORD>(&head->InLoadOrderModuleList);
	executable->InLoadOrderLinks.Blink = reinterpret_cast<DWORD>(&head->InLoadOrderModuleList);
#ifdef _VIRTUALIZE_
	VMProtectEnd();
#endif
}

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

bool hook_CreateNamedPipeW(uint32_t parent)
{
#ifdef _VIRTUALIZE_
	VMProtectBeginVirtualization("hook_CreateNamedPipeW");
#endif
	static uint32_t parent_process_id = parent;
	static decltype(&CreateNamedPipeW) _CreateNamedPipeW = reinterpret_cast<decltype(&CreateNamedPipeW)>(GetProcAddress(GetModuleHandleA("KERNELBASE"), "CreateNamedPipeW"));

	decltype(&CreateNamedPipeW) CreateNamedPipeW_hook = [](LPCWSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes) -> HANDLE
	{
#ifdef _VIRTUALIZE_
		VMProtectBeginVirtualization("CreateNamedPipeW_hook");
#endif
		if (lpName)
		{
			if (black::utility::CompareSubstringW(lpName, L"\\\\.\\pipe\\BlackCipher\\"))
				wcscpy_s(const_cast<wchar_t*>(wcsrchr(lpName, '\\') + 1), 256, std::to_wstring(parent_process_id).c_str());
		}

		return _CreateNamedPipeW(lpName, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize, nDefaultTimeOut, lpSecurityAttributes);
#ifdef _VIRTUALIZE_
		VMProtectEnd();
#endif
	};

	return black::detours::redirect(true, reinterpret_cast<void**>(&_CreateNamedPipeW), CreateNamedPipeW_hook);
#ifdef _VIRTUALIZE_
	VMProtectEnd();
#endif
}

bool hook_NtGetContextThread()
{
#ifdef _VIRTUALIZE_
	VMProtectBeginVirtualization("hook_NtGetContextThread");
#endif
	typedef NTSTATUS (NTAPI* NtGetContextThread_t)(HANDLE ThreadHandle, PCONTEXT pContext);
	static NtGetContextThread_t _NtGetContextThread = reinterpret_cast<NtGetContextThread_t>(GetProcAddress(GetModuleHandleA("ntdll"), "NtGetContextThread"));

	NtGetContextThread_t NtGetContextThread_hook = [](HANDLE ThreadHandle, PCONTEXT pContext) -> NTSTATUS
	{
#ifdef _VIRTUALIZE_
		VMProtectBeginVirtualization("NtGetContextThread_hook");
#endif
		NTSTATUS result = _NtGetContextThread(ThreadHandle, pContext);

		if (pContext->ContextFlags & (CONTEXT_DEBUG_REGISTERS & ~CONTEXT_i386))
		{
			pContext->Dr0 = 0;
			pContext->Dr1 = 0;
			pContext->Dr2 = 0;
			pContext->Dr3 = 0;
			pContext->Dr6 = 0;
			pContext->Dr7 = 0;
		}

		return result;
#ifdef _VIRTUALIZE_
		VMProtectEnd();
#endif
	};

	return black::detours::redirect(true, reinterpret_cast<void**>(&_NtGetContextThread), NtGetContextThread_hook);
#ifdef _VIRTUALIZE_
	VMProtectEnd();
#endif
}

bool initialize(std::wstring const& module_name, uint32_t parent)
{
#ifdef _VIRTUALIZE_
	VMProtectBeginVirtualization("initialize");
#endif
	unlink_modules();

	if (!black::detours::redirect_x64(black::utility::ModifyModulePath(module_name, 1, L"\\common.dll"), { "NtOpenProcess", "NtQueryVirtualMemory", "NtReadVirtualMemory", "NtQuerySystemInformation" }))
		return false;

	return (hook_CopyFileW() && hook_CreateNamedPipeW(parent) && hook_NtGetContextThread());
#ifdef _VIRTUALIZE_
	VMProtectEnd();
#endif
}

} // namespace blackcipher

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

			std::wstring module_name(&module_name_buffer[0]);

			if (black::utility::CompareModuleNameW(module_name, L"BlackCipher.aes"))
			{
				int argc = 0;
				wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);

				if (argc >= 3)
				{
					if (!blackcipher::initialize(module_name, std::stoul(std::wstring(argv[2]), 0, 8)))
						black::utility::DisplayMessageBox("Failed to initialize BlackCipherThreat.", "BlackCipher");
				}
			}
		}

		DisableThreadLibraryCalls(hModule);
	}

	return TRUE;
#ifdef _VIRTUALIZE_
	VMProtectEnd();
#endif
}

#pragma optimize("g", on)