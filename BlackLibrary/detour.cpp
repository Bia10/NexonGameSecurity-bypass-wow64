#include "detour.hpp"

#include "x64_intrinsic.hpp"
#include "x64_structures.hpp"

#include <detours.h>
#pragma comment(lib, "detours")

#include <array>

#include <VMProtectSDK.h>

#ifndef _VIRTUALIZE_
#define _VIRTUALIZE_
#endif

#pragma optimize("g", off)

namespace black {
namespace detours {
namespace detail {

bool apply_hook_x64(DWORD64* target, DWORD hook)
{
#ifdef _VIRTUALIZE_
	VMProtectBeginVirtualization("apply_hook_x64");
#endif
	std::array<uint8_t, 8> jmp_hook = 
	{{
		0xB8, 0x00, 0x00, 0x00, 0x00,									// +00 : mov eax,00000000				<-- (+01) Overwrite
		0xFF, 0xE0,														// +05 : jmp rax
		0x90															// +07 : nop
	}};

	*reinterpret_cast<DWORD*>(jmp_hook.data() + 1) = hook;
	
	std::array<uint8_t, 8 + 16> jmp_return =
	{{
		/* Original memory */
		0x00, 0x00, 0x00,												// +00 : mov r10,rcx					<-- (+00) Overwrite
		0x00, 0x00, 0x00, 0x00, 0x00,									// +03 : mov eax,<api number>			<-- (+03) Overwrite

		/* Return memory */
		0x50,															// +08 : push rax
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		// +09 : mov rax,0000000000000000		<-- (+11) Overwrite
		0x48, 0x87, 0x04, 0x24,											// +19 : xchg [rsp],rax
		0xC3															// +23 : ret
	}};

	if (!x64_ReadProcessMemory(GetCurrentProcess(), *target, jmp_return.data(), 8, NULL))
		return false;

	*reinterpret_cast<DWORD64*>(jmp_return.data() + 11) = (*target + 8);

	DWORD old_protect = 0;
		
	if (x64_VirtualProtectEx(GetCurrentProcess(), *target, jmp_hook.size(), PAGE_EXECUTE_READWRITE, &old_protect) &&
		x64_WriteProcessMemory(GetCurrentProcess(), *target, jmp_hook.data(), jmp_hook.size(), NULL) &&
		x64_VirtualProtectEx(GetCurrentProcess(), *target, jmp_hook.size(), old_protect, &old_protect))
	{
		if (*target = x64_VirtualAllocEx(GetCurrentProcess(), NULL, jmp_return.size(), MEM_COMMIT, PAGE_EXECUTE_READWRITE))
		{
			if (x64_WriteProcessMemory(GetCurrentProcess(), *target, jmp_return.data(), jmp_return.size(), NULL))
				return true;
		}
	}

	return false;
#ifdef _VIRTUALIZE_
	VMProtectEnd();
#endif
}

bool hook_native_api_x64(DWORD64 module_base, std::string const& function_name, std::string const& export_name)
{
#ifdef _VIRTUALIZE_
	VMProtectBeginVirtualization("hook_native_api_x64");
#endif
	DWORD64* function_jmp = reinterpret_cast<DWORD64*>(x64_GetProcAddress(module_base, "_" + export_name + "x"));
	DWORD64 function_hook = x64_GetProcAddress(module_base, "_" + export_name + "y");

	*function_jmp = x64_GetProcAddress(x64_GetBaseModule(), function_name);

	return apply_hook_x64(function_jmp, static_cast<DWORD>(function_hook));
#ifdef _VIRTUALIZE_
	VMProtectEnd();
#endif
}

} // namespace detail

bool redirect(bool enable, void** function, void* hook)
{
#ifdef _VIRTUALIZE_
	VMProtectBeginVirtualization("redirect");
#endif
	if (DetourTransactionBegin() == NO_ERROR)
	{
		if (DetourUpdateThread(GetCurrentThread()) == NO_ERROR)
		{
			if ((enable ? DetourAttach : DetourDetach)(function, hook) == NO_ERROR)
			{
				if (DetourTransactionCommit() == NO_ERROR)
					return true;
			}
		}

		DetourTransactionAbort();
	}

	return false;
#ifdef _VIRTUALIZE_
	VMProtectEnd();
#endif
}

bool redirect_x64(std::wstring const& module_name, std::initializer_list<std::string> target_apis)
{
#ifdef _VIRTUALIZE_
	VMProtectBeginVirtualization("redirect_x64");
#endif
	DWORD64 module_base = x64_LdrLoadDll(module_name);

	if (!module_base)
		return false;
	else
	{
		std::size_t index = 1;

		for (std::string const& api : target_apis)
		{
			if (!detail::hook_native_api_x64(module_base, api, std::to_string(index++)))
				return false;
		}

		return true;
	}
#ifdef _VIRTUALIZE_
	VMProtectEnd();
#endif
}

} // namespace detours
} // namespace black

#pragma optimize("g", on)