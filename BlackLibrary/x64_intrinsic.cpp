#include "x64_intrinsic.hpp"
#include "x64_internals.hpp"
#include "x64_structures.hpp"

#include <functional>
#include <vector>

#include <iostream>

namespace black {

#pragma warning(push)
#pragma warning(disable: 4409)
DWORD64 x64_call(DWORD64 func, int argc, ...)
{
    va_list argv;
    va_start(argv, argc);

    x64_reg _rcx = { (argc > 0) ? argc--, va_arg(argv, DWORD64) : 0 };
	x64_reg _rdx = { (argc > 0) ? argc--, va_arg(argv, DWORD64) : 0 };
	x64_reg _r8 = { (argc > 0) ? argc--, va_arg(argv, DWORD64) : 0 };
	x64_reg _r9 = { (argc > 0) ? argc--, va_arg(argv, DWORD64) : 0 };
	x64_reg _rax = { 0 };
	x64_reg _remaining = { reinterpret_cast<DWORD64>(&va_arg(argv, DWORD64)) };
	x64_reg _argc = { static_cast<DWORD64>(argc) };

	WORD old_fs = 0;
	DWORD old_esp = 0;

    __asm
    {
		mov old_fs,fs									// Backup FS segment
		mov eax,0x2B
		mov fs,ax										// Reset FS segment to properly handle RFG
		mov old_esp,esp									// Backup stack pointer
		and esp,0xFFFFFFF0								// Align to esp to 0x10. Without aligned stack, some syscalls may return errors (0x08 is sufficient for syscalls, but SSE opcodes requires 0x10 alignment). It will be further adjusted according to the number of arguments above 4.

        X64_Start();

  REX_W	mov ecx,_rcx.dw[0]								// mov rcx,qword ptr [_rcx]
  REX_W mov edx,_rdx.dw[0]								// mov rdx,qword ptr [_rdx]
        push _r8.qw										// push qword ptr [_r8]
        X64_Pop(_R8);									// pop r8
        push _r9.qw										// push qword ptr [_r9]
        X64_Pop(_R9);									// pop r9

  REX_W mov eax,_argc.dw[0]								// mov rax,qword ptr [_argc]

        test al,1										// test al,1
        jnz _skip_adjust								// jnz _skip_adjust
        sub esp,8										// sub rsp,8
	_skip_adjust:

        push edi										// push rdi
  REX_W mov edi,_remaining.dw[0]						// mov rdi,qword ptr [_remaining]

  REX_W test eax,eax									// test rax,rax
        jz _push_argument_end							// je _perform_call

  REX_W lea edi,dword ptr [edi+8*eax-8]					// lea rdi,[rdi+rax*8-8]

	_push_argument:
  REX_W test eax,eax									// test rax,rax
        jz _push_argument_end							// je _perform_call
        push dword ptr [edi]							// push qword ptr [rdi]
  REX_W sub edi,8										// sub rdi,8
  REX_W sub eax,1										// sub rax,1
        jmp _push_argument								// jmp _push_argument

	_push_argument_end:
  REX_W sub esp,0x20									// sub rsp,20h ; Create stack space for spilling registers
        call func										// call qword ptr [func]

  REX_W mov ecx,_argc.dw[0]								// mov rcx,qword ptr [_argc]
  REX_W lea esp,dword ptr [esp+8*ecx+0x20]				// lea rsp,[rsp+rcx*8+20h]
        pop edi											// pop rdi
  REX_W mov _rax.dw[0],eax								// mov qword ptr [_rax],rax

        X64_End();

		mov ax,ds
		mov ss,ax										// Restore SS segment
		mov esp,old_esp									// Restore stack pointer
		mov ax,old_fs
		mov fs,ax										// Restore FS segment
    }

    return _rax.qw;
}
#pragma warning(default: 4409)
#pragma warning(pop)

DWORD64 x64_NtCurrentTeb()
{
	x64_reg reg;
	reg.qw = 0;

	X64_Start();
	X64_Push(_R12);										// R12 register should always contain pointer to TEB64 in WOW64 processes
	__asm pop reg.dw[0]									// Pop will pop QWORD from stack, as we're in x64 mode now
	X64_End();

	return reg.qw;
}

void x64_memcpy(DWORD64 destination, DWORD64 source, std::size_t bytes)
{
	if (destination != 0 && source != 0 && bytes != 0)
	{
		x64_reg destination_register;
		destination_register.qw = destination;

		x64_reg source_register;
		source_register.qw = source;

		__asm
		{
			X64_Start();

			push edi									// push rdi
			push esi									// push rsi
			
	  REX_W	mov edi,destination_register.dw[0]			// mov rdi, qword ptr [destination_register]
	  REX_W	mov esi,source_register.dw[0]				// mov rsi, qword ptr [source_register]
			mov ecx,bytes								// mov ecx, dword ptr [bytes]					; high part of RCX is zeroed
			
			mov eax,ecx									// mov eax, ecx
			and eax,3									// and eax, 3
			shr ecx,2									// shr ecx, 2
			rep movsd									// rep movs dword ptr [rdi], dword ptr [rsi]
			test eax,eax								// test eax, eax
			je _move_0									// je _move_0
			cmp eax,1									// cmp eax, 1
			je _move_1									// je _move_1
				
			movsw										// movs word ptr [rdi], word ptr [rsi]
			cmp eax,2									// cmp eax, 2
			je _move_0									// je _move_0

		_move_1:
			movsb										// movs byte ptr [rdi], byte ptr [rsi]

		_move_0:
			pop esi										// pop rsi
			pop edi										// pop rdi

			X64_End();
		}
	}
}

template <typename T>
T x64_fetch_nt_headers(DWORD64 module_base, std::function<T(DWORD64, IMAGE_NT_HEADERS64 const&)> dispatch)
{
	T result = 0;

	if (module_base)
	{
		IMAGE_DOS_HEADER dos_header;
		x64_memcpy(reinterpret_cast<DWORD64>(&dos_header), module_base, sizeof(IMAGE_DOS_HEADER));

		IMAGE_NT_HEADERS64 nt_headers;
		x64_memcpy(reinterpret_cast<DWORD64>(&nt_headers), module_base + dos_header.e_lfanew, sizeof(IMAGE_NT_HEADERS64));

		result = dispatch(module_base, nt_headers);
	}

	return result;
}

BOOL x64_enumerate_peb_loader(std::function<bool(LDR_DATA_TABLE_ENTRY64 const&)> dispatch)
{
	TEB64 x64_teb;
	x64_memcpy(reinterpret_cast<DWORD64>(&x64_teb), x64_NtCurrentTeb(), sizeof(TEB64));

	PEB64 x64_peb;
	x64_memcpy(reinterpret_cast<DWORD64>(&x64_peb), x64_teb.ProcessEnvironmentBlock, sizeof(PEB64));

	PEB_LDR_DATA64 x64_ldr;
	x64_memcpy(reinterpret_cast<DWORD64>(&x64_ldr), x64_peb.Ldr, sizeof(PEB_LDR_DATA64));

	DWORD64 head = x64_peb.Ldr + offsetof(PEB_LDR_DATA64, InLoadOrderModuleList);

	LDR_DATA_TABLE_ENTRY64 current;
	current.InLoadOrderLinks.Flink = x64_ldr.InLoadOrderModuleList.Flink;

	do
	{
		x64_memcpy(reinterpret_cast<DWORD64>(&current), current.InLoadOrderLinks.Flink, sizeof(LDR_DATA_TABLE_ENTRY64));

		if (dispatch(current))
			return TRUE;
	} 
	while (current.InLoadOrderLinks.Flink != head);

	return FALSE;
}

DWORD64 x64_GetLdrGetProcedureAddress(DWORD64 module_base)
{
	return x64_fetch_nt_headers<DWORD64>(module_base, [](DWORD64 module_base, IMAGE_NT_HEADERS64 const& nt_headers) -> DWORD64
	{
		constexpr std::size_t kMaxNameLength = 256;

		if (DWORD export_address = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
		{
			IMAGE_EXPORT_DIRECTORY export_directory;
			x64_memcpy(reinterpret_cast<DWORD64>(&export_directory), module_base + export_address, sizeof(IMAGE_EXPORT_DIRECTORY));

			std::vector<DWORD> rva_table(export_directory.NumberOfFunctions);
			x64_memcpy(reinterpret_cast<DWORD64>(&rva_table[0]), module_base + export_directory.AddressOfFunctions, sizeof(DWORD) * rva_table.size());

			std::vector<WORD> ordinal_table(export_directory.NumberOfFunctions);
			x64_memcpy(reinterpret_cast<DWORD64>(&ordinal_table[0]), module_base + export_directory.AddressOfNameOrdinals, sizeof(WORD) * ordinal_table.size());

			std::vector<DWORD> name_table(export_directory.NumberOfNames);
			x64_memcpy(reinterpret_cast<DWORD64>(&name_table[0]), module_base + export_directory.AddressOfNames, sizeof(DWORD) * name_table.size());

			for (DWORD i = 0; i < export_directory.NumberOfNames; i++)
			{
				std::vector<char> temp(kMaxNameLength);
				x64_memcpy(reinterpret_cast<DWORD64>(&temp[0]), module_base + name_table[i], kMaxNameLength);

				if (!strcmp(&temp[0], "LdrGetProcedureAddress"))
					return (module_base + rva_table[ordinal_table[i]]);
			}
		}
		
		return 0;
	});
}

DWORD64 x64_call_module_entry_point(DWORD64 module_base, DWORD reason)
{
	return x64_fetch_nt_headers<DWORD64>(module_base, [&](DWORD64 module_base, IMAGE_NT_HEADERS64 const& nt_headers) -> DWORD64
	{
		return x64_call(module_base + nt_headers.OptionalHeader.AddressOfEntryPoint, 3, module_base, static_cast<DWORD64>(reason), static_cast<DWORD64>(NULL));
	});
}

BOOL x64_FreeKnownDllMemory(std::wstring const& lpKnownDllName)
{
	if (HANDLE hSection = reinterpret_cast<HANDLE>(x64_LdrGetKnownDllSectionHandle(&lpKnownDllName[0], FALSE)))
	{
		x64_memcpy(x64_NtCurrentTeb() + offsetof(TEB64, NtTib.ArbitraryUserPointer), reinterpret_cast<DWORD64>(&lpKnownDllName[0]), sizeof(DWORD64));

		DWORD64 base_address = 0;
		SIZE_T view_size = 0;

		if (x64_NtMapViewOfSection(hSection, GetCurrentProcess(), &base_address, 0, 0, 0, &view_size, ViewUnmap, 0, PAGE_READONLY))
		{
			return x64_fetch_nt_headers<BOOL>(base_address, [&](DWORD64 module_base, IMAGE_NT_HEADERS64 const& nt_headers) -> BOOL
			{
				if (!x64_VirtualFreeEx(GetCurrentProcess(), nt_headers.OptionalHeader.ImageBase, 0, MEM_RELEASE) && GetLastError() != ERROR_INVALID_ADDRESS)
					return false;

				return x64_NtUnmapViewOfSection(GetCurrentProcess(), module_base);
			});
		}
	}

	return FALSE;
}

BOOL x64_InitializeWow64Library(DWORD64 module_base)
{
	if (x64_call_module_entry_point(module_base, DLL_PROCESS_ATTACH))
	{
		return x64_enumerate_peb_loader([&](LDR_DATA_TABLE_ENTRY64 const& current) -> bool
		{
			if (current.DllBase == module_base)
			{
				LDR_DATA_TABLE_ENTRY64 next;
				x64_memcpy(reinterpret_cast<DWORD64>(&next), current.InLoadOrderLinks.Flink, sizeof(LDR_DATA_TABLE_ENTRY64));

				DWORD flags = current.Flags | LDRP_ENTRY_PROCESSED | LDRP_PROCESS_ATTACH_CALLED;
				x64_memcpy(next.InLoadOrderLinks.Blink + offsetof(LDR_DATA_TABLE_ENTRY64, Flags), reinterpret_cast<DWORD64>(&flags), sizeof(DWORD));

				WORD load_count = 0xFFFF;
				x64_memcpy(next.InLoadOrderLinks.Blink + offsetof(LDR_DATA_TABLE_ENTRY64, LoadCount), reinterpret_cast<DWORD64>(&load_count), sizeof(WORD));

				return true;
			}

			return false;
		});
	}

	return FALSE;
}

BOOL x64_InitializeWow64Components()
{
	if (x64_FreeKnownDllMemory(L"kernel32.dll"))
	{
		if (DWORD64 kernel32 = x64_LdrLoadDll(L"KERNEL32.dll"))
		{
			return (x64_InitializeWow64Library(x64_GetModuleHandleW(L"KERNELBASE.dll")) && x64_InitializeWow64Library(kernel32));
		}
	}

	return FALSE;
}

DWORD64 x64_GetModuleHandleW(std::wstring const& lpModuleName)
{
	DWORD64 module_base = 0;

	x64_enumerate_peb_loader([&](LDR_DATA_TABLE_ENTRY64 const& current) -> bool
	{
		std::vector<wchar_t> temp(current.BaseDllName.MaximumLength);
		x64_memcpy(reinterpret_cast<DWORD64>(&temp[0]), current.BaseDllName.Buffer, current.BaseDllName.MaximumLength);

		if (!_wcsicmp(lpModuleName.c_str(), &temp[0]))
		{
			module_base = current.DllBase;
			return true;
		}

		return false;
	});

	return module_base;
}

DWORD64 x64_GetBaseModule()
{
	static DWORD64 x64_ntdll = 0;

	if (!x64_ntdll)
		x64_ntdll = x64_GetModuleHandleW(L"ntdll.dll");

	return x64_ntdll;
}

DWORD64 x64_SetLastError(DWORD64 status)
{
	typedef ULONG(WINAPI* RtlSetLastWin32Error_t)(NTSTATUS Status);
	static RtlSetLastWin32Error_t RtlSetLastWin32Error = nullptr;

	if (!RtlSetLastWin32Error)
		RtlSetLastWin32Error = reinterpret_cast<RtlSetLastWin32Error_t>(GetProcAddress(GetModuleHandleA("ntdll"), "RtlSetLastWin32Error"));

	typedef ULONG(WINAPI* RtlNtStatusToDosError_t)(NTSTATUS Status);
	static RtlNtStatusToDosError_t RtlNtStatusToDosError = nullptr;

	if (!RtlNtStatusToDosError)
		RtlNtStatusToDosError = reinterpret_cast<RtlNtStatusToDosError_t>(GetProcAddress(GetModuleHandleA("ntdll"), "RtlNtStatusToDosError"));

	if (RtlSetLastWin32Error && RtlNtStatusToDosError)
		RtlSetLastWin32Error(RtlNtStatusToDosError(static_cast<DWORD>(status)));

	return status;
}

DWORD64 x64_GetProcAddress(DWORD64 hModule, std::string const& lpProcName)
{
	static DWORD64 _LdrGetProcedureAddress = 0;

	if (!_LdrGetProcedureAddress)
		_LdrGetProcedureAddress = x64_GetLdrGetProcedureAddress(x64_GetBaseModule());

	DWORD64 result = 0;

	if (_LdrGetProcedureAddress)
	{
		_ANSI_STRING_T<DWORD64> ansi_name = { 0 };
		ansi_name.Buffer = reinterpret_cast<DWORD64>(lpProcName.c_str());
		ansi_name.Length = static_cast<WORD>(lpProcName.size() * sizeof(char));
		ansi_name.MaximumLength = ansi_name.Length + sizeof(char);

		x64_SetLastError(x64_call(_LdrGetProcedureAddress, 4, hModule, reinterpret_cast<DWORD64>(&ansi_name), static_cast<DWORD64>(0), reinterpret_cast<DWORD64>(&result)));
	}

	return result;
}

DWORD64 x64_LdrLoadDll(std::wstring const& lpLibFileName)
{
	static DWORD64 _LdrLoadDll = 0;

	if (!_LdrLoadDll)
		_LdrLoadDll = x64_GetProcAddress(x64_GetBaseModule(), "LdrLoadDll");

	DWORD64 result = 0;

	if (_LdrLoadDll)
	{
		_UNICODE_STRING_T<DWORD64> unicode_name = { 0 };
		unicode_name.Buffer = reinterpret_cast<DWORD64>(lpLibFileName.c_str());
		unicode_name.Length = static_cast<WORD>(lpLibFileName.size() * sizeof(wchar_t));
		unicode_name.MaximumLength = unicode_name.Length + sizeof(wchar_t);

		x64_SetLastError(x64_call(_LdrLoadDll, 4, static_cast<DWORD64>(NULL), static_cast<DWORD64>(0), reinterpret_cast<DWORD64>(&unicode_name), reinterpret_cast<DWORD64>(&result)));
	}

	return result;
}

DWORD64 x64_LdrGetKnownDllSectionHandle(std::wstring const& lpKnownDllName, BOOL bIs32BitSection)
{
	static DWORD64 _LdrGetKnownDllSectionHandle = 0;

	if (!_LdrGetKnownDllSectionHandle)
		_LdrGetKnownDllSectionHandle = x64_GetProcAddress(x64_GetBaseModule(), "LdrGetKnownDllSectionHandle");

	DWORD64 result = 0;

	if (_LdrGetKnownDllSectionHandle)
		x64_SetLastError(x64_call(_LdrGetKnownDllSectionHandle, 3, reinterpret_cast<DWORD64>(lpKnownDllName.c_str()), static_cast<DWORD64>(bIs32BitSection), reinterpret_cast<DWORD64>(&result)));

	return result;
}

BOOL x64_NtMapViewOfSection(HANDLE hSection, HANDLE hProcess, DWORD64* lpBaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect)
{
	static DWORD64 _NtMapViewOfSection = 0;

	if (!_NtMapViewOfSection)
		_NtMapViewOfSection = x64_GetProcAddress(x64_GetBaseModule(), "NtMapViewOfSection");

	if (_NtMapViewOfSection)
	{
		DWORD64 temp_base_address = (lpBaseAddress ? *lpBaseAddress : 0);
		DWORD64 temp_view_size = (ViewSize ? *ViewSize : 0);

		if (NT_SUCCESS(x64_SetLastError(x64_call(_NtMapViewOfSection, 10, reinterpret_cast<DWORD64>(hSection), reinterpret_cast<DWORD64>(hProcess), reinterpret_cast<DWORD64>(&temp_base_address), static_cast<DWORD64>(ZeroBits), static_cast<DWORD64>(CommitSize), reinterpret_cast<DWORD64>(SectionOffset), reinterpret_cast<DWORD64>(&temp_view_size), static_cast<DWORD64>(InheritDisposition), static_cast<DWORD64>(AllocationType), static_cast<DWORD64>(Win32Protect)))))
		{
			if (lpBaseAddress)
				*lpBaseAddress = temp_base_address;

			if (ViewSize)
				*ViewSize = static_cast<SIZE_T>(temp_view_size);

			return TRUE;
		}
	}

	return FALSE;
}

BOOL x64_NtUnmapViewOfSection(HANDLE hProcess, DWORD64 lpBaseAddress)
{
	static DWORD64 _NtUnmapViewOfSection = 0;

	if (!_NtUnmapViewOfSection)
		_NtUnmapViewOfSection = x64_GetProcAddress(x64_GetBaseModule(), "NtUnmapViewOfSection");

	if (_NtUnmapViewOfSection)
	{
		if (NT_SUCCESS(x64_SetLastError(x64_call(_NtUnmapViewOfSection, 2, reinterpret_cast<DWORD64>(hProcess), lpBaseAddress))))
			return TRUE;
	}

	return FALSE;
}

DWORD64 x64_VirtualAllocEx(HANDLE hProcess, DWORD64 lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
	static DWORD64 _NtAllocateVirtualMemory = 0;

	if (!_NtAllocateVirtualMemory)
		_NtAllocateVirtualMemory = x64_GetProcAddress(x64_GetBaseModule(), "NtAllocateVirtualMemory");

	if (_NtAllocateVirtualMemory)
	{
		DWORD64 temp_address = lpAddress;
		DWORD64 temp_size = dwSize;

		if (NT_SUCCESS(x64_SetLastError(x64_call(_NtAllocateVirtualMemory, 6, reinterpret_cast<DWORD64>(hProcess), reinterpret_cast<DWORD64>(&temp_address), static_cast<DWORD64>(0), reinterpret_cast<DWORD64>(&temp_size), static_cast<DWORD64>(flAllocationType), static_cast<DWORD64>(flProtect)))))
			return temp_address;
	}

	return 0;
}

BOOL x64_VirtualFreeEx(HANDLE hProcess, DWORD64 lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
	static DWORD64 _NtFreeVirtualMemory = 0;

	if (!_NtFreeVirtualMemory)
		_NtFreeVirtualMemory = x64_GetProcAddress(x64_GetBaseModule(), "NtFreeVirtualMemory");

	if (_NtFreeVirtualMemory)
	{
		DWORD64 temp_address = lpAddress;
		DWORD64 temp_size = dwSize;

		if (NT_SUCCESS(x64_SetLastError(x64_call(_NtFreeVirtualMemory, 4, reinterpret_cast<DWORD64>(hProcess), reinterpret_cast<DWORD64>(&temp_address), reinterpret_cast<DWORD64>(&temp_size), static_cast<DWORD64>(dwFreeType)))))
			return TRUE;
	}

	return FALSE;
}

BOOL x64_VirtualProtectEx(HANDLE hProcess, DWORD64 lpAddress, SIZE_T dwSize, DWORD flNewProtect, DWORD* lpflOldProtect)
{
	static DWORD64 _NtProtectVirtualMemory = 0;

	if (!_NtProtectVirtualMemory)
		_NtProtectVirtualMemory = x64_GetProcAddress(x64_GetBaseModule(), "NtProtectVirtualMemory");

	if (_NtProtectVirtualMemory)
	{
		DWORD64 temp_address = lpAddress;
		DWORD64 temp_size = dwSize;

		if (NT_SUCCESS(x64_SetLastError(x64_call(_NtProtectVirtualMemory, 5, reinterpret_cast<DWORD64>(hProcess), reinterpret_cast<DWORD64>(&temp_address), reinterpret_cast<DWORD64>(&temp_size), static_cast<DWORD64>(flNewProtect), reinterpret_cast<DWORD64>(lpflOldProtect)))))
			return TRUE;
	}

	return FALSE;
}

SIZE_T x64_VirtualQueryEx(HANDLE hProcess, DWORD64 lpAddress, MEMORY_BASIC_INFORMATION64* lpBuffer, SIZE_T dwLength)
{
	static DWORD64 _NtQueryVirtualMemory = 0;

	if (!_NtQueryVirtualMemory)
		_NtQueryVirtualMemory = x64_GetProcAddress(x64_GetBaseModule(), "NtQueryVirtualMemory");

	DWORD64 result = 0;

	if (_NtQueryVirtualMemory)
		x64_SetLastError(x64_call(_NtQueryVirtualMemory, 6, reinterpret_cast<DWORD64>(hProcess), lpAddress, static_cast<DWORD64>(0), reinterpret_cast<DWORD64>(lpBuffer), static_cast<DWORD64>(dwLength), reinterpret_cast<DWORD64>(&result)));

	return static_cast<SIZE_T>(result);
}

BOOL x64_ReadProcessMemory(HANDLE hProcess, DWORD64 lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead)
{
	static DWORD64 _NtReadVirtualMemory = 0;

	if (!_NtReadVirtualMemory)
		_NtReadVirtualMemory = x64_GetProcAddress(x64_GetBaseModule(), "NtReadVirtualMemory");

	if (_NtReadVirtualMemory)
	{
		DWORD64 number_of_bytes = lpNumberOfBytesRead ? *lpNumberOfBytesRead : 0;

		if (NT_SUCCESS(x64_SetLastError(x64_call(_NtReadVirtualMemory, 5, reinterpret_cast<DWORD64>(hProcess), lpBaseAddress, reinterpret_cast<DWORD64>(lpBuffer), static_cast<DWORD64>(nSize), reinterpret_cast<DWORD64>(&number_of_bytes)))))
		{
			if (lpNumberOfBytesRead)
				*lpNumberOfBytesRead = static_cast<SIZE_T>(number_of_bytes);

			return TRUE;
		}
	}

	return FALSE;
}

BOOL x64_WriteProcessMemory(HANDLE hProcess, DWORD64 lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten)
{
	static DWORD64 _NtWriteVirtualMemory = 0;

	if (!_NtWriteVirtualMemory)
		_NtWriteVirtualMemory = x64_GetProcAddress(x64_GetBaseModule(), "NtWriteVirtualMemory");

	if (_NtWriteVirtualMemory)
	{
		DWORD64 number_of_bytes = lpNumberOfBytesWritten ? *lpNumberOfBytesWritten : 0;

		if (NT_SUCCESS(x64_SetLastError(x64_call(_NtWriteVirtualMemory, 5, reinterpret_cast<DWORD64>(hProcess), lpBaseAddress, reinterpret_cast<DWORD64>(lpBuffer), static_cast<DWORD64>(nSize), reinterpret_cast<DWORD64>(&number_of_bytes)))))
		{
			if (lpNumberOfBytesWritten)
				*lpNumberOfBytesWritten = static_cast<SIZE_T>(number_of_bytes);

			return TRUE;
		}
	}

	return FALSE;
}

} // namespace black