#pragma once

#include <Windows.h>
#include <Winternl.h>
#include <string>

namespace black {

typedef enum _SECTION_INHERIT
{
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT;

DWORD64 x64_GetModuleHandleW(std::wstring const& lpModuleName);
DWORD64 x64_GetBaseModule();

DWORD64 x64_SetLastError(DWORD64 status);
DWORD64 x64_GetProcAddress(DWORD64 hModule, std::string const& lpProcName);
DWORD64 x64_LdrLoadDll(std::wstring const& lpLibFileName);
DWORD64 x64_LdrGetKnownDllSectionHandle(std::wstring const& lpKnownDllName, BOOL bIs32BitSection);
BOOL x64_NtMapViewOfSection(HANDLE hSection, HANDLE hProcess, DWORD64* lpBaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset,	PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
BOOL x64_NtUnmapViewOfSection(HANDLE hProcess, DWORD64 lpBaseAddress);
DWORD64 x64_VirtualAllocEx(HANDLE hProcess, DWORD64 lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
BOOL x64_VirtualFreeEx(HANDLE hProcess, DWORD64 lpAddress, SIZE_T dwSize, DWORD dwFreeType);
BOOL x64_VirtualProtectEx(HANDLE hProcess, DWORD64 lpAddress, SIZE_T dwSize, DWORD flNewProtect, DWORD* lpflOldProtect);
SIZE_T x64_VirtualQueryEx(HANDLE hProcess, DWORD64 lpAddress, MEMORY_BASIC_INFORMATION64* lpBuffer, SIZE_T dwLength);
BOOL x64_ReadProcessMemory(HANDLE hProcess, DWORD64 lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead);
BOOL x64_WriteProcessMemory(HANDLE hProcess, DWORD64 lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);

} // namespace black