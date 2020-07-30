#include "exports.hpp"
#include "detour.hpp"
#include "utility.hpp"

#include <ShlObj.h>
#include <strsafe.h>

namespace exports {

FARPROC MiniDumpReadDumpStream = nullptr;

void __declspec(naked) MiniDumpReadDumpStream_trampoline()
{
	__asm jmp dword ptr[MiniDumpReadDumpStream]
}

FARPROC MiniDumpWriteDump = nullptr;

void __declspec(naked) MiniDumpWriteDump_trampoline()
{
	__asm jmp dword ptr[MiniDumpWriteDump]
}

bool setup(HMODULE module)
{
	char file_path[MAX_PATH];
	memset(file_path, 0, sizeof(file_path));

	if (FAILED(SHGetFolderPathA(NULL, CSIDL_SYSTEM, NULL, 0, file_path)))
	{
		black::utility::DisplayMessageBox("Failed to fetch system folder path.", "NGSThreat");
		return false;
	}

	if (FAILED(StringCchPrintfA(file_path, MAX_PATH, "%s%s", file_path, "\\dbgcore.dll")))
	{
		black::utility::DisplayMessageBox("Failed to generate dbgcore loading string.", "NGSThreat");
		return false;
	}

	HMODULE dbgcore = LoadLibraryA(file_path);

	if (!dbgcore)
	{
		black::utility::DisplayMessageBox("Failed to load library \"dbgcore.dll\".", "NGSThreat");
		return false;
	}

	MiniDumpReadDumpStream = GetProcAddress(dbgcore, reinterpret_cast<LPCSTR>(1));
	MiniDumpWriteDump = GetProcAddress(dbgcore, reinterpret_cast<LPCSTR>(2));

	if (MiniDumpReadDumpStream == nullptr || MiniDumpWriteDump == nullptr)
	{
		black::utility::DisplayMessageBox("Failed to load imports from \"dbgcore.dll\".", "NGSThreat");
		return false;
	}

	return true;
}

} // namespace exports