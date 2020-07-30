#include "utility.hpp"

namespace black {
namespace utility {

std::wstring ModifyModulePath(std::wstring const& module_path, std::size_t layers, std::wstring const& appendix)
{
	std::wstring result = module_path;

	for (std::size_t i = 0, position = 0; i < layers; i++)
	{
		if ((position = result.find_last_of(L'\\')) != std::string::npos)
			result = result.substr(0, position);
	}

	return result.append(appendix);
}

bool CompareSubstringW(std::wstring const& source, std::wstring const& target)
{
	return (lstrcmpiW(source.substr(0, target.size()).c_str(), target.c_str()) == 0);
}

bool CompareModuleNameA(std::string const& module_name, std::string const& target)
{
	return (lstrcmpiA(module_name.substr(module_name.find_last_of('\\') + 1).c_str(), target.c_str()) == 0);
}

bool CompareModuleNameW(std::wstring const& module_name, std::wstring const& target)
{
	return (lstrcmpiW(module_name.substr(module_name.find_last_of(L'\\') + 1).c_str(), target.c_str()) == 0);
}

void DisplayMessageBox(std::string const& message, std::string const& caption)
{
	MessageBoxA(NULL, message.c_str(), caption.c_str(), MB_OK | MB_ICONERROR | MB_TOPMOST | MB_SETFOREGROUND);
}

} // namespace utility
} // namespace black