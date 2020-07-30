#pragma once

#include <Windows.h>
#include <string>

namespace black {
namespace utility {

std::wstring ModifyModulePath(std::wstring const& module_path, std::size_t layers, std::wstring const& appendix);

bool CompareSubstringW(std::wstring const& source, std::wstring const& target);

bool CompareModuleNameA(std::string const& module_name, std::string const& target);
bool CompareModuleNameW(std::wstring const& module_name, std::wstring const& target);

void DisplayMessageBox(std::string const& message, std::string const& caption);

} // namespace utility
} // namespace black