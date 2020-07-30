#pragma once

#include <Windows.h>

#include <functional>
#include <string>

namespace black {
namespace detours {

bool redirect(bool enable, void** function, void* hook);
bool redirect_x64(std::wstring const& module_name, std::initializer_list<std::string> target_apis);

} // namespace detours
} // namespace black