// Copyright (C) 2010-2015 Joshua Boyce
// See the file COPYING for copying permission.

#pragma once

#include <string>

#include <windows.h>

#include <hadesmem/detail/assert.hpp>
#include <hadesmem/detail/smart_handle.hpp>
#include <hadesmem/error.hpp>

namespace hadesmem
{
namespace detail
{
inline WORD GetMachineTypeFromFile(std::wstring const& path)
{
  // Open file for reading so we can examine its headers.
  HANDLE const file = ::CreateFileW(path.c_str(),
                                    GENERIC_READ,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE |
                                      FILE_SHARE_DELETE,
                                    nullptr,
                                    OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL,
                                    nullptr);
  if (file == INVALID_HANDLE_VALUE)
  {
    DWORD const last_error = ::GetLastError();
    HADESMEM_DETAIL_THROW_EXCEPTION(
      Error{} << ErrorString{"CreateFileW failed."}
              << ErrorCodeWinLast{last_error});
  }

  detail::SmartHandle const file_handle{file};

  detail::SmartHandle const mapping{
    ::CreateFileMappingW(file_handle.GetHandle(),
                         nullptr,
                         PAGE_READONLY,
                         0,
                         0,
                         nullptr)};
  if (!mapping.IsValid())
  {
    DWORD const last_error = ::GetLastError();
    HADESMEM_DETAIL_THROW_EXCEPTION(
      Error{} << ErrorString{"CreateFileMappingW failed."}
              << ErrorCodeWinLast{last_error});
  }

  PVOID view = ::MapViewOfFile(mapping.GetHandle(), FILE_MAP_READ, 0, 0, 0);
  if (!view)
  {
    DWORD const last_error = ::GetLastError();
    HADESMEM_DETAIL_THROW_EXCEPTION(
      Error{} << ErrorString{"MapViewOfFile failed."}
              << ErrorCodeWinLast{last_error});
  }

  // Make sure we unmap the view before returning.
  struct ViewUnmapper
  {
    PVOID view_;
    ~ViewUnmapper() noexcept
    {
      if (view_)
      {
        ::UnmapViewOfFile(view_);
      }
    }
  } unmapper{view};

  auto const dos = reinterpret_cast<IMAGE_DOS_HEADER const*>(view);
  if (dos->e_magic != IMAGE_DOS_SIGNATURE)
  {
    HADESMEM_DETAIL_THROW_EXCEPTION(
      Error{} << ErrorString{"Invalid DOS header."});
  }

  auto const nt_hdrs =
    reinterpret_cast<IMAGE_NT_HEADERS const*>(
      static_cast<std::uint8_t const*>(view) + dos->e_lfanew);
  if (nt_hdrs->Signature != IMAGE_NT_SIGNATURE)
  {
    HADESMEM_DETAIL_THROW_EXCEPTION(
      Error{} << ErrorString{"Invalid NT headers."});
  }

  return nt_hdrs->FileHeader.Machine;
}

inline bool IsFile64Bit(std::wstring const& path)
{
  WORD const machine = GetMachineTypeFromFile(path);
  return machine == IMAGE_FILE_MACHINE_AMD64 ||
         machine == IMAGE_FILE_MACHINE_IA64;
}

inline bool IsProcess64Bit(Process const& process)
{
#ifdef _WIN64
  // 64-bit build: process is 64-bit if it is not running under WoW64.
  return !detail::IsWoW64Process(process.GetHandle());
#else
  // 32-bit build: we currently never support manipulating a 64-bit process, so
  // any Process object we have must be 32-bit.
  (void)process;
  return false;
#endif
}

} // namespace detail
} // namespace hadesmem
