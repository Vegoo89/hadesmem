// Copyright (C) 2010-2015 Joshua Boyce
// See the file COPYING for copying permission.

#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <utility>
#include <vector>

#include <windows.h>

#include <hadesmem/alloc.hpp>
#include <hadesmem/call.hpp>
#include <hadesmem/config.hpp>
#include <hadesmem/detail/argv_quote.hpp>
#include <hadesmem/detail/assert.hpp>
#include <hadesmem/detail/environment_variable.hpp>
#include <hadesmem/detail/filesystem.hpp>
#include <hadesmem/detail/force_initialize.hpp>
#include <hadesmem/detail/self_path.hpp>
#include <hadesmem/detail/static_assert.hpp>
#include <hadesmem/detail/smart_handle.hpp>
#include <hadesmem/detail/trace.hpp>
#include <hadesmem/error.hpp>
#include <hadesmem/find_procedure.hpp>
#include <hadesmem/module.hpp>
#include <hadesmem/process.hpp>
#include <hadesmem/write.hpp>
#include <hadesmem/detail/pe_utils.hpp>

// TODO: IAT based injection. Required to allow injection before DllMain etc. of
// other moudles are executed. Include support for .NET target processes.
// Important because some obfuscated games have anti-debug etc. tricks hidden in
// the DllMain of a static import.

// TODO: .NET injection (without DLL dependency if possible).

// TODO: Add manual mapping support again.

// TODO: IME injection. https://github.com/dwendt/UniversalInject

// TODO: SetWindowsHookEx based injction. Useful for bypassing
// ObRegistercallbacks based protections?

namespace hadesmem
{
namespace detail
{
class SteamEnvironmentVariable
{
public:
  explicit SteamEnvironmentVariable(std::wstring const& name,
                                    std::uint32_t app_id)
    : name_(name), app_id_{app_id}
  {
    if (!app_id_)
    {
      return;
    }

    old_value_ = ReadEnvironmentVariable(name);

    auto const app_id_str = detail::NumToStr<wchar_t>(app_id_);
    WriteEnvironmentVariable(name_, app_id_str.c_str());
  }

  ~SteamEnvironmentVariable()
  {
    if (!app_id_)
    {
      return;
    }

    try
    {
      WriteEnvironmentVariable(
        name_, old_value_.first ? old_value_.second.data() : nullptr);
    }
    catch (...)
    {
      HADESMEM_DETAIL_TRACE_A(
        boost::current_exception_diagnostic_information().c_str());
      HADESMEM_DETAIL_ASSERT(false);
    }
  }

private:
  SteamEnvironmentVariable(SteamEnvironmentVariable const&) = delete;
  SteamEnvironmentVariable& operator=(SteamEnvironmentVariable const&) = delete;

  std::wstring name_{};
  std::uint32_t app_id_{};
  std::pair<bool, std::vector<wchar_t>> old_value_{};
};
}

// TODO: Type safety.
struct InjectFlags
{
  enum : std::uint32_t
  {
    kNone = 0,
    kPathResolution = 1 << 0,
    kAddToSearchOrder = 1 << 1,
    kKeepSuspended = 1 << 2,
    kManualMap = 1 << 3,              // perform reflective/manual mapping
    kNoRemoteEntry = 1 << 4,          // do not call entry point after mapping
    kInvalidFlagMaxValue = 1 << 5
  };
};

//------------------------------------------------------------------------------
// Manual mapping
//
// `ManualMapDll` implements a full reflective/manual loader for a DLL.  It
// reads the file locally, allocates memory in the remote process, copies the
// headers and sections, applies base relocations, resolves imports by calling
// the target's LoadLibrary/GetProcAddress, runs any TLS callbacks, and
// finally invokes the DLL's entry point (unless the caller specifies
// `InjectFlags::kNoRemoteEntry`).
//
// This is the technique required when the target process has hooked the
// normal loader APIs (LoadLibrary/LdrLoadDll) in order to prevent ordinary
// injection.  You can either call `ManualMapDll` directly or supply the
// `InjectFlags::kManualMap` bit to `InjectDll`, which will forward to this
// implementation.
//------------------------------------------------------------------------------

inline HMODULE ManualMapDll(Process const& process,
                            std::wstring const& path,
                            std::uint32_t flags)
{
  HADESMEM_DETAIL_ASSERT(!(flags & ~(InjectFlags::kInvalidFlagMaxValue - 1UL)));

  bool const path_resolution = !!(flags & InjectFlags::kPathResolution);

  // replicate resolution logic from InjectDll
  std::wstring const path_real = [&]() -> std::wstring
  {
    if (path_resolution && detail::IsPathRelative(path))
    {
      return detail::CombinePath(detail::GetSelfDirPath(), path);
    }

    return path;
  }();

  bool const add_path = !!(flags & InjectFlags::kAddToSearchOrder);
  if (add_path && detail::IsPathRelative(path_real))
  {
    HADESMEM_DETAIL_THROW_EXCEPTION(
      Error() << ErrorString("Cannot modify search order unless an absolute "
                             "path or path resolution is used."));
  }

  // make sure file exists (we need its contents locally for mapping)
  if (!detail::DoesFileExist(path_real))
  {
    HADESMEM_DETAIL_THROW_EXCEPTION(
      Error{} << ErrorString{"Could not find module file."});
  }

  // simple architecture sanity check (same as in InjectDll)
  try
  {
    bool const file64 = detail::IsFile64Bit(path_real);
    bool const proc64 = detail::IsProcess64Bit(process);
    if (file64 != proc64)
    {
      std::string arch_err = "Module architecture does not match target ";
      arch_err += proc64 ? "process (process is 64-bit)" :
                           "process (process is 32-bit)";
      arch_err += ": ";
      arch_err += file64 ? "DLL is 64-bit" : "DLL is 32-bit";
      arch_err += ".";
      HADESMEM_DETAIL_THROW_EXCEPTION(
        Error{} << ErrorString{arch_err});
    }
  }
  catch (...){}

  // read file contents entirely
  std::vector<std::uint8_t> file_data;
  {
    std::ifstream file(path_real, std::ios::binary | std::ios::ate);
    if (!file)
    {
      HADESMEM_DETAIL_THROW_EXCEPTION(
        Error{} << ErrorString{"Failed to open module file."});
    }
    std::streamsize sz = file.tellg();
    if (sz <= 0)
    {
      HADESMEM_DETAIL_THROW_EXCEPTION(
        Error{} << ErrorString{"Module file is empty."});
    }
    file_data.resize(static_cast<std::size_t>(sz));
    file.seekg(0);
    file.read(reinterpret_cast<char*>(file_data.data()), sz);
    if (!file)
    {
      HADESMEM_DETAIL_THROW_EXCEPTION(
        Error{} << ErrorString{"Failed to read module file."});
    }
  }

  // PE header helpers
  auto const dos = reinterpret_cast<IMAGE_DOS_HEADER const*>(file_data.data());
  if (dos->e_magic != IMAGE_DOS_SIGNATURE)
  {
    HADESMEM_DETAIL_THROW_EXCEPTION(
      Error{} << ErrorString{"Invalid DOS header."});
  }

  auto const nt_hdrs =
    reinterpret_cast<IMAGE_NT_HEADERS const*>(file_data.data() + dos->e_lfanew);
  if (nt_hdrs->Signature != IMAGE_NT_SIGNATURE)
  {
    HADESMEM_DETAIL_THROW_EXCEPTION(
      Error{} << ErrorString{"Invalid NT headers."});
  }

  WORD const num_sections = nt_hdrs->FileHeader.NumberOfSections;
  auto const sections = IMAGE_FIRST_SECTION(nt_hdrs);

  auto rva_to_ptr = [&](DWORD rva) -> std::uint8_t*
  {
    // headers region
    if (rva < nt_hdrs->OptionalHeader.SizeOfHeaders)
    {
      return file_data.data() + rva;
    }

    for (WORD i = 0; i < num_sections; ++i)
    {
      DWORD const va = sections[i].VirtualAddress;
      DWORD const size = (std::max)(sections[i].SizeOfRawData,
                                 sections[i].Misc.VirtualSize);
      if (rva >= va && rva < va + size)
      {
        return file_data.data() + sections[i].PointerToRawData + (rva - va);
      }
    }

    HADESMEM_DETAIL_THROW_EXCEPTION(
      Error{} << ErrorString{"RVA out of bounds."});
  };

  // allocate remote region for entire image
  SIZE_T const image_size = nt_hdrs->OptionalHeader.SizeOfImage;
  Allocator const remote{process, image_size};

  // copy headers
  SIZE_T const headers_size = nt_hdrs->OptionalHeader.SizeOfHeaders;
  Write(process, remote.GetBase(), file_data.data(), headers_size);

  // copy sections
  for (WORD i = 0; i < num_sections; ++i)
  {
    auto const& sec = sections[i];
    if (!sec.SizeOfRawData)
    {
      continue;
    }
    Write(process,
          reinterpret_cast<std::uint8_t*>(remote.GetBase()) + sec.VirtualAddress,
          file_data.data() + sec.PointerToRawData,
          sec.SizeOfRawData);
  }

  // perform base relocations
  DWORD_PTR const base_delta =
    reinterpret_cast<DWORD_PTR>(remote.GetBase()) -
    static_cast<DWORD_PTR>(nt_hdrs->OptionalHeader.ImageBase);
  if (base_delta)
  {
    auto const& reloc_dir =
      nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (reloc_dir.Size)
    {
      std::uint8_t* reloc_ptr = rva_to_ptr(reloc_dir.VirtualAddress);
      std::uint8_t* const reloc_end = reloc_ptr + reloc_dir.Size;
      while (reloc_ptr < reloc_end)
      {
        auto const block =
          reinterpret_cast<IMAGE_BASE_RELOCATION const*>(reloc_ptr);
        DWORD const block_va = block->VirtualAddress;
        DWORD const block_size = block->SizeOfBlock;
        std::uint16_t* const entries =
          reinterpret_cast<std::uint16_t*>(reloc_ptr + sizeof(IMAGE_BASE_RELOCATION));
        int const count =
          static_cast<int>((block_size - sizeof(IMAGE_BASE_RELOCATION)) /
                           sizeof(std::uint16_t));
        for (int j = 0; j < count; ++j)
        {
          std::uint16_t const entry = entries[j];
          DWORD const type = entry >> 12;
          DWORD const offset = entry & 0x0FFF;
          if (type == IMAGE_REL_BASED_HIGHLOW && sizeof(void*) == 4)
          {
            std::uint32_t original;
            std::memcpy(&original,
                        rva_to_ptr(block_va + offset),
                        sizeof(original));
            original += static_cast<std::uint32_t>(base_delta);
            Write(process,
                  reinterpret_cast<std::uint8_t*>(remote.GetBase()) +
                    block_va + offset,
                  original);
          }
          else if (type == IMAGE_REL_BASED_DIR64 && sizeof(void*) == 8)
          {
            std::uint64_t original;
            std::memcpy(&original,
                        rva_to_ptr(block_va + offset),
                        sizeof(original));
            original += static_cast<std::uint64_t>(base_delta);
            Write(process,
                  reinterpret_cast<std::uint8_t*>(remote.GetBase()) +
                    block_va + offset,
                  original);
          }
        }

        reloc_ptr += block_size;
      }
    }
  }

  // resolve imports
  auto const& import_dir =
    nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  if (import_dir.Size)
  {
    auto import_desc =
      reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
        rva_to_ptr(import_dir.VirtualAddress));
    Module const kernel32_mod{process, L"kernel32.dll"};
    auto const load_library_a =
      FindProcedure(process, kernel32_mod, "LoadLibraryA");
    auto const get_proc_address =
      FindProcedure(process, kernel32_mod, "GetProcAddress");

    for (; import_desc->Name; ++import_desc)
    {
      char const* dll_name =
        reinterpret_cast<char*>(rva_to_ptr(import_desc->Name));
      Allocator const dll_remote{process, std::strlen(dll_name) + 1};
      WriteString(process, dll_remote.GetBase(), dll_name);
      auto const lib_handle_ret =
        Call(process,
             reinterpret_cast<decltype(&LoadLibraryA)>(load_library_a),
             CallConv::kStdCall,
             static_cast<LPCSTR>(dll_remote.GetBase()));
      HMODULE const lib_handle =
        reinterpret_cast<HMODULE>(lib_handle_ret.GetReturnValue());
      if (!lib_handle)
      {
        HADESMEM_DETAIL_THROW_EXCEPTION(
          Error{} << ErrorString{"LoadLibraryA failed during manual map."}
                  << ErrorCodeWinLast{lib_handle_ret.GetLastError()});
      }

      // iterate thunks
      IMAGE_THUNK_DATA* thunk =
        reinterpret_cast<IMAGE_THUNK_DATA*>(
          rva_to_ptr(import_desc->FirstThunk));
      IMAGE_THUNK_DATA* orig =
        reinterpret_cast<IMAGE_THUNK_DATA*>(
          rva_to_ptr(import_desc->OriginalFirstThunk
                     ? import_desc->OriginalFirstThunk
                     : import_desc->FirstThunk));
      for (; orig->u1.AddressOfData; ++orig, ++thunk)
      {
        DWORD_PTR func_addr = 0;
        if (orig->u1.Ordinal & IMAGE_ORDINAL_FLAG)
        {
          WORD ord = IMAGE_ORDINAL(orig->u1.Ordinal);
          auto const proc_ret =
            Call(process,
                 reinterpret_cast<decltype(&GetProcAddress)>(
                   get_proc_address),
                 CallConv::kStdCall,
                 lib_handle,
                 MAKEINTRESOURCEA(ord));
          func_addr = reinterpret_cast<DWORD_PTR>(proc_ret.GetReturnValue());
        }
        else
        {
          auto const ibn =
            reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
              rva_to_ptr(orig->u1.AddressOfData));
          char const* fn_name = reinterpret_cast<char*>(ibn->Name);
          Allocator const fn_remote{process, std::strlen(fn_name) + 1};
          WriteString(process, fn_remote.GetBase(), fn_name);
          auto const proc_ret =
            Call(process,
                 reinterpret_cast<decltype(&GetProcAddress)>(
                   get_proc_address),
                 CallConv::kStdCall,
                 lib_handle,
                 static_cast<LPCSTR>(fn_remote.GetBase()));
          func_addr = reinterpret_cast<DWORD_PTR>(proc_ret.GetReturnValue());
        }

        if (!func_addr)
        {
          DWORD const last_err = orig->u1.Ordinal & IMAGE_ORDINAL_FLAG
                                   ? ERROR_INVALID_ORDINAL
                                   : ::GetLastError();
          HADESMEM_DETAIL_THROW_EXCEPTION(
            Error{} << ErrorString{"GetProcAddress failed during manual map."}
                    << ErrorCodeWinLast{last_err});
        }

        DWORD const rva =
          static_cast<DWORD>(
            reinterpret_cast<std::uint8_t*>(thunk) - file_data.data());
        Write(process,
              reinterpret_cast<std::uint8_t*>(remote.GetBase()) + rva,
              func_addr);
      }
    }
  }

  // call TLS callbacks if present
  auto const& tls_dir =
    nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
  if (tls_dir.Size)
  {
    auto const tls =
      reinterpret_cast<IMAGE_TLS_DIRECTORY const*>(
        rva_to_ptr(tls_dir.VirtualAddress));
    auto callbacks =
      reinterpret_cast<PDWORD_PTR>(tls->AddressOfCallBacks);
    if (callbacks)
    {
      // TLS callbacks are defined as: void CALLBACK Callback(PVOID DllHandle,
      //                                         DWORD Reason,
      //                                         PVOID Reserved);
      using TlsCallbackFn = void(WINAPI*)(PVOID, DWORD, PVOID);

      for (; *callbacks; ++callbacks)
      {
        auto const cb_addr = reinterpret_cast<TlsCallbackFn>(
          *callbacks + reinterpret_cast<DWORD_PTR>(remote.GetBase()) -
          nt_hdrs->OptionalHeader.ImageBase);
        // return value is ignored
        Call(process,
             cb_addr,
             CallConv::kStdCall,
             reinterpret_cast<PVOID>(remote.GetBase()),
             DLL_PROCESS_ATTACH,
             static_cast<PVOID>(nullptr));
      }
    }
  }

  // call entry point unless user asked us not to
  if (!(flags & InjectFlags::kNoRemoteEntry))
  {
    DWORD const entry_rva = nt_hdrs->OptionalHeader.AddressOfEntryPoint;
    if (entry_rva)
    {
      using DllMainFn = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);

      auto const entry_addr =
        reinterpret_cast<DllMainFn>(
          reinterpret_cast<std::uint8_t*>(remote.GetBase()) + entry_rva);
      auto const entry_ret =
        Call(process,
             entry_addr,
             CallConv::kStdCall,
             reinterpret_cast<HINSTANCE>(remote.GetBase()),
             DLL_PROCESS_ATTACH,
             static_cast<LPVOID>(nullptr));
      if (!entry_ret.GetReturnValue())
      {
        HADESMEM_DETAIL_THROW_EXCEPTION(
          Error{} << ErrorString{"DllMain returned FALSE."}
                  << ErrorCodeWinLast{entry_ret.GetLastError()});
      }
    }
  }

  return reinterpret_cast<HMODULE>(remote.GetBase());
}

inline HMODULE InjectDll(Process const& process,
                         std::wstring const& path,
                         std::uint32_t flags)
{
  HADESMEM_DETAIL_ASSERT(!(flags & ~(InjectFlags::kInvalidFlagMaxValue - 1UL)));

  bool const path_resolution = !!(flags & InjectFlags::kPathResolution);

  std::wstring const path_real = [&]() -> std::wstring
  {
    if (path_resolution && detail::IsPathRelative(path))
    {
      return detail::CombinePath(detail::GetSelfDirPath(), path);
    }

    return path;
  }();

  bool const add_path = !!(flags & InjectFlags::kAddToSearchOrder);
  if (add_path && detail::IsPathRelative(path_real))
  {
    HADESMEM_DETAIL_THROW_EXCEPTION(
      Error() << ErrorString("Cannot modify search order unless an absolute "
                             "path or path resolution is used."));
  }

  // If the file exists locally perform a quick sanity check to ensure the
  // module's machine type matches the target process.  This detects the
  // common "wrong bitness" mistake which otherwise results in a very
  // unhelpful "LoadLibraryExW failed (remote GetLastError returned 0)".
  //
  // We intentionally don't make this a hard requirement when the file is
  // missing; LoadLibraryExW will report the error in that case.  Likewise we
  // don't attempt to validate the path when path resolution is disabled and the
  // caller gave a relative path because the remote process may resolve that
  // differently than we can locally.
  if (detail::DoesFileExist(path_real))
  {
    try
    {
      bool const file64 = detail::IsFile64Bit(path_real);
      bool const proc64 = detail::IsProcess64Bit(process);
      if (file64 != proc64)
      {
        std::string arch_err = "Module architecture does not match target ";
        arch_err += proc64 ? "process (process is 64-bit)" :
                             "process (process is 32-bit)";
        arch_err += ": ";
        arch_err += file64 ? "DLL is 64-bit" : "DLL is 32-bit";
        arch_err += ".";
        HADESMEM_DETAIL_THROW_EXCEPTION(
          Error{} << ErrorString{arch_err});
      }
    }
    catch (...) // if something goes wrong while probing just ignore it and
                // let the loader handle the error later.
    {
    }
  }

  // Only performing this check when path resolution is enabled
  // because otherwise we would need to perform the check in the
  // context of the remote process, which is not possible to do without
  // introducing race conditions and other potential problems. So we
  // just let LoadLibraryExW do the check for us.
  if (path_resolution && !detail::DoesFileExist(path_real))
  {
    HADESMEM_DETAIL_THROW_EXCEPTION(
      Error() << ErrorString("Could not find module file."));
  }

  // Manual map variant bypasses the kernel loader entirely.
  if (flags & InjectFlags::kManualMap)
  {
    return ManualMapDll(process, path_real, flags);
  }

  HADESMEM_DETAIL_TRACE_A("Calling ForceLdrInitializeThunk.");

  detail::ForceLdrInitializeThunk(process.GetId());

  HADESMEM_DETAIL_TRACE_FORMAT_W(L"Module path is \"%s\".", path_real.c_str());

  std::size_t const path_buf_size = (path_real.size() + 1) * sizeof(wchar_t);

  HADESMEM_DETAIL_TRACE_A("Allocating memory for module path.");

  Allocator const lib_file_remote{process, path_buf_size};

  HADESMEM_DETAIL_TRACE_A("Writing memory for module path.");

  WriteString(process, lib_file_remote.GetBase(), path_real);

  HADESMEM_DETAIL_TRACE_A("Finding LoadLibraryExW.");

  Module const kernel32_mod{process, L"kernel32.dll"};
  auto const load_library =
    FindProcedure(process, kernel32_mod, "LoadLibraryExW");

  HADESMEM_DETAIL_TRACE_A("Calling LoadLibraryExW.");

  auto const load_library_ret =
    Call(process,
         reinterpret_cast<decltype(&LoadLibraryExW)>(load_library),
         CallConv::kStdCall,
         static_cast<LPCWSTR>(lib_file_remote.GetBase()),
         __nullptr, // Can't use nullptr here because /clr...
         add_path ? LOAD_WITH_ALTERED_SEARCH_PATH : 0UL);

  if (!load_library_ret.GetReturnValue())
  {
    // Build a slightly more detailed message so users can diagnose
    // mysterious failures (remote GetLastError may be zero).
    std::string err_msg = "LoadLibraryExW failed";
    try
    {
      if (!path_real.empty())
      {
        bool lossy = false;
        auto path_str = detail::WideCharToMultiByte(path_real, &lossy);
        err_msg += ": ";
        err_msg += path_str;
        if (lossy)
        {
          err_msg += " (lossy conversion)";
        }
      }
    }
    catch (...) // conversion shouldn't throw, but be defensive
    {
    }

    auto const last_error = load_library_ret.GetLastError();
    if (last_error == 0)
    {
      err_msg += " (remote GetLastError returned 0)";
    }

    HADESMEM_DETAIL_THROW_EXCEPTION(
      Error{} << ErrorString{err_msg}
              << ErrorCodeWinLast{last_error});
  }

  return load_library_ret.GetReturnValue();
}

inline void FreeDll(Process const& process, HMODULE module)
{
  Module const kernel32_mod{process, L"kernel32.dll"};
  auto const free_library = FindProcedure(process, kernel32_mod, "FreeLibrary");

  auto const free_library_ret =
    Call(process,
         reinterpret_cast<decltype(&FreeLibrary)>(free_library),
         CallConv::kStdCall,
         module);
  if (!free_library_ret.GetReturnValue())
  {
    HADESMEM_DETAIL_THROW_EXCEPTION(
      Error{} << ErrorString{"FreeLibrary failed."}
              << ErrorCodeWinLast{free_library_ret.GetLastError()});
  }
}

// TODO: Support passing an arg to the export (e.g. a string).
inline CallResult<DWORD_PTR> CallExport(Process const& process,
                                        HMODULE module,
                                        std::string const& export_name)
{
  Module const module_remote{process, module};
  auto const export_ptr = FindProcedure(process, module_remote, export_name);

  return Call(
    process, reinterpret_cast<DWORD_PTR (*)()>(export_ptr), CallConv::kDefault);
}

class CreateAndInjectData
{
public:
  explicit CreateAndInjectData(Process const& process,
                               HMODULE module,
                               DWORD_PTR export_ret,
                               DWORD export_last_error,
                               detail::SmartHandle&& thread_handle)
    : process_{process},
      module_{module},
      export_ret_{export_ret},
      export_last_error_{export_last_error},
      thread_handle_{std::move(thread_handle)}
  {
  }

  explicit CreateAndInjectData(Process const&& process,
                               HMODULE module,
                               DWORD_PTR export_ret,
                               DWORD export_last_error,
                               detail::SmartHandle&& thread_handle) = delete;

  Process GetProcess() const
  {
    return process_;
  }

  HMODULE GetModule() const noexcept
  {
    return module_;
  }

  DWORD_PTR GetExportRet() const noexcept
  {
    return export_ret_;
  }

  DWORD GetExportLastError() const noexcept
  {
    return export_last_error_;
  }

  HANDLE GetThreadHandle() const noexcept
  {
    return thread_handle_.GetHandle();
  }

  void ResumeThread() const
  {
    if (::ResumeThread(thread_handle_.GetHandle()) == static_cast<DWORD>(-1))
    {
      DWORD const last_error = ::GetLastError();
      HADESMEM_DETAIL_THROW_EXCEPTION(Error{}
                                      << ErrorString{"ResumeThread failed."}
                                      << ErrorCodeWinLast{last_error});
    }
  }

private:
  Process process_;
  HMODULE module_;
  DWORD_PTR export_ret_;
  DWORD export_last_error_;
  detail::SmartHandle thread_handle_;
};

// TODO: Improve argument passing suppport for programs with complex command
// lines. E.g. Aion (from NCWest) requires a command line with embedded
// quotation marks which we don't correctly handle.
template <typename ArgsIter>
inline CreateAndInjectData CreateAndInject(std::wstring const& path,
                                           std::wstring const& work_dir,
                                           ArgsIter args_beg,
                                           ArgsIter args_end,
                                           std::wstring const& module,
                                           std::string const& export_name,
                                           std::uint32_t flags,
                                           std::uint32_t steam_app_id = 0)
{
  using ArgsIterValueType = typename std::iterator_traits<ArgsIter>::value_type;
  HADESMEM_DETAIL_STATIC_ASSERT(
    std::is_base_of<std::wstring, ArgsIterValueType>::value);

  std::wstring const command_line = [&]()
  {
    std::wstring command_line_temp;
    detail::ArgvQuote(&command_line_temp, path, false);
    auto const parse_arg = [&](std::wstring const& arg)
    {
      command_line_temp += L' ';
      detail::ArgvQuote(&command_line_temp, arg, false);
    };
    std::for_each(args_beg, args_end, parse_arg);
    return command_line_temp;
  }();

  std::vector<wchar_t> proc_args(std::begin(command_line),
                                 std::end(command_line));
  proc_args.push_back(L'\0');

  std::wstring const work_dir_real = [&]() -> std::wstring
  {
    if (work_dir.empty() && !path.empty() && !detail::IsPathRelative(path))
    {
      std::size_t const separator = path.find_last_of(L"\\/");
      if (separator != std::wstring::npos && separator != path.size() - 1)
      {
        return path.substr(0, separator + 1);
      }
    }

    return work_dir;
  }();

  // TODO: Make this thread-safe. If multiple injections occur simultaneously
  // from different threads the environment variables may trample each other
  // etc.
  detail::SteamEnvironmentVariable app_id(L"SteamAppId", steam_app_id);
  detail::SteamEnvironmentVariable game_id(L"SteamGameId", steam_app_id);

  STARTUPINFO start_info{};
  start_info.cb = static_cast<DWORD>(sizeof(start_info));
  PROCESS_INFORMATION proc_info{};
  if (!::CreateProcessW(path.c_str(),
                        proc_args.data(),
                        nullptr,
                        nullptr,
                        FALSE,
                        CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
                        nullptr,
                        work_dir_real.empty() ? nullptr : work_dir_real.c_str(),
                        &start_info,
                        &proc_info))
  {
    DWORD const last_error = ::GetLastError();
    HADESMEM_DETAIL_THROW_EXCEPTION(Error{}
                                    << ErrorString{"CreateProcess failed."}
                                    << ErrorCodeWinLast{last_error});
  }

  detail::SmartHandle const proc_handle{proc_info.hProcess};
  detail::SmartHandle thread_handle{proc_info.hThread};

  try
  {
    Process const process{proc_info.dwProcessId};

    HMODULE const remote_module = InjectDll(process, module, flags);

    CallResult<DWORD_PTR> const export_ret = [&]()
    {
      if (!export_name.empty())
      {
        return CallExport(process, remote_module, export_name);
      }

      return CallResult<DWORD_PTR>(0, 0);
    }();

    if (!(flags & InjectFlags::kKeepSuspended))
    {
      if (::ResumeThread(thread_handle.GetHandle()) == static_cast<DWORD>(-1))
      {
        DWORD const last_error = ::GetLastError();
        HADESMEM_DETAIL_THROW_EXCEPTION(
          Error{} << ErrorString{"ResumeThread failed."}
                  << ErrorCodeWinLast{last_error}
                  << ErrorCodeWinRet{export_ret.GetReturnValue()}
                  << ErrorCodeWinOther{export_ret.GetLastError()});
      }
    }

    return CreateAndInjectData{process,
                               remote_module,
                               export_ret.GetReturnValue(),
                               export_ret.GetLastError(),
                               std::move(thread_handle)};
  }
  catch (std::exception const& /*e*/)
  {
    // Terminate process if injection failed, otherwise the 'zombie' process
    // would be leaked.
    BOOL const terminated = ::TerminateProcess(proc_handle.GetHandle(), 0);
    (void)terminated;
    HADESMEM_DETAIL_ASSERT(terminated != FALSE);

    throw;
  }
}
}
