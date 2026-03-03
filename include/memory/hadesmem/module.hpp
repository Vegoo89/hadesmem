// Copyright (C) 2010-2015 Joshua Boyce
// See the file COPYING for copying permission.

#pragma once

#include <cstddef>
#include <cstring>
#include <functional>
#include <ostream>
#include <string>
#include <utility>

#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>  // NT structures for PEB enumeration
#include <hadesmem/read.hpp>

#include <hadesmem/config.hpp>
#include <hadesmem/detail/assert.hpp>
#include <hadesmem/detail/filesystem.hpp>
#include <hadesmem/detail/smart_handle.hpp>
#include <hadesmem/detail/toolhelp.hpp>
#include <hadesmem/detail/to_upper_ordinal.hpp>
#include <hadesmem/error.hpp>
#include <hadesmem/process.hpp>

namespace hadesmem
{
class Module
{
public:
  explicit Module(Process const& process, HMODULE handle) : process_{&process}
  {
    Initialize(handle);
  }

  explicit Module(Process const& process, std::wstring const& path)
    : process_{&process}
  {
    Initialize(path);
  }

  HMODULE GetHandle() const noexcept
  {
    return handle_;
  }

  DWORD GetSize() const noexcept
  {
    return size_;
  }

  std::wstring GetName() const
  {
    return name_;
  }

  std::wstring GetPath() const
  {
    return path_;
  }

private:
  template <typename ModuleT> friend class ModuleIterator;

  using EntryCallback = std::function<bool(MODULEENTRY32W const&)>;

  explicit Module(Process const& process, MODULEENTRY32W const& entry)
    : process_(&process), handle_(nullptr), size_(0), name_(), path_()
  {
    Initialize(entry);
  }

  void Initialize(HMODULE handle)
  {
    auto const handle_check = [&](MODULEENTRY32W const& entry) -> bool {
      return (reinterpret_cast<HMODULE>(entry.modBaseAddr) == handle ||
              !handle);
    };

    InitializeIf(handle_check);
  }

  void Initialize(std::wstring const& path)
  {
    bool const is_path = (path.find_first_of(L"\\/") != std::wstring::npos);

    std::wstring const path_upper = detail::ToUpperOrdinal(path);

    auto const path_check = [&](MODULEENTRY32W const& entry) -> bool {
      return is_path ? (detail::ArePathsEquivalent(path, entry.szExePath))
                     : (path_upper == detail::ToUpperOrdinal(entry.szModule));
    };

    InitializeIf(path_check);
  }

  void Initialize(MODULEENTRY32W const& entry)
  {
    handle_ = reinterpret_cast<HMODULE>(entry.modBaseAddr);
    size_ = entry.modBaseSize;
    name_ = entry.szModule;
    path_ = entry.szExePath;
  }

  void InitializeIf(EntryCallback const& check_func)
  {
    // Attempt toolhelp snapshot first.  If the snapshot handle is invalid
    // due to protection (ERROR_PARTIAL_COPY), fall back to reading the PEB
    // manually.  We also treat the case where snapshot succeeds but enumeration
    // returns no matching entry by falling back afterwards.
    bool need_peb = false;
    detail::SmartSnapHandle snap;
    try
    {
      snap = detail::CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_->GetId());
    }
    catch (Error const& e)
    {
      if (e.GetErrorData<ErrorCodeWinLast>()->GetCode() == ERROR_PARTIAL_COPY)
      {
        need_peb = true;
      }
      else
      {
        throw;
      }
    }

    if (snap.IsValid())
    {
      hadesmem::detail::Optional<MODULEENTRY32W> entry;
      for (entry = detail::Module32First(snap.GetHandle()); entry;
           entry = detail::Module32Next(snap.GetHandle()))
      {
        if (check_func(*entry))
        {
          Initialize(*entry);
          return;
        }
      }
      // enumeration completed but no match
      need_peb = true;
    }

    if (need_peb)
    {
      // We don't know whether the original check was comparing by path or by
      // handle; the caller might have wrapped that.  Instead we simply iterate
      // the PEB list ourselves and look for an entry that satisfies the
      // predicate, using a small adapter.
      // Build a wrapper predicate that transforms MODULEENTRY32W and calls
      // the user's predicate.
      auto const peb_check = [&](MODULEENTRY32W const& entry) -> bool {
        return check_func(entry);
      };

      hadesmem::detail::Optional<MODULEENTRY32W> peb_entry;
      try
      {
        // we can't easily know if the original check was path-based, so the
        // PEB helper performs both name and path matches.  to simplify we
        // re-run the snapshot logic using the same check_func but drive it
        // with entries produced by PEB.
        // to get entries from PEB we can call the new function repeatedly but
        // it only returns one match; instead just replicate its iteration
        // here (reuse the helper) – but for simplicity just call the
        // underlying helper if there was an explicit path or name we can
        // extract from check_func; that's complicated.  easier: we cheat by
        // using the PEB helper directly below.
        // (we could also add a more generic enum function; leaving for later)
      }
      catch (...)
      {
      }
      
      // simpler: use GetModuleEntryFromPeb for both path and non-path
      // attempts.  the helper already takes name + bool path.  unfortunately
      // we don't know those values.  instead we can repeat the user check by
      // enumerating all modules and applying the predicate ourselves.
      
      // enumerate via PEB manually:
      PEB64 peb;
      // The code from GetModuleEntryFromPeb above could be refactored here to
      // provide full enumeration.  to avoid duplication, we will implement a
      // tiny local lambda that iterates and invokes check_func.
      auto enum_peb = [&]() -> hadesmem::detail::Optional<MODULEENTRY32W> {
        // reimplement minimal PEB walk from GetModuleEntryFromPeb
        struct UNICODE_STRING64 { USHORT Length; USHORT MaximumLength; ULONG_PTR Buffer; };
        struct LIST_ENTRY64 { ULONG_PTR Flink; ULONG_PTR Blink; };
        struct LDR_DATA_TABLE_ENTRY64 {
          LIST_ENTRY64 InLoadOrderLinks;
          LIST_ENTRY64 InMemoryOrderLinks;
          LIST_ENTRY64 InInitializationOrderLinks;
          ULONG_PTR DllBase;
          ULONG_PTR EntryPoint;
          ULONG SizeOfImage;
          UNICODE_STRING64 FullDllName;
          UNICODE_STRING64 BaseDllName;
        };
        struct PEB_LDR_DATA64 { ULONG Length; BOOLEAN Initialized; ULONG_PTR SsHandle; LIST_ENTRY64 InLoadOrderModuleList; };
        struct PEB64 { BYTE Reserved1[2]; BYTE BeingDebugged; BYTE Reserved2[1]; ULONG_PTR Reserved3[2]; ULONG_PTR Ldr; };
        
        using NtQueryInformationProcessFn = NTSTATUS(WINAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        static NtQueryInformationProcessFn ntq = nullptr;
        if (!ntq)
        {
          ntq = reinterpret_cast<NtQueryInformationProcessFn>(
            ::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"),
                              "NtQueryInformationProcess"));
        }
        PROCESS_BASIC_INFORMATION pbi{};
        ntq(process_->GetHandle(), 0, &pbi, sizeof(pbi), nullptr);
        Read(*process_, pbi.PebBaseAddress, peb);
        PEB_LDR_DATA64 ldr;
        Read(*process_, peb.Ldr, ldr);
        ULONG_PTR head = reinterpret_cast<ULONG_PTR>(peb.Ldr) +
                         offsetof(PEB_LDR_DATA64, InLoadOrderModuleList);
        ULONG_PTR curr = ldr.InLoadOrderModuleList.Flink;
        while (curr && curr != head)
        {
          LDR_DATA_TABLE_ENTRY64 ent;
          Read(*process_, curr - offsetof(LDR_DATA_TABLE_ENTRY64, InLoadOrderLinks), ent);
          MODULEENTRY32W result{};
          result.dwSize = sizeof(result);
          result.modBaseAddr = reinterpret_cast<BYTE*>(ent.DllBase);
          result.modBaseSize = ent.SizeOfImage;
          auto readString = [&](UNICODE_STRING64 const& us) {
            std::wstring s;
            if (us.Buffer && us.Length)
            {
              s.resize(us.Length / sizeof(wchar_t));
              Read(*process_, reinterpret_cast<void*>(us.Buffer), &s[0], us.Length);
            }
            return s;
          };
          std::wstring full = readString(ent.FullDllName);
          std::wstring base = readString(ent.BaseDllName);
          wcsncpy_s(result.szExePath, full.c_str(), _TRUNCATE);
          wcsncpy_s(result.szModule, base.c_str(), _TRUNCATE);
          if (check_func(result))
          {
            return result;
          }
          curr = ent.InLoadOrderLinks.Flink;
        }
        return hadesmem::detail::Optional<MODULEENTRY32W>();
      };

      auto peb_res = enum_peb();
      if (peb_res)
      {
        Initialize(*peb_res);
        return;
      }
    }

    HADESMEM_DETAIL_THROW_EXCEPTION(Error{}
                                    << ErrorString{"Could not find module."});
  }

  Process const* process_;
  HMODULE handle_{nullptr};
  DWORD size_{0UL};
  std::wstring name_;
  std::wstring path_;
};

inline bool operator==(Module const& lhs, Module const& rhs) noexcept
{
  return lhs.GetHandle() == rhs.GetHandle();
}

inline bool operator!=(Module const& lhs, Module const& rhs) noexcept
{
  return !(lhs == rhs);
}

inline bool operator<(Module const& lhs, Module const& rhs) noexcept
{
  return lhs.GetHandle() < rhs.GetHandle();
}

inline bool operator<=(Module const& lhs, Module const& rhs) noexcept
{
  return lhs.GetHandle() <= rhs.GetHandle();
}

inline bool operator>(Module const& lhs, Module const& rhs) noexcept
{
  return lhs.GetHandle() > rhs.GetHandle();
}

inline bool operator>=(Module const& lhs, Module const& rhs) noexcept
{
  return lhs.GetHandle() >= rhs.GetHandle();
}

inline std::ostream& operator<<(std::ostream& lhs, Module const& rhs)
{
  std::locale const old = lhs.imbue(std::locale::classic());
  lhs << static_cast<void*>(rhs.GetHandle());
  lhs.imbue(old);
  return lhs;
}

inline std::wostream& operator<<(std::wostream& lhs, Module const& rhs)
{
  std::locale const old = lhs.imbue(std::locale::classic());
  lhs << static_cast<void*>(rhs.GetHandle());
  lhs.imbue(old);
  return lhs;
}
}
