// Copyright (C) 2010-2015 Joshua Boyce
// See the file COPYING for copying permission.

#pragma once

#include <type_traits>

#include <windows.h>
#include <tlhelp32.h>

#include <hadesmem/detail/optional.hpp>
#include <hadesmem/detail/smart_handle.hpp>
#include <hadesmem/detail/static_assert.hpp>
#include <hadesmem/error.hpp>

namespace hadesmem
{
namespace detail
{
// Work around protected/anti-cheat processes that return
// ERROR_PARTIAL_COPY (299) from CreateToolhelp32Snapshot.  Callers can
// detect this condition and fall back to a PEB-based enumeration instead.
inline detail::SmartSnapHandle CreateToolhelp32Snapshot(DWORD flags, DWORD pid)
{
  detail::SmartSnapHandle snap;
  do
  {
    snap = ::CreateToolhelp32Snapshot(flags, pid);
  } while (!snap.IsValid() && ::GetLastError() == ERROR_BAD_LENGTH);

  if (!snap.IsValid())
  {
    DWORD const last_error = ::GetLastError();
    if (last_error == ERROR_PARTIAL_COPY)
    {
      // return invalid handle without throwing; caller should detect this
      // and attempt an alternate enumeration method.
      return detail::SmartSnapHandle(nullptr);
    }

    HADESMEM_DETAIL_THROW_EXCEPTION(
      Error{} << ErrorString{"CreateToolhelp32Snapshot failed."}
              << ErrorCodeWinLast{last_error});
  }

  return snap;
}

// PEB/ldr support for when snapshots are unavailable.
inline hadesmem::detail::Optional<MODULEENTRY32W>
  GetModuleEntryFromPeb(Process const& process,
                        std::wstring const& name,
                        bool path)
{
  // Minimal declarations needed for reading the PEB.
  struct UNICODE_STRING64 {
    USHORT Length;
    USHORT MaximumLength;
    ULONG_PTR Buffer;
  };
  struct LIST_ENTRY64 {
    ULONG_PTR Flink;
    ULONG_PTR Blink;
  };
  struct LDR_DATA_TABLE_ENTRY64 {
    LIST_ENTRY64 InLoadOrderLinks;
    LIST_ENTRY64 InMemoryOrderLinks;
    LIST_ENTRY64 InInitializationOrderLinks;
    ULONG_PTR DllBase;
    ULONG_PTR EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING64 FullDllName;
    UNICODE_STRING64 BaseDllName;
    // we don't need anything else
  };
  struct PEB_LDR_DATA64 {
    ULONG Length;
    BOOLEAN Initialized;
    ULONG_PTR SsHandle;
    LIST_ENTRY64 InLoadOrderModuleList;
    // rest omitted
  };
  struct PEB64 {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    ULONG_PTR Reserved3[2];
    ULONG_PTR Ldr; // PEB_LDR_DATA*
    // rest omitted
  };

  // helper to read remote memory
  auto readStruct = [&](auto const addr, auto &out)
  {
    out = Read<std::decay_t<decltype(out)>>(process, reinterpret_cast<void*>(addr));
  };

  // query basic information to get PEB address
  using NtQueryInformationProcessFn =
    NTSTATUS(WINAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
  static NtQueryInformationProcessFn ntq = nullptr;
  if (!ntq)
  {
    ntq = reinterpret_cast<NtQueryInformationProcessFn>(
      ::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"),
                        "NtQueryInformationProcess"));
  }
  if (!ntq)
  {
    HADESMEM_DETAIL_THROW_EXCEPTION(
      Error{} << ErrorString{"NtQueryInformationProcess unavailable."});
  }

  PROCESS_BASIC_INFORMATION pbi{};
  NTSTATUS const status = ntq(process.GetHandle(),
                              0 /*ProcessBasicInformation*/,
                              &pbi,
                              sizeof(pbi),
                              nullptr);
  if (!NT_SUCCESS(status))
  {
    HADESMEM_DETAIL_THROW_EXCEPTION(
      Error{} << ErrorString{"NtQueryInformationProcess failed."});
  }

  PEB64 peb{};
  readStruct(reinterpret_cast<ULONG_PTR>(pbi.PebBaseAddress), peb);
  if (!peb.Ldr)
  {
    return hadesmem::detail::Optional<MODULEENTRY32W>();
  }

  PEB_LDR_DATA64 ldr{};
  readStruct(peb.Ldr, ldr);
  ULONG_PTR head = reinterpret_cast<ULONG_PTR>(peb.Ldr) +
                   offsetof(PEB_LDR_DATA64, InLoadOrderModuleList);
  ULONG_PTR curr = ldr.InLoadOrderModuleList.Flink;

  while (curr && curr != head)
  {
    LDR_DATA_TABLE_ENTRY64 ent{};
    readStruct(curr - offsetof(LDR_DATA_TABLE_ENTRY64, InLoadOrderLinks), ent);

    // read names
    std::wstring full;
    if (ent.FullDllName.Buffer && ent.FullDllName.Length)
    {
      full.resize(ent.FullDllName.Length / sizeof(wchar_t));
      Read(process, reinterpret_cast<void*>(ent.FullDllName.Buffer),
           &full[0], ent.FullDllName.Length);
    }
    std::wstring base;
    if (ent.BaseDllName.Buffer && ent.BaseDllName.Length)
    {
      base.resize(ent.BaseDllName.Length / sizeof(wchar_t));
      Read(process, reinterpret_cast<void*>(ent.BaseDllName.Buffer),
           &base[0], ent.BaseDllName.Length);
    }

    bool match = false;
    if (path)
    {
      match = detail::ArePathsEquivalent(full, name);
    }
    else
    {
      match = (detail::ToUpperOrdinal(base) == detail::ToUpperOrdinal(name));
    }

    if (match)
    {
      MODULEENTRY32W result{};
      result.dwSize = sizeof(result);
      result.modBaseAddr = reinterpret_cast<BYTE*>(ent.DllBase);
      result.modBaseSize = ent.SizeOfImage;
      if (!full.empty())
      {
        wcsncpy_s(result.szExePath, full.c_str(), _TRUNCATE);
      }
      if (!base.empty())
      {
        wcsncpy_s(result.szModule, base.c_str(), _TRUNCATE);
      }
      return result;
    }

    curr = ent.InLoadOrderLinks.Flink;
  }

  return hadesmem::detail::Optional<MODULEENTRY32W>();
}

template <typename Entry, typename Func>
hadesmem::detail::Optional<Entry>
  Toolhelp32Enum(Func func, HANDLE snap, std::string const& error)
{
  HADESMEM_DETAIL_STATIC_ASSERT(std::is_pod<Entry>::value);

  Entry entry{};
  entry.dwSize = static_cast<DWORD>(sizeof(entry));
  if (!func(snap, &entry))
  {
    DWORD const last_error = ::GetLastError();
    if (last_error == ERROR_NO_MORE_FILES)
    {
      return hadesmem::detail::Optional<Entry>();
    }

    HADESMEM_DETAIL_THROW_EXCEPTION(Error{} << ErrorString{error.c_str()}
                                            << ErrorCodeWinLast{last_error});
  }

  return hadesmem::detail::Optional<Entry>(entry);
}

inline hadesmem::detail::Optional<MODULEENTRY32W> Module32First(HANDLE snap)
{
  return Toolhelp32Enum<MODULEENTRY32W, decltype(&::Module32FirstW)>(
    &::Module32FirstW, snap, "Module32First failed.");
}

inline hadesmem::detail::Optional<MODULEENTRY32W> Module32Next(HANDLE snap)
{
  return Toolhelp32Enum<MODULEENTRY32W, decltype(&::Module32NextW)>(
    &::Module32NextW, snap, "Module32Next failed.");
}

inline hadesmem::detail::Optional<PROCESSENTRY32W> Process32First(HANDLE snap)
{
  return Toolhelp32Enum<PROCESSENTRY32W, decltype(&::Process32FirstW)>(
    &::Process32FirstW, snap, "Process32First failed.");
}

inline hadesmem::detail::Optional<PROCESSENTRY32W> Process32Next(HANDLE snap)
{
  return Toolhelp32Enum<PROCESSENTRY32W, decltype(&::Process32NextW)>(
    &::Process32NextW, snap, "Process32Next failed.");
}

inline hadesmem::detail::Optional<THREADENTRY32> Thread32First(HANDLE snap)
{
  return Toolhelp32Enum<THREADENTRY32, decltype(&::Thread32First)>(
    &::Thread32First, snap, "Thread32First failed.");
}

inline hadesmem::detail::Optional<THREADENTRY32> Thread32Next(HANDLE snap)
{
  return Toolhelp32Enum<THREADENTRY32, decltype(&::Thread32Next)>(
    &::Thread32Next, snap, "Thread32Next failed.");
}
}
}
