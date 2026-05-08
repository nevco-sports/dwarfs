/* vim:set ts=2 sw=2 sts=2 et: */
/**
 * \author     Marcus Holland-Moritz (github@mhxnet.de)
 * \copyright  Copyright (c) Marcus Holland-Moritz
 *
 * This file is part of dwarfs.
 *
 * dwarfs is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * dwarfs is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with dwarfs.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <cerrno>
#include <ctime>
#include <filesystem>
#include <stdexcept>
#include <vector>

#ifdef _WIN32
#include <folly/portability/Windows.h>
#else
#include <fcntl.h>
#endif

#include <folly/portability/Unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <fmt/format.h>

#include "dwarfs/error.h"
#include "dwarfs/mmap.h"
#include "dwarfs/os_access_generic.h"
#include "dwarfs/util.h"

namespace dwarfs {

#ifdef _WIN32
namespace detail {
extern void win32_stat_cache_store(std::wstring const& path,
                                   ::WIN32_FIND_DATAW const& data);
extern bool win32_stat_cache_lookup(std::wstring const& path,
                                    ::WIN32_FIND_DATAW& out);
} // namespace detail
#endif

namespace {

namespace fs = std::filesystem;

#ifdef _WIN32

uint64_t time_from_filetime(FILETIME const& ft) {
  static constexpr uint64_t FT_TICKS_PER_SECOND = UINT64_C(10000000);
  static constexpr uint64_t FT_EPOCH_OFFSET = UINT64_C(11644473600);
  uint64_t ticks =
      (static_cast<uint64_t>(ft.dwHighDateTime) << 32) + ft.dwLowDateTime;
  return (ticks / FT_TICKS_PER_SECOND) - FT_EPOCH_OFFSET;
}

#endif

} // namespace

#ifdef _WIN32

file_stat make_file_stat(fs::path const& path) {
  auto wps = path.wstring();

  // Three-tier resolution strategy for NTFS junction-traversal paths:
  // 1. Thread-local cache populated by generic_dir_reader::read() — zero cost,
  //    covers the common case (all entries enumerated via wildcard FindFirst).
  // 2. FindFirstFileExW(exact) — works for non-junction paths (e.g. scan root).
  // 3. Parent directory enumeration fallback — FindFirstFileExW("parent\*") with
  //    a case-insensitive filename scan. This uses NtOpenFile+NtQueryDirectoryFile
  //    which follows NTFS junctions in intermediate path components, unlike
  //    NtQueryFullAttributesFile (used by exact FindFirstFileExW and GetFileAttributesW).
  ::WIN32_FIND_DATAW fdata{};
  if (!detail::win32_stat_cache_lookup(wps, fdata)) {
    HANDLE fh = ::FindFirstFileExW(wps.c_str(), FindExInfoBasic, &fdata,
                                    FindExSearchNameMatch, nullptr, 0);
    if (fh == INVALID_HANDLE_VALUE) {
      // Tier 3: enumerate parent directory to find this entry.
      fs::path parent_path = path.parent_path();
      std::wstring leaf = path.filename().wstring();
      if (parent_path.empty() || leaf.empty()) {
        DWARFS_THROW(system_error, u8string_to_string(path.u8string()), ENOENT);
      }
      std::wstring pattern = parent_path.wstring() + L"\\*";
      HANDLE sh = ::FindFirstFileExW(pattern.c_str(), FindExInfoBasic, &fdata,
                                      FindExSearchNameMatch, nullptr, 0);
      if (sh == INVALID_HANDLE_VALUE) {
        DWARFS_THROW(system_error, u8string_to_string(path.u8string()), ENOENT);
      }
      bool found = false;
      do {
        if (::_wcsicmp(fdata.cFileName, leaf.c_str()) == 0) {
          found = true;
          break;
        }
      } while (::FindNextFileW(sh, &fdata));
      ::FindClose(sh);
      if (!found) {
        DWARFS_THROW(system_error, u8string_to_string(path.u8string()), ENOENT);
      }
    } else {
      ::FindClose(fh);
    }
  }

  DWORD const attrs = fdata.dwFileAttributes;
  fs::file_status status;
  if (attrs & FILE_ATTRIBUTE_REPARSE_POINT) {
    // NTFS junctions (reparse + directory): report as directory so the scanner
    // recurses into them. Non-directory reparse points: report as symlink.
    if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
      status = fs::file_status(fs::file_type::directory, fs::perms::all);
    } else {
      status = fs::file_status(fs::file_type::symlink, fs::perms::all);
    }
  } else if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
    status = fs::file_status(fs::file_type::directory, fs::perms::all);
  } else {
    status = fs::file_status(fs::file_type::regular, fs::perms::all);
  }

  file_stat rv;
  rv.mode = file_status_to_mode(status);
  rv.blksize = 0;
  rv.blocks = 0;
  rv.dev = 0;
  rv.uid = 0;
  rv.gid = 0;
  rv.rdev = 0;
  rv.ino = 0;
  rv.nlink = 1;
  rv.size = (static_cast<uint64_t>(fdata.nFileSizeHigh) << 32) + fdata.nFileSizeLow;
  rv.atime = time_from_filetime(fdata.ftLastAccessTime);
  rv.mtime = time_from_filetime(fdata.ftLastWriteTime);
  rv.ctime = time_from_filetime(fdata.ftCreationTime);

  if (status.type() == fs::file_type::symlink) {
    // Symlink stats are fully satisfied by WIN32_FIND_DATA above.
  } else {
    // For non-symlinks, try _wstat64 to fill dev/uid/gid and, for regular
    // files, try CreateFileW to get the inode number and link count (needed for
    // hardlink deduplication). Both may fail for junction-traversal paths; in
    // that case, the WIN32_FIND_DATA values (ino=0, nlink=1) are kept and
    // hardlink deduplication is skipped for the file — it is still archived.
    struct ::__stat64 st;
    if (::_wstat64(wps.c_str(), &st) == 0) {
      rv.dev = st.st_dev;
      rv.uid = st.st_uid;
      rv.gid = st.st_gid;
      rv.rdev = st.st_rdev;
      rv.size = st.st_size;
      rv.atime = st.st_atime;
      rv.mtime = st.st_mtime;
      rv.ctime = st.st_ctime;
    }

    if (status.type() == fs::file_type::regular) {
      ::HANDLE hdl =
          ::CreateFileW(wps.c_str(), 0, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);

      if (hdl != INVALID_HANDLE_VALUE) {
        ::BY_HANDLE_FILE_INFORMATION info;
        if (::GetFileInformationByHandle(hdl, &info)) {
          rv.ino = (static_cast<uint64_t>(info.nFileIndexHigh) << 32) +
                   info.nFileIndexLow;
          rv.nlink = info.nNumberOfLinks;
        }
        ::CloseHandle(hdl);
      }
    }
  }

  return rv;
}

#else

file_stat make_file_stat(fs::path const& path) {
  struct ::stat st;

  if (::lstat(path.string().c_str(), &st) != 0) {
    throw std::system_error(errno, std::generic_category(), "lstat");
  }

  file_stat rv;
  rv.dev = st.st_dev;
  rv.ino = st.st_ino;
  rv.nlink = st.st_nlink;
  rv.mode = st.st_mode;
  rv.uid = st.st_uid;
  rv.gid = st.st_gid;
  rv.rdev = st.st_rdev;
  rv.size = st.st_size;
  rv.blksize = st.st_blksize;
  rv.blocks = st.st_blocks;

  rv.atime = st.st_atime;
  rv.mtime = st.st_mtime;
  rv.ctime = st.st_ctime;

//  Tebako -- using legacy syntax above to comply with MacOS definitions (~ FreeBSD)
//  rv.atime = st.st_atim.tv_sec;
//  rv.mtime = st.st_mtim.tv_sec;
//  rv.ctime = st.st_ctim.tv_sec;

  return rv;
}

#endif

} // namespace dwarfs
