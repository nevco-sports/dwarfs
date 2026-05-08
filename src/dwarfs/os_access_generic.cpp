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

#ifdef _WIN32
#include <windows.h>
#endif

#include <unordered_map>

#include <folly/portability/Unistd.h>

#include "dwarfs/mmap.h"
#include "dwarfs/os_access_generic.h"

namespace dwarfs {

namespace fs = std::filesystem;

#ifdef _WIN32
namespace detail {
void win32_stat_cache_store(std::wstring const& path,
                            ::WIN32_FIND_DATAW const& data);
} // namespace detail
#endif

namespace {

#ifdef _WIN32

// Use Win32 FindFirstFileExW/FindNextFileW directly instead of
// std::filesystem::directory_iterator. On MinGW-w64 GCC 16, the
// directory_iterator can cause STATUS_ACCESS_VIOLATION (SIGSEGV) when
// iterating paths inside NTFS junction directories via the \\?\ prefix.
// The Win32 API returns recoverable error codes instead of crashing.
class generic_dir_reader final : public dir_reader {
 public:
  explicit generic_dir_reader(fs::path const& path) : dir_path_(path) {
    std::wstring pattern = path.wstring() + L"\\*";
    handle_ = ::FindFirstFileExW(pattern.c_str(), FindExInfoBasic, &data_,
                                  FindExSearchNameMatch, nullptr, 0);
    if (handle_ == INVALID_HANDLE_VALUE) {
      DWORD err = ::GetLastError();
      if (err == ERROR_FILE_NOT_FOUND || err == ERROR_NO_MORE_FILES) {
        // directory is empty — valid state, no entries
      } else if (err == ERROR_PATH_NOT_FOUND || err == ERROR_DIRECTORY ||
                 err == ERROR_INVALID_NAME) {
        throw std::system_error(ENOENT, std::generic_category(), path.string());
      } else {
        throw std::system_error(static_cast<int>(err), std::system_category(),
                               "FindFirstFileExW: " + path.string());
      }
    } else {
      advance_past_dots();
    }
  }

  ~generic_dir_reader() {
    if (handle_ != INVALID_HANDLE_VALUE) {
      ::FindClose(handle_);
    }
  }

  bool read(fs::path& name) override {
    if (!has_entry_) {
      return false;
    }
    name = dir_path_ / data_.cFileName;
    detail::win32_stat_cache_store(name.wstring(), data_);
    has_entry_ = false;
    while (::FindNextFileW(handle_, &data_)) {
      if (!is_dot()) {
        has_entry_ = true;
        break;
      }
    }
    if (!has_entry_) {
      ::FindClose(handle_);
      handle_ = INVALID_HANDLE_VALUE;
    }
    return true;
  }

 private:
  bool is_dot() const {
    const WCHAR* n = data_.cFileName;
    return n[0] == L'.' &&
           (n[1] == L'\0' || (n[1] == L'.' && n[2] == L'\0'));
  }

  void advance_past_dots() {
    while (is_dot()) {
      if (!::FindNextFileW(handle_, &data_)) {
        ::FindClose(handle_);
        handle_ = INVALID_HANDLE_VALUE;
        return;
      }
    }
    has_entry_ = true;
  }

  fs::path dir_path_;
  HANDLE handle_{INVALID_HANDLE_VALUE};
  WIN32_FIND_DATAW data_{};
  bool has_entry_{false};
};

#else

class generic_dir_reader final : public dir_reader {
 public:
  explicit generic_dir_reader(fs::path const& path)
      : it_(fs::directory_iterator(path)) {}

  bool read(fs::path& name) override {
    if (it_ != fs::directory_iterator()) {
      name.assign(it_->path());
      ++it_;
      return true;
    }

    return false;
  }

 private:
  fs::directory_iterator it_;
};

#endif

} // namespace

#ifdef _WIN32
namespace {
thread_local std::unordered_map<std::wstring, ::WIN32_FIND_DATAW> g_win32_stat_cache;
} // namespace

namespace detail {
void win32_stat_cache_store(std::wstring const& path,
                            ::WIN32_FIND_DATAW const& data) {
  g_win32_stat_cache[path] = data;
}

bool win32_stat_cache_lookup(std::wstring const& path,
                             ::WIN32_FIND_DATAW& out) {
  auto it = g_win32_stat_cache.find(path);
  if (it == g_win32_stat_cache.end())
    return false;
  out = it->second;
  g_win32_stat_cache.erase(it);
  return true;
}
} // namespace detail
#endif

std::shared_ptr<dir_reader>
os_access_generic::opendir(fs::path const& path) const {
  return std::make_shared<generic_dir_reader>(path);
}

file_stat os_access_generic::symlink_info(fs::path const& path) const {
  return make_file_stat(path);
}

fs::path os_access_generic::read_symlink(fs::path const& path) const {
  return fs::read_symlink(path);
}

std::shared_ptr<mmif>
os_access_generic::map_file(fs::path const& path, size_t size) const {
  return std::make_shared<mmap>(path, size);
}

int os_access_generic::access(fs::path const& path, int mode) const {
#ifdef _WIN32
  return ::_waccess(path.wstring().c_str(), mode);
#else
  return ::access(path.string().c_str(), mode);
#endif
}

} // namespace dwarfs
