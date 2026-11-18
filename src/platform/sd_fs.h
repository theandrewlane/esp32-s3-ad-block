#pragma once
// IFileSystem over the SD card, for the blocklist files. Every call takes the card
// lock, so the block log can write in between the blocklist's 4 KB reads.

#include <FS.h>
#include <SD.h>

#include <algorithm>
#include <memory>

#include "hal/file_system.h"
#include "platform/sd_card.h"

namespace platform {

class SdFile final : public hal::IFile {
 public:
  SdFile(SdCard& card, fs::File f) : card_(card), f_(f) {}
  ~SdFile() override {
    LockGuard g(card_.lock());
    f_.close();
  }
  size_t read(uint8_t* buf, size_t len) override {
    LockGuard g(card_.lock());
    return f_.read(buf, len);
  }
  size_t write(const uint8_t* buf, size_t len) override {
    LockGuard g(card_.lock());
    return f_.write(buf, len);
  }
  bool seek(size_t pos) override {
    LockGuard g(card_.lock());
    return f_.seek(pos);
  }
  size_t size() const override {
    LockGuard g(card_.lock());
    return const_cast<fs::File&>(f_).size();
  }
  bool flush() override {
    LockGuard g(card_.lock());
    f_.flush();
    return true;
  }

 private:
  SdCard& card_;
  fs::File f_;
};

class SdFileSystem final : public hal::IFileSystem {
 public:
  explicit SdFileSystem(SdCard& card) : card_(card) {}

  std::unique_ptr<hal::IFile> open(const char* path, hal::FileMode mode) override {
    LockGuard g(card_.lock());
    if (!card_.mounted()) return nullptr;
    if (mode == hal::FileMode::kRead && !SD.exists(path)) return nullptr;
    fs::File f = SD.open(path, mode == hal::FileMode::kRead ? FILE_READ : FILE_WRITE);
    if (!f) return nullptr;
    return std::unique_ptr<hal::IFile>(new SdFile(card_, f));
  }
  bool exists(const char* path) const override {
    LockGuard g(card_.lock());
    return card_.mounted() && SD.exists(path);
  }
  bool remove(const char* path) override {
    LockGuard g(card_.lock());
    return card_.mounted() && SD.exists(path) && SD.remove(path);
  }
  bool rename(const char* from, const char* to) override {
    LockGuard g(card_.lock());
    return card_.mounted() && !SD.exists(to) && SD.rename(from, to);
  }
  size_t freeBytes() const override {
    // The real figure needs a scan of the whole FAT (tens of seconds on a 64 GB card).
    // Blocklist copies are a few MB, so a fixed allowance is accurate enough; a full
    // card shows up as a write error.
    constexpr uint64_t kAllowance = 64ULL * 1024 * 1024;
    return static_cast<size_t>(std::min<uint64_t>(card_.totalBytes(), kAllowance));
  }

 private:
  SdCard& card_;
};

}  // namespace platform
