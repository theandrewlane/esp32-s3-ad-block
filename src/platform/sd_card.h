#pragma once
// The SD card (CS 10, MOSI 11, CLK 12, MISO 13; FAT32) shared by the blocklist storage
// (sd_fs.h) and the block log (sd_log.h). The Arduino SD library is not thread-safe, so
// every call into it, from any task, holds lock(). mount()/unmount() take the lock
// themselves: don't hold it when calling them.
//
// The card is on the second SPI host (HSPI): the display's QSPI owns SPI2.

#include <atomic>
#include <cstdint>

#include "platform/rtos.h"

namespace platform {

class SdCard {
 public:
  // Mounts the card (idempotent). False when there is none or it isn't FAT.
  bool mount();
  void unmount();
  bool mounted() const { return mounted_; }
  // Card capacity (free space is not available: counting it scans the whole FAT).
  uint64_t totalBytes() const { return total_; }
  Mutex& lock() { return lock_; }

 private:
  Mutex lock_;
  std::atomic<bool> mounted_{false};
  std::atomic<uint64_t> total_{0};
};

}  // namespace platform
