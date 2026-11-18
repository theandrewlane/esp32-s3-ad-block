#pragma once
// Blocked-query log on the SD card (CS 10, MOSI 11, CLK 12, MISO 13; FAT32), one CSV
// file per local day under /log, the last querylog::kKeepDays days kept.
//
// record() is the only call on the DNS path: it never blocks, never allocates and
// drops the entry when the queue is full. A low-priority writer task does all card
// I/O, so a slow or missing card can never stall DNS. The card is mounted when logging is on and
// retried every 30 s until it appears.
//
// The card itself is owned by SdCard (shared with the blocklist storage).

#include <Arduino.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>

#include <atomic>
#include <cstddef>
#include <cstdint>

#include "platform/rtos.h"
#include "platform/sd_card.h"
#include "querylog/query_log.h"

namespace platform {

class SdBlockLog {
 public:
  enum class State : uint8_t {
    kOff,     // logging is switched off; the card is not touched
    kNoCard,  // on, but no readable FAT card (retrying)
    kReady,   // on and logging
    kError,   // a write failed (retrying after a remount)
  };

  struct Status {
    State state = State::kOff;
    uint64_t totalBytes = 0;  // card capacity (free space is not reported: counting it scans the FAT)
    uint32_t logged = 0;      // lines written since boot
    uint32_t dropped = 0;     // lines lost (queue full, clock not synced, write error)
  };

  struct DayFile {
    char name[16];  // "2026-11-17.csv"
    uint32_t bytes;
  };
  static constexpr size_t kMaxDays = querylog::kKeepDays + 2;

  explicit SdBlockLog(SdCard& card) : card_(card) {}

  // Creates the queue and the writer task. Call once from setup().
  void begin();
  void setEnabled(bool on);

  // DNS path. `clientIp` in network byte order.
  void record(const char* domain, size_t len, uint32_t clientIp, querylog::Reason reason);

  Status status() const;

  // Web task. All three take the card lock briefly and return false when the card is
  // not ready. readDay() reads up to `cap` bytes of a day's file from `offset`.
  bool listDays(DayFile* out, size_t cap, size_t* count);
  bool readDay(const char* name, uint32_t offset, uint8_t* buf, size_t cap, size_t* got);
  bool clearAll();

 private:
  struct Item {
    uint32_t epoch;
    uint32_t clientIp;
    uint8_t len;
    uint8_t reason;
    char domain[94];
  };

  static void taskEntry(void* self);
  void run();
  bool ensureDir();
  void prune(int32_t today);
  bool append(const Item& it, char* line);

  SdCard& card_;
  QueueHandle_t queue_ = nullptr;
  std::atomic<bool> enabled_{false};
  std::atomic<State> state_{State::kOff};
  std::atomic<uint32_t> logged_{0};
  std::atomic<uint32_t> dropped_{0};
  std::atomic<uint32_t> lastMountTry_{0};
};

}  // namespace platform
