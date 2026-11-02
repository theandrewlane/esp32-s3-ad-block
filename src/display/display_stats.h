#pragma once
// Lightweight per-query stats accumulator shared between the DNS hot path and the
// display task.  The only hot-path operation is record(), which takes a short mutex
// for a fixed-size copy — consistent with the existing clients_.record() call in
// AppPolicy::decide().

#include <cstddef>
#include <cstdint>

#include "platform/rtos.h"

namespace display {

class DisplayStats {
 public:
  static constexpr size_t kLogCapacity    = 80;
  static constexpr size_t kTopDomainsN    = 10;
  static constexpr size_t kHourlyBuckets  = 24;
  static constexpr size_t kMinuteBuckets  = 30;  // queries-per-minute graph window

  // One entry in the recent-query ring buffer.
  struct QueryEvent {
    char     domain[40];  // truncated, null-terminated dotted text
    uint32_t clientIp;    // network byte order
    uint32_t timeMs;      // millis() at query time
    bool     blocked;
  };

  struct HourlyBucket {
    uint32_t queries = 0;
    uint32_t blocked = 0;
  };

  struct MinuteBucket {
    uint32_t allowed = 0;
    uint32_t blocked = 0;
  };

  struct TopDomain {
    char     name[48];
    uint32_t count = 0;
  };

  // Called from the DNS hot path (any DNS task). Takes a short mutex; must not
  // block for long.  `timeMs` should be millis(), `hourIdx` = (millis/3600000) % 24.
  void record(const char* qname, uint8_t qnameLen, uint32_t clientIp, bool blocked,
              uint32_t timeMs, uint8_t hourIdx);

  // Snapshot accessors — called from display task only.
  void copyLog(QueryEvent out[kLogCapacity], size_t* count) const;
  void copyHourly(HourlyBucket out[kHourlyBuckets]) const;
  // Last kMinuteBuckets minutes, oldest first, newest (current, partial minute) last.
  void copyMinutes(uint32_t nowMs, MinuteBucket out[kMinuteBuckets]) const;
  void copyTopDomains(TopDomain out[kTopDomainsN], size_t* count) const;

 private:
  mutable platform::Mutex mutex_;

  // Circular log of recent queries.
  QueryEvent log_[kLogCapacity] = {};
  size_t     logHead_  = 0;  // next write position
  size_t     logCount_ = 0;  // valid entries (saturates at kLogCapacity)

  // Per-hour counters (ring by hourIdx; hour index is NOT wall-clock aligned until
  // the first 24-hour wrap, but buckets are comparable to each other).
  HourlyBucket hourly_[kHourlyBuckets] = {};

  // Per-minute counters; minuteId_[i] says which minute (millis/60000) bucket i holds.
  MinuteBucket minutes_[kMinuteBuckets] = {};
  uint32_t     minuteId_[kMinuteBuckets] = {};
  bool         minuteUsed_[kMinuteBuckets] = {};

  // Top blocked domains, kept sorted descending by count.
  TopDomain topDomains_[kTopDomainsN] = {};
  size_t    topCount_ = 0;

  void updateTop(const char* domain);  // caller holds mutex_
};

}  // namespace display
