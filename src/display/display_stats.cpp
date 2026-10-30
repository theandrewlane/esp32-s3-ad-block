#include "display/display_stats.h"

#include <algorithm>
#include <cstring>

namespace display {

void DisplayStats::record(const char* qname, uint8_t qnameLen, uint32_t clientIp,
                          bool blocked, uint32_t timeMs, uint8_t hourIdx) {
  platform::LockGuard lock(mutex_);

  // --- recent-query ring buffer ---
  QueryEvent& ev = log_[logHead_];
  size_t copyLen = std::min<size_t>(qnameLen, sizeof(ev.domain) - 1);
  memcpy(ev.domain, qname, copyLen);
  ev.domain[copyLen] = '\0';
  ev.clientIp = clientIp;
  ev.timeMs   = timeMs;
  ev.blocked  = blocked;
  logHead_    = (logHead_ + 1) % kLogCapacity;
  if (logCount_ < kLogCapacity) ++logCount_;

  // --- hourly buckets ---
  HourlyBucket& b = hourly_[hourIdx % kHourlyBuckets];
  ++b.queries;
  if (blocked) ++b.blocked;

  // --- top blocked domains ---
  if (blocked) updateTop(ev.domain);
}

void DisplayStats::updateTop(const char* domain) {
  // Linear search through topCount_ entries; N <= 10, negligible cost.
  for (size_t i = 0; i < topCount_; ++i) {
    if (strncmp(topDomains_[i].name, domain, sizeof(topDomains_[i].name)) == 0) {
      ++topDomains_[i].count;
      // Bubble up to maintain descending order.
      for (size_t j = i; j > 0 && topDomains_[j].count > topDomains_[j - 1].count; --j) {
        std::swap(topDomains_[j], topDomains_[j - 1]);
      }
      return;
    }
  }
  // New entry: replace the last slot if full, or append.
  size_t idx = topCount_ < kTopDomainsN ? topCount_++ : kTopDomainsN - 1;
  strncpy(topDomains_[idx].name, domain, sizeof(topDomains_[idx].name) - 1);
  topDomains_[idx].name[sizeof(topDomains_[idx].name) - 1] = '\0';
  topDomains_[idx].count = 1;
}

void DisplayStats::copyLog(QueryEvent out[kLogCapacity], size_t* count) const {
  platform::LockGuard lock(mutex_);
  *count = logCount_;
  // Copy in chronological order (oldest first).
  if (logCount_ < kLogCapacity) {
    memcpy(out, log_, logCount_ * sizeof(QueryEvent));
  } else {
    // Ring is full: logHead_ points to the oldest entry.
    size_t tail = kLogCapacity - logHead_;
    memcpy(out, log_ + logHead_, tail * sizeof(QueryEvent));
    memcpy(out + tail, log_, logHead_ * sizeof(QueryEvent));
  }
}

void DisplayStats::copyHourly(HourlyBucket out[kHourlyBuckets]) const {
  platform::LockGuard lock(mutex_);
  memcpy(out, hourly_, kHourlyBuckets * sizeof(HourlyBucket));
}

void DisplayStats::copyTopDomains(TopDomain out[kTopDomainsN], size_t* count) const {
  platform::LockGuard lock(mutex_);
  *count = topCount_;
  memcpy(out, topDomains_, topCount_ * sizeof(TopDomain));
}

}  // namespace display
