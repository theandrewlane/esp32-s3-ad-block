#pragma once
// Decides what to do with a valid client query before cache/upstream. Implemented by
// the application (blocklist, banned clients, pause); see src/main.cpp.

#include <cstddef>
#include <cstdint>

#include "dns/message.h"

namespace dns {

enum class PolicyAction {
  kForward,  // cache / upstream
  kBlock,    // sinkhole (EDE 15 "Blocked")
  kBan,      // client is banned: sinkhole everything (EDE 17 "Filtered")
};

class IQueryPolicy {
 public:
  virtual ~IQueryPolicy() = default;
  // Called from the DNS task for every valid query: must be fast and never block
  // for long (no network, no flash writes). `clientIpv4` is in network byte order.
  virtual PolicyAction decide(const Query& q, uint32_t clientIpv4) = 0;
  // Called for each CNAME target in an answer about to be sent for `q` (CNAME cloaking
  // protection). Returns true to replace the whole answer with a block reply; the
  // implementation also reclassifies the query as blocked in its statistics. Runs on
  // the DNS tasks for cache hits too, so the same rules apply as for decide().
  virtual bool blockedCname(const Query& q, uint32_t clientIpv4, const char* target, size_t len) {
    (void)q;
    (void)clientIpv4;
    (void)target;
    (void)len;
    return false;
  }
};

}  // namespace dns
