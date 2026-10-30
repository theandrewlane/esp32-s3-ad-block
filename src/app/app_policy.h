#pragma once
// The DNS policy: banned clients, the blocking pause, then the blocklist matcher
// (custom allow > custom block > main list, parent domains). Called from the DNS
// tasks for every valid query, so it only takes short locks.

#include <Arduino.h>
#include <lwip/sockets.h>

#include "app/blocklist_manager.h"
#include "app/clients.h"
#include "dns/query_policy.h"

#include "display/display_stats.h"

namespace app {

class AppPolicy final : public dns::IQueryPolicy {
 public:
  AppPolicy(ClientTable& clients, BlocklistManager& blocklist,
            display::DisplayStats* stats = nullptr)
      : clients_(clients), blocklist_(blocklist), stats_(stats) {}

  dns::PolicyAction decide(const dns::Query& q, uint32_t clientIpv4) override {
    if ((ntohl(clientIpv4) >> 24) == 127) return dns::PolicyAction::kForward;  // the device's own lookups
    if (clients_.checkBanned(clientIpv4)) return dns::PolicyAction::kBan;
    const bool blocked = clients_.blockingOn() &&
                         blocklist_.matcher().match(q.qname, q.qnameLen) == blocklist::MatchResult::kBlocked;
    clients_.record(clientIpv4, blocked);
    if (stats_) {
      uint32_t now    = millis();
      uint8_t  hourIdx = static_cast<uint8_t>((now / 3600000UL) % 24);
      stats_->record(q.qname, q.qnameLen, clientIpv4, blocked, now, hourIdx);
    }
    return blocked ? dns::PolicyAction::kBlock : dns::PolicyAction::kForward;
  }

 private:
  ClientTable& clients_;
  BlocklistManager& blocklist_;
  display::DisplayStats* stats_ = nullptr;
};

}  // namespace app
