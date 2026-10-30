#pragma once
// Display FreeRTOS task: drives the LVGL dashboard on the NV3041A panel.
// Runs on Core 0 at priority 1.

// Forward-declare heavy types to avoid pulling lwIP/FreeRTOS headers
// into every translation unit that includes this header.
namespace display { class DisplayStats; }
namespace app    { class DnsService; class ClientTable; class BlocklistManager; }

namespace display {

struct DisplayContext {
  DisplayStats*          stats;
  app::DnsService*       dns;
  app::ClientTable*      clients;
  app::BlocklistManager* blocklist;
};

void spawnDisplayTask(const DisplayContext& ctx);

}  // namespace display
