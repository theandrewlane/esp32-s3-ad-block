// Arduino.h must come first — it configures macros needed by ESP32 headers.
#include <Arduino.h>
#include <Wire.h>
#include <esp_heap_caps.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <algorithm>
#include <ctime>
#include <lvgl.h>

// Display hardware drivers (Arduino_GFX after LVGL to avoid header conflicts).
#include "display/panel/gt911_touch.h"
#include "display/panel/nv3041a.h"

// Application types (include after Arduino.h to ensure lwIP is set up correctly).
#include "display/display_task.h"
#include "display/display_stats.h"
#include "tasks/dns_service.h"
#include "app/blocklist_manager.h"
#include "app/clients.h"
#include "upstream/health.h"


// LVGL allocator (lv_conf.h: LV_STDLIB_CUSTOM). Everything LVGL allocates (objects,
// styles, chart/table data) goes to PSRAM so internal RAM stays free for TLS sessions
// (a third TLS handshake needs ~45 KB contiguous; see ARCHITECTURE.md memory budget).
extern "C" {
void lv_mem_init(void) {}
void lv_mem_deinit(void) {}
lv_mem_pool_t lv_mem_add_pool(void*, size_t) { return nullptr; }
void lv_mem_remove_pool(lv_mem_pool_t) {}
void* lv_malloc_core(size_t size) { return heap_caps_malloc(size, MALLOC_CAP_SPIRAM); }
void* lv_realloc_core(void* p, size_t size) { return heap_caps_realloc(p, size, MALLOC_CAP_SPIRAM); }
void lv_free_core(void* p) { heap_caps_free(p); }
void lv_mem_monitor_core(lv_mem_monitor_t*) {}
lv_result_t lv_mem_test_core(void) { return LV_RESULT_OK; }
}

namespace display {

// ============================================================
// Colour palette (AdGuard-inspired dark theme)
// ============================================================
static constexpr lv_color_t kColBg         = LV_COLOR_MAKE(0x1C, 0x1B, 0x1F);
static constexpr lv_color_t kColCard       = LV_COLOR_MAKE(0x2D, 0x2C, 0x33);
static constexpr lv_color_t kColAccent     = LV_COLOR_MAKE(0x67, 0xA2, 0xE6);
static constexpr lv_color_t kColBlocked    = LV_COLOR_MAKE(0xE0, 0x6C, 0x75);
static constexpr lv_color_t kColAllowed    = LV_COLOR_MAKE(0x98, 0xC3, 0x79);
static constexpr lv_color_t kColText       = LV_COLOR_MAKE(0xFF, 0xFF, 0xFF);
static constexpr lv_color_t kColSubtext    = LV_COLOR_MAKE(0x9E, 0x9E, 0x9E);
static constexpr lv_color_t kColHeaderBg   = LV_COLOR_MAKE(0x14, 0x14, 0x18);
static constexpr lv_color_t kColUp         = LV_COLOR_MAKE(0x61, 0xAF, 0x64);
static constexpr lv_color_t kColDown       = LV_COLOR_MAKE(0xE0, 0x6C, 0x75);
static constexpr lv_color_t kColUnknown    = LV_COLOR_MAKE(0xFF, 0xB8, 0x6C);

// ============================================================
// Screen-local state (updated each second by the timer)
// ============================================================
struct Screens {
  // --- Overview ---
  lv_obj_t* ovRoot          = nullptr;
  lv_obj_t* ovQueries       = nullptr;
  lv_obj_t* ovBlocked       = nullptr;
  lv_obj_t* ovRatio         = nullptr;
  lv_obj_t* ovLatency       = nullptr;
  lv_obj_t* ovChart         = nullptr;
  lv_chart_series_t* ovSeries1 = nullptr;  // total queries
  lv_chart_series_t* ovSeries2 = nullptr;  // blocked
  lv_obj_t* ovChartMax      = nullptr;  // y-axis max label
  lv_obj_t* ovCache         = nullptr;
  lv_obj_t* ovFwd           = nullptr;
  lv_obj_t* ovLocal         = nullptr;
  lv_obj_t* ovLog[4]        = {};           // 4 recent-query rows
  lv_obj_t* ovUptime        = nullptr;

  // --- Top Blocked ---
  lv_obj_t* tbRoot          = nullptr;
  lv_obj_t* tbRows[8]       = {};  // label for each row

};

static DisplayContext gCtx;
static Screens        gScr;
static int            gCurrentScreen = 0;  // 0=overview, 1=top-blocked

// ============================================================
// Helpers
// ============================================================

static void applyBg(lv_obj_t* obj, lv_color_t col) {
  lv_obj_set_style_bg_color(obj, col, LV_PART_MAIN);
  lv_obj_set_style_bg_opa(obj, LV_OPA_COVER, LV_PART_MAIN);
  lv_obj_set_style_border_width(obj, 0, LV_PART_MAIN);
  lv_obj_set_style_radius(obj, 0, LV_PART_MAIN);
}

static void applyCard(lv_obj_t* obj) {
  applyBg(obj, kColCard);
  lv_obj_set_style_radius(obj, 6, LV_PART_MAIN);
  lv_obj_set_style_pad_all(obj, 4, LV_PART_MAIN);
}

static lv_obj_t* makeLabel(lv_obj_t* parent, const lv_font_t* font, lv_color_t col,
                            lv_text_align_t align = LV_TEXT_ALIGN_LEFT) {
  lv_obj_t* l = lv_label_create(parent);
  lv_obj_set_style_text_font(l, font, LV_PART_MAIN);
  lv_obj_set_style_text_color(l, col, LV_PART_MAIN);
  lv_obj_set_style_text_align(l, align, LV_PART_MAIN);
  lv_label_set_text(l, "");
  return l;
}

// Format a count for a tile: 1,234 below 10k, then 14.6k, then 1.2M.
static void fmtInt(char* buf, size_t bufsz, uint32_t v) {
  if (v < 1000) {
    snprintf(buf, bufsz, "%lu", (unsigned long)v);
  } else if (v < 10000) {
    snprintf(buf, bufsz, "%lu,%03lu", (unsigned long)(v / 1000), (unsigned long)(v % 1000));
  } else if (v < 999950) {  // 14561 -> "14.6k" (rounded; 999950+ would show "1000.0k")
    uint32_t tenths = (v + 50) / 100;
    snprintf(buf, bufsz, "%lu.%luk", (unsigned long)(tenths / 10), (unsigned long)(tenths % 10));
  } else {  // 1234567 -> "1.2M"
    uint32_t tenths = (v + 50000) / 100000;
    snprintf(buf, bufsz, "%lu.%luM", (unsigned long)(tenths / 10), (unsigned long)(tenths % 10));
  }
}

// Cycle to the next screen on tap.
static void screenTapCb(lv_event_t* /*e*/) {
  gCurrentScreen = (gCurrentScreen + 1) % 2;
  lv_obj_t* next = gCurrentScreen == 0 ? gScr.ovRoot : gScr.tbRoot;
  lv_screen_load_anim(next, LV_SCR_LOAD_ANIM_MOVE_LEFT, 250, 0, false);
}

static void addTapToScreen(lv_obj_t* scr) {
  lv_obj_add_flag(scr, LV_OBJ_FLAG_CLICKABLE);
  lv_obj_add_event_cb(scr, screenTapCb, LV_EVENT_SHORT_CLICKED, nullptr);
}

// ============================================================
// Screen 0: Overview
// ============================================================
static void buildOverview() {
  lv_obj_t* scr = lv_obj_create(nullptr);
  gScr.ovRoot   = scr;
  applyBg(scr, kColBg);
  lv_obj_set_size(scr, kLcdWidth, kLcdHeight);
  lv_obj_set_style_pad_all(scr, 0, LV_PART_MAIN);
  addTapToScreen(scr);

  // ---- Header bar (y=0, h=34) ----
  lv_obj_t* hdr = lv_obj_create(scr);
  lv_obj_set_size(hdr, 480, 34);
  lv_obj_set_pos(hdr, 0, 0);
  applyBg(hdr, kColHeaderBg);
  lv_obj_set_style_pad_hor(hdr, 8, LV_PART_MAIN);
  lv_obj_set_style_pad_ver(hdr, 6, LV_PART_MAIN);
  lv_obj_clear_flag(hdr, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t* title = makeLabel(hdr, &lv_font_montserrat_16, kColText);
  lv_label_set_text(title, "theandrewlane DNS Adblocker");
  lv_obj_set_pos(title, 0, 1);

  gScr.ovUptime = makeLabel(hdr, &lv_font_montserrat_10, kColText, LV_TEXT_ALIGN_RIGHT);
  lv_obj_set_size(gScr.ovUptime, 200, 18);
  lv_obj_align(gScr.ovUptime, LV_ALIGN_RIGHT_MID, 0, 0);

  // ---- Stat tiles (y=36, h=62): traffic | resolution | latency ----
  struct Stat { lv_obj_t** val; const char* label; lv_color_t col; };
  auto makeTile = [&](int x, int w, const Stat* stats, int n) {
    lv_obj_t* card = lv_obj_create(scr);
    lv_obj_set_size(card, w, 62);
    lv_obj_set_pos(card, x, 36);
    applyCard(card);
    lv_obj_set_style_pad_all(card, 0, LV_PART_MAIN);
    lv_obj_clear_flag(card, LV_OBJ_FLAG_SCROLLABLE);
    int colW = w / n;
    for (int i = 0; i < n; ++i) {
      *stats[i].val = makeLabel(card, &lv_font_montserrat_20, stats[i].col, LV_TEXT_ALIGN_CENTER);
      lv_obj_set_size(*stats[i].val, colW, 28);
      lv_obj_set_pos(*stats[i].val, i * colW, 6);
      lv_obj_t* lbl = makeLabel(card, &lv_font_montserrat_10, kColSubtext, LV_TEXT_ALIGN_CENTER);
      lv_obj_set_size(lbl, colW, 14);
      lv_obj_set_pos(lbl, i * colW, 40);
      lv_label_set_text(lbl, stats[i].label);
    }
  };
  const Stat traffic[] = {{&gScr.ovQueries, "QUERIES", kColAccent},
                          {&gScr.ovBlocked, "BLOCKED", kColBlocked},
                          {&gScr.ovRatio, "BLOCK %", kColAllowed}};
  const Stat resolve[] = {{&gScr.ovCache, "CACHE", kColAccent},
                          {&gScr.ovFwd, "FORWARDED", kColUnknown},
                          {&gScr.ovLocal, "LOCAL", kColAllowed}};
  const Stat latency[] = {{&gScr.ovLatency, "LATENCY", kColText}};
  makeTile(2, 176, traffic, 3);
  makeTile(182, 216, resolve, 3);  // wide enough for FORWARDED
  makeTile(402, 76, latency, 1);

  // ---- Queries-per-minute line chart, last 30 min (y=100, h=92) ----
  lv_obj_t* chart = lv_chart_create(scr);
  gScr.ovChart    = chart;
  lv_obj_set_size(chart, 476, 92);
  lv_obj_set_pos(chart, 2, 100);
  lv_chart_set_type(chart, LV_CHART_TYPE_LINE);
  lv_chart_set_point_count(chart, DisplayStats::kMinuteBuckets);
  lv_obj_set_style_size(chart, 0, 0, LV_PART_INDICATOR);  // no point markers
  lv_obj_set_style_line_width(chart, 2, LV_PART_ITEMS);
  applyBg(chart, kColCard);
  lv_obj_set_style_radius(chart, 4, LV_PART_MAIN);
  lv_obj_set_style_pad_all(chart, 4, LV_PART_MAIN);
  lv_obj_set_style_pad_top(chart, 20, LV_PART_MAIN);  // keep the plot below the title row
  lv_chart_set_div_line_count(chart, 3, 0);
  lv_obj_set_style_line_color(chart, LV_COLOR_MAKE(0x40, 0x40, 0x50), LV_PART_MAIN);

  gScr.ovSeries1 = lv_chart_add_series(chart, kColAccent,  LV_CHART_AXIS_PRIMARY_Y);
  gScr.ovSeries2 = lv_chart_add_series(chart, kColBlocked, LV_CHART_AXIS_PRIMARY_Y);

  lv_obj_t* chartTitle = makeLabel(scr, &lv_font_montserrat_10, kColText, LV_TEXT_ALIGN_LEFT);
  lv_label_set_text(chartTitle, "Queries per minute (30 min):  blue allowed, red blocked");
  lv_obj_set_pos(chartTitle, 8, 103);  // over the chart's padded-off top row
  gScr.ovChartMax = makeLabel(scr, &lv_font_montserrat_12, kColSubtext, LV_TEXT_ALIGN_RIGHT);
  lv_obj_set_size(gScr.ovChartMax, 90, 16);
  lv_obj_set_pos(gScr.ovChartMax, 384, 103);

  // ---- Recent query log (y=195, h=77) ----
  for (int i = 0; i < 4; ++i) {
    lv_obj_t* row = lv_obj_create(scr);
    gScr.ovLog[i] = row;
    lv_obj_set_size(row, 476, 18);
    lv_obj_set_pos(row, 2, 196 + i * 19);
    applyBg(row, i % 2 == 0 ? kColCard : kColBg);
    lv_obj_set_style_pad_hor(row, 4, LV_PART_MAIN);
    lv_obj_set_style_pad_ver(row, 2, LV_PART_MAIN);
    lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);
    // Placeholder label; updated by refresh.
    lv_obj_t* lbl = lv_label_create(row);
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_12, LV_PART_MAIN);
    lv_obj_set_style_text_color(lbl, kColSubtext, LV_PART_MAIN);
    lv_label_set_long_mode(lbl, LV_LABEL_LONG_CLIP);
    lv_obj_set_size(lbl, 468, 16);
    lv_label_set_text(lbl, "");
  }
}

// ============================================================
// Screen 1: Top Blocked Domains
// ============================================================
static void buildTopBlocked() {
  lv_obj_t* scr  = lv_obj_create(nullptr);
  gScr.tbRoot    = scr;
  applyBg(scr, kColBg);
  lv_obj_set_size(scr, 480, 272);
  lv_obj_set_style_pad_all(scr, 0, LV_PART_MAIN);
  addTapToScreen(scr);

  // Header
  lv_obj_t* hdr = lv_obj_create(scr);
  lv_obj_set_size(hdr, 480, 34);
  lv_obj_set_pos(hdr, 0, 0);
  applyBg(hdr, kColHeaderBg);
  lv_obj_set_style_pad_hor(hdr, 8, LV_PART_MAIN);
  lv_obj_set_style_pad_ver(hdr, 6, LV_PART_MAIN);
  lv_obj_clear_flag(hdr, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t* title = makeLabel(hdr, &lv_font_montserrat_16, kColText);
  lv_label_set_text(title, "Top Blocked Domains (24h)");
  lv_obj_set_pos(title, 0, 1);

  // 8 domain rows (y=36, 29px each)
  for (int i = 0; i < 8; ++i) {
    lv_obj_t* row = lv_obj_create(scr);
    lv_obj_set_size(row, 476, 27);
    lv_obj_set_pos(row, 2, 36 + i * 29);
    applyBg(row, i % 2 == 0 ? kColCard : kColBg);
    lv_obj_set_style_pad_hor(row, 6, LV_PART_MAIN);
    lv_obj_set_style_pad_ver(row, 3, LV_PART_MAIN);
    lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t* lbl = lv_label_create(row);
    gScr.tbRows[i] = lbl;
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_14, LV_PART_MAIN);
    lv_obj_set_style_text_color(lbl, kColSubtext, LV_PART_MAIN);
    lv_label_set_long_mode(lbl, LV_LABEL_LONG_CLIP);
    lv_obj_set_size(lbl, 464, 20);
    lv_label_set_text(lbl, "—");
  }
}

// ============================================================
// Periodic data-refresh timer (fires every second)
// ============================================================
// 10% from 23:00 to 07:00 local time, 80% otherwise (and while the clock isn't synced).
static void updateBrightness() {
  static int lastPct = -1;
  time_t now = time(nullptr);
  int pct = 80;
  if (now > 1700000000) {  // clock synced
    struct tm t;
    localtime_r(&now, &t);
    if (t.tm_hour >= 23 || t.tm_hour < 7) pct = 10;
  }
  if (pct != lastPct) {
    Nv3041aPanel::setBrightness(static_cast<uint8_t>(pct));
    lastPct = pct;
  }
}

static void refreshCb(lv_timer_t* /*t*/) {
  updateBrightness();
  // ---- Stats from DNS service ----
  app::DnsStats    ds  = gCtx.dns->stats();
  app::UpstreamSnapshot us = gCtx.dns->upstreams();
  char buf[32];

  // ---- Overview ----
  fmtInt(buf, sizeof(buf), ds.queries);
  lv_label_set_text(gScr.ovQueries, buf);

  fmtInt(buf, sizeof(buf), ds.blocked);
  lv_label_set_text(gScr.ovBlocked, buf);

  if (ds.queries > 0) {
    snprintf(buf, sizeof(buf), "%.1f%%", 100.0f * ds.blocked / ds.queries);
  } else {
    snprintf(buf, sizeof(buf), "0.0%%");
  }
  lv_label_set_text(gScr.ovRatio, buf);

  auto pct = [&](uint32_t n, lv_obj_t* lbl) {
    if (ds.queries > 0) snprintf(buf, sizeof(buf), "%.0f%%", 100.0f * n / ds.queries);
    else                snprintf(buf, sizeof(buf), "0%%");
    lv_label_set_text(lbl, buf);
  };
  pct(ds.cacheHits, gScr.ovCache);
  pct(ds.forwarded, gScr.ovFwd);
  pct(ds.local, gScr.ovLocal);

  // Avg latency from upstream stats (last_latency of best upstream).
  uint32_t latency = 0;
  for (size_t i = 0; i < us.count; ++i) {
    if (us.status[i].state == upstream::HealthState::kUp) {
      latency = us.status[i].stats.lastLatencyMs;
      break;
    }
  }
  snprintf(buf, sizeof(buf), "%lums", (unsigned long)latency);
  lv_label_set_text(gScr.ovLatency, buf);

  // Uptime.
  uint32_t sec  = millis() / 1000;
  uint32_t days = sec / 86400; sec %= 86400;
  uint32_t hrs  = sec / 3600;  sec %= 3600;
  uint32_t mins = sec / 60;
  snprintf(buf, sizeof(buf), "System Uptime %02lu:%02lu:%02lu", (unsigned long)days, (unsigned long)hrs,
           (unsigned long)mins);  // DD:HH:MM
  lv_label_set_text(gScr.ovUptime, buf);

  // ---- Queries-per-minute chart ----
  {
    DisplayStats::MinuteBucket mins[DisplayStats::kMinuteBuckets];
    gCtx.stats->copyMinutes(millis(), mins);
    int32_t maxQ = 5;
    for (size_t i = 0; i < DisplayStats::kMinuteBuckets; ++i) {
      maxQ = std::max<int32_t>(maxQ, std::max<int32_t>(mins[i].allowed, mins[i].blocked));
    }
    lv_chart_set_range(gScr.ovChart, LV_CHART_AXIS_PRIMARY_Y, 0, maxQ);
    for (size_t i = 0; i < DisplayStats::kMinuteBuckets; ++i) {
      lv_chart_set_value_by_id(gScr.ovChart, gScr.ovSeries1, (uint16_t)i,
                               static_cast<int32_t>(mins[i].allowed));
      lv_chart_set_value_by_id(gScr.ovChart, gScr.ovSeries2, (uint16_t)i,
                               static_cast<int32_t>(mins[i].blocked));
    }
    snprintf(buf, sizeof(buf), "max %ld", (long)maxQ);
    lv_label_set_text(gScr.ovChartMax, buf);
    lv_chart_refresh(gScr.ovChart);
  }
  // ---- Recent query log (last 4, newest last) ----
  {
    DisplayStats::QueryEvent log[DisplayStats::kLogCapacity];
    size_t count;
    gCtx.stats->copyLog(log, &count);
    // Show the 4 most-recent entries.
    int start = (count >= 4) ? (int)count - 4 : 0;
    for (int i = 0; i < 4; ++i) {
      lv_obj_t* row = gScr.ovLog[i];
      lv_obj_t* lbl = lv_obj_get_child(row, 0);
      int idx = start + i;
      if (idx < (int)count) {
        const auto& ev = log[idx];
        // Convert network-byte-order IP to dotted-decimal without lwip/inet.h.
        uint32_t h    = ntohl(ev.clientIp);
        char ipBuf[16];
        snprintf(ipBuf, sizeof(ipBuf), "%lu.%lu.%lu.%lu",
                 (unsigned long)((h >> 24) & 0xFF), (unsigned long)((h >> 16) & 0xFF),
                 (unsigned long)((h >>  8) & 0xFF), (unsigned long)( h        & 0xFF));
        // Show only last two octets (e.g. ".1.5") to save space.
        const char* dot2 = strrchr(ipBuf, '.');
        const char* dot1 = (dot2 && dot2 > ipBuf) ? strrchr(ipBuf, '.') : nullptr;
        const char* shortIp = (dot1 && dot1 < dot2) ? dot1 : ipBuf;
        snprintf(buf, sizeof(buf), "%-30s  %-7s  %s",
                 ev.domain[0] ? ev.domain : "?",
                 ev.blocked ? "blocked" : "allowed",
                 shortIp);
        lv_obj_set_style_text_color(lbl, ev.blocked ? kColBlocked : kColAllowed, LV_PART_MAIN);
        lv_label_set_text(lbl, buf);
      } else {
        lv_label_set_text(lbl, "");
      }
    }
  }

  // ---- Top Blocked ----
  {
    DisplayStats::TopDomain top[DisplayStats::kTopDomainsN];
    size_t topCount;
    gCtx.stats->copyTopDomains(top, &topCount);
    uint32_t maxCount = topCount > 0 ? top[0].count : 1;

    for (int i = 0; i < 8; ++i) {
      if (i < (int)topCount && top[i].count > 0) {
        // Build a simple ASCII bar (scale to 20 chars max).
        int bars = (int)(20 * top[i].count / maxCount);
        char bar[22]; memset(bar, '\xE2', bars); bar[bars] = '\0';  // filled square approx
        fmtInt(buf, sizeof(buf), top[i].count);
        char row[80];
        snprintf(row, sizeof(row), "%-30s  %5s", top[i].name, buf);
        lv_obj_set_style_text_color(gScr.tbRows[i], kColBlocked, LV_PART_MAIN);
        lv_label_set_text(gScr.tbRows[i], row);
      } else {
        lv_label_set_text(gScr.tbRows[i], "—");
        lv_obj_set_style_text_color(gScr.tbRows[i], kColSubtext, LV_PART_MAIN);
      }
    }
  }

}

// ============================================================
// Display task entry point
// ============================================================
static void displayTaskEntry(void* arg) {
  // 1. Hardware init.
  Wire.begin(8 /*SDA*/, 4 /*SCL*/);
  Gt911Touch::instance().init();

  lv_init();
  lv_tick_set_cb([]() -> uint32_t { return millis(); });  // LVGL 9 has no LV_TICK_CUSTOM

  lv_display_t* disp = nullptr;
  if (!Nv3041aPanel::instance().init(&disp)) {
    // Display init failed — task has nothing to do.
    vTaskDelete(nullptr);
    return;
  }

  // 2. Register touch input device.
  lv_indev_t* indev = lv_indev_create();
  lv_indev_set_type(indev, LV_INDEV_TYPE_POINTER);
  lv_indev_set_read_cb(indev, Gt911Touch::readCb);

  // 3. Build all screens.
  buildOverview();
  buildTopBlocked();

  // 4. Load the overview screen.
  lv_screen_load(gScr.ovRoot);

  // 5. Start a 1-second refresh timer.
  lv_timer_create(refreshCb, 1000, nullptr);

  // 6. LVGL tick loop (~5 ms period).
  while (true) {
    lv_timer_handler();
    vTaskDelay(pdMS_TO_TICKS(5));
  }
}

void spawnDisplayTask(const DisplayContext& ctx) {
  gCtx = ctx;
  xTaskCreatePinnedToCore(displayTaskEntry, "display", 12 * 1024,
                          nullptr, 1, nullptr, 1 /*Core 1: keeps QSPI off the web-task core*/);
}

}  // namespace display
