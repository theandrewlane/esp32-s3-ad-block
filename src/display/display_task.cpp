// Arduino.h must come first — it configures macros needed by ESP32 headers.
#include <Arduino.h>
#include <Wire.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <algorithm>
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
  lv_obj_t* ovLog[4]        = {};           // 4 recent-query rows
  lv_obj_t* ovUpDot[2]      = {};           // upstream status dots
  lv_obj_t* ovUptime        = nullptr;

  // --- Top Blocked ---
  lv_obj_t* tbRoot          = nullptr;
  lv_obj_t* tbRows[8]       = {};  // label for each row

  // --- Top Clients ---
  lv_obj_t* tcRoot          = nullptr;
  lv_obj_t* tcTable         = nullptr;

  // Navigation dots on each screen
  lv_obj_t* ovDots[3]       = {};
  lv_obj_t* tbDots[3]       = {};
  lv_obj_t* tcDots[3]       = {};
};

static DisplayContext gCtx;
static Screens        gScr;
static int            gCurrentScreen = 0;  // 0=overview, 1=top-blocked, 2=top-clients

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

static lv_obj_t* makeDot(lv_obj_t* parent, bool active) {
  lv_obj_t* d = lv_obj_create(parent);
  lv_obj_set_size(d, 8, 8);
  lv_obj_set_style_radius(d, 4, LV_PART_MAIN);
  lv_obj_set_style_bg_color(d, active ? kColText : kColSubtext, LV_PART_MAIN);
  lv_obj_set_style_bg_opa(d, LV_OPA_COVER, LV_PART_MAIN);
  lv_obj_set_style_border_width(d, 0, LV_PART_MAIN);
  return d;
}

// Format an integer with comma-thousands separator into buf.
static void fmtInt(char* buf, size_t bufsz, uint32_t v) {
  if (v < 1000) {
    snprintf(buf, bufsz, "%lu", (unsigned long)v);
  } else if (v < 1000000) {
    snprintf(buf, bufsz, "%lu,%03lu", (unsigned long)(v / 1000), (unsigned long)(v % 1000));
  } else {
    snprintf(buf, bufsz, "%lu.%luM", (unsigned long)(v / 1000000),
             (unsigned long)((v % 1000000) / 100000));
  }
}

// Cycle to the next screen on tap.
static void screenTapCb(lv_event_t* /*e*/) {
  gCurrentScreen = (gCurrentScreen + 1) % 3;
  lv_obj_t* next = nullptr;
  if (gCurrentScreen == 0) next = gScr.ovRoot;
  else if (gCurrentScreen == 1) next = gScr.tbRoot;
  else                           next = gScr.tcRoot;
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
  lv_label_set_text(title, "DNS AdBlock");
  lv_obj_set_pos(title, 0, 1);

  // Upstream dots
  for (int i = 0; i < 2; ++i) {
    gScr.ovUpDot[i] = lv_obj_create(hdr);
    lv_obj_set_size(gScr.ovUpDot[i], 10, 10);
    lv_obj_set_style_radius(gScr.ovUpDot[i], 5, LV_PART_MAIN);
    lv_obj_set_style_bg_opa(gScr.ovUpDot[i], LV_OPA_COVER, LV_PART_MAIN);
    lv_obj_set_style_bg_color(gScr.ovUpDot[i], kColUnknown, LV_PART_MAIN);
    lv_obj_set_style_border_width(gScr.ovUpDot[i], 0, LV_PART_MAIN);
    lv_obj_set_pos(gScr.ovUpDot[i], 260 + i * 16, 5);
  }

  gScr.ovUptime = makeLabel(hdr, &lv_font_montserrat_12, kColSubtext, LV_TEXT_ALIGN_RIGHT);
  lv_obj_set_size(gScr.ovUptime, 160, 20);
  lv_obj_align(gScr.ovUptime, LV_ALIGN_RIGHT_MID, -4, 0);

  // Navigation dots (top-right area after uptime)
  for (int i = 0; i < 3; ++i) {
    gScr.ovDots[i] = makeDot(hdr, i == 0);
    lv_obj_set_pos(gScr.ovDots[i], 430 + i * 10, 13);
  }

  // ---- Stat cards (y=36, h=64) ----
  const char* cardLabels[] = {"QUERIES", "BLOCKED", "RATIO", "LATENCY"};
  lv_obj_t** cardVals[]    = {&gScr.ovQueries, &gScr.ovBlocked, &gScr.ovRatio, &gScr.ovLatency};
  static const lv_color_t cardValCols[] = {kColAccent, kColBlocked, kColAllowed, kColSubtext};

  for (int i = 0; i < 4; ++i) {
    lv_obj_t* card = lv_obj_create(scr);
    lv_obj_set_size(card, 118, 62);
    lv_obj_set_pos(card, 2 + i * 120, 36);
    applyCard(card);
    lv_obj_clear_flag(card, LV_OBJ_FLAG_SCROLLABLE);

    *cardVals[i] = makeLabel(card, &lv_font_montserrat_20, cardValCols[i],
                             LV_TEXT_ALIGN_CENTER);
    lv_obj_set_size(*cardVals[i], 110, 28);
    lv_obj_set_pos(*cardVals[i], 0, 4);

    lv_obj_t* lbl = makeLabel(card, &lv_font_montserrat_12, kColSubtext, LV_TEXT_ALIGN_CENTER);
    lv_obj_set_size(lbl, 110, 18);
    lv_obj_set_pos(lbl, 0, 36);
    lv_label_set_text(lbl, cardLabels[i]);
  }

  // ---- 24h bar chart (y=100, h=96) ----
  lv_obj_t* chart = lv_chart_create(scr);
  gScr.ovChart    = chart;
  lv_obj_set_size(chart, 476, 92);
  lv_obj_set_pos(chart, 2, 100);
  lv_chart_set_type(chart, LV_CHART_TYPE_BAR);
  lv_chart_set_point_count(chart, DisplayStats::kHourlyBuckets);
  applyBg(chart, kColCard);
  lv_obj_set_style_radius(chart, 4, LV_PART_MAIN);
  lv_obj_set_style_pad_all(chart, 4, LV_PART_MAIN);
  lv_chart_set_div_line_count(chart, 3, 0);
  lv_obj_set_style_line_color(chart, LV_COLOR_MAKE(0x40, 0x40, 0x50), LV_PART_MAIN);

  gScr.ovSeries1 = lv_chart_add_series(chart, kColAccent,  LV_CHART_AXIS_PRIMARY_Y);
  gScr.ovSeries2 = lv_chart_add_series(chart, kColBlocked, LV_CHART_AXIS_PRIMARY_Y);

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

  for (int i = 0; i < 3; ++i) {
    gScr.tbDots[i] = makeDot(hdr, i == 1);
    lv_obj_set_pos(gScr.tbDots[i], 430 + i * 10, 13);
  }

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
// Screen 2: Top Clients
// ============================================================
static void buildTopClients() {
  lv_obj_t* scr  = lv_obj_create(nullptr);
  gScr.tcRoot    = scr;
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
  lv_label_set_text(title, "Top Clients");
  lv_obj_set_pos(title, 0, 1);

  for (int i = 0; i < 3; ++i) {
    gScr.tcDots[i] = makeDot(hdr, i == 2);
    lv_obj_set_pos(gScr.tcDots[i], 430 + i * 10, 13);
  }

  // Table
  lv_obj_t* tbl = lv_table_create(scr);
  gScr.tcTable  = tbl;
  lv_obj_set_size(tbl, 476, 234);
  lv_obj_set_pos(tbl, 2, 36);
  lv_obj_set_style_text_font(tbl, &lv_font_montserrat_12, LV_PART_MAIN);
  lv_obj_set_style_text_font(tbl, &lv_font_montserrat_12, LV_PART_ITEMS);
  applyBg(tbl, kColCard);
  lv_obj_set_style_pad_hor(tbl, 0, LV_PART_MAIN);
  lv_obj_set_style_pad_ver(tbl, 0, LV_PART_MAIN);
  lv_obj_set_style_border_width(tbl, 0, LV_PART_MAIN);

  // Column widths: IP(160) Queries(80) Blocked(80) %(72)
  lv_table_set_col_cnt(tbl, 4);
  lv_table_set_col_width(tbl, 0, 160);
  lv_table_set_col_width(tbl, 1, 90);
  lv_table_set_col_width(tbl, 2, 90);
  lv_table_set_col_width(tbl, 3, 80);

  lv_table_set_cell_value(tbl, 0, 0, "Client IP");
  lv_table_set_cell_value(tbl, 0, 1, "Queries");
  lv_table_set_cell_value(tbl, 0, 2, "Blocked");
  lv_table_set_cell_value(tbl, 0, 3, "Rate");

  // Rows 1..8 filled by refresh callback.
  lv_table_set_row_cnt(tbl, 9);
  for (uint16_t r = 1; r < 9; ++r) {
    for (uint16_t c = 0; c < 4; ++c) {
      lv_table_set_cell_value(tbl, r, c, "");
    }
  }
}

// ============================================================
// Periodic data-refresh timer (fires every second)
// ============================================================
static void refreshCb(lv_timer_t* /*t*/) {
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

  // Upstream status dots.
  for (size_t i = 0; i < 2; ++i) {
    if (i >= us.count) {
      lv_obj_set_style_bg_color(gScr.ovUpDot[i], kColUnknown, LV_PART_MAIN);
      continue;
    }
    upstream::HealthState state = us.status[i].state;
    lv_color_t col = (state == upstream::HealthState::kUp)    ? kColUp :
                     (state == upstream::HealthState::kDown)   ? kColDown : kColUnknown;
    lv_obj_set_style_bg_color(gScr.ovUpDot[i], col, LV_PART_MAIN);
  }

  // Uptime.
  uint32_t sec  = millis() / 1000;
  uint32_t days = sec / 86400; sec %= 86400;
  uint32_t hrs  = sec / 3600;  sec %= 3600;
  uint32_t mins = sec / 60;
  if (days > 0) snprintf(buf, sizeof(buf), "%lud %02lu:%02lu", (unsigned long)days,
                         (unsigned long)hrs, (unsigned long)mins);
  else          snprintf(buf, sizeof(buf), "%02lu:%02lu", (unsigned long)hrs,
                         (unsigned long)mins);
  lv_label_set_text(gScr.ovUptime, buf);

  // ---- 24h chart ----
  {
    DisplayStats::HourlyBucket hourly[DisplayStats::kHourlyBuckets];
    gCtx.stats->copyHourly(hourly);
    uint32_t curHour = (millis() / 3600000UL) % DisplayStats::kHourlyBuckets;
    int32_t maxQ = 1;
    for (size_t i = 0; i < DisplayStats::kHourlyBuckets; ++i) {
      if ((int32_t)hourly[i].queries > maxQ) maxQ = (int32_t)hourly[i].queries;
    }
    lv_chart_set_range(gScr.ovChart, LV_CHART_AXIS_PRIMARY_Y, 0, maxQ);
    // Map bucket[curHour] → rightmost column (index 23 = most recent hour).
    for (size_t i = 0; i < DisplayStats::kHourlyBuckets; ++i) {
      size_t srcBucket = (curHour + 1 + i) % DisplayStats::kHourlyBuckets;
      lv_chart_set_value_by_id(gScr.ovChart, gScr.ovSeries1, (uint16_t)i,
                               static_cast<int32_t>(hourly[srcBucket].queries));
      lv_chart_set_value_by_id(gScr.ovChart, gScr.ovSeries2, (uint16_t)i,
                               static_cast<int32_t>(hourly[srcBucket].blocked));
    }
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

  // ---- Top Clients ----
  {
    auto clients = gCtx.clients->snapshot();
    // Sort by (allowed + blocked) desc.
    std::sort(clients.begin(), clients.end(), [](const app::ClientInfo& a, const app::ClientInfo& b) {
      return (a.allowed + a.blocked) > (b.allowed + b.blocked);
    });

    int rows = std::min<int>(8, (int)clients.size());
    lv_table_set_row_cnt(gScr.tcTable, rows + 1);

    for (int i = 0; i < rows; ++i) {
      const auto& c = clients[i];
      uint32_t h = ntohl(c.ip);
      char ipCell[16];
      snprintf(ipCell, sizeof(ipCell), "%lu.%lu.%lu.%lu",
               (unsigned long)((h >> 24) & 0xFF), (unsigned long)((h >> 16) & 0xFF),
               (unsigned long)((h >>  8) & 0xFF), (unsigned long)( h        & 0xFF));
      lv_table_set_cell_value(gScr.tcTable, i + 1, 0, ipCell);

      char tmp[16];
      fmtInt(tmp, sizeof(tmp), c.allowed + c.blocked);
      lv_table_set_cell_value(gScr.tcTable, i + 1, 1, tmp);

      fmtInt(tmp, sizeof(tmp), c.blocked);
      lv_table_set_cell_value(gScr.tcTable, i + 1, 2, tmp);

      uint32_t total = c.allowed + c.blocked;
      if (total > 0) snprintf(tmp, sizeof(tmp), "%lu%%", (unsigned long)(100UL * c.blocked / total));
      else           snprintf(tmp, sizeof(tmp), "0%%");
      lv_table_set_cell_value(gScr.tcTable, i + 1, 3, tmp);
    }
    // Clear unused rows.
    for (int i = rows; i < 8; ++i) {
      for (int c = 0; c < 4; ++c) lv_table_set_cell_value(gScr.tcTable, i + 1, c, "");
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
  buildTopClients();

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
                          nullptr, 1, nullptr, 0 /*Core 0*/);
}

}  // namespace display
