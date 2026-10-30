#include "display/panel/nv3041a.h"

#include <Arduino.h>
#include <esp_heap_caps.h>

namespace display {

Nv3041aPanel Nv3041aPanel::instance_;

// Draw buffer size: 480 × 20 lines × 2 bytes (RGB565).
// Allocated in internal DMA-capable RAM (not PSRAM).
static constexpr size_t kBufLines = 20;
static constexpr size_t kBufBytes = kLcdWidth * kBufLines * sizeof(uint16_t);

static uint8_t* sBuf1 = nullptr;
static uint8_t* sBuf2 = nullptr;

bool Nv3041aPanel::init(lv_display_t** dispOut) {
  // ---- QSPI bus + NV3041A panel (Arduino_GFX) ----
  bus_ = new Arduino_ESP32QSPI(kPinCs, kPinClk, kPinD0, kPinD1, kPinD2, kPinD3);
  // rotation=2 (180°) + IPS=true matches the ESPHome invert_colors + MADCTL setup.
  gfx_ = new Arduino_NV3041A(bus_, GFX_NOT_DEFINED /*RST*/, 2 /*rotation*/, true /*IPS*/);
  if (!gfx_->begin()) return false;

  // ---- Backlight (GPIO1) — Arduino-ESP32 3.x pin-based LEDC API ----
  ledcAttach(kPinBl, 1000, 8);
  ledcWrite(kPinBl, 255);

  // ---- LVGL draw buffers in internal DMA RAM ----
  sBuf1 = static_cast<uint8_t*>(heap_caps_malloc(kBufBytes, MALLOC_CAP_INTERNAL | MALLOC_CAP_DMA));
  sBuf2 = static_cast<uint8_t*>(heap_caps_malloc(kBufBytes, MALLOC_CAP_INTERNAL | MALLOC_CAP_DMA));
  if (!sBuf1 || !sBuf2) return false;

  // ---- Register LVGL display ----
  lv_display_t* disp = lv_display_create(kLcdWidth, kLcdHeight);
  lv_display_set_color_format(disp, LV_COLOR_FORMAT_RGB565_SWAPPED);  // big-endian for NV3041A
  lv_display_set_flush_cb(disp, flushCb);
  lv_display_set_buffers(disp, sBuf1, sBuf2, kBufBytes, LV_DISPLAY_RENDER_MODE_PARTIAL);
  lv_display_set_user_data(disp, this);

  if (dispOut) *dispOut = disp;
  return true;
}

void Nv3041aPanel::flushCb(lv_display_t* disp, const lv_area_t* area, uint8_t* pxMap) {
  auto* self = static_cast<Nv3041aPanel*>(lv_display_get_user_data(disp));
  int32_t w  = area->x2 - area->x1 + 1;
  int32_t h  = area->y2 - area->y1 + 1;
  self->gfx_->draw16bitRGBBitmap(area->x1, area->y1,
                                  reinterpret_cast<uint16_t*>(pxMap), w, h);
  lv_display_flush_ready(disp);
}

}  // namespace display
