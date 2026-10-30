#pragma once
// NV3041A 480x272 QSPI display driver.
// Uses Arduino_GFX_Library (Arduino_NV3041A) to drive the panel, so the LVGL
// flush callback only needs to call gfx->draw16bitRGBBitmap().
//
// Hardware (Guition JC4827W543C):
//   CLK=47, D0=21, D1=48, D2=40, D3=39, CS=45, BL=1
//   IPS=true (invert colours), rotation=2 (180°) to match physical mount.

#include <Arduino_GFX_Library.h>
#include <lvgl.h>

namespace display {

// Width × height after accounting for rotation.
static constexpr int16_t kLcdWidth  = 480;
static constexpr int16_t kLcdHeight = 272;

// GPIO assignments (Guition JC4827W543C).
static constexpr int kPinCs  = 45;
static constexpr int kPinClk = 47;
static constexpr int kPinD0  = 21;
static constexpr int kPinD1  = 48;
static constexpr int kPinD2  = 40;
static constexpr int kPinD3  = 39;
static constexpr int kPinBl  = 1;

class Nv3041aPanel {
 public:
  // Initialises the panel, sets backlight to full, registers the LVGL display.
  // Must be called before lv_init().  Returns false on allocation failure.
  bool init(lv_display_t** dispOut);

  // Static flush callback registered with LVGL.
  static void flushCb(lv_display_t* disp, const lv_area_t* area, uint8_t* pxMap);

  static Nv3041aPanel& instance() { return instance_; }

 private:
  static Nv3041aPanel instance_;

  Arduino_ESP32QSPI* bus_  = nullptr;
  Arduino_GFX*       gfx_  = nullptr;
};

}  // namespace display
