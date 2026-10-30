#pragma once
// GT911 capacitive touch controller driver (I2C polling).
// Hardware (Guition JC4827W543C): SCL=4, SDA=8, INT=3, RST=38.
// ESPHome had mirror_x=true + mirror_y=true for this panel, which we apply here.

#include <cstdint>
#include <lvgl.h>

namespace display {

class Gt911Touch {
 public:
  bool init();  // Call after Wire.begin(). Returns false if the device doesn't ACK.

  // LVGL input-device read callback.
  static void readCb(lv_indev_t* indev, lv_indev_data_t* data);

  static Gt911Touch& instance() { return instance_; }

 private:
  static Gt911Touch instance_;

  static constexpr uint8_t kAddr   = 0x5D;
  static constexpr int     kRstPin = 38;
  static constexpr int     kIntPin = 3;

  bool    readReg(uint16_t reg, uint8_t* buf, size_t len);
  bool    writeReg(uint16_t reg, uint8_t val);
  bool    readTouch(int16_t& x, int16_t& y);  // true = finger down

  bool    present_ = false;
};

}  // namespace display
