#include "display/panel/gt911_touch.h"
#include "display/panel/nv3041a.h"

#include <Arduino.h>
#include <Wire.h>

namespace display {

Gt911Touch Gt911Touch::instance_;

bool Gt911Touch::init() {
  // Reset GT911: drive RST low for 10 ms, then high.  INT floats → I2C addr 0x5D.
  pinMode(kIntPin, INPUT);
  pinMode(kRstPin, OUTPUT);
  digitalWrite(kRstPin, LOW);
  delay(10);
  digitalWrite(kRstPin, HIGH);
  delay(50);

  // Verify device responds.
  Wire.beginTransmission(kAddr);
  present_ = (Wire.endTransmission() == 0);
  return present_;
}

bool Gt911Touch::readReg(uint16_t reg, uint8_t* buf, size_t len) {
  Wire.beginTransmission(kAddr);
  Wire.write(static_cast<uint8_t>(reg >> 8));
  Wire.write(static_cast<uint8_t>(reg & 0xFF));
  if (Wire.endTransmission(false) != 0) return false;
  if (Wire.requestFrom(kAddr, static_cast<uint8_t>(len)) != len) return false;
  for (size_t i = 0; i < len; ++i) buf[i] = Wire.read();
  return true;
}

bool Gt911Touch::writeReg(uint16_t reg, uint8_t val) {
  Wire.beginTransmission(kAddr);
  Wire.write(static_cast<uint8_t>(reg >> 8));
  Wire.write(static_cast<uint8_t>(reg & 0xFF));
  Wire.write(val);
  return Wire.endTransmission() == 0;
}

bool Gt911Touch::readTouch(int16_t& x, int16_t& y) {
  if (!present_) return false;

  uint8_t status;
  if (!readReg(0x814E, &status, 1)) return false;

  uint8_t touchCount = status & 0x0F;
  bool    valid      = (status & 0x80) != 0;

  // Clear the status register regardless.
  writeReg(0x814E, 0x00);

  if (!valid || touchCount == 0) return false;

  // Read first touch point: [x_lo, x_hi, y_lo, y_hi, size_lo, size_hi].
  uint8_t pt[6];
  if (!readReg(0x8150, pt, 6)) return false;

  int16_t rawX = static_cast<int16_t>(pt[0] | (pt[1] << 8));
  int16_t rawY = static_cast<int16_t>(pt[2] | (pt[3] << 8));

  // ESPHome had mirror_x=true + mirror_y=true for this panel.
  x = static_cast<int16_t>(kLcdWidth  - 1 - rawX);
  y = static_cast<int16_t>(kLcdHeight - 1 - rawY);

  return true;
}

void Gt911Touch::readCb(lv_indev_t* /*indev*/, lv_indev_data_t* data) {
  int16_t x, y;
  if (instance_.readTouch(x, y)) {
    data->point.x = x;
    data->point.y = y;
    data->state   = LV_INDEV_STATE_PRESSED;
  } else {
    data->state = LV_INDEV_STATE_RELEASED;
  }
}

}  // namespace display
