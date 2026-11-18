#include "platform/sd_card.h"

#include <SD.h>
#include <SPI.h>

namespace platform {

namespace {
constexpr int kPinCs = 10, kPinMosi = 11, kPinClk = 12, kPinMiso = 13;
constexpr uint32_t kSpiHz = 20000000;
SPIClass sSpi(HSPI);
}  // namespace

bool SdCard::mount() {
  LockGuard g(lock_);
  if (mounted_) return true;
  sSpi.begin(kPinClk, kPinMiso, kPinMosi, kPinCs);
  if (!SD.begin(kPinCs, sSpi, kSpiHz, "/sd", 5, false)) {
    sSpi.end();
    return false;
  }
  total_ = SD.totalBytes();
  mounted_ = true;
  return true;
}

void SdCard::unmount() {
  LockGuard g(lock_);
  if (!mounted_) return;
  SD.end();
  sSpi.end();
  mounted_ = false;
}

}  // namespace platform
