#include "platform/sd_log.h"

#include <FS.h>
#include <SD.h>

#include <cstring>
#include <ctime>

namespace platform {

namespace {

constexpr size_t kQueueLen = 48;
constexpr uint32_t kRemountMs = 30000;
constexpr uint32_t kBatchMs = 2000;
constexpr time_t kMinSaneEpoch = 1700000000;  // before this the clock has not synced

util::CivilTime civil(time_t t) {
  struct tm tmv;
  localtime_r(&t, &tmv);
  util::CivilTime c;
  c.year = tmv.tm_year + 1900;
  c.month = tmv.tm_mon + 1;
  c.day = tmv.tm_mday;
  c.hour = tmv.tm_hour;
  c.minute = tmv.tm_min;
  c.second = tmv.tm_sec;
  return c;
}

int32_t dayOf(const util::CivilTime& c) {
  return static_cast<int32_t>(util::unixFromCivil(c, 0) / 86400);
}

}  // namespace

void SdBlockLog::begin() {
  queue_ = xQueueCreate(kQueueLen, sizeof(Item));
  if (!queue_) return;
  xTaskCreatePinnedToCore(taskEntry, "sd_log", 6144, this, 1, nullptr, 0);
}

void SdBlockLog::setEnabled(bool on) {
  if (on == enabled_) return;
  if (on) lastMountTry_ = 0;  // try the card at the next tick
  enabled_ = on;
}

void SdBlockLog::record(const char* domain, size_t len, uint32_t clientIp, querylog::Reason reason) {
  if (!enabled_ || !queue_) return;
  Item it;
  it.epoch = static_cast<uint32_t>(time(nullptr));
  it.clientIp = clientIp;
  it.len = static_cast<uint8_t>(len < sizeof(it.domain) ? len : sizeof(it.domain) - 1);
  it.reason = static_cast<uint8_t>(reason);
  memcpy(it.domain, domain, it.len);
  if (xQueueSend(queue_, &it, 0) != pdTRUE) dropped_++;
}

SdBlockLog::Status SdBlockLog::status() const {
  Status s;
  s.state = state_;
  s.logged = logged_;
  s.dropped = dropped_;
  if (s.state == State::kReady) s.totalBytes = card_.totalBytes();
  return s;
}

void SdBlockLog::taskEntry(void* self) {
  static_cast<SdBlockLog*>(self)->run();
}

bool SdBlockLog::ensureDir() {
  LockGuard lock(card_.lock());
  if (!SD.exists(querylog::kDir)) SD.mkdir(querylog::kDir);
  return SD.exists(querylog::kDir);
}

void SdBlockLog::prune(int32_t today) {
  // Collect first, delete after: removing while iterating a FAT directory skips entries.
  char doomed[kMaxDays][16];
  size_t n = 0;
  File dir = SD.open(querylog::kDir);
  if (!dir) return;
  while (File f = dir.openNextFile()) {
    const char* name = f.name();
    int32_t day = 0;
    if (!f.isDirectory() && querylog::parseDayFileName(name, &day) &&
        querylog::expired(day, today, querylog::kKeepDays) && n < kMaxDays)
      snprintf(doomed[n++], sizeof(doomed[0]), "%s", name);
    f.close();
  }
  dir.close();
  for (size_t i = 0; i < n; i++) {
    char path[40];
    snprintf(path, sizeof(path), "%s/%s", querylog::kDir, doomed[i]);
    SD.remove(path);
  }
}

bool SdBlockLog::append(const Item& it, char* line) {
  const util::CivilTime t = civil(static_cast<time_t>(it.epoch));
  char path[32];
  if (!querylog::dayFilePath(path, sizeof(path), t)) return false;
  const bool fresh = !SD.exists(path);
  File f = SD.open(path, FILE_APPEND);
  if (!f) return false;
  bool ok = true;
  if (fresh) ok = f.print(querylog::kHeader) > 0;
  const size_t n = querylog::formatLine(line, querylog::kMaxLineLen, t, it.clientIp, it.domain, it.len,
                                        static_cast<querylog::Reason>(it.reason));
  ok = ok && n > 0 && f.write(reinterpret_cast<const uint8_t*>(line), n) == n;
  f.close();
  return ok;
}

void SdBlockLog::run() {
  char line[querylog::kMaxLineLen];
  int32_t prunedDay = -1;
  while (true) {
    vTaskDelay(pdMS_TO_TICKS(kBatchMs));
    if (!enabled_) {
      // Nothing to write; drain what was queued just before switching off.
      Item discard;
      while (xQueueReceive(queue_, &discard, 0) == pdTRUE) {
      }
      state_ = State::kOff;  // the card stays mounted: the blocklist may live on it
      continue;
    }
    if (state_ != State::kReady) {
      const uint32_t now = millis();
      if (lastMountTry_ && now - lastMountTry_ < kRemountMs) {
        Item discard;  // no card: don't let the queue hold stale entries for minutes
        while (xQueueReceive(queue_, &discard, 0) == pdTRUE) dropped_++;
        continue;
      }
      lastMountTry_ = now ? now : 1;
      if (state_ == State::kError) card_.unmount();
      state_ = card_.mount() && ensureDir() ? State::kReady : State::kNoCard;
      if (state_ == State::kReady) prunedDay = -1;
      if (state_ != State::kReady) continue;
    }
    Item it;
    bool failed = false;
    while (!failed && xQueueReceive(queue_, &it, 0) == pdTRUE) {
      if (static_cast<time_t>(it.epoch) < kMinSaneEpoch) {  // clock not synced yet
        dropped_++;
        continue;
      }
      LockGuard lock(card_.lock());
      if (!append(it, line)) {
        failed = true;
        dropped_++;
      } else {
        logged_++;
        const int32_t today = dayOf(civil(static_cast<time_t>(it.epoch)));
        if (today != prunedDay) {
          prune(today);
          prunedDay = today;
        }
      }
    }
    if (failed) {
      state_ = State::kError;
      lastMountTry_ = millis() ? millis() : 1;
    }
  }
}

bool SdBlockLog::listDays(DayFile* out, size_t cap, size_t* count) {
  *count = 0;
  LockGuard lock(card_.lock());
  if (state_ != State::kReady) return false;
  File dir = SD.open(querylog::kDir);
  if (!dir) return false;
  while (File f = dir.openNextFile()) {
    if (!f.isDirectory() && querylog::parseDayFileName(f.name(), nullptr) && *count < cap) {
      snprintf(out[*count].name, sizeof(out[*count].name), "%s", f.name());
      out[*count].bytes = static_cast<uint32_t>(f.size());
      ++*count;
    }
    f.close();
  }
  dir.close();
  return true;
}

bool SdBlockLog::readDay(const char* name, uint32_t offset, uint8_t* buf, size_t cap, size_t* got) {
  *got = 0;
  if (!querylog::parseDayFileName(name, nullptr) || strchr(name, '/')) return false;  // no path tricks
  char path[40];
  snprintf(path, sizeof(path), "%s/%s", querylog::kDir, name);
  LockGuard lock(card_.lock());
  if (state_ != State::kReady) return false;
  File f = SD.open(path, FILE_READ);
  if (!f) return false;
  bool ok = f.seek(offset);
  if (ok) *got = f.read(buf, cap);
  f.close();
  return ok;
}

bool SdBlockLog::clearAll() {
  DayFile days[kMaxDays];
  size_t n = 0;
  if (!listDays(days, kMaxDays, &n)) return false;
  LockGuard lock(card_.lock());
  if (state_ != State::kReady) return false;
  bool ok = true;
  for (size_t i = 0; i < n; i++) {
    char path[40];
    snprintf(path, sizeof(path), "%s/%s", querylog::kDir, days[i].name);
    ok = SD.remove(path) && ok;
  }
  return ok;
}

}  // namespace platform
