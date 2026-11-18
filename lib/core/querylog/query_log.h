#pragma once
// Text format and file naming of the blocked-query log kept on the SD card
// (one CSV file per local day, old days pruned). Pure functions, no I/O, so the
// ESP32 writer in src/platform/sd_log.* stays thin and this part is tested natively.
//
//   /log/2026-11-17.csv
//   time,client,domain,reason
//   2026-11-17 22:30:02,192.168.1.20,ads.example.com,blocklist
//   2026-11-17 22:30:07,192.168.1.20,metrics.site.com,cname

#include <cstddef>
#include <cstdint>

#include "util/civil_time.h"

namespace querylog {

constexpr const char* kDir = "/log";
constexpr const char* kHeader = "time,client,domain,reason\n";
constexpr int kKeepDays = 30;
constexpr size_t kMaxLineLen = 320;  // longest formatLine() output

enum class Reason : uint8_t {
  kBlocked,  // the name itself is on a list
  kCname,    // an answer's CNAME target is on a list
};

// "time,client,domain,reason\n" into `out` (NUL-terminated). `clientIp` is in network
// byte order as lwIP stores it. The domain is sanitised (anything but letters, digits
// and . - _ becomes '?'). Returns the length, or 0 if `cap` is too small.
size_t formatLine(char* out, size_t cap, const util::CivilTime& t, uint32_t clientIp, const char* domain,
                  size_t domainLen, Reason reason);

// "/log/2026-11-17.csv"; returns the length, or 0 if `cap` is too small.
size_t dayFilePath(char* out, size_t cap, const util::CivilTime& t);

// Days since 1970-01-01 of the date in a file name like "2026-11-17.csv" (a leading
// directory is ignored). False if `name` is not a log file name.
bool parseDayFileName(const char* name, int32_t* dayNum);

// True if a log from `fileDay` is older than `keepDays` days as of `today`.
bool expired(int32_t fileDay, int32_t today, int keepDays);

}  // namespace querylog
