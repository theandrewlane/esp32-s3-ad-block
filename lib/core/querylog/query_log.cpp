#include "querylog/query_log.h"

#include <cstdio>
#include <cstring>

namespace querylog {

namespace {

const char* reasonName(Reason r) {
  return r == Reason::kCname ? "cname" : "blocklist";
}

bool isDigit(char c) {
  return c >= '0' && c <= '9';
}

}  // namespace

size_t formatLine(char* out, size_t cap, const util::CivilTime& t, uint32_t clientIp, const char* domain,
                  size_t domainLen, Reason reason) {
  if (!out || cap == 0) return 0;
  char name[256];
  if (domainLen >= sizeof(name)) domainLen = sizeof(name) - 1;
  for (size_t i = 0; i < domainLen; i++) {
    const char c = domain[i];
    const bool ok =
        (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || isDigit(c) || c == '.' || c == '-' || c == '_';
    name[i] = ok ? c : '?';
  }
  name[domainLen] = '\0';
  uint8_t ip[4];
  memcpy(ip, &clientIp, 4);  // network order: the first byte in memory is the first octet
  const int n =
      snprintf(out, cap, "%04d-%02d-%02d %02d:%02d:%02d,%u.%u.%u.%u,%s,%s\n", t.year, t.month, t.day, t.hour,
               t.minute, t.second, ip[0], ip[1], ip[2], ip[3], name, reasonName(reason));
  if (n < 0 || static_cast<size_t>(n) >= cap) {
    out[0] = '\0';
    return 0;
  }
  return static_cast<size_t>(n);
}

size_t dayFilePath(char* out, size_t cap, const util::CivilTime& t) {
  if (!out || cap == 0) return 0;
  const int n = snprintf(out, cap, "%s/%04d-%02d-%02d.csv", kDir, t.year, t.month, t.day);
  if (n < 0 || static_cast<size_t>(n) >= cap) {
    out[0] = '\0';
    return 0;
  }
  return static_cast<size_t>(n);
}

bool parseDayFileName(const char* name, int32_t* dayNum) {
  if (!name) return false;
  const char* slash = strrchr(name, '/');
  if (slash) name = slash + 1;
  // YYYY-MM-DD.csv
  if (strlen(name) != 14 || strcmp(name + 10, ".csv") != 0) return false;
  for (int i = 0; i < 10; i++) {
    const bool dash = i == 4 || i == 7;
    if (dash ? name[i] != '-' : !isDigit(name[i])) return false;
  }
  const int y = (name[0] - '0') * 1000 + (name[1] - '0') * 100 + (name[2] - '0') * 10 + (name[3] - '0');
  const int m = (name[5] - '0') * 10 + (name[6] - '0');
  const int d = (name[8] - '0') * 10 + (name[9] - '0');
  if (y < 2000 || m < 1 || m > 12 || d < 1 || d > 31) return false;
  if (dayNum) {
    util::CivilTime c;
    c.year = y;
    c.month = m;
    c.day = d;
    *dayNum = static_cast<int32_t>(util::unixFromCivil(c, 0) / 86400);
  }
  return true;
}

bool expired(int32_t fileDay, int32_t today, int keepDays) {
  return today - fileDay >= keepDays;
}

}  // namespace querylog
