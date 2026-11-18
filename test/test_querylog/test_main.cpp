// Tests for lib/core/querylog: CSV line format, day file names, retention.

#include <unity.h>

#include <cstring>
#include <initializer_list>

#include "querylog/query_log.h"
#include "util/civil_time.h"

using namespace querylog;

void setUp() {}
void tearDown() {}

static util::CivilTime at(int y, int mo, int d, int h = 0, int mi = 0, int s = 0) {
  util::CivilTime t;
  t.year = y;
  t.month = mo;
  t.day = d;
  t.hour = h;
  t.minute = mi;
  t.second = s;
  return t;
}

static uint32_t ipNet(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
  const uint8_t bytes[4] = {a, b, c, d};  // lwIP order: first octet first in memory
  uint32_t v;
  memcpy(&v, bytes, 4);
  return v;
}

static void test_line_format() {
  char out[kMaxLineLen];
  const char* d = "ads.example.com";
  size_t n = formatLine(out, sizeof(out), at(2026, 11, 7, 22, 3, 9), ipNet(192, 168, 1, 20), d, strlen(d),
                        Reason::kBlocked);
  TEST_ASSERT_EQUAL_STRING("2026-11-07 22:03:09,192.168.1.20,ads.example.com,blocklist\n", out);
  TEST_ASSERT_EQUAL(strlen(out), n);
  n = formatLine(out, sizeof(out), at(2026, 1, 1), ipNet(10, 0, 0, 1), "m.site.com", 10, Reason::kCname);
  TEST_ASSERT_EQUAL_STRING("2026-01-01 00:00:00,10.0.0.1,m.site.com,cname\n", out);
}

static void test_line_sanitises_the_domain_and_always_fits() {
  char out[kMaxLineLen];
  const char* evil = "a,b\"c\n\x01.com";
  formatLine(out, sizeof(out), at(2026, 1, 1), 0, evil, strlen(evil), Reason::kBlocked);
  TEST_ASSERT_EQUAL_STRING("2026-01-01 00:00:00,0.0.0.0,a?b?c??.com,blocklist\n", out);
  TEST_ASSERT_EQUAL(1, static_cast<int>(strchr(out, '\n') == out + strlen(out) - 1));  // exactly one line

  char longName[400];
  memset(longName, 'a', sizeof(longName));
  const size_t n = formatLine(out, sizeof(out), at(2026, 12, 31, 23, 59, 59), ipNet(255, 255, 255, 255),
                              longName, sizeof(longName), Reason::kCname);
  TEST_ASSERT_GREATER_THAN(0, static_cast<int>(n));  // over-long names are truncated, not dropped
  TEST_ASSERT_LESS_THAN(kMaxLineLen, n);
}

static void test_line_reports_too_small_buffers() {
  char out[8];
  TEST_ASSERT_EQUAL(0, formatLine(out, sizeof(out), at(2026, 1, 1), 0, "a.com", 5, Reason::kBlocked));
  TEST_ASSERT_EQUAL(0, formatLine(nullptr, 10, at(2026, 1, 1), 0, "a.com", 5, Reason::kBlocked));
  TEST_ASSERT_EQUAL(0, formatLine(out, 0, at(2026, 1, 1), 0, "a.com", 5, Reason::kBlocked));
}

static void test_day_file_path() {
  char out[32];
  TEST_ASSERT_EQUAL(19, dayFilePath(out, sizeof(out), at(2026, 3, 9)));
  TEST_ASSERT_EQUAL_STRING("/log/2026-03-09.csv", out);
  char tiny[8];
  TEST_ASSERT_EQUAL(0, dayFilePath(tiny, sizeof(tiny), at(2026, 3, 9)));
}

static void test_parse_day_file_name() {
  int32_t day = 0;
  TEST_ASSERT_TRUE(parseDayFileName("2026-11-17.csv", &day));
  TEST_ASSERT_TRUE(parseDayFileName("/log/2026-11-17.csv", &day));
  int32_t other = 0;
  TEST_ASSERT_TRUE(parseDayFileName("2026-11-18.csv", &other));
  TEST_ASSERT_EQUAL(1, other - day);
  TEST_ASSERT_TRUE(parseDayFileName("2027-01-01.csv", &other));  // across a year boundary
  TEST_ASSERT_TRUE(parseDayFileName("2026-12-31.csv", &day));
  TEST_ASSERT_EQUAL(1, other - day);
  TEST_ASSERT_TRUE(parseDayFileName("2026-11-17.csv", nullptr));

  for (const char* bad :
       {"", "2026-11-17.txt", "2026-13-01.csv", "2026-00-10.csv", "2026-11-00.csv", "2026-11-32.csv",
        "26-11-17.csv", "2026-11-17.csv.tmp", "abcd-ef-gh.csv", "1999-01-01.csv", "../etc/passwd"})
    TEST_ASSERT_FALSE_MESSAGE(parseDayFileName(bad, &day), bad);
  TEST_ASSERT_FALSE(parseDayFileName(nullptr, &day));
}

static void test_retention() {
  int32_t today = 0, old = 0, recent = 0;
  parseDayFileName("2026-11-17.csv", &today);
  parseDayFileName("2026-10-18.csv", &old);     // 30 days ago: pruned
  parseDayFileName("2026-10-19.csv", &recent);  // 29 days ago: kept
  TEST_ASSERT_TRUE(expired(old, today, kKeepDays));
  TEST_ASSERT_FALSE(expired(recent, today, kKeepDays));
  TEST_ASSERT_FALSE(expired(today, today, kKeepDays));
  TEST_ASSERT_FALSE(expired(today + 3, today, kKeepDays));  // a clock that stepped back keeps the file
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_line_format);
  RUN_TEST(test_line_sanitises_the_domain_and_always_fits);
  RUN_TEST(test_line_reports_too_small_buffers);
  RUN_TEST(test_day_file_path);
  RUN_TEST(test_parse_day_file_name);
  RUN_TEST(test_retention);
  return UNITY_END();
}
