#include "web/dashboard.h"

#include <LittleFS.h>
#include <Update.h>
#include <WiFi.h>
#include <mbedtls/base64.h>

#include <ctime>
#include <memory>

#include "platform/restart_info.h"
#include "platform/watchdog.h"
#include "web/page.h"
#include "web/portal.h"

namespace web {

using hal::LogLevel;

namespace {

constexpr const char* kTag = "web";
constexpr const char* kCsrfHeader = "X-Requested-With";
constexpr const char* kCsrfValue = "adblock";
constexpr const char* kUploadTmp = "/upload.tmp";
constexpr const char* kSessionCookie = "ab_session";

// Where the dashboard's "Check for updates" looks for update.json and the firmware
// (published to GitHub Pages by release.yml: Pages sends CORS headers, release
// downloads don't). Forks: point this at their own Pages site.
#ifndef UPDATE_BASE_URL
#define UPDATE_BASE_URL "https://denzilrdz.github.io/esp32-s3-adblock/"
#endif

// The dashboard page may only fetch from the device itself and the update site.
String pageCsp() {
  String csp =
      "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'";
  char origin[96];
  if (auth::urlOrigin(UPDATE_BASE_URL, origin, sizeof(origin))) {
    csp += ' ';
    csp += origin;
  }
  csp += "; frame-ancestors 'none'";
  return csp;
}

String jsonEscape(const String& s) {
  String o;
  o.reserve(s.length() + 2);
  for (char c : s) {
    switch (c) {
      case '"': o += "\\\""; break;
      case '\\': o += "\\\\"; break;
      case '\n': o += "\\n"; break;
      case '\r': o += "\\r"; break;
      case '\t': o += "\\t"; break;
      default:
        if (static_cast<uint8_t>(c) < 0x20) {
          char buf[8];
          snprintf(buf, sizeof(buf), "\\u%04x", c);
          o += buf;
        } else {
          o += c;
        }
    }
  }
  return o;
}

String q(const String& s) {
  return "\"" + jsonEscape(s) + "\"";
}
const char* b(bool v) {
  return v ? "true" : "false";
}

String macString(const uint8_t* m) {
  char s[18];
  snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
  return s;
}

String formatTime(int64_t unixSeconds) {
  if (unixSeconds <= 0) return "never";
  const time_t t = static_cast<time_t>(unixSeconds);
  struct tm tmv;
  localtime_r(&t, &tmv);
  char buf[24];
  strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M", &tmv);
  return buf;
}

// Parses "Authorization: Basic base64(user:pass)".
bool parseBasicAuth(const String& header, String& user, String& pass) {
  if (!header.startsWith("Basic ")) return false;
  const String enc = header.substring(6);
  unsigned char out[192];
  size_t len = 0;
  if (enc.length() > 250 ||
      mbedtls_base64_decode(out, sizeof(out) - 1, &len, reinterpret_cast<const unsigned char*>(enc.c_str()),
                            enc.length()) != 0)
    return false;
  out[len] = 0;
  const char* colon = strchr(reinterpret_cast<const char*>(out), ':');
  if (!colon) return false;
  user = String(reinterpret_cast<const char*>(out)).substring(0, colon - reinterpret_cast<const char*>(out));
  pass = String(colon + 1);
  return true;
}

}  // namespace

void Dashboard::sendPage() {
  WebServer& s = *ctx_.server;
  if (ctx_.alive) ctx_.alive();
  s.sendHeader("Content-Encoding", "gzip");
  // send_P sends headers + body in one shot; NetworkClient::write() retries on
  // backpressure (select+send, up to 10 s) so the full 16 KB goes through without
  // the manual chunking that was causing early RST.
  s.send_P(200, "text/html", reinterpret_cast<PGM_P>(kPageGz), kPageGzLen);
  if (ctx_.alive) ctx_.alive();
}

void Dashboard::uploadProgress() {
  platform::feedWatchdog();  // skipped while the web task is off the hardware watchdog
  if (ctx_.alive) ctx_.alive();
}

void Dashboard::sendText(int code, const String& text) {
  ctx_.server->send(code, "text/plain", text);
}

Dashboard::Check Dashboard::postChecks() {
  WebServer& s = *ctx_.server;
  if (s.method() != HTTP_POST) return {false, 405, "use POST"};
  if (s.header(kCsrfHeader) != kCsrfValue) return {false, 403, "missing X-Requested-With header"};
  if (!auth::originAllowed(s.header("Origin").c_str(), s.header("Referer").c_str(),
                           WiFi.localIP().toString().c_str(), ctx_.hostname))
    return {false, 403, "cross-site request refused"};
  return {true, 200, ""};
}

Dashboard::Check Dashboard::verifyPassword(const String& user, const String& pass) {
  WebServer& s = *ctx_.server;
  const uint32_t client = static_cast<uint32_t>(s.client().remoteIP());
  if (!ctx_.logins->allowed(client)) return {false, 429, "too many failed logins; try again later"};
  if (!ctx_.passwords->verify(user.c_str(), pass.c_str())) {
    ctx_.logins->onFailure(client);
    ctx_.log->log(LogLevel::kWarn, kTag, "failed login from %s", s.client().remoteIP().toString().c_str());
    // Global brute-force brake without a lockout anyone could trigger: the single
    // web task spends a fixed second per failure (on top of PBKDF2), capping
    // guesses at ~1/s in total however many addresses an attacker uses.
    delay(1000);
    return {false, 401, "wrong user name or password"};
  }
  ctx_.logins->onSuccess(client);
  return {true, 200, ""};
}

bool Dashboard::hasSession() {
  char token[auth::SessionStore::kTokenLength + 1];
  return auth::cookieValue(ctx_.server->header("Cookie").c_str(), kSessionCookie, token, sizeof(token)) &&
         ctx_.sessions->valid(token);
}

Dashboard::Check Dashboard::check(Access access) {
  WebServer& s = *ctx_.server;
  if (!auth::hostAllowed(s.header("Host").c_str(), WiFi.localIP().toString().c_str(), ctx_.hostname))
    return {false, 403, "unknown Host header (use the device IP or its .local name)"};
  if (access == Access::kPublic) return {true, 200, ""};
  if (access != Access::kRead) {
    const Check c = postChecks();
    if (!c.ok) return c;
  }
  if (!hasSession()) {
    // Scripts may still send Basic Auth; browsers get a plain 401 and the page's own
    // login form (no WWW-Authenticate, so no browser pop-up).
    String user, pass;
    if (!parseBasicAuth(s.header("Authorization"), user, pass)) return {false, 401, "login required"};
    const Check c = verifyPassword(user, pass);
    if (!c.ok) return c;
  }
  if (ctx_.passwords->mustChange() && access == Access::kAuth)
    return {false, 403, "set a dashboard password first"};
  return {true, 200, ""};
}

bool Dashboard::guard(Access access) {
  const Check c = check(access);
  if (c.ok) return true;
  if (c.code == 429) {
    const uint32_t client = static_cast<uint32_t>(ctx_.server->client().remoteIP());
    ctx_.server->sendHeader("Retry-After", String(ctx_.logins->retryAfterSeconds(client)));
  }
  sendText(c.code, c.message);
  return false;
}

void Dashboard::begin() {
  WebServer& s = *ctx_.server;
  const char* headers[] = {"Host", "Origin", "Referer", "Cookie", kCsrfHeader};
  s.collectHeaders(headers, sizeof(headers) / sizeof(headers[0]));  // Authorization is always kept

  s.on("/", HTTP_GET, [this]() {
    if (!guard(Access::kPublic)) return;
    static const String csp = pageCsp();
    ctx_.server->sendHeader("Content-Security-Policy", csp);
    ctx_.server->sendHeader("X-Frame-Options", "DENY");
    sendPage();
  });
  s.on("/api/stats", HTTP_GET, [this]() { handleStats(); });
  s.on("/api/activity", HTTP_GET, [this]() { handleActivity(); });
  s.on("/api/why", HTTP_GET, [this]() { handleWhy(); });
  s.on("/api/log/files", HTTP_GET, [this]() { handleLogFiles(); });
  s.on("/api/log", HTTP_GET, [this]() { handleLogDownload(); });
  s.on("/api/log/clear", HTTP_POST, [this]() { handleLogClear(); });
  s.on("/api/config", HTTP_GET, [this]() { handleGetConfig(); });
  s.on("/api/config", HTTP_POST, [this]() { handleSetConfig(); });
  s.on("/api/login", HTTP_POST, [this]() { handleLogin(); });
  s.on("/api/logout", HTTP_POST, [this]() { handleLogout(); });
  s.on("/api/password", HTTP_POST, [this]() { handlePassword(); });
  s.on("/api/rules/add", HTTP_POST, [this]() { handleRule(true); });
  s.on("/api/rules/remove", HTTP_POST, [this]() { handleRule(false); });
  s.on("/api/clients/ban", HTTP_POST, [this]() { handleBan(); });
  s.on("/api/blocking/pause", HTTP_POST, [this]() { handlePause(); });
  s.on("/api/blocking/resume", HTTP_POST, [this]() {
    if (!guard(Access::kAuth)) return;
    ctx_.clients->resume();
    sendText(200, "blocking resumed");
  });
  s.on("/api/blocklist/settings", HTTP_POST, [this]() { handleBlocklistSettings(); });
  s.on("/api/blocklist/update", HTTP_POST, [this]() {
    if (!guard(Access::kAuth)) return;
    ctx_.blocklist->requestUpdate();
    sendText(200, "update queued; result appears under Blocklist");
  });
  s.on("/api/cache/flush", HTTP_POST, [this]() {
    if (!guard(Access::kAuth)) return;
    ctx_.dns->flushCache();
    sendText(200, "cache flushed");
  });
  s.on("/api/wifi/forget", HTTP_POST, [this]() {
    if (!guard(Access::kAuth)) return;
    sendText(200, "Wi-Fi forgotten; rebooting into the setup portal");
    forgetWifi();
    delay(500);
    platform::restart("Wi-Fi forgotten (dashboard)");
  });
#ifdef ADBLOCK_SELFTEST
  s.on("/api/selftest", HTTP_POST, [this]() {
    if (!guard(Access::kAuth)) return;
    const String what = ctx_.server->arg("hang");
    sendText(200, "self-test: hanging " + what);
    ctx_.server->client().stop();  // the answer must leave before a web-task hang
    if (ctx_.selftest) ctx_.selftest(what);
  });
#endif
  s.on("/api/reboot", HTTP_POST, [this]() {
    if (!guard(Access::kAuth)) return;
    sendText(200, "rebooting");
    delay(500);
    platform::restart("Reboot button (dashboard)");
  });
  s.on(
      "/api/blocklist/upload", HTTP_POST, [this]() { handleListUploadDone(); },
      [this]() { handleListUpload(); });
  s.on(
      "/api/firmware", HTTP_POST, [this]() { handleFirmwareUploadDone(); },
      [this]() { handleFirmwareUpload(); });
  s.onNotFound([this]() {
    if (guard(Access::kPublic)) sendText(404, "not found");
  });
}

// Recent queries (newest first) and the most blocked names, for the Activity tab.
void Dashboard::handleActivity() {
  if (!guard(Access::kRead)) return;
  using display::DisplayStats;
  String j;
  j.reserve(8192);
  j += "{\"recent\":[";
  if (ctx_.activity) {
    std::unique_ptr<DisplayStats::QueryEvent[]> log(new DisplayStats::QueryEvent[DisplayStats::kLogCapacity]);
    size_t n = 0;
    ctx_.activity->copyLog(log.get(), &n);
    const uint32_t now = millis();
    for (size_t i = n; i-- > 0;) {  // the copy is oldest first
      const DisplayStats::QueryEvent& e = log[i];
      if (i + 1 != n) j += ",";
      j += "{\"d\":" + q(e.domain) + ",\"ip\":" + q(IPAddress(e.clientIp).toString()) +
           ",\"ago\":" + String((now - e.timeMs) / 1000) + ",\"blocked\":" + b(e.blocked) + "}";
    }
  }
  j += "],\"top\":[";
  if (ctx_.activity) {
    DisplayStats::TopDomain top[DisplayStats::kTopDomainsN];
    size_t n = 0;
    ctx_.activity->copyTopDomains(top, &n);
    for (size_t i = 0; i < n; i++)
      j += (i ? "," : "") + String("{\"d\":") + q(top[i].name) + ",\"n\":" + String(top[i].count) + "}";
  }
  j += "]}";
  ctx_.server->send(200, "application/json", j);
}

// "Why was this blocked?": which rule decides a name (same logic as the DNS path).
void Dashboard::handleWhy() {
  if (!guard(Access::kRead)) return;
  String name = ctx_.server->arg("name");
  name.trim();
  name.toLowerCase();
  if (name.endsWith(".")) name.remove(name.length() - 1);
  bool valid = name.length() > 0 && name.length() <= 253;
  for (size_t i = 0; valid && i < name.length(); i++) {
    const char c = name[i];
    valid = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.';
  }
  if (!valid) {
    sendText(400, "enter a domain name such as ads.example.com");
    return;
  }
  const blocklist::Explanation e = ctx_.blocklist->matcher().explain(name.c_str(), name.length());
  const char* verdict = e.result == blocklist::MatchResult::kBlocked   ? "blocked"
                        : e.result == blocklist::MatchResult::kAllowed ? "allowed"
                                                                       : "none";
  const char* source = e.source == blocklist::MatchSource::kCustomAllow   ? "allowlist"
                       : e.source == blocklist::MatchSource::kCustomBlock ? "custom block"
                       : e.source == blocklist::MatchSource::kMainList    ? "blocklist"
                                                                          : "none";
  String j = "{\"name\":" + q(name) + ",\"verdict\":" + q(verdict) + ",\"source\":" + q(source) +
             ",\"rule\":" + q(e.rule.c_str()) + ",\"blockingOn\":" + b(ctx_.clients->blockingOn()) + "}";
  ctx_.server->send(200, "application/json", j);
}

// SD block log: card status for the Device tab and the list of day files.
void Dashboard::handleLogFiles() {
  if (!guard(Access::kRead)) return;
  const char* state = "unavailable";
  String j = "{";
  uint64_t cardMb = 0;
  uint32_t logged = 0, dropped = 0;
  if (ctx_.sdLog) {
    const platform::SdBlockLog::Status st = ctx_.sdLog->status();
    state = st.state == platform::SdBlockLog::State::kOff      ? "off"
            : st.state == platform::SdBlockLog::State::kNoCard ? "no card"
            : st.state == platform::SdBlockLog::State::kReady  ? "logging"
                                                               : "error";
    cardMb = st.totalBytes / 1048576ULL;
    logged = st.logged;
    dropped = st.dropped;
  }
  j += "\"state\":" + q(state) + ",\"cardMb\":" + String(static_cast<unsigned long>(cardMb)) +
       ",\"logged\":" + String(logged) + ",\"dropped\":" + String(dropped) + ",\"files\":[";
  platform::SdBlockLog::DayFile days[platform::SdBlockLog::kMaxDays];
  size_t n = 0;
  if (ctx_.sdLog && ctx_.sdLog->listDays(days, platform::SdBlockLog::kMaxDays, &n)) {
    // Newest first (file names sort by date).
    for (size_t i = 0; i < n; i++)
      for (size_t k = i + 1; k < n; k++)
        if (strcmp(days[k].name, days[i].name) > 0) std::swap(days[i], days[k]);
    for (size_t i = 0; i < n; i++)
      j += (i ? "," : "") + String("{\"name\":") + q(days[i].name) + ",\"bytes\":" + String(days[i].bytes) +
           "}";
  }
  j += "]}";
  ctx_.server->send(200, "application/json", j);
}

// GET /api/log?day=2026-11-17.csv streams one day as CSV, a chunk at a time so DNS
// logging can interleave (the card lock is held per chunk, not per download).
void Dashboard::handleLogDownload() {
  if (!guard(Access::kRead)) return;
  const String name = ctx_.server->arg("day");
  if (!ctx_.sdLog || name.length() != 14) {
    sendText(404, "no such log");
    return;
  }
  static constexpr size_t kChunk = 2048;
  std::unique_ptr<uint8_t[]> buf(new uint8_t[kChunk]);
  size_t got = 0;
  if (!ctx_.sdLog->readDay(name.c_str(), 0, buf.get(), kChunk, &got)) {
    sendText(404, "no such log (or the card is not ready)");
    return;
  }
  WebServer& s = *ctx_.server;
  s.setContentLength(CONTENT_LENGTH_UNKNOWN);
  s.sendHeader("Content-Disposition", "attachment; filename=\"adblock-" + name + "\"");
  s.send(200, "text/csv", "");
  uint32_t offset = 0;
  while (got > 0) {
    s.sendContent(reinterpret_cast<const char*>(buf.get()), got);
    offset += got;
    uploadProgress();  // keeps the software watchdog fed during a long download
    if (!ctx_.sdLog->readDay(name.c_str(), offset, buf.get(), kChunk, &got)) break;
  }
  s.sendContent("");  // terminates the chunked body
}

void Dashboard::handleLogClear() {
  if (!guard(Access::kAuth)) return;
  if (!ctx_.sdLog) {
    sendText(404, "no SD card support");
    return;
  }
  const bool ok = ctx_.sdLog->clearAll();
  sendText(ok ? 200 : 409, ok ? "log files deleted" : "the SD card is not ready");
}

void Dashboard::handleStats() {
  if (!guard(Access::kRead)) return;
  const uint32_t up = millis() / 1000;
  char uptime[24];
  snprintf(uptime, sizeof(uptime), "%lud %luh %lum", static_cast<unsigned long>(up / 86400),
           static_cast<unsigned long>((up % 86400) / 3600), static_cast<unsigned long>((up % 3600) / 60));
  const app::BlocklistStatus bl = ctx_.blocklist->status();
  const app::DnsStats d = ctx_.dns->stats();
  const cache::CacheStats cs = ctx_.dns->cacheStats();
  const app::UpstreamSnapshot us = ctx_.dns->upstreams();
  char hhmm[8];
  snprintf(hhmm, sizeof(hhmm), "%02u:%02u", bl.hour, bl.minute);

  String j;
  j.reserve(4096);
  j += "{\"version\":" + q(ctx_.version) + ",\"hostname\":" + q(ctx_.hostname) +
       ",\"updateUrl\":" + q(UPDATE_BASE_URL);
  j += ",\"ip\":" + q(WiFi.localIP().toString()) + ",\"rssi\":" + String(WiFi.RSSI());
  j += ",\"uptime\":" + q(uptime) + ",\"heap\":" + String(ESP.getFreeHeap()) +
       ",\"heapMin\":" + String(ESP.getMinFreeHeap()) + ",\"heapBlock\":" + String(ESP.getMaxAllocHeap()) +
       ",\"psram\":" + String(ESP.getFreePsram()) + ",\"temp\":" + String(temperatureRead(), 1);
  j += ",\"setupRequired\":" + String(b(ctx_.passwords->mustChange()));
  if (ctx_.restart) {
    const diag::RestartInfo& r = *ctx_.restart;
    char why[160];
    diag::describe(r, why, sizeof(why));
    j += ",\"restart\":{\"cause\":" + q(diag::resetCauseName(r.cause)) + ",\"summary\":" + q(why) +
         ",\"crash\":";
    if (r.crash.present) {
      char bt[200];
      diag::formatBacktrace(r.crash, bt, sizeof(bt));
      j += "{\"thisBoot\":" + String(b(r.crashThisBoot())) + ",\"task\":" + q(r.crash.task) +
           ",\"reason\":" + q(r.crash.reason) + ",\"backtrace\":" + q(bt) +
           ",\"corrupted\":" + b(r.crash.corrupted) + ",\"elf\":" + q(r.crash.elfSha) + "}";
    } else {
      j += "null";
    }
    j += "}";
  }
  j += ",\"timeSynced\":" + String(b(bl.timeSynced)) + ",\"now\":" + q(formatTime(time(nullptr)));
  j += ",\"blocking\":" + String(b(ctx_.clients->blockingOn())) +
       ",\"resumeIn\":" + String(ctx_.clients->resumeInSeconds());
  j += ",\"dns\":{\"queries\":" + String(d.queries) + ",\"tcp\":" + String(d.tcpQueries) +
       ",\"blocked\":" + String(d.blocked) + ",\"cnameBlocked\":" + String(d.cnameBlocked) +
       ",\"local\":" + String(d.local) + ",\"cacheHits\":" + String(d.cacheHits) +
       ",\"forwarded\":" + String(d.forwarded) + ",\"servfail\":" + String(d.servfail) +
       ",\"cacheEntries\":" + String(cs.entries) + "}";
  j += ",\"plainFallback\":" + String(b(us.plainFallback)) + ",\"upstreams\":[";
  for (size_t i = 0; i < us.count; i++) {
    const upstream::UpstreamStatus& u = us.status[i];
    if (i) j += ",";
    j += "{\"name\":" + q(u.name) + ",\"encrypted\":" + b(u.authenticated) +
         ",\"state\":" + q(upstream::healthStateName(u.state)) + ",\"ok\":" + String(u.stats.ok) +
         ",\"failed\":" + String(u.stats.failed) + ",\"latencyMs\":" + String(u.stats.lastLatencyMs) + "}";
  }
  j += "],\"blocklist\":{\"entries\":" + String(bl.entries) + ",\"inMemory\":" + b(bl.inMemory) +
       ",\"built\":" + q(formatTime(bl.buildTime)) + ",\"lastAttempt\":" + q(formatTime(bl.lastAttempt)) +
       ",\"lastOk\":" + b(bl.lastOk) + ",\"lastResult\":" + q(bl.lastResult) + ",\"url\":" + q(bl.url) +
       ",\"time\":" + q(hhmm) + ",\"storage\":" + q(bl.onSdCard ? "sd" : "flash") + "}";
  j += ",\"rules\":{\"block\":[";
  const auto block = ctx_.blocklist->rules(false);
  for (size_t i = 0; i < block.size(); i++) j += (i ? "," : "") + q(block[i]);
  j += "],\"allow\":[";
  const auto allow = ctx_.blocklist->rules(true);
  for (size_t i = 0; i < allow.size(); i++) j += (i ? "," : "") + q(allow[i]);
  j += "]},\"clients\":[";
  const auto clients = ctx_.clients->snapshot();
  for (size_t i = 0; i < clients.size(); i++) {
    const app::ClientInfo& c = clients[i];
    if (i) j += ",";
    j += "{\"ip\":" + q(IPAddress(c.ip).toString()) + ",\"mac\":" + q(macString(c.mac)) +
         ",\"blocked\":" + String(c.blocked) + ",\"allowed\":" + String(c.allowed) +
         ",\"banned\":" + b(c.banned) + "}";
  }
  j += "]}";
  ctx_.server->send(200, "application/json", j);
}

void Dashboard::handleGetConfig() {
  if (!guard(Access::kRead)) return;
  const config::AppConfig& c = *ctx_.config;
  String j = "{\"up_pri\":" + q(config::providerName(c.primary)) +
             ",\"up_sec\":" + q(config::providerName(c.secondary));
  j += ",\"up_doh\":" + String(b(c.dohFallback)) + ",\"up_plain\":" + b(c.plainFallback);
  j += ",\"up_cip\":" + q(c.customIp) + ",\"up_cip2\":" + q(c.customIp2) +
       ",\"up_cname\":" + q(c.customName) + ",\"up_cdoh\":" + b(c.customDoh);
  j += ",\"pad\":" + String(b(c.padding)) + ",\"ad\":" + b(c.passAd) + ",\"blk_ttl\":" + String(c.blockedTtl);
  j += ",\"ff_canary\":" + String(b(c.firefoxCanary)) + ",\"icloud\":" + b(c.icloudRelay) +
       ",\"priv_rev\":" + b(c.privateReverse) + ",\"sd_log\":" + b(c.sdLog) + ",\"sd_list\":" + b(c.sdList);
  j += ",\"tz\":" + q(c.timezone) + ",\"log\":" + String(c.logLevel) + "}";
  ctx_.server->send(200, "application/json", j);
}

void Dashboard::handleSetConfig() {
  if (!guard(Access::kAuth)) return;
  WebServer& s = *ctx_.server;
  config::AppConfig next = *ctx_.config;
  for (int i = 0; i < s.args(); i++) {
    const String k = s.argName(i);
    if (k == "plain") continue;  // WebServer exposes the raw body under "plain"
    const config::SetResult r = config::setField(next, k.c_str(), s.arg(i).c_str());
    if (r != config::SetResult::kOk) {
      sendText(400, "invalid value for " + k);
      return;
    }
  }
  const char* why = nullptr;
  if (!config::validate(next, &why)) {
    sendText(400, why);
    return;
  }
  if (!config::save(*ctx_.kv, next)) {
    sendText(500, "could not save settings");
    return;
  }
  const bool restart = config::requiresRestart(*ctx_.config, next);
  *ctx_.config = next;
  ctx_.log->log(LogLevel::kInfo, kTag, "settings saved%s", restart ? "; restarting" : "");
  if (restart) {
    sendText(200, "saved; restarting to apply DNS settings");
    delay(500);
    platform::restart("DNS settings changed");
  }
  if (ctx_.applyLive) ctx_.applyLive(next);
  sendText(200, "saved");
}

void Dashboard::handleLogin() {
  Check c = check(Access::kPublic);
  if (c.ok) c = postChecks();
  if (c.ok) c = verifyPassword(ctx_.server->arg("user"), ctx_.server->arg("pass"));
  if (!c.ok) {
    if (c.code == 429) {
      const uint32_t client = static_cast<uint32_t>(ctx_.server->client().remoteIP());
      ctx_.server->sendHeader("Retry-After", String(ctx_.logins->retryAfterSeconds(client)));
    }
    sendText(c.code, c.message);
    return;
  }
  char token[auth::SessionStore::kTokenLength + 1];
  ctx_.sessions->create(token);
  // No Max-Age: a browser-session cookie; the board ends it after 30 min idle or 24 h.
  ctx_.server->sendHeader("Set-Cookie",
                          String(kSessionCookie) + "=" + token + "; Path=/; HttpOnly; SameSite=Strict");
  ctx_.server->sendHeader("Cache-Control", "no-store");
  sendText(200, ctx_.passwords->mustChange() ? "setup" : "ok");
}

void Dashboard::handleLogout() {
  Check c = check(Access::kPublic);
  if (c.ok) c = postChecks();
  if (!c.ok) {
    sendText(c.code, c.message);
    return;
  }
  char token[auth::SessionStore::kTokenLength + 1];
  if (auth::cookieValue(ctx_.server->header("Cookie").c_str(), kSessionCookie, token, sizeof(token)))
    ctx_.sessions->revoke(token);
  ctx_.server->sendHeader("Set-Cookie",
                          String(kSessionCookie) + "=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict");
  sendText(200, "logged out");
}

void Dashboard::handlePassword() {
  if (!guard(Access::kAuthDuringSetup)) return;
  const char* why = nullptr;
  if (!ctx_.passwords->change(ctx_.server->arg("current").c_str(), ctx_.server->arg("next").c_str(), &why)) {
    sendText(400, why ? why : "rejected");
    return;
  }
  ctx_.log->log(LogLevel::kInfo, kTag, "dashboard password changed");
  ctx_.sessions->revokeAll();  // every browser, this one included, logs in again
  ctx_.server->sendHeader("Set-Cookie",
                          String(kSessionCookie) + "=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict");
  sendText(200, "password changed; log in with the new one");
}

void Dashboard::handleRule(bool add) {
  if (!guard(Access::kAuth)) return;
  const bool allow = ctx_.server->arg("list") == "allow";
  const String d = ctx_.server->arg("d");
  const bool ok = add ? ctx_.blocklist->addRule(allow, d) : ctx_.blocklist->removeRule(allow, d);
  sendText(ok ? 200 : 400, ok ? "ok" : (add ? "invalid domain or list full" : "not found"));
}

void Dashboard::handleBan() {
  if (!guard(Access::kAuth)) return;
  IPAddress ip;
  if (!ip.fromString(ctx_.server->arg("ip"))) {
    sendText(400, "invalid IP");
    return;
  }
  switch (ctx_.clients->toggleBan(static_cast<uint32_t>(ip))) {
    case app::ClientTable::BanResult::kBanned: sendText(200, "banned"); break;
    case app::ClientTable::BanResult::kUnbanned: sendText(200, "unbanned"); break;
    case app::ClientTable::BanResult::kListFull:
      sendText(409, "ban list full (" + String(app::ClientTable::kMaxBans) + "): unban a client first");
      break;
  }
}

void Dashboard::handlePause() {
  if (!guard(Access::kAuth)) return;
  const long secs = ctx_.server->arg("s").toInt();
  if (secs < 0 || secs > 86400) {
    sendText(400, "pause must be 0..86400 s");
    return;
  }
  ctx_.clients->pause(static_cast<uint32_t>(secs));
  sendText(200, secs ? "blocking paused" : "blocking paused until resumed");
}

void Dashboard::handleBlocklistSettings() {
  if (!guard(Access::kAuth)) return;
  WebServer& s = *ctx_.server;
  if (s.hasArg("u") && !ctx_.blocklist->setUrl(s.arg("u"))) {
    sendText(400, "URL must start with https://");
    return;
  }
  if (s.hasArg("t")) {
    const String t = s.arg("t");
    const int c = t.indexOf(':');
    const long h = c > 0 ? t.substring(0, c).toInt() : -1, m = c > 0 ? t.substring(c + 1).toInt() : -1;
    if (h < 0 || h > 23 || m < 0 || m > 59) {
      sendText(400, "time must be HH:MM");
      return;
    }
    ctx_.blocklist->setTime(static_cast<uint8_t>(h), static_cast<uint8_t>(m));
  }
  sendText(200, "saved");
}

// Uploads: the auth check runs once at UPLOAD_FILE_START (before any data is written).
void Dashboard::handleListUpload() {
  HTTPUpload& u = ctx_.server->upload();
  static File file;
  switch (u.status) {
    case UPLOAD_FILE_START: {
      const Check c = check(Access::kAuth);
      uploadAuthorized_ = c.ok;
      uploadResult_ = c.ok ? "upload incomplete" : c.message;
      if (c.ok) file = LittleFS.open(kUploadTmp, "w");
      break;
    }
    case UPLOAD_FILE_WRITE:
      uploadProgress();  // the whole upload runs inside one handleClient() call
      if (uploadAuthorized_ && file && file.write(u.buf, u.currentSize) != u.currentSize) {
        file.close();
        uploadResult_ = "not enough flash";
      }
      break;
    case UPLOAD_FILE_END:
      if (!uploadAuthorized_) break;
      if (file) {
        file.close();
        const update::UpdateReport r = ctx_.blocklist->installUpload(kUploadTmp);
        uploadResult_ = String(update::updateStatusName(r.status)) + ": " + r.detail;
      }
      LittleFS.remove(kUploadTmp);
      break;
    case UPLOAD_FILE_ABORTED:
      if (file) file.close();
      LittleFS.remove(kUploadTmp);
      uploadResult_ = "upload aborted";
      break;
  }
}

void Dashboard::handleListUploadDone() {
  if (!uploadAuthorized_) {
    guard(Access::kAuth);  // sends the proper 401/403/429
    return;
  }
  sendText(uploadResult_.startsWith("updated") ? 200 : 400, uploadResult_);
}

void Dashboard::handleFirmwareUpload() {
  HTTPUpload& u = ctx_.server->upload();
  if (u.status == UPLOAD_FILE_START) {
    uploadAuthorized_ = check(Access::kAuth).ok;
    if (!uploadAuthorized_) return;
    ctx_.log->log(LogLevel::kInfo, "ota", "firmware upload: %s", u.filename.c_str());
    if (!Update.begin(UPDATE_SIZE_UNKNOWN)) Update.printError(Serial);
  } else if (!uploadAuthorized_) {
    return;
  } else if (u.status == UPLOAD_FILE_WRITE) {
    // The whole upload (and each sector erase) runs inside one handleClient() call: a
    // 1.3 MB image over a weak link took longer than the 5 s task watchdog and panicked
    // the web task mid-upload (found on hardware, 2026-10-15).
    uploadProgress();
    if (Update.write(u.buf, u.currentSize) != u.currentSize) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_END) {
    uploadProgress();  // end() hashes and verifies the image before activating it
    if (Update.end(true))
      ctx_.log->log(LogLevel::kInfo, "ota", "firmware %u bytes OK", u.totalSize);
    else
      Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_ABORTED) {
    Update.abort();
  }
}

void Dashboard::handleFirmwareUploadDone() {
  if (!uploadAuthorized_) {
    guard(Access::kAuth);
    return;
  }
  const bool ok = !Update.hasError() && Update.isFinished();
  sendText(ok ? 200 : 500,
           ok ? "firmware accepted; rebooting (rolls back if unhealthy)" : "firmware update failed");
  if (ok) {
    delay(500);
    platform::restart("firmware update (dashboard)");
  }
}

}  // namespace web
