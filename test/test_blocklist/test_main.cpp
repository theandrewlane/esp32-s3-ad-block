// Tests for lib/core/blocklist: hashing, file format validation, memory/file
// indexes, parent-domain matching, custom allow/block rules, collisions, and the
// lock-free index swap under concurrent readers.

#include <unity.h>

#include <atomic>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "blocklist/format.h"
#include "blocklist/hash.h"
#include "blocklist/index.h"
#include "blocklist/matcher.h"
#include "blocklist/rules.h"
#include "fakes/blocklist_builder.h"
#include "fakes/mem_file_system.h"

using namespace blocklist;
using testbl::Bytes;

void setUp() {}
void tearDown() {}

static uint64_t h(const char* s) {
  return hashDomain(s, strlen(s));
}

static std::unique_ptr<IIndex> memIndex(const Bytes& file) {
  auto owner = std::make_shared<Bytes>(file);
  Header hdr;
  parseHeader(owner->data(), owner->size(), hdr);
  return std::make_unique<MemoryIndex>(owner->data() + kHeaderSize, hdr.count, owner);
}

static Limits small() {
  Limits l;
  l.minEntries = 1;
  return l;
}

// --- hashing ------------------------------------------------------------------------

static void test_hash_matches_python_golden_values() {
  // Same values as tools/test_build_blocklist.py: change both together.
  TEST_ASSERT_TRUE(h("ads.example.com") == 0x3158979aa55eull);
  TEST_ASSERT_TRUE(h("doubleclick.net") == 0x04cd127775cdull);
  TEST_ASSERT_TRUE(h("example.com") == 0x46634e2714c6ull);
  TEST_ASSERT_EQUAL_HEX32(0x3158, bucketOf(h("ads.example.com")));
  TEST_ASSERT_EQUAL_HEX32(0x979aa55e, suffixOf(h("ads.example.com")));
}

// --- format -------------------------------------------------------------------------

static void test_valid_file_passes_full_validation() {
  MemFileSystem fs;
  fs.put("/bl.bin", testbl::build(testbl::syntheticNames(5000)));
  Header hdr;
  TEST_ASSERT_EQUAL(static_cast<int>(FormatError::kNone),
                    static_cast<int>(validateFile(fs, "/bl.bin", small(), &hdr)));
  TEST_ASSERT_EQUAL_UINT32(5000, hdr.count);
  TEST_ASSERT_TRUE(hdr.buildTime == 1792000000);
}

static void assertInvalid(FormatError want, const Bytes& file, Limits limits = small()) {
  MemFileSystem fs;
  fs.put("/bl.bin", file);
  TEST_ASSERT_EQUAL_STRING(formatErrorName(want),
                           formatErrorName(validateFile(fs, "/bl.bin", limits, nullptr)));
  // The streaming validator (download path) must agree on header/size/CRC errors.
  if (want != FormatError::kBadBuckets && want != FormatError::kUnsorted) {
    StreamValidator v(limits);
    for (size_t i = 0; i < file.size(); i += 777)
      v.feed(file.data() + i, std::min<size_t>(777, file.size() - i));
    TEST_ASSERT_EQUAL_STRING(formatErrorName(want), formatErrorName(v.finish()));
  }
}

static int ticks = 0;
static void countTick() {
  ticks++;
}

static void test_validation_reports_progress_for_large_files() {
  MemFileSystem fs;
  fs.put("/bl.bin", testbl::build(testbl::syntheticNames(100000)));  // ~650 KB
  ticks = 0;
  TEST_ASSERT_EQUAL(static_cast<int>(FormatError::kNone),
                    static_cast<int>(validateFile(fs, "/bl.bin", small(), nullptr, countTick)));
  TEST_ASSERT_TRUE(ticks >= 10);  // the watchdog gets fed during long validations
}

static void test_corrupt_files_are_rejected() {
  const Bytes good = testbl::build(testbl::syntheticNames(2000));
  Bytes f = good;
  f[0] = 'X';
  assertInvalid(FormatError::kBadMagic, f);
  f = good;
  f[4] = 1;
  assertInvalid(FormatError::kBadVersion, f);
  f = good;
  f[5] = 40;  // a 40-bit (upstream) list is not accepted
  assertInvalid(FormatError::kBadParams, f);
  f = good;
  f[f.size() - 1] ^= 0xFF;  // flipped bit in the payload
  assertInvalid(FormatError::kBadCrc, f);
  f = Bytes(good.begin(), good.end() - 4);  // truncated download
  assertInvalid(FormatError::kSizeMismatch, f);
  f = good;
  f.push_back(0);  // trailing junk
  assertInvalid(FormatError::kSizeMismatch, f);
  assertInvalid(FormatError::kTooShort, Bytes(good.begin(), good.begin() + 10));
  Limits strict;
  strict.minEntries = 5000;
  assertInvalid(FormatError::kTooFewEntries, good, strict);
  strict.minEntries = 1;
  strict.maxEntries = 100;
  assertInvalid(FormatError::kTooManyEntries, good, strict);
}

static void test_structural_corruption_with_valid_crc_is_rejected() {
  // A writer bug (not transport corruption): CRC is right but the data is wrong.
  const Bytes good = testbl::build(testbl::syntheticNames(2000));
  Bytes f = good;
  // Find a bucket with >= 2 entries and swap its first two suffixes.
  for (uint32_t b = 0; b < kBucketCount; b++) {
    uint32_t s = util::readU32Le(&f[kHeaderSize + 4 * b]), e = util::readU32Le(&f[kHeaderSize + 4 * (b + 1)]);
    if (e - s >= 2) {
      uint8_t* p = &f[kHeaderSize + kBucketTableBytes + 4 * s];
      uint8_t tmp[4];
      memcpy(tmp, p, 4);
      memcpy(p, p + 4, 4);
      memcpy(p + 4, tmp, 4);
      break;
    }
  }
  testbl::fixCrc(f);
  assertInvalid(FormatError::kUnsorted, f);

  f = good;
  util::writeU32Le(&f[kHeaderSize + 4 * 100], 0xFFFFFF);  // bucket start beyond N
  testbl::fixCrc(f);
  assertInvalid(FormatError::kBadBuckets, f);
}

// --- lookup -------------------------------------------------------------------------

static void test_memory_and_file_index_agree() {
  const auto names = testbl::syntheticNames(20000);
  const Bytes file = testbl::build(names);
  auto mem = memIndex(file);
  MemFileSystem fs;
  fs.put("/bl.bin", file);
  FileIndex fileIdx(fs.open("/bl.bin", hal::FileMode::kRead), 20000);
  for (size_t i = 0; i < names.size(); i += 37) {
    TEST_ASSERT_TRUE(mem->contains(h(names[i].c_str())));
    TEST_ASSERT_TRUE(fileIdx.contains(h(names[i].c_str())));
  }
  const auto absent = testbl::syntheticNames(2000, "absent");
  for (const auto& n : absent) {
    TEST_ASSERT_FALSE(mem->contains(h(n.c_str())));
    TEST_ASSERT_FALSE(fileIdx.contains(h(n.c_str())));
  }
}

static void test_large_buckets_have_no_false_negatives() {
  // Upstream's MAX_RANGE=256 clamp missed entries in crowded buckets. Force a crowded
  // bucket: 3000 hashes sharing one 16-bit prefix.
  std::vector<uint64_t> hashes;
  for (uint32_t i = 0; i < 3000; i++) hashes.push_back((uint64_t{0xABCD} << 32) | (i * 7919u));
  auto idx = memIndex(testbl::buildFromHashes(hashes));
  for (uint64_t x : hashes) TEST_ASSERT_TRUE(idx->contains(x));
  TEST_ASSERT_FALSE(idx->contains((uint64_t{0xABCD} << 32) | 1));
}

// --- matching -----------------------------------------------------------------------

struct MatchFixture {
  IndexHolder holder;
  Matcher matcher{holder};
  explicit MatchFixture(const std::vector<std::string>& names) {
    holder.publish(memIndex(testbl::build(names)));
  }
  MatchResult m(const char* name) const { return matcher.match(name, strlen(name)); }
};

static void test_parent_domain_matching() {
  MatchFixture f({"ads.example.com", "tracker.net"});
  TEST_ASSERT_EQUAL(static_cast<int>(MatchResult::kBlocked), static_cast<int>(f.m("ads.example.com")));
  TEST_ASSERT_EQUAL(static_cast<int>(MatchResult::kBlocked), static_cast<int>(f.m("x.ads.example.com")));
  TEST_ASSERT_EQUAL(static_cast<int>(MatchResult::kBlocked), static_cast<int>(f.m("a.b.c.tracker.net")));
  TEST_ASSERT_EQUAL(static_cast<int>(MatchResult::kNone), static_cast<int>(f.m("example.com")));
  TEST_ASSERT_EQUAL(static_cast<int>(MatchResult::kNone), static_cast<int>(f.m("notads.example.com")));
  TEST_ASSERT_EQUAL(static_cast<int>(MatchResult::kNone), static_cast<int>(f.m("ads.example.com.evil")));
}

static void test_bare_tld_is_never_matched_and_www_is_not_stripped() {
  MatchFixture f({"com", "www.listed.org"});
  TEST_ASSERT_EQUAL(static_cast<int>(MatchResult::kNone), static_cast<int>(f.m("anything.com")));
  TEST_ASSERT_EQUAL(static_cast<int>(MatchResult::kBlocked), static_cast<int>(f.m("www.listed.org")));
  TEST_ASSERT_EQUAL(static_cast<int>(MatchResult::kNone), static_cast<int>(f.m("listed.org")));
}

static void test_custom_allow_overrides_blocklist_and_custom_block_adds() {
  MatchFixture f({"example.com"});
  DomainSet allow, block;
  allow.add("safe.example.com", 16);
  allow.finalize();
  block.add("extra.org", 9);
  block.finalize();
  f.matcher.setCustom(std::move(block), std::move(allow));
  TEST_ASSERT_EQUAL(static_cast<int>(MatchResult::kBlocked), static_cast<int>(f.m("ads.example.com")));
  TEST_ASSERT_EQUAL(static_cast<int>(MatchResult::kAllowed), static_cast<int>(f.m("safe.example.com")));
  TEST_ASSERT_EQUAL(static_cast<int>(MatchResult::kAllowed), static_cast<int>(f.m("cdn.safe.example.com")));
  TEST_ASSERT_EQUAL(static_cast<int>(MatchResult::kBlocked), static_cast<int>(f.m("x.extra.org")));
}

static void test_cname_blocked_when_target_is_listed() {
  MatchFixture f({"tracker-cdn.net"});
  auto cb = [&](const char* q, const char* t) { return f.matcher.cnameBlocked(q, strlen(q), t, strlen(t)); };
  TEST_ASSERT_TRUE(cb("metrics.mysite.com", "mysite.tracker-cdn.net"));  // cloaked tracker
  TEST_ASSERT_FALSE(cb("metrics.mysite.com", "cdn.fine.org"));           // harmless CNAME
  TEST_ASSERT_FALSE(cb("metrics.mysite.com", ""));                       // nothing to check
}

static void test_cname_blocking_respects_allow_and_custom_rules() {
  MatchFixture f({"tracker-cdn.net"});
  DomainSet allow, block;
  allow.add("metrics.mysite.com", 18);  // the user trusts this first-party name
  allow.finalize();
  block.add("evil-cname.org", 14);
  block.finalize();
  f.matcher.setCustom(std::move(block), std::move(allow));
  auto cb = [&](const char* q, const char* t) { return f.matcher.cnameBlocked(q, strlen(q), t, strlen(t)); };
  TEST_ASSERT_FALSE(cb("metrics.mysite.com", "mysite.tracker-cdn.net"));  // allowed query name wins
  TEST_ASSERT_TRUE(cb("other.mysite.com", "mysite.tracker-cdn.net"));     // a sibling is still caught
  TEST_ASSERT_TRUE(cb("x.example.com", "a.evil-cname.org"));              // custom block rules apply
  TEST_ASSERT_FALSE(cb("x.example.com", "tracker-cdn.net.fake"));         // no accidental suffix match
}

// --- custom rule syntax and wildcard matching ---------------------------------------

static ParsedRule pr(const char* s) {
  return parseRule(s, strlen(s));
}

static void test_rule_parser_accepts_plain_adblock_and_hosts_forms() {
  TEST_ASSERT_EQUAL_STRING("ads.example.com", pr("Ads.Example.COM").text.c_str());
  TEST_ASSERT_EQUAL_STRING("ads.example.com", pr("  ads.example.com.  ").text.c_str());
  TEST_ASSERT_EQUAL_STRING("ads.example.com", pr("||ads.example.com^").text.c_str());
  TEST_ASSERT_EQUAL_STRING("ads.example.com", pr("||ads.example.com^$important").text.c_str());
  TEST_ASSERT_EQUAL_STRING("ads.example.com", pr("0.0.0.0 ads.example.com").text.c_str());
  TEST_ASSERT_EQUAL_STRING("ads.example.com", pr("127.0.0.1\tads.example.com  # note").text.c_str());
  TEST_ASSERT_EQUAL_STRING("ads.example.com", pr(":: ads.example.com").text.c_str());
  TEST_ASSERT_EQUAL(static_cast<int>(RuleKind::kDomain), static_cast<int>(pr("ads.example.com").kind));
  TEST_ASSERT_FALSE(pr("||ads.example.com^").allow);
}

static void test_rule_parser_allow_prefix_and_subdomain_only() {
  const ParsedRule a = pr("@@||safe.example.com^");
  TEST_ASSERT_TRUE(a.allow);
  TEST_ASSERT_EQUAL_STRING("safe.example.com", a.text.c_str());
  const ParsedRule s = pr("*.example.com");
  TEST_ASSERT_EQUAL(static_cast<int>(RuleKind::kSubdomains), static_cast<int>(s.kind));
  TEST_ASSERT_EQUAL_STRING("*.example.com", s.text.c_str());
  // A leading dot is not a wildcard: it means the domain.
  TEST_ASSERT_EQUAL_STRING("example.com", pr(".example.com").text.c_str());
}

static void test_rule_parser_globs() {
  const ParsedRule g = pr("Ads*.Example.com");
  TEST_ASSERT_EQUAL(static_cast<int>(RuleKind::kGlob), static_cast<int>(g.kind));
  TEST_ASSERT_EQUAL_STRING("ads*.example.com", g.text.c_str());
  TEST_ASSERT_EQUAL(static_cast<int>(RuleKind::kGlob), static_cast<int>(pr("*track*").kind));
  TEST_ASSERT_EQUAL(static_cast<int>(RuleKind::kGlob), static_cast<int>(pr("*.ads?.example.com").kind));
  TEST_ASSERT_EQUAL_STRING("*.ads?.example.com", pr("*.ads?.example.com").text.c_str());
}

static void test_rule_parser_rejects_junk_and_overbroad_patterns() {
  const char* bad[] = {"",
                       "   ",
                       "# comment",
                       "! comment",
                       "localhost",
                       "ab",
                       "bad domain.com",
                       "ex ample.com",
                       "http://x.com",
                       "exa..mple.com",
                       "-lead.com",

                       "*",
                       "*.*",
                       "a*",
                       "*.com",
                       "*x*",
                       "ex@mple.com",
                       "ex!ample.com",
                       "0.0.0.0"};
  for (const char* b : bad) {
    char msg[96];
    snprintf(msg, sizeof(msg), "should be invalid: '%s'", b);
    TEST_ASSERT_EQUAL_MESSAGE(static_cast<int>(RuleKind::kInvalid), static_cast<int>(pr(b).kind), msg);
  }
  std::string longGlob(kMaxGlobLen, 'a');
  longGlob += "*";
  TEST_ASSERT_EQUAL(static_cast<int>(RuleKind::kInvalid), static_cast<int>(pr(longGlob.c_str()).kind));
  std::string longName(260, 'a');
  longName += ".com";
  TEST_ASSERT_EQUAL(static_cast<int>(RuleKind::kInvalid), static_cast<int>(pr(longName.c_str()).kind));
}

static bool gm(const char* pat, const char* name) {
  return globMatch(pat, strlen(pat), name, strlen(name));
}

static void test_glob_match_semantics() {
  TEST_ASSERT_TRUE(gm("ads*.example.com", "ads.example.com"));
  TEST_ASSERT_TRUE(gm("ads*.example.com", "ads123.example.com"));
  TEST_ASSERT_FALSE(gm("ads*.example.com", "xads.example.com"));
  TEST_ASSERT_TRUE(gm("*track*", "my.tracker.net"));
  TEST_ASSERT_TRUE(gm("ad?.net", "ads.net"));
  TEST_ASSERT_FALSE(gm("ad?.net", "ad.net"));
  TEST_ASSERT_FALSE(gm("ad?.net", "adss.net"));
  TEST_ASSERT_TRUE(gm("a*b*c", "aXXbYYc"));
  TEST_ASSERT_FALSE(gm("a*b*c", "aXXbYY"));
  TEST_ASSERT_TRUE(gm("a**b", "ab"));
  TEST_ASSERT_TRUE(gm("*", ""));
  TEST_ASSERT_FALSE(gm("abc", ""));
  TEST_ASSERT_TRUE(gm("*.example.com", "a.b.example.com"));
  TEST_ASSERT_FALSE(gm("*.example.com", "example.com"));
}

static void test_glob_match_is_linear_on_adversarial_input() {
  // A backtracking matcher takes exponential time on this; ours must finish at once.
  std::string name(60, 'a');
  TEST_ASSERT_FALSE(globMatch("*a*a*a*a*a*a*a*a*a*b", 20, name.data(), name.size()));
}

static RuleSet rules(std::initializer_list<const char*> lines) {
  RuleSet s;
  for (const char* l : lines) {
    const ParsedRule r = pr(l);
    if (r.kind == RuleKind::kDomain)
      s.addDomain(r.text.data(), r.text.size());
    else if (r.kind == RuleKind::kSubdomains)
      s.addSubdomains(r.text.data() + 2, r.text.size() - 2);
    else if (r.kind == RuleKind::kGlob)
      TEST_ASSERT_TRUE(s.addGlob(r.text.data(), r.text.size()));
  }
  s.finalize();
  return s;
}

static void test_ruleset_domain_subdomain_and_glob_matching() {
  MatchFixture f({});
  f.matcher.setCustom(rules({"plain.org", "*.only-subs.net", "ads*.example.com", "*track*"}), RuleSet());
  auto blocked = [&](const char* n) { return f.m(n) == MatchResult::kBlocked; };
  TEST_ASSERT_TRUE(blocked("plain.org"));
  TEST_ASSERT_TRUE(blocked("x.plain.org"));
  TEST_ASSERT_FALSE(blocked("only-subs.net"));  // "*.x" leaves the apex alone
  TEST_ASSERT_TRUE(blocked("a.only-subs.net"));
  TEST_ASSERT_TRUE(blocked("a.b.only-subs.net"));
  TEST_ASSERT_TRUE(blocked("ads7.example.com"));
  TEST_ASSERT_TRUE(blocked("x.ads7.example.com"));  // globs also cover subdomains of a match
  TEST_ASSERT_FALSE(blocked("example.com"));
  TEST_ASSERT_FALSE(blocked("notads.example.com"));
  TEST_ASSERT_TRUE(blocked("pixel.tracker.io"));
  TEST_ASSERT_FALSE(blocked("clean.io"));
}

static void test_ruleset_allow_glob_beats_block_and_main_list() {
  MatchFixture f({"example.com"});
  f.matcher.setCustom(rules({"*.shop.example.com"}), rules({"safe*.example.com"}));
  TEST_ASSERT_EQUAL(static_cast<int>(MatchResult::kAllowed), static_cast<int>(f.m("safe1.example.com")));
  TEST_ASSERT_EQUAL(static_cast<int>(MatchResult::kBlocked), static_cast<int>(f.m("other.example.com")));
  TEST_ASSERT_EQUAL(static_cast<int>(MatchResult::kBlocked), static_cast<int>(f.m("a.shop.example.com")));
}

static void test_ruleset_caps_globs_and_reports_size() {
  RuleSet s;
  for (size_t i = 0; i < kMaxGlobsPerList; i++) {
    const std::string g = "adserver" + std::to_string(i) + "*.net";
    TEST_ASSERT_TRUE(s.addGlob(g.data(), g.size()));
  }
  TEST_ASSERT_FALSE(s.addGlob("one-too-many*.net", 17));
  TEST_ASSERT_EQUAL(static_cast<int>(kMaxGlobsPerList), static_cast<int>(s.globCount()));
  s.addDomain("a.com", 5);
  TEST_ASSERT_EQUAL(static_cast<int>(kMaxGlobsPerList + 1), static_cast<int>(s.size()));
}

static void test_collision_overblocks_and_allowlist_fixes_it() {
  // A hash collision makes an innocent name look listed. Simulate it by listing the
  // innocent name's hash under a "different" entry; the allowlist must rescue it.
  std::vector<uint64_t> hashes = {h("innocent.example"), h("ads.example")};
  IndexHolder holder;
  holder.publish(memIndex(testbl::buildFromHashes(hashes)));
  Matcher matcher(holder);
  TEST_ASSERT_EQUAL(static_cast<int>(MatchResult::kBlocked),
                    static_cast<int>(matcher.match("innocent.example", 16)));
  DomainSet allow;
  allow.add("innocent.example", 16);
  allow.finalize();
  matcher.setCustom(DomainSet(), std::move(allow));
  TEST_ASSERT_EQUAL(static_cast<int>(MatchResult::kAllowed),
                    static_cast<int>(matcher.match("innocent.example", 16)));
  TEST_ASSERT_EQUAL(static_cast<int>(MatchResult::kBlocked),
                    static_cast<int>(matcher.match("ads.example", 11)));
}

static void test_empty_holder_blocks_nothing() {
  IndexHolder holder;
  Matcher matcher(holder);
  TEST_ASSERT_EQUAL(static_cast<int>(MatchResult::kNone),
                    static_cast<int>(matcher.match("ads.example.com", 15)));
  TEST_ASSERT_EQUAL_UINT32(0, holder.count());
}

// --- swap under load ----------------------------------------------------------------

static void test_publish_while_readers_run_never_uses_freed_index() {
  // Two lists that both contain "always.example"; readers hammer lookups while the
  // writer swaps lists repeatedly. Under ASan any use-after-free aborts the test.
  const Bytes a = testbl::build({"always.example", "a-only.example"});
  const Bytes b = testbl::build({"always.example", "b-only.example"});
  IndexHolder holder;
  holder.publish(memIndex(a));
  Matcher matcher(holder);
  std::atomic<bool> stop{false};
  std::atomic<uint32_t> misses{0};
  std::vector<std::thread> readers;
  for (int t = 0; t < 4; t++)
    readers.emplace_back([&] {
      while (!stop.load()) {
        if (matcher.match("always.example", 14) != MatchResult::kBlocked) misses++;
      }
    });
  for (int i = 0; i < 300; i++) holder.publish(memIndex(i % 2 ? a : b));
  stop = true;
  for (auto& t : readers) t.join();
  TEST_ASSERT_EQUAL_UINT32(0, misses.load());  // never a moment without a list
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_hash_matches_python_golden_values);
  RUN_TEST(test_valid_file_passes_full_validation);
  RUN_TEST(test_validation_reports_progress_for_large_files);
  RUN_TEST(test_corrupt_files_are_rejected);
  RUN_TEST(test_structural_corruption_with_valid_crc_is_rejected);
  RUN_TEST(test_memory_and_file_index_agree);
  RUN_TEST(test_large_buckets_have_no_false_negatives);
  RUN_TEST(test_parent_domain_matching);
  RUN_TEST(test_bare_tld_is_never_matched_and_www_is_not_stripped);
  RUN_TEST(test_custom_allow_overrides_blocklist_and_custom_block_adds);
  RUN_TEST(test_cname_blocked_when_target_is_listed);
  RUN_TEST(test_cname_blocking_respects_allow_and_custom_rules);
  RUN_TEST(test_rule_parser_accepts_plain_adblock_and_hosts_forms);
  RUN_TEST(test_rule_parser_allow_prefix_and_subdomain_only);
  RUN_TEST(test_rule_parser_globs);
  RUN_TEST(test_rule_parser_rejects_junk_and_overbroad_patterns);
  RUN_TEST(test_glob_match_semantics);
  RUN_TEST(test_glob_match_is_linear_on_adversarial_input);
  RUN_TEST(test_ruleset_domain_subdomain_and_glob_matching);
  RUN_TEST(test_ruleset_allow_glob_beats_block_and_main_list);
  RUN_TEST(test_ruleset_caps_globs_and_reports_size);
  RUN_TEST(test_collision_overblocks_and_allowlist_fixes_it);
  RUN_TEST(test_empty_holder_blocks_nothing);
  RUN_TEST(test_publish_while_readers_run_never_uses_freed_index);
  return UNITY_END();
}
