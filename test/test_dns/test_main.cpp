// Tests for lib/core/dns: query validation, synthesized replies, EDNS0, upstream
// query encoding, response inspection, TTL aging, truncation, and fuzzing.

#include <unity.h>

#include <cstring>

#include "dns/message.h"
#include "dns/name.h"
#include "fakes/dns_builder.h"
#include "fakes/fake_random.h"

using namespace testdns;
using dns::ParseStatus;
using dns::Query;
using dns::Rcode;

static uint8_t out[2048];

void setUp() {
  memset(out, 0xAA, sizeof(out));
}
void tearDown() {}

static Query parseOk(const Bytes& pkt) {
  Query q;
  TEST_ASSERT_EQUAL(static_cast<int>(ParseStatus::kOk),
                    static_cast<int>(dns::parseQuery(pkt.data(), pkt.size(), q)));
  return q;
}

static ParseStatus parseStatus(const Bytes& pkt) {
  Query q;
  return dns::parseQuery(pkt.data(), pkt.size(), q);
}

static void assertStatus(ParseStatus want, const Bytes& pkt) {
  TEST_ASSERT_EQUAL(static_cast<int>(want), static_cast<int>(parseStatus(pkt)));
}

// --- parsing ----------------------------------------------------------------

static void test_parse_valid_query_lowercases_name() {
  Query q = parseOk(makeQuery("Ads.EXAMPLE.com", dns::kTypeA));
  TEST_ASSERT_EQUAL_HEX16(0x1234, q.id);
  TEST_ASSERT_TRUE(q.rd());
  TEST_ASSERT_EQUAL_STRING("ads.example.com", q.qname);
  TEST_ASSERT_EQUAL(15, q.qnameLen);
  TEST_ASSERT_EQUAL(17, q.qnameWireLen);
  TEST_ASSERT_EQUAL_UINT8('a', q.qnameWire[1]);
  TEST_ASSERT_EQUAL(dns::kTypeA, q.qtype);
  TEST_ASSERT_FALSE(q.edns.present);
  TEST_ASSERT_EQUAL(512, q.udpReplyLimit());
}

static void test_parse_root_name() {
  Query q = parseOk(makeQuery("", dns::kTypeNs));
  TEST_ASSERT_EQUAL(0, q.qnameLen);
  TEST_ASSERT_EQUAL(1, q.qnameWireLen);
}

static void test_parse_edns_fields_and_udp_limit_clamping() {
  QueryOpts o;
  o.edns = true;
  o.udpSize = 4096;
  o.dnssecOk = true;
  Query q = parseOk(makeQuery("example.com", dns::kTypeA, o));
  TEST_ASSERT_TRUE(q.edns.present);
  TEST_ASSERT_TRUE(q.edns.dnssecOk);
  TEST_ASSERT_EQUAL(4096, q.edns.udpSize);
  TEST_ASSERT_EQUAL(1232, q.udpReplyLimit());
  TEST_ASSERT_TRUE(q.wantsAd());
  o.udpSize = 100;
  q = parseOk(makeQuery("example.com", dns::kTypeA, o));
  TEST_ASSERT_EQUAL(512, q.udpReplyLimit());
}

static void test_parse_drops_short_packets_and_responses() {
  assertStatus(ParseStatus::kDrop, Bytes{0x12, 0x34, 0x01});
  QueryOpts o;
  o.flags = 0x8180;  // QR set
  assertStatus(ParseStatus::kDrop, makeQuery("example.com", dns::kTypeA, o));
}

static void test_parse_rejects_non_query_opcode() {
  QueryOpts o;
  o.flags = 0x2800;  // opcode 5 (UPDATE)
  Bytes pkt = makeQuery("example.com", dns::kTypeA, o);
  Query q;
  TEST_ASSERT_EQUAL(static_cast<int>(ParseStatus::kNotImp),
                    static_cast<int>(dns::parseQuery(pkt.data(), pkt.size(), q)));
  size_t n = dns::buildErrorReply(q, Rcode::kNotImp, out, sizeof(out));
  TEST_ASSERT_EQUAL(12, n);
  TEST_ASSERT_EQUAL_HEX16(0x1234, get16(out, 0));
  TEST_ASSERT_EQUAL(4, get16(out, 2) & 0xF);
  TEST_ASSERT_EQUAL(5, (get16(out, 2) >> 11) & 0xF);  // opcode echoed
  TEST_ASSERT_EQUAL(0, get16(out, 4));
}

static void test_parse_rejects_bad_question_counts() {
  Bytes pkt = makeQuery("example.com", dns::kTypeA);
  pkt[5] = 0;  // QDCOUNT 0
  assertStatus(ParseStatus::kFormErr, pkt);
  pkt[5] = 2;  // QDCOUNT 2
  assertStatus(ParseStatus::kFormErr, pkt);
  pkt = makeQuery("example.com", dns::kTypeA);
  pkt[7] = 1;  // ANCOUNT 1 in a query
  assertStatus(ParseStatus::kFormErr, pkt);
}

static void test_parse_rejects_compression_in_question() {
  Bytes pkt = makeQuery("example.com", dns::kTypeA);
  pkt.resize(12);
  put16(pkt, 0xC00C);  // pointer loop to itself
  put16(pkt, 1);
  put16(pkt, 1);
  assertStatus(ParseStatus::kFormErr, pkt);
}

static void test_parse_rejects_label_overrun_and_truncation() {
  Bytes pkt = makeQuery("example.com", dns::kTypeA);
  pkt[12] = 60;  // first label claims 60 bytes
  assertStatus(ParseStatus::kFormErr, pkt);
  pkt = makeQuery("example.com", dns::kTypeA);
  pkt.resize(pkt.size() - 3);  // cut into QTYPE/QCLASS
  assertStatus(ParseStatus::kFormErr, pkt);
  pkt = makeQuery("example.com", dns::kTypeA);
  pkt.resize(15);  // cut inside the first label
  assertStatus(ParseStatus::kFormErr, pkt);
}

static void test_parse_rejects_overlong_name_and_bad_bytes() {
  std::string longName;
  for (int i = 0; i < 5; i++) longName += std::string(60, 'a') + ".";
  longName += "com";  // 5*61 + 4 + 1 > 255
  assertStatus(ParseStatus::kFormErr, makeQuery(longName, dns::kTypeA));
  // 63-char labels are fine, 64 is not.
  assertStatus(ParseStatus::kOk, makeQuery(std::string(63, 'a') + ".com", dns::kTypeA));
  assertStatus(ParseStatus::kFormErr, makeQuery(std::string(64, 'a') + ".com", dns::kTypeA));
  Bytes pkt = makeQuery("ex mple.com", dns::kTypeA);  // space inside a label
  assertStatus(ParseStatus::kFormErr, pkt);
  pkt = makeQuery("example.com", dns::kTypeA);
  pkt[14] = '.';  // a literal dot inside a label would alias another name
  assertStatus(ParseStatus::kFormErr, pkt);
}

static void test_parse_rejects_duplicate_or_malformed_opt() {
  QueryOpts o;
  o.edns = true;
  Bytes pkt = makeQuery("example.com", dns::kTypeA, o);
  Bytes opt(pkt.end() - 11, pkt.end());
  pkt.insert(pkt.end(), opt.begin(), opt.end());
  pkt[11] = 2;  // ARCOUNT 2, both OPT
  assertStatus(ParseStatus::kFormErr, pkt);

  pkt = makeQuery("example.com", dns::kTypeA, o);
  pkt[pkt.size() - 1] = 4;  // RDLENGTH 4 but no option bytes follow
  assertStatus(ParseStatus::kFormErr, pkt);

  pkt = makeQuery("example.com", dns::kTypeA, o);
  pkt[pkt.size() - 1] = 3;  // RDLENGTH 3: shorter than an option header
  pkt.insert(pkt.end(), {0, 12, 0});
  assertStatus(ParseStatus::kFormErr, pkt);
}

static void test_parse_badvers_reply_carries_extended_rcode() {
  QueryOpts o;
  o.edns = true;
  o.version = 1;
  Bytes pkt = makeQuery("example.com", dns::kTypeA, o);
  Query q;
  TEST_ASSERT_EQUAL(static_cast<int>(ParseStatus::kBadVers),
                    static_cast<int>(dns::parseQuery(pkt.data(), pkt.size(), q)));
  size_t n = dns::buildErrorReply(q, Rcode::kBadVers, out, sizeof(out));
  TEST_ASSERT_TRUE(n > 0);
  TEST_ASSERT_EQUAL(0, get16(out, 2) & 0xF);    // low bits of 16
  TEST_ASSERT_EQUAL(1, get16(out, 10));         // OPT present
  TEST_ASSERT_EQUAL_UINT8(1, out[n - 11 + 5]);  // extended RCODE high bits
}

static void test_parse_refuses_non_in_class() {
  QueryOpts o;
  o.qclass = 3;  // CHAOS, e.g. version.bind
  assertStatus(ParseStatus::kRefused, makeQuery("version.bind", dns::kTypeTxt, o));
}

// --- blocked / local replies --------------------------------------------------

static void test_blocked_a_returns_zero_address() {
  Query q = parseOk(makeQuery("ads.example.com", dns::kTypeA));
  size_t n = dns::buildBlockedReply(q, {}, out, sizeof(out));
  TEST_ASSERT_EQUAL(12 + 17 + 4 + 16, n);
  TEST_ASSERT_EQUAL_HEX16(0x1234, get16(out, 0));
  TEST_ASSERT_EQUAL_HEX16(0x8180, get16(out, 2));  // QR RD RA, NOERROR, AA=0 AD=0
  TEST_ASSERT_EQUAL(1, get16(out, 4));
  TEST_ASSERT_EQUAL(1, get16(out, 6));
  TEST_ASSERT_EQUAL(0, get16(out, 8));
  TEST_ASSERT_EQUAL(0, get16(out, 10));
  const size_t a = 12 + 17 + 4;
  TEST_ASSERT_EQUAL_HEX16(0xC00C, get16(out, a));
  TEST_ASSERT_EQUAL(dns::kTypeA, get16(out, a + 2));
  TEST_ASSERT_EQUAL_UINT32(10, get32(out, a + 6));
  TEST_ASSERT_EQUAL(4, get16(out, a + 10));
  const uint8_t zero[4] = {0, 0, 0, 0};
  TEST_ASSERT_EQUAL_HEX8_ARRAY(zero, out + a + 12, 4);
}

static void test_blocked_aaaa_returns_unspecified_address() {
  Query q = parseOk(makeQuery("ads.example.com", dns::kTypeAaaa));
  size_t n = dns::buildBlockedReply(q, {}, out, sizeof(out));
  TEST_ASSERT_EQUAL(12 + 17 + 4 + 28, n);
  TEST_ASSERT_EQUAL(dns::kTypeAaaa, get16(out, 33 + 2));
  TEST_ASSERT_EQUAL(16, get16(out, 33 + 10));
  const uint8_t zero[16] = {0};
  TEST_ASSERT_EQUAL_HEX8_ARRAY(zero, out + 33 + 12, 16);
}

static void test_blocked_https_is_nodata_with_soa_not_nxdomain() {
  Query q = parseOk(makeQuery("ads.example.com", dns::kTypeHttps));
  dns::BlockedReplyOptions opt;
  opt.ttl = 30;
  size_t n = dns::buildBlockedReply(q, opt, out, sizeof(out));
  TEST_ASSERT_TRUE(n > 0);
  TEST_ASSERT_EQUAL(0, get16(out, 2) & 0xF);  // NOERROR
  TEST_ASSERT_EQUAL(0, get16(out, 6));        // no answer
  TEST_ASSERT_EQUAL(1, get16(out, 8));        // SOA in authority
  dns::ResponseInfo info;
  TEST_ASSERT_TRUE(dns::inspectResponse(out, n, info));
  TEST_ASSERT_TRUE(info.hasSoa);
  TEST_ASSERT_EQUAL_UINT32(30, info.negativeTtl);
}

static void test_blocked_reply_with_edns_has_ede_and_echoes_do() {
  QueryOpts o;
  o.edns = true;
  o.dnssecOk = true;
  Query q = parseOk(makeQuery("ads.example.com", dns::kTypeA, o));
  size_t n = dns::buildBlockedReply(q, {}, out, sizeof(out));
  TEST_ASSERT_EQUAL(1, get16(out, 10));
  const size_t opt = n - 17;  // 11 fixed + 6 EDE
  TEST_ASSERT_EQUAL(dns::kTypeOpt, get16(out, opt + 1));
  TEST_ASSERT_EQUAL(1232, get16(out, opt + 3));
  TEST_ASSERT_EQUAL_HEX16(0x8000, get16(out, opt + 7));  // DO echoed
  TEST_ASSERT_EQUAL(6, get16(out, opt + 9));
  TEST_ASSERT_EQUAL(dns::kOptEde, get16(out, opt + 11));
  TEST_ASSERT_EQUAL(dns::kEdeBlocked, get16(out, opt + 15));

  dns::BlockedReplyOptions banned;
  banned.ede = dns::kEdeFiltered;
  n = dns::buildBlockedReply(q, banned, out, sizeof(out));
  TEST_ASSERT_EQUAL(dns::kEdeFiltered, get16(out, n - 2));
}

static void test_blocked_reply_fails_cleanly_when_buffer_too_small() {
  Query q = parseOk(makeQuery("ads.example.com", dns::kTypeA));
  TEST_ASSERT_EQUAL(0, dns::buildBlockedReply(q, {}, out, 40));
  TEST_ASSERT_EQUAL(0, dns::buildBlockedReply(q, {}, out, 10));
}

static void test_local_address_reply_and_negative_reply() {
  const uint8_t lo4[4] = {127, 0, 0, 1};
  Query q = parseOk(makeQuery("localhost", dns::kTypeA));
  size_t n = dns::buildAddressReply(q, lo4, nullptr, 60, out, sizeof(out));
  TEST_ASSERT_EQUAL(1, get16(out, 6));
  TEST_ASSERT_EQUAL_HEX8_ARRAY(lo4, out + n - 4, 4);
  q = parseOk(makeQuery("localhost", dns::kTypeAaaa));
  dns::buildAddressReply(q, lo4, nullptr, 60, out, sizeof(out));
  TEST_ASSERT_EQUAL(0, get16(out, 6));  // no v6 given -> NODATA
  TEST_ASSERT_EQUAL(1, get16(out, 8));

  q = parseOk(makeQuery("use-application-dns.net", dns::kTypeA));
  n = dns::buildNegativeReply(q, Rcode::kNxDomain, 300, out, sizeof(out));
  TEST_ASSERT_TRUE(n > 0);
  TEST_ASSERT_EQUAL(3, get16(out, 2) & 0xF);
}

static void test_writer_rejects_out_of_order_sections() {
  Query q = parseOk(makeQuery("example.com", dns::kTypeA));
  const uint8_t a[4] = {1, 2, 3, 4};
  dns::ReplyWriter w(out, sizeof(out));
  w.begin(q, Rcode::kNoError);
  w.addAuthoritySoa(10);
  w.addAnswerA(10, a);  // answer after authority is a bug
  TEST_ASSERT_EQUAL(0, w.finish());
}

// --- upstream query -------------------------------------------------------------

static void test_upstream_query_is_padded_to_128_bytes() {
  QueryOpts o;
  o.edns = true;
  o.dnssecOk = true;
  o.flags = 0x0110;  // RD + CD
  Query q = parseOk(makeQuery("Tracker.Example.com", dns::kTypeA, o));
  size_t n = dns::buildUpstreamQuery(q, 0xBEEF, {}, out, sizeof(out));
  TEST_ASSERT_EQUAL(128, n);
  TEST_ASSERT_EQUAL_HEX16(0xBEEF, get16(out, 0));
  TEST_ASSERT_EQUAL_HEX16(0x0130, get16(out, 2));  // RD AD CD
  TEST_ASSERT_EQUAL(1, get16(out, 10));
  Query back;
  TEST_ASSERT_EQUAL(static_cast<int>(ParseStatus::kOk), static_cast<int>(dns::parseQuery(out, n, back)));
  TEST_ASSERT_EQUAL_STRING("tracker.example.com", back.qname);
  TEST_ASSERT_TRUE(back.edns.dnssecOk);
  const size_t opt = 12 + q.qnameWireLen + 4;
  TEST_ASSERT_EQUAL(dns::kOptPadding, get16(out, opt + 11));
}

static void test_upstream_query_without_padding() {
  Query q = parseOk(makeQuery("example.com", dns::kTypeA));
  dns::UpstreamQueryOptions opt;
  opt.padding = false;
  opt.requestAd = false;
  size_t n = dns::buildUpstreamQuery(q, 7, opt, out, sizeof(out));
  TEST_ASSERT_EQUAL(12 + 13 + 4 + 11, n);
  TEST_ASSERT_EQUAL_HEX16(0x0100, get16(out, 2));
  TEST_ASSERT_EQUAL(0, dns::buildUpstreamQuery(q, 7, opt, out, 20));
}

// --- responses ----------------------------------------------------------------

static void test_response_matches_id_and_question_case_insensitively() {
  Query q = parseOk(makeQuery("example.com", dns::kTypeA));
  Bytes r = ResponseBuilder(0x4242, "EXAMPLE.com", dns::kTypeA).answerA(300, 1, 2, 3, 4).build();
  TEST_ASSERT_TRUE(dns::responseMatches(r.data(), r.size(), 0x4242, q));
  TEST_ASSERT_FALSE(dns::responseMatches(r.data(), r.size(), 0x4243, q));
  Bytes other = ResponseBuilder(0x4242, "example.org", dns::kTypeA).build();
  TEST_ASSERT_FALSE(dns::responseMatches(other.data(), other.size(), 0x4242, q));
  Bytes wrongType = ResponseBuilder(0x4242, "example.com", dns::kTypeAaaa).build();
  TEST_ASSERT_FALSE(dns::responseMatches(wrongType.data(), wrongType.size(), 0x4242, q));
}

static void test_inspect_collects_ttls_and_strips_trailing_opt() {
  Bytes r = ResponseBuilder(1, "example.com", dns::kTypeA)
                .answerA(300, 1, 2, 3, 4)
                .answerA(120, 5, 6, 7, 8)
                .opt(1232, 40)
                .build();
  dns::ResponseInfo info;
  TEST_ASSERT_TRUE(dns::inspectResponse(r.data(), r.size(), info));
  TEST_ASSERT_EQUAL(2, info.an);
  TEST_ASSERT_TRUE(info.hasOpt);
  TEST_ASSERT_TRUE(info.optIsLast);
  TEST_ASSERT_EQUAL_UINT32(120, info.minTtl);
  size_t n = dns::stripTrailingOpt(r.data(), r.size(), info);
  TEST_ASSERT_EQUAL(info.optOffset, n);
  TEST_ASSERT_EQUAL(0, get16(r.data(), 10));
  TEST_ASSERT_TRUE(dns::inspectResponse(r.data(), n, info));
  TEST_ASSERT_FALSE(info.hasOpt);
}

static void test_inspect_negative_ttl_from_soa() {
  Bytes r = ResponseBuilder(1, "nx.example.com", dns::kTypeA, 0x8183).authoritySoa(3600, 900).build();
  dns::ResponseInfo info;
  TEST_ASSERT_TRUE(dns::inspectResponse(r.data(), r.size(), info));
  TEST_ASSERT_EQUAL(3, info.rcode);
  TEST_ASSERT_TRUE(info.hasSoa);
  TEST_ASSERT_EQUAL_UINT32(900, info.negativeTtl);
}

static void test_inspect_rejects_malformed_responses() {
  Bytes r = ResponseBuilder(1, "example.com", dns::kTypeA).answerA(300, 1, 2, 3, 4).build();
  dns::ResponseInfo info;
  Bytes cut(r.begin(), r.end() - 2);  // RDATA overruns
  TEST_ASSERT_FALSE(dns::inspectResponse(cut.data(), cut.size(), info));
  Bytes notResponse = r;
  notResponse[2] &= 0x7F;  // QR cleared
  TEST_ASSERT_FALSE(dns::inspectResponse(notResponse.data(), notResponse.size(), info));
  Bytes optInAnswer = ResponseBuilder(1, "example.com", dns::kTypeA).opt().build();
  optInAnswer[7] = 1;  // claim the OPT is an answer record
  optInAnswer[11] = 0;
  TEST_ASSERT_FALSE(dns::inspectResponse(optInAnswer.data(), optInAnswer.size(), info));
}

static void test_age_ttls_decrements_and_floors_at_zero() {
  Bytes r = ResponseBuilder(1, "example.com", dns::kTypeA)
                .answerA(300, 1, 2, 3, 4)
                .answerA(100, 5, 6, 7, 8)
                .build();
  TEST_ASSERT_TRUE(dns::ageTtls(r.data(), r.size(), 150));
  dns::ResponseInfo info;
  dns::inspectResponse(r.data(), r.size(), info);
  TEST_ASSERT_EQUAL_UINT32(0, info.minTtl);
  TEST_ASSERT_EQUAL_UINT32(150, get32(r.data(), 29 + 6));
}

static void test_ttl_above_2_pow_31_is_treated_as_zero() {
  Bytes r = ResponseBuilder(1, "example.com", dns::kTypeA).answerA(0x80000000u, 1, 2, 3, 4).build();
  dns::ResponseInfo info;
  TEST_ASSERT_TRUE(dns::inspectResponse(r.data(), r.size(), info));
  TEST_ASSERT_EQUAL_UINT32(0, info.minTtl);
}

static void test_finalize_restores_id_and_applies_ad_policy() {
  QueryOpts o;
  o.id = 0x7777;
  o.edns = true;
  o.dnssecOk = true;
  Query q = parseOk(makeQuery("example.com", dns::kTypeA, o));
  Bytes r = ResponseBuilder(0x0101, "example.com", dns::kTypeA, 0x81A0)  // QR RD RA AD
                .answerA(60, 1, 2, 3, 4)
                .build();
  dns::ClientReplyOptions co;
  co.sizeLimit = q.udpReplyLimit();
  size_t n = dns::finalizeForClient(r.data(), r.size(), q, co, out, sizeof(out));
  TEST_ASSERT_EQUAL(r.size() + 11, n);
  TEST_ASSERT_EQUAL_HEX16(0x7777, get16(out, 0));
  TEST_ASSERT_TRUE(get16(out, 2) & dns::flag::kAd);
  TEST_ASSERT_EQUAL(1, get16(out, 10));  // our OPT appended

  co.authenticatedUpstream = false;  // plain-UDP fallback: never claim AD
  dns::finalizeForClient(r.data(), r.size(), q, co, out, sizeof(out));
  TEST_ASSERT_FALSE(get16(out, 2) & dns::flag::kAd);

  Query plain = parseOk(makeQuery("example.com", dns::kTypeA));  // no AD/DO asked
  co.authenticatedUpstream = true;
  n = dns::finalizeForClient(r.data(), r.size(), plain, co, out, sizeof(out));
  TEST_ASSERT_FALSE(get16(out, 2) & dns::flag::kAd);
  TEST_ASSERT_EQUAL(r.size(), n);  // no OPT for a non-EDNS client
}

static void test_finalize_truncates_oversized_udp_answer() {
  Query q = parseOk(makeQuery("big.example.com", dns::kTypeTxt));
  Bytes r = ResponseBuilder(1, "big.example.com", dns::kTypeTxt).answerTxt(60, 900).build();
  dns::ClientReplyOptions co;
  co.sizeLimit = q.udpReplyLimit();  // 512
  size_t n = dns::finalizeForClient(r.data(), r.size(), q, co, out, sizeof(out));
  TEST_ASSERT_EQUAL(12 + 17 + 4, n);
  TEST_ASSERT_TRUE(get16(out, 2) & dns::flag::kTc);
  TEST_ASSERT_EQUAL(1, get16(out, 4));
  TEST_ASSERT_EQUAL(0, get16(out, 6));
  co.sizeLimit = 65535;  // TCP gets the whole thing
  n = dns::finalizeForClient(r.data(), r.size(), q, co, out, sizeof(out));
  TEST_ASSERT_EQUAL(r.size(), n);
  TEST_ASSERT_FALSE(get16(out, 2) & dns::flag::kTc);
}

// --- fuzzing ------------------------------------------------------------------

// Truncations and random byte flips of valid packets must never read out of bounds
// (run under AddressSanitizer in the native env) and never yield inconsistent output.
// --- name decoding and the CNAME walk (CNAME-cloaking protection) ------------------

static void test_decode_name_plain_and_compressed() {
  Bytes b;
  put16(b, 0);  // padding so offsets are not 0
  putName(b, "Ads.Tracker.NET");
  char text[dns::kMaxNameText + 1];
  TEST_ASSERT_EQUAL(15, dns::decodeName(b.data(), b.size(), 2, text));
  TEST_ASSERT_EQUAL_STRING("ads.tracker.net", text);

  const size_t ptrAt = b.size();
  b.push_back(3);
  b.push_back('w');
  b.push_back('w');
  b.push_back('w');
  put16(b, 0xC000 | 2);  // www + pointer to ads.tracker.net
  TEST_ASSERT_EQUAL(19, dns::decodeName(b.data(), b.size(), ptrAt, text));
  TEST_ASSERT_EQUAL_STRING("www.ads.tracker.net", text);

  const uint8_t root[] = {0};
  TEST_ASSERT_EQUAL(0, dns::decodeName(root, 1, 0, text));
  TEST_ASSERT_EQUAL_STRING("", text);
}

static void test_decode_name_rejects_loops_overlong_and_bad_bytes() {
  char text[dns::kMaxNameText + 1];
  const uint8_t loop[] = {0xC0, 0x00};  // points at itself
  TEST_ASSERT_EQUAL(-1, dns::decodeName(loop, sizeof(loop), 0, text));
  const uint8_t trunc[] = {5, 'a', 'b'};
  TEST_ASSERT_EQUAL(-1, dns::decodeName(trunc, sizeof(trunc), 0, text));
  const uint8_t badByte[] = {3, 'a', 0x01, 'c', 0};
  TEST_ASSERT_EQUAL(-1, dns::decodeName(badByte, sizeof(badByte), 0, text));
  const uint8_t reserved[] = {0x40, 0};
  TEST_ASSERT_EQUAL(-1, dns::decodeName(reserved, sizeof(reserved), 0, text));
  Bytes longName;  // 5 labels of 63 chars = 319 chars of text
  for (int i = 0; i < 5; i++) {
    longName.push_back(63);
    longName.insert(longName.end(), 63, 'a');
  }
  longName.push_back(0);
  TEST_ASSERT_EQUAL(-1, dns::decodeName(longName.data(), longName.size(), 0, text));
}

struct CnameCollector {
  std::vector<std::string> seen;
  std::string stopAt;
};

static bool collectCname(void* ctx, const char* target, size_t len) {
  auto* c = static_cast<CnameCollector*>(ctx);
  c->seen.emplace_back(target, len);
  return !c->stopAt.empty() && c->seen.back() == c->stopAt;
}

static void test_cname_walk_visits_every_target_in_a_chain() {
  const Bytes r = ResponseBuilder(1, "metrics.mysite.com", 1)
                      .answerCname(300, "mysite.tracker-cdn.net")
                      .answerCnameFrom("mysite.tracker-cdn.net", 300, "edge.Real-Tracker.com")
                      .answerA(60, 1, 2, 3, 4)
                      .build();
  CnameCollector c;
  TEST_ASSERT_FALSE(dns::anyCnameTarget(r.data(), r.size(), collectCname, &c));
  TEST_ASSERT_EQUAL(2, static_cast<int>(c.seen.size()));
  TEST_ASSERT_EQUAL_STRING("mysite.tracker-cdn.net", c.seen[0].c_str());
  TEST_ASSERT_EQUAL_STRING("edge.real-tracker.com", c.seen[1].c_str());  // lowercased
}

static void test_cname_walk_stops_when_visitor_says_so() {
  const Bytes r = ResponseBuilder(1, "a.example.com", 1)
                      .answerCname(300, "first.net")
                      .answerCnameFrom("first.net", 300, "second.net")
                      .answerCnameFrom("second.net", 300, "third.net")
                      .build();
  CnameCollector c;
  c.stopAt = "second.net";
  TEST_ASSERT_TRUE(dns::anyCnameTarget(r.data(), r.size(), collectCname, &c));
  TEST_ASSERT_EQUAL(2, static_cast<int>(c.seen.size()));  // third.net never visited
}

static void test_cname_walk_ignores_non_cname_and_handles_malformed() {
  CnameCollector c;
  const Bytes plain = ResponseBuilder(1, "a.example.com", 1).answerA(60, 1, 2, 3, 4).build();
  TEST_ASSERT_FALSE(dns::anyCnameTarget(plain.data(), plain.size(), collectCname, &c));
  TEST_ASSERT_TRUE(c.seen.empty());

  const Bytes ptr = ResponseBuilder(1, "a.example.com", 1).answerCnameToQname("x.example.com", 60).build();
  TEST_ASSERT_FALSE(dns::anyCnameTarget(ptr.data(), ptr.size(), collectCname, &c));
  TEST_ASSERT_EQUAL(1, static_cast<int>(c.seen.size()));
  TEST_ASSERT_EQUAL_STRING("a.example.com", c.seen[0].c_str());  // pointer was decompressed

  // Truncated anywhere: never crashes, never reads past the end, reports no match.
  const Bytes full = ResponseBuilder(1, "a.example.com", 1).answerCname(60, "b.net").build();
  for (size_t cut = 0; cut < full.size(); cut++) {
    CnameCollector t;
    TEST_ASSERT_FALSE(dns::anyCnameTarget(full.data(), cut, collectCname, &t));
  }
  // A query (QR=0) is not a response.
  const Bytes query = makeQuery("a.example.com", 1);
  TEST_ASSERT_FALSE(dns::anyCnameTarget(query.data(), query.size(), collectCname, &c));
  // More CNAMEs than kMaxCnameChain: the walk gives up instead of looping on garbage.
  ResponseBuilder many(1, "a.example.com", 1);
  std::string prev = "a.example.com";
  for (size_t i = 0; i < dns::kMaxCnameChain + 4; i++) {
    std::string next = "h" + std::to_string(i) + ".net";
    many.answerCnameFrom(prev, 60, next);
    prev = next;
  }
  const Bytes m = many.build();
  CnameCollector mc;
  TEST_ASSERT_FALSE(dns::anyCnameTarget(m.data(), m.size(), collectCname, &mc));
  TEST_ASSERT_EQUAL(static_cast<int>(dns::kMaxCnameChain), static_cast<int>(mc.seen.size()));
}

static void test_fuzz_parsers_on_mutated_packets() {
  FakeRandom rnd;
  QueryOpts o;
  o.edns = true;
  const Bytes seeds[] = {
      makeQuery("a.b.example.com", dns::kTypeA, o),
      ResponseBuilder(1, "example.com", dns::kTypeA).answerA(1, 1, 2, 3, 4).opt(1232, 8).build(),
      ResponseBuilder(1, "nx.example", dns::kTypeA, 0x8183).authoritySoa(5, 5).build(),
  };
  for (const Bytes& seed : seeds) {
    for (int iter = 0; iter < 4000; iter++) {
      Bytes b = seed;
      const int flips = 1 + static_cast<int>(rnd.uniform(4));
      for (int f = 0; f < flips; f++)
        b[rnd.uniform(static_cast<uint32_t>(b.size()))] = static_cast<uint8_t>(rnd.next32());
      b.resize(rnd.uniform(static_cast<uint32_t>(b.size()) + 1));
      // Copy into an exact-size heap buffer so ASan catches any overread.
      std::vector<uint8_t> exact(b.begin(), b.end());
      const uint8_t* p = exact.empty() ? nullptr : exact.data();
      Query q;
      ParseStatus st = dns::parseQuery(p ? p : out, exact.size(), q);
      if (st == ParseStatus::kOk) {
        TEST_ASSERT_TRUE(dns::buildBlockedReply(q, {}, out, sizeof(out)) > 0);
        TEST_ASSERT_TRUE(dns::buildUpstreamQuery(q, 1, {}, out, sizeof(out)) > 0);
      }
      dns::ResponseInfo info;
      if (dns::inspectResponse(p ? p : out, exact.size(), info)) {
        TEST_ASSERT_TRUE(dns::ageTtls(exact.data(), exact.size(), 10));
      }
    }
  }
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_parse_valid_query_lowercases_name);
  RUN_TEST(test_parse_root_name);
  RUN_TEST(test_parse_edns_fields_and_udp_limit_clamping);
  RUN_TEST(test_parse_drops_short_packets_and_responses);
  RUN_TEST(test_parse_rejects_non_query_opcode);
  RUN_TEST(test_parse_rejects_bad_question_counts);
  RUN_TEST(test_parse_rejects_compression_in_question);
  RUN_TEST(test_parse_rejects_label_overrun_and_truncation);
  RUN_TEST(test_parse_rejects_overlong_name_and_bad_bytes);
  RUN_TEST(test_parse_rejects_duplicate_or_malformed_opt);
  RUN_TEST(test_parse_badvers_reply_carries_extended_rcode);
  RUN_TEST(test_parse_refuses_non_in_class);
  RUN_TEST(test_blocked_a_returns_zero_address);
  RUN_TEST(test_blocked_aaaa_returns_unspecified_address);
  RUN_TEST(test_blocked_https_is_nodata_with_soa_not_nxdomain);
  RUN_TEST(test_blocked_reply_with_edns_has_ede_and_echoes_do);
  RUN_TEST(test_blocked_reply_fails_cleanly_when_buffer_too_small);
  RUN_TEST(test_local_address_reply_and_negative_reply);
  RUN_TEST(test_writer_rejects_out_of_order_sections);
  RUN_TEST(test_upstream_query_is_padded_to_128_bytes);
  RUN_TEST(test_upstream_query_without_padding);
  RUN_TEST(test_response_matches_id_and_question_case_insensitively);
  RUN_TEST(test_inspect_collects_ttls_and_strips_trailing_opt);
  RUN_TEST(test_inspect_negative_ttl_from_soa);
  RUN_TEST(test_inspect_rejects_malformed_responses);
  RUN_TEST(test_age_ttls_decrements_and_floors_at_zero);
  RUN_TEST(test_ttl_above_2_pow_31_is_treated_as_zero);
  RUN_TEST(test_finalize_restores_id_and_applies_ad_policy);
  RUN_TEST(test_finalize_truncates_oversized_udp_answer);
  RUN_TEST(test_decode_name_plain_and_compressed);
  RUN_TEST(test_decode_name_rejects_loops_overlong_and_bad_bytes);
  RUN_TEST(test_cname_walk_visits_every_target_in_a_chain);
  RUN_TEST(test_cname_walk_stops_when_visitor_says_so);
  RUN_TEST(test_cname_walk_ignores_non_cname_and_handles_malformed);
  RUN_TEST(test_fuzz_parsers_on_mutated_packets);
  return UNITY_END();
}
