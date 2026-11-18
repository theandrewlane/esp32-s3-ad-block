#pragma once
// Decides whether a name is blocked: custom allowlist first, then custom blocklist,
// then the main list. A rule for a domain also covers its subdomains, so for
// "a.b.example.com" we check the name and each parent down to two labels.

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "blocklist/index.h"
#include "blocklist/rules.h"

namespace blocklist {

// Small sorted set of 48-bit domain hashes (custom rules, at most a few thousand).
class DomainSet {
 public:
  DomainSet() = default;
  void add(const char* name, size_t len);
  void finalize();  // sort + dedupe; call after adding
  bool contains(uint64_t hash48) const;
  size_t size() const { return hashes_.size(); }

 private:
  std::vector<uint64_t> hashes_;
};

// One custom list (block or allow): domain rules, subdomain-only rules and globs.
// Not thread-safe by itself; Matcher swaps whole sets under its lock.
class RuleSet {
 public:
  RuleSet() = default;
  RuleSet(DomainSet domains) : domains_(std::move(domains)) {}  // NOLINT: implicit on purpose

  void addDomain(const char* name, size_t len) { domains_.add(name, len); }
  void addSubdomains(const char* name, size_t len) { subdomains_.add(name, len); }
  // False (and nothing added) once kMaxGlobsPerList patterns are stored.
  bool addGlob(const char* pattern, size_t len);
  void finalize();  // sort + dedupe the hash sets; call after adding
  size_t size() const { return domains_.size() + subdomains_.size() + globs_.size(); }
  size_t globCount() const { return globs_.size(); }
  bool matches(const char* name, size_t len) const;
  // Like matches(), but also says which rule fired (as it is written in the list:
  // "example.com", "*.example.com" or the glob). Allocates: not for the hot path.
  bool explain(const char* name, size_t len, std::string* rule) const;

 private:
  bool find(const char* name, size_t len, std::string* rule) const;  // rule may be null

  DomainSet domains_;
  DomainSet subdomains_;
  std::vector<std::string> globs_;
};

enum class MatchResult { kNone, kBlocked, kAllowed };

// Where a verdict came from (for "why was this blocked?").
enum class MatchSource { kNone, kCustomAllow, kCustomBlock, kMainList };

struct Explanation {
  MatchResult result = MatchResult::kNone;
  MatchSource source = MatchSource::kNone;
  std::string rule;  // the custom rule, or the listed (parent) name for the main list
};

class Matcher {
 public:
  explicit Matcher(const IndexHolder& index) : index_(index) {}

  // Replaces both custom sets at once (web task). Lookups never see a half-update.
  void setCustom(RuleSet block, RuleSet allow);

  // `name`: lowercase, no trailing dot. Allocation-free.
  MatchResult match(const char* name, size_t len) const;

  // Same decision as match(), plus the rule that caused it. Allocates; for the
  // dashboard's "why" lookup, never the DNS path.
  Explanation explain(const char* name, size_t len) const;

  // CNAME cloaking: true if `target` (a CNAME target in the answer for `qname`) is
  // blocked. A name the user explicitly allowed is never blocked through its CNAME,
  // so `allow metrics.mysite.com` keeps working even when it points at a tracker.
  bool cnameBlocked(const char* qname, size_t qlen, const char* target, size_t tlen) const;

 private:
  const IndexHolder& index_;
  mutable std::mutex customMutex_;
  RuleSet customBlock_;
  RuleSet customAllow_;
};

// Calls fn(suffix, suffixLen) for the name and each parent with at least two labels;
// stops early when fn returns true. Returns whether any call returned true.
template <typename Fn>
bool forEachSuffix(const char* name, size_t len, Fn fn) {
  size_t start = 0;
  while (start < len) {
    if (fn(name + start, len - start)) return true;
    // Advance to the next label; stop before the last label (never match a bare TLD).
    size_t dot = start;
    while (dot < len && name[dot] != '.') dot++;
    if (dot >= len) break;
    size_t next = dot + 1;
    bool moreDots = false;
    for (size_t k = next; k < len; k++)
      if (name[k] == '.') {
        moreDots = true;
        break;
      }
    if (!moreDots) break;
    start = next;
  }
  return false;
}

// Same walk, but fn gets the 48-bit hash of each candidate.
template <typename Fn>
bool forEachCandidate(const char* name, size_t len, Fn fn) {
  return forEachSuffix(name, len, [&fn](const char* s, size_t n) { return fn(hashDomain(s, n)); });
}

}  // namespace blocklist
