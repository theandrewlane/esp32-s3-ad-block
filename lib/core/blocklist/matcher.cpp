#include "blocklist/matcher.h"

#include <algorithm>

namespace blocklist {

void DomainSet::add(const char* name, size_t len) {
  hashes_.push_back(hashDomain(name, len));
}

void DomainSet::finalize() {
  std::sort(hashes_.begin(), hashes_.end());
  hashes_.erase(std::unique(hashes_.begin(), hashes_.end()), hashes_.end());
}

bool DomainSet::contains(uint64_t hash48) const {
  return std::binary_search(hashes_.begin(), hashes_.end(), hash48);
}

bool RuleSet::addGlob(const char* pattern, size_t len) {
  if (globs_.size() >= kMaxGlobsPerList) return false;
  globs_.emplace_back(pattern, len);
  return true;
}

void RuleSet::finalize() {
  domains_.finalize();
  subdomains_.finalize();
  std::sort(globs_.begin(), globs_.end());
  globs_.erase(std::unique(globs_.begin(), globs_.end()), globs_.end());
}

bool RuleSet::matches(const char* name, size_t len) const {
  return find(name, len, nullptr);
}

bool RuleSet::explain(const char* name, size_t len, std::string* rule) const {
  return find(name, len, rule);
}

bool RuleSet::find(const char* name, size_t len, std::string* rule) const {
  if (domains_.size() && forEachSuffix(name, len, [&](const char* s, size_t n) {
        if (!domains_.contains(hashDomain(s, n))) return false;
        if (rule) rule->assign(s, n);
        return true;
      }))
    return true;
  if (subdomains_.size()) {
    bool first = true;  // the name itself is skipped: "*.x" does not cover x
    if (forEachSuffix(name, len, [&](const char* s, size_t n) {
          if (first) {
            first = false;
            return false;
          }
          if (!subdomains_.contains(hashDomain(s, n))) return false;
          if (rule) {
            rule->assign("*.");
            rule->append(s, n);
          }
          return true;
        }))
      return true;
  }
  for (const std::string& g : globs_) {
    // "*.x" style globs ("*.ads*.net") cover subdomains of the rest, so a pattern is
    // tried against the name and every parent name with at least two labels.
    if (forEachSuffix(name, len,
                      [&g](const char* s, size_t n) { return globMatch(g.data(), g.size(), s, n); })) {
      if (rule) *rule = g;
      return true;
    }
  }
  return false;
}

void Matcher::setCustom(RuleSet block, RuleSet allow) {
  std::lock_guard<std::mutex> lock(customMutex_);
  customBlock_ = std::move(block);
  customAllow_ = std::move(allow);
}

bool Matcher::cnameBlocked(const char* qname, size_t qlen, const char* target, size_t tlen) const {
  if (match(qname, qlen) == MatchResult::kAllowed) return false;
  return match(target, tlen) == MatchResult::kBlocked;
}

MatchResult Matcher::match(const char* name, size_t len) const {
  if (len == 0) return MatchResult::kNone;
  {
    std::lock_guard<std::mutex> lock(customMutex_);
    if (customAllow_.size() && customAllow_.matches(name, len)) return MatchResult::kAllowed;
    if (customBlock_.size() && customBlock_.matches(name, len)) return MatchResult::kBlocked;
  }
  IndexHolder::ReadGuard g = index_.acquire();
  const IIndex* idx = g.get();
  if (idx && forEachCandidate(name, len, [idx](uint64_t h) { return idx->contains(h); }))
    return MatchResult::kBlocked;
  return MatchResult::kNone;
}

Explanation Matcher::explain(const char* name, size_t len) const {
  Explanation e;
  if (len == 0) return e;
  {
    std::lock_guard<std::mutex> lock(customMutex_);
    if (customAllow_.size() && customAllow_.explain(name, len, &e.rule)) {
      e.result = MatchResult::kAllowed;
      e.source = MatchSource::kCustomAllow;
      return e;
    }
    if (customBlock_.size() && customBlock_.explain(name, len, &e.rule)) {
      e.result = MatchResult::kBlocked;
      e.source = MatchSource::kCustomBlock;
      return e;
    }
  }
  IndexHolder::ReadGuard g = index_.acquire();
  const IIndex* idx = g.get();
  if (idx && forEachSuffix(name, len, [&](const char* s, size_t n) {
        if (!idx->contains(hashDomain(s, n))) return false;
        e.rule.assign(s, n);
        return true;
      })) {
    e.result = MatchResult::kBlocked;
    e.source = MatchSource::kMainList;
  }
  return e;
}

}  // namespace blocklist
