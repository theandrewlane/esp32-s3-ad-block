#pragma once
// Parsing of custom block/allow rules typed into the dashboard or read from
// /custom.txt and /allow.txt, and the glob matcher used by wildcard rules.
//
// Accepted input (one rule per line):
//   example.com             the domain and all its subdomains
//   *.example.com           subdomains only (not example.com itself)
//   ads*.example.com        glob: '*' is any run of characters, '?' exactly one; matched
//                           against the queried name and each of its parent names
//   ||example.com^          Adblock syntax (modifiers after '^' or '$' are ignored)
//   @@||example.com^        same, but an allow rule (see ParsedRule::allow)
//   0.0.0.0 example.com     hosts-file line (127.0.0.1, ::1 and :: work too)
// Lines starting with '#' or '!' are comments.

#include <cstddef>
#include <string>

namespace blocklist {

enum class RuleKind : unsigned char {
  kInvalid,
  kDomain,      // name + subdomains
  kSubdomains,  // subdomains only ("*.name")
  kGlob,        // contains '*' or '?' somewhere other than a leading "*."
};

struct ParsedRule {
  RuleKind kind = RuleKind::kInvalid;
  bool allow = false;  // written with the Adblock "@@" prefix
  std::string text;    // canonical form (what is stored and shown); empty if invalid
};

constexpr size_t kMaxGlobLen = 100;
constexpr size_t kMinGlobLiterals = 4;  // "*" or "a*" would block half the internet
constexpr size_t kMaxGlobsPerList = 64;

ParsedRule parseRule(const char* line, size_t len);

// True if `pattern` (lowercase; '*' and '?' wildcards) matches the whole of `name`.
// Linear time, no allocation, no recursion.
bool globMatch(const char* pattern, size_t plen, const char* name, size_t nlen);

}  // namespace blocklist
