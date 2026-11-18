#include "blocklist/rules.h"

namespace blocklist {

namespace {

bool isSpace(char c) {
  return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

char lower(char c) {
  return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + ('a' - 'A')) : c;
}

bool isNameChar(char c) {
  return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_';
}

bool startsWith(const std::string& s, const char* prefix) {
  size_t i = 0;
  for (; prefix[i]; i++)
    if (i >= s.size() || s[i] != prefix[i]) return false;
  return true;
}

// A hosts-file line: "<address> <name>". Returns the name part, or the input unchanged.
std::string stripHostsAddress(const std::string& s) {
  const size_t sp = s.find_first_of(" \t");
  if (sp == std::string::npos) return s;
  const std::string addr = s.substr(0, sp);
  if (addr != "0.0.0.0" && addr != "127.0.0.1" && addr != "::" && addr != "::1") return s;
  size_t i = sp;
  while (i < s.size() && isSpace(s[i])) i++;
  size_t e = i;
  while (e < s.size() && !isSpace(s[e])) e++;
  return s.substr(i, e - i);
}

}  // namespace

ParsedRule parseRule(const char* line, size_t len) {
  ParsedRule r;
  size_t b = 0, e = len;
  while (b < e && isSpace(line[b])) b++;
  while (e > b && isSpace(line[e - 1])) e--;
  if (b == e || line[b] == '#' || line[b] == '!') return r;
  std::string s;
  for (size_t i = b; i < e; i++) s += lower(line[i]);

  s = stripHostsAddress(s);
  if (startsWith(s, "@@")) {
    r.allow = true;
    s.erase(0, 2);
  }
  if (startsWith(s, "||")) s.erase(0, 2);
  const size_t cut = s.find_first_of("^$/");  // separator, modifiers, or a path: not part of a host
  if (cut != std::string::npos) s.erase(cut);
  while (!s.empty() && s.back() == '.') s.pop_back();
  while (!s.empty() && s.front() == '.') s.erase(0, 1);

  bool subdomainsOnly = false;
  if (startsWith(s, "*.")) {
    subdomainsOnly = true;
    s.erase(0, 2);
  }
  if (s.empty() || s.size() > 253) return r;

  bool wild = false;
  size_t literals = 0;
  for (char c : s) {
    if (c == '*' || c == '?') {
      wild = true;
    } else if (isNameChar(c)) {
      literals++;
    } else {
      return r;  // anything else is not part of a host name
    }
  }
  if (s.find("..") != std::string::npos) return r;

  if (wild) {
    // "*.x" keeps meaning "subdomains of x" only when what is left has no wildcard.
    const std::string full = subdomainsOnly ? "*." + s : s;
    if (full.size() > kMaxGlobLen || literals < kMinGlobLiterals) return r;
    r.kind = RuleKind::kGlob;
    r.text = full;
    return r;
  }
  if (s.size() < 3 || s.find('.') == std::string::npos || s.front() == '-') return r;
  bool hasLetter = false;
  for (char c : s) hasLetter = hasLetter || (c >= 'a' && c <= 'z');
  if (!hasLetter) return r;  // "0.0.0.0" or "10.1.2.3": an address, not a host name
  r.kind = subdomainsOnly ? RuleKind::kSubdomains : RuleKind::kDomain;
  r.text = subdomainsOnly ? "*." + s : s;
  return r;
}

bool globMatch(const char* pat, size_t plen, const char* name, size_t nlen) {
  size_t p = 0, n = 0;
  size_t starP = static_cast<size_t>(-1), starN = 0;
  while (n < nlen) {
    if (p < plen && (pat[p] == '?' || (pat[p] != '*' && pat[p] == name[n]))) {
      p++;
      n++;
    } else if (p < plen && pat[p] == '*') {
      starP = p++;
      starN = n;
    } else if (starP != static_cast<size_t>(-1)) {
      p = starP + 1;
      n = ++starN;
    } else {
      return false;
    }
  }
  while (p < plen && pat[p] == '*') p++;
  return p == plen;
}

}  // namespace blocklist
