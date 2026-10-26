#pragma once

#include <ctype.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>

// Pure text handling for blocklist.cpp, free of hardware calls so the native
// tests can exercise it directly.

namespace blparse {

inline bool isSpace(char c) { return c == ' ' || c == '\t'; }

inline bool endsWith(const char* s, size_t len, const char* suffix) {
  size_t n = strlen(suffix);
  return len >= n && strcmp(s + len - n, suffix) == 0;
}

// Lowercases in place, strips one trailing dot and a leading "www.". Returns
// the new length, or 0 if the result is not a plausible domain name: needs a
// dot, only a-z 0-9 - _ ., shorter than maxLen, not an IP literal such as the
// "0.0.0.0 0.0.0.0" line at the top of hosts files, and not a local-only name
// such as hosts files' own "localhost.localdomain".
inline size_t normalize(char* name, size_t maxLen) {
  size_t len = strlen(name);
  if (len > 0 && name[len - 1] == '.') name[--len] = 0;
  if (strncasecmp(name, "www.", 4) == 0) {
    memmove(name, name + 4, len - 3);   // includes the terminator
    len -= 4;
  }
  if (len == 0 || len >= maxLen) return 0;

  bool dot = false, letter = false;
  for (size_t i = 0; i < len; i++) {
    char c = (char)tolower((unsigned char)name[i]);
    name[i] = c;
    if (c == '.') dot = true;
    else if ((c >= 'a' && c <= 'z') || c == '-' || c == '_') letter = true;
    else if (c < '0' || c > '9') return 0;
  }
  if (!dot || !letter || name[0] == '.' || name[len - 1] == '.') return 0;
  if (endsWith(name, len, ".localdomain") || endsWith(name, len, ".local") ||
      endsWith(name, len, ".localhost")) return 0;
  return len;
}

// Pulls the domain out of one line, in any of:
//   0.0.0.0 ads.example.com      HOSTS
//   127.0.0.1 ads.example.com    HOSTS
//   ||ads.example.com^           Adblock (domain rules only)
//   ads.example.com              plain list
// Terminates the line after the domain and returns a pointer into it, or
// nullptr for comments, other rule types and junk. The result still needs
// normalize().
inline char* extractDomain(char* line) {
  char* p = line;
  while (isSpace(*p)) p++;
  if (*p == 0 || *p == '#' || *p == '!' || *p == '[') return nullptr;

  char* dom = nullptr;
  if (strncmp(p, "0.0.0.0", 7) == 0 && isSpace(p[7])) {
    dom = p + 7;
  } else if (strncmp(p, "127.0.0.1", 9) == 0 && isSpace(p[9])) {
    dom = p + 9;
  } else if (p[0] == '|' && p[1] == '|') {
    dom = p + 2;
    char* end = dom;
    while (*end && *end != '^' && *end != '$' && *end != '/') end++;
    // Only plain "||domain^" rules. Anything with options or a path is a
    // URL filter, which a DNS sinkhole cannot honour.
    char* tail = end + (*end == '^' ? 1 : 0);
    while (isSpace(*tail)) tail++;
    if (*end != '^' || *tail != 0) return nullptr;
    *end = 0;
    return dom;
  } else {
    dom = p;
  }

  while (isSpace(*dom)) dom++;
  char* end = dom;
  while (*end && !isSpace(*end) && *end != '#') end++;
  *end = 0;
  return dom;
}

}  // namespace blparse
