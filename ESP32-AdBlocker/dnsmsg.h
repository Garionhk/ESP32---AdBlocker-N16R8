#pragma once

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// DNS wire-format helpers for sinkhole.cpp: parsing queries, walking the
// records of an upstream reply, and building the few replies the device
// answers itself. Pure functions over byte buffers, so the native tests can
// feed them hostile packets.

namespace dnsmsg {

const uint16_t T_A     = 1;
const uint16_t T_CNAME = 5;
const uint16_t T_SOA   = 6;
const uint16_t T_PTR   = 12;
const uint16_t T_AAAA  = 28;
const uint16_t T_OPT   = 41;

const uint8_t RC_OK       = 0;
const uint8_t RC_SERVFAIL = 2;
const uint8_t RC_NXDOMAIN = 3;
const uint8_t RC_REFUSED  = 5;

const int HEADER = 12;
const int MAX_NAME = 256;   // dotted text, including the terminator

inline uint16_t rd16(const uint8_t* p) { return (uint16_t)((p[0] << 8) | p[1]); }
inline uint32_t rd32(const uint8_t* p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
inline void wr16(uint8_t* p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xFF; }
inline void wr32(uint8_t* p, uint32_t v) {
  p[0] = v >> 24; p[1] = (v >> 16) & 0xFF; p[2] = (v >> 8) & 0xFF; p[3] = v & 0xFF;
}

inline uint16_t id(const uint8_t* m) { return rd16(m); }
inline void setId(uint8_t* m, uint16_t v) { wr16(m, v); }
inline bool isResponse(const uint8_t* m) { return m[2] & 0x80; }
inline uint8_t opcode(const uint8_t* m) { return (m[2] >> 3) & 0x0F; }
inline bool truncated(const uint8_t* m) { return m[2] & 0x02; }
inline uint8_t rcode(const uint8_t* m) { return m[3] & 0x0F; }
inline uint16_t qdcount(const uint8_t* m) { return rd16(m + 4); }
inline uint16_t ancount(const uint8_t* m) { return rd16(m + 6); }
inline uint16_t nscount(const uint8_t* m) { return rd16(m + 8); }
inline uint16_t arcount(const uint8_t* m) { return rd16(m + 10); }

// Reads the possibly-compressed name at `off` into `out` as lowercase dotted
// text without a trailing dot ("" for the root). Returns the offset just past
// the name where it sits in the packet, or -1 if it is malformed: overruns,
// pointer loops, forward-only nonsense, or too long for `out`.
inline int readName(const uint8_t* m, int len, int off, char* out, int outSize) {
  int pos = off, ret = -1, o = 0, jumps = 0;
  for (;;) {
    if (pos < 0 || pos >= len) return -1;
    uint8_t l = m[pos];
    if ((l & 0xC0) == 0xC0) {
      if (pos + 1 >= len) return -1;
      if (ret < 0) ret = pos + 2;
      int target = ((l & 0x3F) << 8) | m[pos + 1];
      if (target >= pos || ++jumps > 32) return -1;   // pointers only point back
      pos = target;
      continue;
    }
    if (l & 0xC0) return -1;                           // reserved label types
    pos++;
    if (l == 0) break;
    if (pos + l > len) return -1;
    if (o + l + 2 > outSize) return -1;
    if (o) out[o++] = '.';
    for (int i = 0; i < l; i++) out[o++] = (char)tolower(m[pos + i]);
    pos += l;
  }
  if (outSize < 1) return -1;
  out[o] = 0;
  return ret >= 0 ? ret : pos;
}

// Offset just past the name at `off`, without decoding it; -1 if malformed.
inline int skipName(const uint8_t* m, int len, int off) {
  for (int guard = 0; guard < 128; guard++) {
    if (off >= len) return -1;
    uint8_t l = m[off];
    if ((l & 0xC0) == 0xC0) return off + 2 <= len ? off + 2 : -1;
    if (l & 0xC0) return -1;
    if (l == 0) return off + 1;
    off += 1 + l;
  }
  return -1;
}

struct Question {
  char     name[MAX_NAME];
  uint16_t type;
  uint16_t cls;
  int      end;   // offset just past the question
};

// A standard query with one question. Rejects responses and other opcodes.
inline bool parseQuery(const uint8_t* m, int len, Question& q) {
  if (len < HEADER + 5) return false;
  if (isResponse(m) || opcode(m) != 0 || qdcount(m) != 1) return false;
  int off = readName(m, len, HEADER, q.name, sizeof(q.name));
  if (off < 0 || off + 4 > len) return false;
  q.type = rd16(m + off);
  q.cls  = rd16(m + off + 2);
  q.end  = off + 4;
  return true;
}

// Does this reply answer the same question? Guards against a stale or forged
// upstream packet that happens to reuse a pending ID.
inline bool sameQuestion(const uint8_t* m, int len, const Question& q) {
  if (len < HEADER + 5 || qdcount(m) != 1) return false;
  char name[MAX_NAME];
  int off = readName(m, len, HEADER, name, sizeof(name));
  if (off < 0 || off + 4 > len) return false;
  return rd16(m + off) == q.type && rd16(m + off + 2) == q.cls && strcmp(name, q.name) == 0;
}

struct RR {
  int      section;   // 0 answer, 1 authority, 2 additional
  int      ownerOff;
  uint16_t type;
  int      ttlOff;
  int      rdOff;
  uint16_t rdLen;
};

// Calls fn(const RR&) for every record after the question section. fn returns
// false to stop early. Returns false if the packet is malformed.
template <typename Fn>
inline bool forEachRR(const uint8_t* m, int len, Fn fn) {
  if (len < HEADER) return false;
  int off = HEADER;
  for (int i = 0; i < qdcount(m); i++) {
    off = skipName(m, len, off);
    if (off < 0 || off + 4 > len) return false;
    off += 4;
  }
  int counts[3] = {ancount(m), nscount(m), arcount(m)};
  for (int s = 0; s < 3; s++) {
    for (int i = 0; i < counts[s]; i++) {
      RR r;
      r.section  = s;
      r.ownerOff = off;
      off = skipName(m, len, off);
      if (off < 0 || off + 10 > len) return false;
      r.type   = rd16(m + off);
      r.ttlOff = off + 4;
      r.rdLen  = rd16(m + off + 8);
      r.rdOff  = off + 10;
      off = r.rdOff + r.rdLen;
      if (off > len) return false;
      if (!fn(r)) return true;
    }
  }
  return true;
}

// How long a reply may be cached: the smallest TTL among its records,
// ignoring the EDNS OPT pseudo-record. For a negative answer the SOA's
// minimum field caps it, per RFC 2308. `fallback` when there are no records.
inline uint32_t cacheTtl(const uint8_t* m, int len, uint32_t fallback) {
  uint32_t best = 0xFFFFFFFFu;
  bool ok = forEachRR(m, len, [&](const RR& r) {
    if (r.type == T_OPT) return true;
    uint32_t ttl = rd32(m + r.ttlOff);
    if (r.type == T_SOA && r.section == 1 && r.rdLen >= 22) {
      // RDATA: mname, rname, then serial refresh retry expire minimum.
      int p = skipName(m, len, r.rdOff);
      p = p < 0 ? -1 : skipName(m, len, p);
      if (p >= 0 && p + 20 <= r.rdOff + r.rdLen) {
        uint32_t minimum = rd32(m + p + 16);
        if (minimum < ttl) ttl = minimum;
      }
    }
    if (ttl < best) best = ttl;
    return true;
  });
  if (!ok) return 0;
  return best == 0xFFFFFFFFu ? fallback : best;
}

// Counts every TTL down by `elapsed` seconds, so a cached reply never
// promises more freshness than it has left.
inline bool ageTtls(uint8_t* m, int len, uint32_t elapsed) {
  return forEachRR(m, len, [&](const RR& r) {
    if (r.type != T_OPT) {
      uint32_t ttl = rd32(m + r.ttlOff);
      wr32(m + r.ttlOff, ttl > elapsed ? ttl - elapsed : 0);
    }
    return true;
  });
}

// Calls fn(const char* name) for each CNAME target in the answer section --
// the names a tracker hides behind a first-party alias.
template <typename Fn>
inline bool forEachCname(const uint8_t* m, int len, Fn fn) {
  return forEachRR(m, len, [&](const RR& r) {
    if (r.section != 0 || r.type != T_CNAME) return true;
    char target[MAX_NAME];
    if (readName(m, len, r.rdOff, target, sizeof(target)) < 0) return true;
    return fn((const char*)target);
  });
}

// ---- replies the device builds itself ------------------------------------

// Header and question copied from the query; flags say "response, recursion
// available"; no records yet. Returns the length, 0 if it does not fit.
inline int startReply(const uint8_t* q, const Question& qq, uint8_t* out, int cap, uint8_t rc) {
  if (qq.end > cap) return 0;
  memcpy(out, q, qq.end);
  out[2] = (uint8_t)(0x80 | (q[2] & 0x79));   // QR, keep opcode and RD
  out[3] = (uint8_t)(0x80 | (rc & 0x0F));     // RA + rcode
  wr16(out + 4, 1);
  wr16(out + 6, 0);
  wr16(out + 8, 0);
  wr16(out + 10, 0);
  return qq.end;
}

// No records: NODATA when rc is RC_OK, otherwise NXDOMAIN / SERVFAIL / ...
inline int makeEmpty(const uint8_t* q, const Question& qq, uint8_t* out, int cap, uint8_t rc) {
  return startReply(q, qq, out, cap, rc);
}

// Appends one answer whose owner is the question name (pointer to offset 12).
inline int addAnswer(uint8_t* out, int at, int cap, uint16_t type, uint32_t ttl,
                     const uint8_t* rdata, uint16_t rdLen) {
  if (at + 12 + rdLen > cap) return 0;
  out[at++] = 0xC0; out[at++] = 0x0C;
  wr16(out + at, type); at += 2;
  wr16(out + at, 1);    at += 2;   // class IN
  wr32(out + at, ttl);  at += 4;
  wr16(out + at, rdLen); at += 2;
  memcpy(out + at, rdata, rdLen);
  wr16(out + 6, (uint16_t)(rd16(out + 6) + 1));
  return at + rdLen;
}

// A or AAAA with one address (4 or 16 bytes).
inline int makeAddress(const uint8_t* q, const Question& qq, uint8_t* out, int cap,
                       const uint8_t* addr, int addrLen, uint32_t ttl) {
  int at = startReply(q, qq, out, cap, RC_OK);
  if (!at) return 0;
  return addAnswer(out, at, cap, addrLen == 16 ? T_AAAA : T_A, ttl, addr, (uint16_t)addrLen);
}

// The sinkhole answer: 0.0.0.0 for A, :: for AAAA, NODATA for anything else.
inline int makeBlocked(const uint8_t* q, const Question& qq, uint8_t* out, int cap, uint32_t ttl) {
  static const uint8_t zero[16] = {0};
  if (qq.type == T_A)    return makeAddress(q, qq, out, cap, zero, 4, ttl);
  if (qq.type == T_AAAA) return makeAddress(q, qq, out, cap, zero, 16, ttl);
  return makeEmpty(q, qq, out, cap, RC_OK);
}

// Encodes "a.b.c" as length-prefixed labels. Returns bytes written, 0 if it
// does not fit or a label is empty / over 63.
inline int encodeName(const char* name, uint8_t* out, int cap) {
  int at = 0;
  const char* p = name;
  while (*p) {
    const char* dot = strchr(p, '.');
    int l = dot ? (int)(dot - p) : (int)strlen(p);
    if (l == 0 || l > 63 || at + l + 2 > cap) return 0;
    out[at++] = (uint8_t)l;
    memcpy(out + at, p, l);
    at += l;
    p += l + (dot ? 1 : 0);
  }
  if (at + 1 > cap) return 0;
  out[at++] = 0;
  return at;
}

inline int makePtr(const uint8_t* q, const Question& qq, uint8_t* out, int cap,
                   const char* target, uint32_t ttl) {
  int at = startReply(q, qq, out, cap, RC_OK);
  if (!at) return 0;
  uint8_t rdata[MAX_NAME + 2];
  int n = encodeName(target, rdata, sizeof(rdata));
  if (!n) return 0;
  return addAnswer(out, at, cap, T_PTR, ttl, rdata, (uint16_t)n);
}

// Builds a query for (name, type), for the device's own lookups. Returns the
// length, 0 if the name cannot be encoded.
inline int makeQuery(uint8_t* out, int cap, uint16_t qid, const char* name, uint16_t type) {
  if (cap < HEADER + 5) return 0;
  memset(out, 0, HEADER);
  wr16(out, qid);
  out[2] = 0x01;            // RD
  wr16(out + 4, 1);
  int n = encodeName(name, out + HEADER, cap - HEADER - 4);
  if (!n) return 0;
  int at = HEADER + n;
  wr16(out + at, type); at += 2;
  wr16(out + at, 1);    at += 2;
  return at;
}

// First A record in the answer section, for the "does it resolve" check.
inline bool firstA(const uint8_t* m, int len, uint8_t ip[4]) {
  bool found = false;
  forEachRR(m, len, [&](const RR& r) {
    if (r.section == 0 && r.type == T_A && r.rdLen == 4) {
      memcpy(ip, m + r.rdOff, 4);
      found = true;
      return false;
    }
    return true;
  });
  return found;
}

// ---- name classification ----------------------------------------------------

enum class NameKind : uint8_t {
  Normal,     // forward upstream
  Loopback,   // localhost -> 127.0.0.1 / ::1
  Mdns,       // .local and wpad: never forwarded, NXDOMAIN
  LocalName,  // single label, .lan, .home, .home.arpa ... -> the router
  LocalPtr,   // reverse lookup of a private IPv4 address -> the router
  Canary,     // DoH / Private Relay canaries -> NXDOMAIN
};

inline bool endsWith(const char* s, const char* suffix) {
  size_t n = strlen(s), k = strlen(suffix);
  return n >= k && strcmp(s + n - k, suffix) == 0;
}

// "4.3.2.1.in-addr.arpa" -> 1.2.3.4. Partial reverse names ("168.192.in-addr.arpa")
// fill from the left and report how many octets they had. Returns false if
// it is not an in-addr.arpa name.
inline bool parseReverseV4(const char* name, uint8_t ip[4], int& octets) {
  if (!endsWith(name, ".in-addr.arpa")) return false;
  size_t stem = strlen(name) - strlen(".in-addr.arpa");
  int vals[4], n = 0;
  const char* p = name;
  while (p < name + stem) {
    if (n == 4 || !isdigit((unsigned char)*p)) return false;
    char* end;
    long v = strtol(p, &end, 10);
    if (v < 0 || v > 255 || end - p > 3) return false;
    vals[n++] = (int)v;
    p = end;
    if (p < name + stem) {
      if (*p != '.') return false;
      p++;
    }
  }
  if (n == 0) return false;
  memset(ip, 0, 4);
  for (int i = 0; i < n; i++) ip[i] = (uint8_t)vals[n - 1 - i];
  octets = n;
  return true;
}

inline bool isPrivateV4(const uint8_t ip[4], int octets) {
  if (octets >= 1 && ip[0] == 10) return true;
  if (octets >= 2 && ip[0] == 192 && ip[1] == 168) return true;
  if (octets >= 2 && ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) return true;
  if (octets >= 2 && ip[0] == 169 && ip[1] == 254) return true;
  return false;
}

// `canaries` enables the Firefox DoH and iCloud Private Relay canaries.
inline NameKind classify(const char* name, bool canaries) {
  if (!name[0]) return NameKind::Normal;   // root
  if (!strcmp(name, "localhost") || endsWith(name, ".localhost")) return NameKind::Loopback;
  if (endsWith(name, ".local") || !strncmp(name, "wpad", 4)) return NameKind::Mdns;
  if (canaries && (!strcmp(name, "use-application-dns.net") ||
                   !strcmp(name, "mask.icloud.com") || !strcmp(name, "mask-h2.icloud.com"))) {
    return NameKind::Canary;
  }
  uint8_t ip[4];
  int octets;
  if (parseReverseV4(name, ip, octets)) {
    return isPrivateV4(ip, octets) ? NameKind::LocalPtr : NameKind::Normal;
  }
  if (!strchr(name, '.')) return NameKind::LocalName;
  if (endsWith(name, ".lan") || endsWith(name, ".home") || endsWith(name, ".home.arpa") ||
      endsWith(name, ".internal") || endsWith(name, ".localdomain")) {
    return NameKind::LocalName;
  }
  return NameKind::Normal;
}

}  // namespace dnsmsg
