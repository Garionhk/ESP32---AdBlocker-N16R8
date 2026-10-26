// Host-side tests for dnsmsg.h: query parsing, record walking, TTL handling,
// CNAME extraction, the replies the device builds itself, and name
// classification -- including the malformed packets a DNS server must survive.
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "dnsmsg.h"

using namespace dnsmsg;

static int failures = 0, checks = 0;

static void ok(bool cond, const char* what) {
  checks++;
  if (!cond) { failures++; printf("  FAIL: %s\n", what); }
}

typedef std::vector<uint8_t> Bytes;

static void put16(Bytes& b, uint16_t v) { b.push_back(v >> 8); b.push_back(v & 0xFF); }
static void put32(Bytes& b, uint32_t v) { put16(b, v >> 16); put16(b, v & 0xFFFF); }
static void putName(Bytes& b, const char* name) {
  uint8_t tmp[300];
  int n = encodeName(name, tmp, sizeof(tmp));
  b.insert(b.end(), tmp, tmp + n);
}

static Bytes query(const char* name, uint16_t type, uint16_t id = 0x1234) {
  Bytes b(HEADER, 0);
  wr16(&b[0], id);
  b[2] = 0x01;            // RD
  wr16(&b[4], 1);
  putName(b, name);
  put16(b, type);
  put16(b, 1);
  return b;
}

// A reply to `name`: one CNAME to `alias` (compressed owner), one A for the
// alias, and optionally an SOA in authority.
static Bytes cnameReply(const char* name, const char* alias, uint32_t ttlCname, uint32_t ttlA) {
  Bytes b = query(name, T_A, 0x4321);
  b[2] = 0x81; b[3] = 0x80;
  wr16(&b[6], 2);
  // CNAME, owner -> pointer to question name
  b.push_back(0xC0); b.push_back(0x0C);
  put16(b, T_CNAME); put16(b, 1); put32(b, ttlCname);
  Bytes target;
  putName(target, alias);
  put16(b, (uint16_t)target.size());
  size_t aliasOff = b.size();
  b.insert(b.end(), target.begin(), target.end());
  // A, owner -> pointer to the alias
  b.push_back(0xC0 | (uint8_t)(aliasOff >> 8)); b.push_back((uint8_t)aliasOff);
  put16(b, T_A); put16(b, 1); put32(b, ttlA);
  put16(b, 4);
  b.push_back(93); b.push_back(184); b.push_back(216); b.push_back(34);
  return b;
}

int main() {
  // --- encode / parse a query ---
  {
    Bytes q = query("WWW.Example.COM", T_AAAA);
    Question qq;
    ok(parseQuery(q.data(), (int)q.size(), qq), "parses a query");
    ok(!strcmp(qq.name, "www.example.com"), "name lowercased");
    ok(qq.type == T_AAAA && qq.cls == 1, "type and class");
    ok(qq.end == (int)q.size(), "end offset");
    ok(sameQuestion(q.data(), (int)q.size(), qq), "same question matches itself");

    Bytes other = query("www.example.org", T_AAAA);
    ok(!sameQuestion(other.data(), (int)other.size(), qq), "different name does not match");
    Bytes otherType = query("www.example.com", T_A);
    ok(!sameQuestion(otherType.data(), (int)otherType.size(), qq), "different type does not match");
  }
  {
    Bytes q = query("example.com", T_A);
    q[2] |= 0x80;   // a response, not a query
    Question qq;
    ok(!parseQuery(q.data(), (int)q.size(), qq), "responses are not queries");
  }
  {
    Bytes q = query("example.com", T_A);
    Question qq;
    ok(!parseQuery(q.data(), 11, qq), "short packet rejected");
    ok(!parseQuery(q.data(), (int)q.size() - 3, qq), "truncated question rejected");
    q[HEADER] = 60;   // label length runs off the end
    ok(!parseQuery(q.data(), (int)q.size(), qq), "label overrun rejected");
  }
  {
    // A pointer that points at itself must not hang the parser.
    Bytes b(HEADER, 0);
    wr16(&b[4], 1);
    b.push_back(0xC0); b.push_back(0x0C);
    put16(b, 1); put16(b, 1);
    Question qq;
    ok(!parseQuery(b.data(), (int)b.size(), qq), "self-referencing pointer rejected");
    char out[MAX_NAME];
    ok(readName(b.data(), (int)b.size(), 12, out, sizeof(out)) < 0, "readName refuses loops");
  }
  {
    // Reserved label type (0x40) is malformed.
    Bytes b(HEADER, 0);
    wr16(&b[4], 1);
    b.push_back(0x41); b.push_back('a');
    b.push_back(0); put16(b, 1); put16(b, 1);
    Question qq;
    ok(!parseQuery(b.data(), (int)b.size(), qq), "reserved label type rejected");
  }
  {
    Bytes root = query("", T_A);
    Question qq;
    ok(parseQuery(root.data(), (int)root.size(), qq) && qq.name[0] == 0, "root query parses as \"\"");
  }

  // --- reply walking ---
  {
    Bytes r = cnameReply("track.shop.com", "shop.tracker-cdn.net", 300, 60);
    int count = 0;
    bool walked = forEachRR(r.data(), (int)r.size(), [&](const RR& rr) { count++; return true; });
    ok(walked && count == 2, "walks both answers");

    std::vector<std::string> targets;
    forEachCname(r.data(), (int)r.size(), [&](const char* t) { targets.push_back(t); return true; });
    ok(targets.size() == 1 && targets[0] == "shop.tracker-cdn.net", "extracts the CNAME target");

    ok(cacheTtl(r.data(), (int)r.size(), 99) == 60, "cache TTL is the smallest");

    ageTtls(r.data(), (int)r.size(), 45);
    ok(cacheTtl(r.data(), (int)r.size(), 99) == 15, "TTLs count down");
    ageTtls(r.data(), (int)r.size(), 1000);
    ok(cacheTtl(r.data(), (int)r.size(), 99) == 0, "TTLs floor at zero");

    uint8_t ip[4];
    ok(firstA(r.data(), (int)r.size(), ip) && ip[0] == 93 && ip[3] == 34, "first A found past the CNAME");

    Bytes cut(r.begin(), r.end() - 3);
    ok(!forEachRR(cut.data(), (int)cut.size(), [](const RR&) { return true; }),
       "truncated record is malformed");
  }
  {
    // NXDOMAIN with an SOA: TTL capped by the SOA minimum.
    Bytes r = query("nope.example.com", T_A);
    r[2] = 0x81; r[3] = 0x83;
    wr16(&r[8], 1);
    r.push_back(0xC0); r.push_back(0x0C);
    put16(r, T_SOA); put16(r, 1); put32(r, 3600);
    Bytes rd;
    putName(rd, "ns.example.com");
    putName(rd, "admin.example.com");
    put32(rd, 1); put32(rd, 7200); put32(rd, 900); put32(rd, 86400); put32(rd, 120);
    put16(r, (uint16_t)rd.size());
    r.insert(r.end(), rd.begin(), rd.end());
    ok(rcode(r.data()) == RC_NXDOMAIN, "rcode read");
    ok(cacheTtl(r.data(), (int)r.size(), 99) == 120, "negative TTL from SOA minimum");
  }
  {
    Bytes r = query("example.com", T_A);
    r[2] = 0x81; r[3] = 0x80;
    ok(cacheTtl(r.data(), (int)r.size(), 77) == 77, "no records: fallback TTL");
  }
  {
    // An EDNS OPT record in additional does not count as a TTL.
    Bytes r = query("example.com", T_A);
    r[2] = 0x81; r[3] = 0x80;
    wr16(&r[10], 1);
    r.push_back(0); put16(r, T_OPT); put16(r, 1232); put32(r, 0); put16(r, 0);
    ok(cacheTtl(r.data(), (int)r.size(), 55) == 55, "OPT ignored for TTL");
  }

  // --- replies we build ---
  {
    Bytes q = query("ads.example.com", T_A, 0xBEEF);
    Question qq;
    parseQuery(q.data(), (int)q.size(), qq);
    uint8_t out[512];
    int n = makeBlocked(q.data(), qq, out, sizeof(out), 10);
    ok(n == (int)q.size() + 16, "blocked A has one 16-byte answer");
    ok(id(out) == 0xBEEF && isResponse(out) && rcode(out) == RC_OK, "header of blocked reply");
    ok(ancount(out) == 1 && out[n - 4] == 0 && out[n - 1] == 0, "answer is 0.0.0.0");
    ok((out[2] & 0x01) && (out[3] & 0x80), "RD kept, RA set");
    ok(sameQuestion(out, n, qq), "reply carries the question");

    Bytes q6 = query("ads.example.com", T_AAAA);
    parseQuery(q6.data(), (int)q6.size(), qq);
    n = makeBlocked(q6.data(), qq, out, sizeof(out), 10);
    ok(ancount(out) == 1 && n == (int)q6.size() + 28, "blocked AAAA is ::");

    Bytes qtxt = query("ads.example.com", 16);
    parseQuery(qtxt.data(), (int)qtxt.size(), qq);
    n = makeBlocked(qtxt.data(), qq, out, sizeof(out), 10);
    ok(ancount(out) == 0 && rcode(out) == RC_OK, "blocked TXT is NODATA");

    n = makeEmpty(q.data(), qq, out, sizeof(out), RC_NXDOMAIN);
    ok(rcode(out) == RC_NXDOMAIN && ancount(out) == 0, "NXDOMAIN");

    ok(makeBlocked(q.data(), qq, out, 20, 10) == 0, "refuses to overflow the buffer");
  }
  {
    Bytes q = query("10.0.168.192.in-addr.arpa", T_PTR);
    Question qq;
    parseQuery(q.data(), (int)q.size(), qq);
    uint8_t out[512];
    int n = makePtr(q.data(), qq, out, sizeof(out), "nas.lan", 300);
    ok(n > 0 && ancount(out) == 1, "PTR answer built");
    bool sawPtr = false;
    forEachRR(out, n, [&](const RR& r) {
      char name[MAX_NAME];
      if (r.type == T_PTR && readName(out, n, r.rdOff, name, sizeof(name)) > 0) {
        sawPtr = !strcmp(name, "nas.lan");
      }
      return true;
    });
    ok(sawPtr, "PTR target reads back");
  }
  {
    uint8_t q[64];
    int n = makeQuery(q, sizeof(q), 0x0102, "one.one.one.one", T_A);
    Question qq;
    ok(n > 0 && parseQuery(q, n, qq) && !strcmp(qq.name, "one.one.one.one") && id(q) == 0x0102,
       "makeQuery round-trips");
    std::string longLabel(64, 'a');
    ok(makeQuery(q, sizeof(q), 1, longLabel.c_str(), T_A) == 0, "64-char label refused");
  }

  // --- reverse names ---
  {
    uint8_t ip[4];
    int oct = 0;
    ok(parseReverseV4("4.3.2.1.in-addr.arpa", ip, oct) && oct == 4 && ip[0] == 1 && ip[3] == 4,
       "full reverse name");
    ok(parseReverseV4("168.192.in-addr.arpa", ip, oct) && oct == 2 && ip[0] == 192 && ip[1] == 168,
       "partial reverse name");
    ok(!parseReverseV4("300.1.168.192.in-addr.arpa", ip, oct), "octet over 255 rejected");
    ok(!parseReverseV4("x.1.168.192.in-addr.arpa", ip, oct), "non-numeric rejected");
    ok(!parseReverseV4("example.com", ip, oct), "not a reverse name");
  }

  // --- classification ---
  ok(classify("localhost", true) == NameKind::Loopback, "localhost");
  ok(classify("foo.localhost", true) == NameKind::Loopback, "*.localhost");
  ok(classify("printer.local", true) == NameKind::Mdns, ".local is mDNS");
  ok(classify("wpad.lan", true) == NameKind::Mdns, "wpad never forwarded");
  ok(classify("printer", true) == NameKind::LocalName, "single label goes to the router");
  ok(classify("nas.lan", true) == NameKind::LocalName, ".lan");
  ok(classify("tv.home", true) == NameKind::LocalName, ".home");
  ok(classify("tv.home.arpa", true) == NameKind::LocalName, ".home.arpa");
  ok(classify("10.0.168.192.in-addr.arpa", true) == NameKind::LocalPtr, "private PTR");
  ok(classify("5.0.16.172.in-addr.arpa", true) == NameKind::LocalPtr, "172.16/12 PTR");
  ok(classify("8.8.8.8.in-addr.arpa", true) == NameKind::Normal, "public PTR forwarded");
  ok(classify("use-application-dns.net", true) == NameKind::Canary, "Firefox canary");
  ok(classify("mask.icloud.com", true) == NameKind::Canary, "Private Relay canary");
  ok(classify("use-application-dns.net", false) == NameKind::Normal, "canaries off");
  ok(classify("example.com", true) == NameKind::Normal, "ordinary name");
  ok(classify("", true) == NameKind::Normal, "root");
  ok(classify("homedepot.com", true) == NameKind::Normal, "\"home\" inside a name is not .home");

  printf("%d/%d checks passed\n", checks - failures, checks);
  return failures ? 1 : 0;
}
