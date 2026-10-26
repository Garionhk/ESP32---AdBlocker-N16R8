// DNS server: decide, answer or relay.
//
// Started from s60sc/ESP32_AdBlocker externalDNS.cpp (AGPL-3.0, dateno1 2026,
// s60sc 2026). The block decision and the localhost rule are theirs; the
// relay, the cache, parallel upstream lookups, TCP and IPv6 are new.
//
// UDP does not use sockets. A socket's receive queue holds 6 packets
// (CONFIG_LWIP_UDP_RECVMBOX_SIZE, fixed in the prebuilt core), so a burst of
// 10 queries -- one web page -- lost 4. Instead lwIP's raw UDP API hands each
// packet straight to a callback, which copies it into a PSRAM pool and queues
// it; the pool and queue are as deep as DNS_RX_SLOTS. Replies go out the same
// way, under the lwIP core lock.
//
// One task drains that queue and never blocks: a query is either answered on
// the spot or sent upstream and remembered in a pending table, and the reply
// is matched back by ID. DoT queries and replies travel through queues too. A
// second task serves the rare client that asks over TCP, with sockets.

#include <Arduino.h>
#include <WiFi.h>
#include <lwip/pbuf.h>
#include <lwip/sockets.h>
#include <lwip/tcpip.h>
#include <lwip/udp.h>

#include "blocklist.h"
#include "config.h"
#include "dnscache.h"
#include "dnsmsg.h"
#include "dot.h"
#include "localdns.h"
#include "localrec.h"
#include "querylog.h"
#include "settings.h"
#include "sinkhole.h"

namespace sinkhole {
namespace {

using dnsmsg::Question;
using querylog::Kind;

enum Route : uint8_t { R_DOT, R_DNS1, R_DNS2, R_ROUTER };

struct Client {
  struct sockaddr_storage addr;
  socklen_t len;
  int       fd;
};

struct Pending {
  bool     used;
  uint16_t upId;
  uint16_t clientId;
  Client   client;
  uint32_t startMs;
  uint32_t sentMs;
  uint8_t  routes[3];
  uint8_t  nroutes;
  uint8_t  at;          // index into routes being tried
  uint16_t udpLimit;    // largest reply the client accepts over UDP
  Question q;
  int      qlen;
  uint8_t  query[DNS_MAX_PACKET];
};

Pending* pend = nullptr;

// ---- receive pool ---------------------------------------------------------

enum Source : uint8_t { SRC_CLIENT, SRC_UPSTREAM, SRC_DOT };

struct Packet {
  uint8_t   src;
  uint16_t  len;
  ip_addr_t addr;   // client, or the upstream server it came from
  uint16_t  port;
  uint8_t   data[DNS_MAX_PACKET];
};

Packet*       pool    = nullptr;
QueueHandle_t freeQ   = nullptr;   // slot indexes ready for the network stack
QueueHandle_t workQ   = nullptr;   // slot indexes waiting for the DNS task
udp_pcb*      clientPcb = nullptr; // :53
udp_pcb*      upPcb     = nullptr; // ephemeral, for upstream servers
volatile uint32_t dropped = 0;     // arrived with the pool full

int tcp4 = -1, tcp6 = -1;
bool started = false;

// Runs in the lwIP thread for every packet. Copy and queue; nothing else.
void onRaw(void* arg, udp_pcb*, pbuf* p, const ip_addr_t* addr, u16_t port) {
  uint8_t idx;
  if (p->tot_len <= DNS_MAX_PACKET && xQueueReceive(freeQ, &idx, 0) == pdTRUE) {
    Packet& k = pool[idx];
    k.src  = (uint8_t)(uintptr_t)arg;
    k.len  = pbuf_copy_partial(p, k.data, p->tot_len, 0);
    ip_addr_copy(k.addr, *addr);
    k.port = port;
    if (xQueueSend(workQ, &idx, 0) != pdTRUE) xQueueSend(freeQ, &idx, 0);
  } else {
    dropped = dropped + 1;
  }
  pbuf_free(p);
}

bool rawSend(udp_pcb* pcb, const ip_addr_t& to, uint16_t port, const uint8_t* data, int len) {
  if (!pcb || len <= 0) return false;
  LOCK_TCPIP_CORE();
  pbuf* p = pbuf_alloc(PBUF_TRANSPORT, len, PBUF_RAM);
  err_t e = ERR_MEM;
  if (p) {
    memcpy(p->payload, data, len);
    e = udp_sendto(pcb, p, &to, port);
    pbuf_free(p);
  }
  UNLOCK_TCPIP_CORE();
  return e == ERR_OK;
}

// The rest of the file speaks sockaddr (TCP, logging); convert at the edges.
void toSockaddr(const ip_addr_t& a, uint16_t port, struct sockaddr_storage& out, socklen_t& len) {
  memset(&out, 0, sizeof(out));
  if (IP_IS_V6(&a)) {
    struct sockaddr_in6* s6 = (struct sockaddr_in6*)&out;
    s6->sin6_family = AF_INET6;
    s6->sin6_port = htons(port);
    memcpy(&s6->sin6_addr, ip_2_ip6(&a)->addr, 16);
    len = sizeof(*s6);
  } else {
    struct sockaddr_in* s4 = (struct sockaddr_in*)&out;
    s4->sin_family = AF_INET;
    s4->sin_port = htons(port);
    s4->sin_addr.s_addr = ip4_addr_get_u32(ip_2_ip4(&a));
    len = sizeof(*s4);
  }
}

void fromSockaddr(const struct sockaddr_storage& in, ip_addr_t& a, uint16_t& port) {
  if (in.ss_family == AF_INET6) {
    const struct sockaddr_in6* s6 = (const struct sockaddr_in6*)&in;
    IP_SET_TYPE_VAL(a, IPADDR_TYPE_V6);
    memcpy(ip_2_ip6(&a)->addr, &s6->sin6_addr, 16);
    ip6_addr_clear_zone(ip_2_ip6(&a));
    port = ntohs(s6->sin6_port);
  } else {
    const struct sockaddr_in* s4 = (const struct sockaddr_in*)&in;
    ip_addr_set_ip4_u32_val(a, s4->sin_addr.s_addr);
    port = ntohs(s4->sin_port);
  }
}

volatile uint32_t routerIp = 0;   // network byte order
uint32_t dns1Ip = 0, dns2Ip = 0;

Stats counters = {};

// Recently blocked names, for "stats".
char recent[BL_RECENT_BLOCKED][BL_MAX_DOMAIN_LEN];
int  recentNext = 0;
portMUX_TYPE recentMux = portMUX_INITIALIZER_UNLOCKED;

void noteBlocked(const char* name) {
  portENTER_CRITICAL(&recentMux);
  int newest = (recentNext + BL_RECENT_BLOCKED - 1) % BL_RECENT_BLOCKED;
  if (strcmp(recent[newest], name) != 0) {
    strncpy(recent[recentNext], name, BL_MAX_DOMAIN_LEN - 1);
    recent[recentNext][BL_MAX_DOMAIN_LEN - 1] = 0;
    recentNext = (recentNext + 1) % BL_RECENT_BLOCKED;
  }
  portEXIT_CRITICAL(&recentMux);
}

uint32_t parseV4(const String& s) {
  IPAddress a;
  return (!s.isEmpty() && a.fromString(s)) ? (uint32_t)a : 0;
}

uint32_t clientV4(const Client& c) {
  if (c.addr.ss_family != AF_INET) return 0;
  return ((const struct sockaddr_in*)&c.addr)->sin_addr.s_addr;
}

void logQuery(const Client& c, const Question& q, Kind kind, uint8_t rc, uint32_t startMs) {
  querylog::Entry e;
  time_t now = time(nullptr);
  e.when = now > (time_t)NTP_MIN_VALID_EPOCH ? (uint32_t)now : 0;
  memset(e.addr, 0, sizeof(e.addr));
  if (c.addr.ss_family == AF_INET6) {
    e.family = 6;
    memcpy(e.addr, &((const struct sockaddr_in6*)&c.addr)->sin6_addr, 16);
  } else {
    e.family = 4;
    memcpy(e.addr, &((const struct sockaddr_in*)&c.addr)->sin_addr, 4);
  }
  e.qtype = q.type;
  e.kind  = kind;
  e.rcode = rc;
  uint32_t ms = millis() - startMs;
  e.ms = ms > 65535 ? 65535 : (uint16_t)ms;
  strncpy(e.name, q.name, sizeof(e.name) - 1);
  e.name[sizeof(e.name) - 1] = 0;
  querylog::record(e);

  switch (kind) {
    case Kind::Blocked:
    case Kind::BlockedCname: counters.blocked++; break;
    case Kind::Forwarded:    counters.forwarded++; break;
    case Kind::Cached:       counters.cached++; break;
    case Kind::Local:
    case Kind::Router:       counters.local++; break;
    case Kind::Failed:       counters.failed++; break;
  }
}

bool serverAddr(Route r, struct sockaddr_in& out) {
  memset(&out, 0, sizeof(out));
  out.sin_family = AF_INET;
  out.sin_port = htons(DNS_PORT);
  switch (r) {
    case R_DOT:
      return false;   // not a network address: queries go through dot::submit()
    case R_DNS1:   out.sin_addr.s_addr = dns1Ip; break;
    case R_DNS2:   out.sin_addr.s_addr = dns2Ip; break;
    case R_ROUTER: out.sin_addr.s_addr = routerIp; break;
  }
  return out.sin_addr.s_addr != 0;
}

// The client's UDP size: 512, or what its EDNS OPT record advertises.
uint16_t udpLimitOf(const uint8_t* q, int len) {
  uint16_t limit = 512;
  dnsmsg::forEachRR(q, len, [&](const dnsmsg::RR& r) {
    if (r.section == 2 && r.type == dnsmsg::T_OPT) {
      uint16_t size = dnsmsg::rd16(q + r.ttlOff - 2);   // OPT keeps it in CLASS
      if (size > limit) limit = size;
      return false;
    }
    return true;
  });
  return limit > DNS_MAX_PACKET ? DNS_MAX_PACKET : limit;
}

// ---- the decision, shared by UDP and TCP --------------------------------

enum class Plan { Answered, Forward };

struct Decision {
  Plan    plan;
  int     len;        // Answered: reply length in `out`
  Kind    kind;
  uint8_t routes[3];  // Forward: servers in order
  uint8_t nroutes;
};

Decision answered(int len, Kind kind) {
  Decision d = {};
  d.plan = Plan::Answered;
  d.len = len;
  d.kind = kind;
  return d;
}

Decision decide(const uint8_t* q, const Question& qq, const Client& c, uint8_t* out, int cap) {
  using dnsmsg::NameKind;
  NameKind nk = dnsmsg::classify(qq.name, g_settings.blockCanaries);

  if (nk == NameKind::Loopback) {
    static const uint8_t lo4[4] = {127, 0, 0, 1};
    static const uint8_t lo6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    int n = qq.type == dnsmsg::T_A    ? dnsmsg::makeAddress(q, qq, out, cap, lo4, 4, DNS_LOCAL_TTL_S)
          : qq.type == dnsmsg::T_AAAA ? dnsmsg::makeAddress(q, qq, out, cap, lo6, 16, DNS_LOCAL_TTL_S)
          : dnsmsg::makeEmpty(q, qq, out, cap, dnsmsg::RC_OK);
    return answered(n, Kind::Local);
  }
  if (nk == NameKind::Mdns || nk == NameKind::Canary) {
    return answered(dnsmsg::makeEmpty(q, qq, out, cap, dnsmsg::RC_NXDOMAIN), Kind::Local);
  }

  // Your own records come before the blocklist: you typed them.
  uint8_t ip[4];
  if ((qq.type == dnsmsg::T_A || qq.type == dnsmsg::T_AAAA) && localdns::lookup(qq.name, ip)) {
    int n = qq.type == dnsmsg::T_A
                ? dnsmsg::makeAddress(q, qq, out, cap, ip, 4, DNS_LOCAL_TTL_S)
                : dnsmsg::makeEmpty(q, qq, out, cap, dnsmsg::RC_OK);   // IPv4 only: use A
    return answered(n, Kind::Local);
  }
  int octets = 0;
  if (qq.type == dnsmsg::T_PTR && dnsmsg::parseReverseV4(qq.name, ip, octets) && octets == 4) {
    char host[localrec::NAME_LEN];
    if (localdns::reverse(ip, host, sizeof(host))) {
      return answered(dnsmsg::makePtr(q, qq, out, cap, host, DNS_LOCAL_TTL_S), Kind::Local);
    }
  }

  // The blocklist is stored without "www." and checked label by label.
  char key[BL_MAX_DOMAIN_LEN + 8];
  if (strlen(qq.name) < sizeof(key)) {
    strcpy(key, qq.name);
    if (blocklist::normalize(key) && blocklist::isBlocked(key)) {
      noteBlocked(key);
      return answered(dnsmsg::makeBlocked(q, qq, out, cap, DNS_BLOCKED_TTL_S), Kind::Blocked);
    }
  }

  int n = dnscache::get(qq, blocklist::generation(), out, cap);
  if (n) {
    dnsmsg::setId(out, dnsmsg::id(q));
    return answered(n, Kind::Cached);
  }

  Decision d = {};
  d.plan = Plan::Forward;
  if (nk == NameKind::LocalName || nk == NameKind::LocalPtr) {
    // The router knows local names. Never send it a query that came from the
    // router itself: if its own DNS points here, that would bounce forever.
    uint32_t router = routerIp;
    if (!g_settings.localForward || !router || clientV4(c) == router) {
      return answered(dnsmsg::makeEmpty(q, qq, out, cap, dnsmsg::RC_NXDOMAIN), Kind::Local);
    }
    d.routes[d.nroutes++] = R_ROUTER;
    d.kind = Kind::Router;
    return d;
  }
  if (dot::ready()) d.routes[d.nroutes++] = R_DOT;
  if (dns1Ip) d.routes[d.nroutes++] = R_DNS1;
  if (dns2Ip) d.routes[d.nroutes++] = R_DNS2;
  d.kind = Kind::Forwarded;
  if (d.nroutes == 0) {
    return answered(dnsmsg::makeEmpty(q, qq, out, cap, dnsmsg::RC_SERVFAIL), Kind::Failed);
  }
  return d;
}

// An upstream reply on its way to the client: the CNAME check, then the
// cache. Rewrites `reply` in place (it may become a blocked answer) and
// returns the length to send.
int finalize(const uint8_t* query, const Question& qq, uint16_t clientId, Route route,
             uint8_t* reply, int len, int cap, Kind& kind) {
  if (route != R_ROUTER && blocklist::enabled()) {
    bool hit = false;
    dnsmsg::forEachCname(reply, len, [&](const char* target) {
      char key[BL_MAX_DOMAIN_LEN + 8];
      if (strlen(target) >= sizeof(key)) return true;
      strcpy(key, target);
      if (blocklist::normalize(key) && blocklist::isBlocked(key)) {
        noteBlocked(key);
        hit = true;
        return false;
      }
      return true;
    });
    if (hit) {
      // The query buffer still has the upstream ID in it; the reply needs the
      // client's.
      int n = dnsmsg::makeBlocked(query, qq, reply, cap, DNS_BLOCKED_TTL_S);
      dnsmsg::setId(reply, clientId);
      kind = Kind::BlockedCname;
      return n;
    }
  }
  dnscache::put(qq, blocklist::generation(), reply, len);
  dnsmsg::setId(reply, clientId);
  kind = route == R_ROUTER ? Kind::Router : Kind::Forwarded;
  return len;
}

// ---- UDP ----------------------------------------------------------------

void sendUdp(const Client& c, uint8_t* reply, int len, uint16_t limit) {
  if (len <= 0) return;
  if (len > limit) {
    // Too big for this client over UDP: send just the question with TC set,
    // and it retries over TCP.
    int end = dnsmsg::skipName(reply, len, dnsmsg::HEADER);
    if (end < 0 || end + 4 > len) return;
    len = end + 4;
    reply[2] |= 0x02;
    dnsmsg::wr16(reply + 6, 0);
    dnsmsg::wr16(reply + 8, 0);
    dnsmsg::wr16(reply + 10, 0);
  }
  ip_addr_t to;
  uint16_t port;
  fromSockaddr(c.addr, to, port);
  rawSend(clientPcb, to, port, reply, len);
}

Pending* allocPending() {
  for (int i = 0; i < DNS_MAX_PENDING; i++) {
    if (!pend[i].used) return &pend[i];
  }
  return nullptr;
}

uint16_t freshId() {
  for (;;) {
    uint16_t id = (uint16_t)esp_random();
    bool taken = false;
    for (int i = 0; i < DNS_MAX_PENDING && !taken; i++) {
      taken = pend[i].used && pend[i].upId == id;
    }
    if (!taken) return id;
  }
}

void failPending(Pending& p) {
  uint8_t out[512];
  dnsmsg::setId(p.query, p.clientId);
  int n = dnsmsg::makeEmpty(p.query, p.q, out, sizeof(out), dnsmsg::RC_SERVFAIL);
  sendUdp(p.client, out, n, p.udpLimit);
  logQuery(p.client, p.q, Kind::Failed, dnsmsg::RC_SERVFAIL, p.startMs);
  p.used = false;
  counters.inFlight--;
}

// Sends to the next server in the route list; fails the query when none is
// left.
void sendNext(Pending& p) {
  while (p.at < p.nroutes) {
    Route r = (Route)p.routes[p.at];
    dnsmsg::setId(p.query, p.upId);
    bool sent = false;
    if (r == R_DOT) {
      sent = dot::submit(p.query, p.qlen);
    } else {
      struct sockaddr_in to;
      if (serverAddr(r, to)) {
        ip_addr_t a;
        ip_addr_set_ip4_u32_val(a, to.sin_addr.s_addr);
        sent = rawSend(upPcb, a, DNS_PORT, p.query, p.qlen);
      }
    }
    if (sent) {
      p.sentMs = millis();
      return;
    }
    p.at++;
  }
  failPending(p);
}

void onClientQuery(Packet& k) {
  uint8_t* buf = k.data;
  int len = k.len;
  Question qq;
  if (!dnsmsg::parseQuery(buf, len, qq)) {
    // Answer FORMERR to anything that looks like a query; drop the rest.
    if (len >= dnsmsg::HEADER && !dnsmsg::isResponse(buf)) {
      uint8_t out[dnsmsg::HEADER];
      memcpy(out, buf, dnsmsg::HEADER);
      out[2] = 0x80 | (buf[2] & 0x79);
      out[3] = 0x81;
      memset(out + 4, 0, 8);
      rawSend(clientPcb, k.addr, k.port, out, sizeof(out));
    }
    return;
  }
  counters.queries++;
  uint32_t start = millis();
  Client c;
  toSockaddr(k.addr, k.port, c.addr, c.len);
  c.fd = -1;
  uint16_t limit = udpLimitOf(buf, len);

  uint8_t out[DNS_MAX_PACKET];
  Decision d = decide(buf, qq, c, out, sizeof(out));
  if (d.plan == Plan::Answered) {
    sendUdp(c, out, d.len, limit);
    logQuery(c, qq, d.kind, d.len ? dnsmsg::rcode(out) : dnsmsg::RC_SERVFAIL, start);
    return;
  }

  Pending* p = allocPending();
  if (!p) {
    int n = dnsmsg::makeEmpty(buf, qq, out, sizeof(out), dnsmsg::RC_SERVFAIL);
    sendUdp(c, out, n, limit);
    logQuery(c, qq, Kind::Failed, dnsmsg::RC_SERVFAIL, start);
    return;
  }
  p->used = true;
  counters.inFlight++;
  p->upId = freshId();
  p->clientId = dnsmsg::id(buf);
  p->client = c;
  p->startMs = start;
  memcpy(p->routes, d.routes, sizeof(p->routes));
  p->nroutes = d.nroutes;
  p->at = 0;
  p->udpLimit = limit;
  p->q = qq;
  p->qlen = len;
  memcpy(p->query, buf, len);
  sendNext(*p);
}

void onUpstreamReply(Packet& k) {
  uint8_t* buf = k.data;
  int len = k.len;
  if (len < dnsmsg::HEADER || !dnsmsg::isResponse(buf)) return;
  uint16_t rid = dnsmsg::id(buf);
  for (int i = 0; i < DNS_MAX_PENDING; i++) {
    Pending& p = pend[i];
    if (!p.used || p.upId != rid) continue;
    // Must come from the server we asked, and answer what we asked.
    Route r = (Route)p.routes[p.at];
    if (r == R_DOT) {
      if (k.src != SRC_DOT) return;
    } else {
      struct sockaddr_in expect;
      if (k.src != SRC_UPSTREAM || !serverAddr(r, expect) || !IP_IS_V4(&k.addr) ||
          ip4_addr_get_u32(ip_2_ip4(&k.addr)) != expect.sin_addr.s_addr || k.port != DNS_PORT) {
        return;
      }
    }
    if (!dnsmsg::sameQuestion(buf, len, p.q)) return;

    uint8_t rc = dnsmsg::rcode(buf);
    if ((rc == dnsmsg::RC_SERVFAIL || rc == dnsmsg::RC_REFUSED) && p.at + 1 < p.nroutes) {
      p.at++;
      sendNext(p);
      return;
    }
    Kind kind;
    int n = finalize(p.query, p.q, p.clientId, (Route)p.routes[p.at], buf, len, DNS_MAX_PACKET, kind);
    sendUdp(p.client, buf, n, p.udpLimit);
    logQuery(p.client, p.q, kind, dnsmsg::rcode(buf), p.startMs);
    p.used = false;
    counters.inFlight--;
    return;
  }
}

void checkTimeouts() {
  uint32_t now = millis();
  for (int i = 0; i < DNS_MAX_PENDING; i++) {
    Pending& p = pend[i];
    if (!p.used || now - p.sentMs < DNS_UPSTREAM_TIMEOUT_MS) continue;
    p.at++;
    sendNext(p);
  }
}

void udpTask(void*) {
  uint32_t reportedDrops = 0, lastReportMs = 0;
  for (;;) {
    // A full receive pool means the burst was deeper than DNS_RX_SLOTS.
    if (dropped != reportedDrops && millis() - lastReportMs > 10000) {
      Serial.printf("[dns] receive pool full: %lu packets dropped so far\n", (unsigned long)dropped);
      reportedDrops = dropped;
      lastReportMs = millis();
    }
    uint8_t idx;
    // Wake for the next packet, or every 20 ms to check upstream timeouts.
    if (xQueueReceive(workQ, &idx, pdMS_TO_TICKS(20)) == pdTRUE) {
      do {
        Packet& k = pool[idx];
        if (k.src == SRC_CLIENT) onClientQuery(k);
        else onUpstreamReply(k);
        xQueueSend(freeQ, &idx, 0);
      } while (xQueueReceive(workQ, &idx, 0) == pdTRUE);
    }
    checkTimeouts();
  }
}

// ---- TCP ----------------------------------------------------------------
//
// Rare: clients use it when a UDP reply came back truncated. Served by its
// own task with plain blocking calls, so the UDP path never waits on it.

bool readAll(int fd, uint8_t* buf, int n) {
  int got = 0;
  while (got < n) {
    int r = recv(fd, buf + got, n - got, 0);
    if (r <= 0) return false;
    got += r;
  }
  return true;
}

bool writeFramed(int fd, const uint8_t* buf, int n) {
  uint8_t lenb[2];
  dnsmsg::wr16(lenb, (uint16_t)n);
  return send(fd, lenb, 2, 0) == 2 && send(fd, buf, n, 0) == n;
}

// One query to one server over TCP, with timeouts. Returns the reply length.
int tcpExchange(uint32_t server, const uint8_t* q, int qlen, uint8_t* out, int cap) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return 0;
  struct timeval tv = {2, 0};
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
  struct sockaddr_in to = {};
  to.sin_family = AF_INET;
  to.sin_port = htons(DNS_PORT);
  to.sin_addr.s_addr = server;
  int n = 0;
  uint8_t lenb[2];
  if (connect(fd, (struct sockaddr*)&to, sizeof(to)) == 0 && writeFramed(fd, q, qlen) &&
      readAll(fd, lenb, 2)) {
    int len = dnsmsg::rd16(lenb);
    if (len <= cap && readAll(fd, out, len)) n = len;
  }
  close(fd);
  return n;
}

void serveTcpQuery(int fd, const Client& c, uint8_t* q, int qlen, uint8_t* out, int cap) {
  Question qq;
  if (!dnsmsg::parseQuery(q, qlen, qq)) return;
  counters.queries++;
  counters.tcp++;
  uint32_t start = millis();

  Decision d = decide(q, qq, c, out, cap);
  if (d.plan == Plan::Answered) {
    if (d.len) writeFramed(fd, out, d.len);
    logQuery(c, qq, d.kind, d.len ? dnsmsg::rcode(out) : dnsmsg::RC_SERVFAIL, start);
    return;
  }
  for (int i = 0; i < d.nroutes; i++) {
    Route r = (Route)d.routes[i];
    if (r == R_DOT) continue;   // DoT replies come back to the UDP task's pending table
    uint32_t server = r == R_DNS1 ? dns1Ip : r == R_DNS2 ? dns2Ip : routerIp;
    if (!server) continue;
    int n = tcpExchange(server, q, qlen, out, cap);
    if (n < dnsmsg::HEADER || !dnsmsg::sameQuestion(out, n, qq)) continue;
    uint8_t rc = dnsmsg::rcode(out);
    if (rc == dnsmsg::RC_SERVFAIL || rc == dnsmsg::RC_REFUSED) continue;
    Kind kind;
    n = finalize(q, qq, dnsmsg::id(q), r, out, n, cap, kind);
    writeFramed(fd, out, n);
    logQuery(c, qq, kind, dnsmsg::rcode(out), start);
    return;
  }
  int n = dnsmsg::makeEmpty(q, qq, out, cap, dnsmsg::RC_SERVFAIL);
  writeFramed(fd, out, n);
  logQuery(c, qq, Kind::Failed, dnsmsg::RC_SERVFAIL, start);
}

void tcpTask(void*) {
  const int TCP_BUF = 4096;
  uint8_t* q   = (uint8_t*)ps_malloc(TCP_BUF);
  uint8_t* out = (uint8_t*)ps_malloc(TCP_BUF);
  for (;;) {
    fd_set rd;
    FD_ZERO(&rd);
    int maxfd = tcp4;
    FD_SET(tcp4, &rd);
    if (tcp6 >= 0) { FD_SET(tcp6, &rd); maxfd = max(maxfd, tcp6); }
    if (select(maxfd + 1, &rd, nullptr, nullptr, nullptr) <= 0) continue;

    int listeners[2] = {tcp4, tcp6};
    for (int lfd : listeners) {
      if (lfd < 0 || !FD_ISSET(lfd, &rd)) continue;
      Client c;
      c.len = sizeof(c.addr);
      int fd = accept(lfd, (struct sockaddr*)&c.addr, &c.len);
      if (fd < 0) continue;
      c.fd = fd;
      struct timeval tv = {(long)(DNS_TCP_IDLE_MS / 1000), 0};
      setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
      setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
      // A client may send several queries on one connection; serve them until
      // it goes quiet.
      for (int k = 0; k < 16; k++) {
        uint8_t lenb[2];
        if (!readAll(fd, lenb, 2)) break;
        int qlen = dnsmsg::rd16(lenb);
        if (qlen < dnsmsg::HEADER || qlen > TCP_BUF || !readAll(fd, q, qlen)) break;
        serveTcpQuery(fd, c, q, qlen, out, TCP_BUF);
      }
      close(fd);
    }
  }
}

// ---- sockets --------------------------------------------------------------

// A raw UDP endpoint. `port` 0 picks an ephemeral one.
udp_pcb* rawListen(uint8_t type, uint16_t port, Source src) {
  LOCK_TCPIP_CORE();
  udp_pcb* pcb = udp_new_ip_type(type);
  if (pcb && udp_bind(pcb, type == IPADDR_TYPE_V4 ? IP4_ADDR_ANY : IP_ANY_TYPE, port) != ERR_OK) {
    udp_remove(pcb);
    pcb = nullptr;
  }
  if (pcb) udp_recv(pcb, onRaw, (void*)(uintptr_t)src);
  UNLOCK_TCPIP_CORE();
  return pcb;
}

int listenTcp(int family) {
  int fd = socket(family, SOCK_STREAM, 0);
  if (fd < 0) return -1;
  int one = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  int rc;
  if (family == AF_INET6) {
    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
    struct sockaddr_in6 a = {};
    a.sin6_family = AF_INET6;
    a.sin6_port = htons(DNS_PORT);
    rc = bind(fd, (struct sockaddr*)&a, sizeof(a));
  } else {
    struct sockaddr_in a = {};
    a.sin_family = AF_INET;
    a.sin_port = htons(DNS_PORT);
    a.sin_addr.s_addr = INADDR_ANY;
    rc = bind(fd, (struct sockaddr*)&a, sizeof(a));
  }
  if (rc < 0 || listen(fd, DNS_TCP_CLIENTS) < 0) { close(fd); return -1; }
  return fd;
}

}  // namespace

void prealloc() {
  if (!pend) pend = (Pending*)ps_calloc(DNS_MAX_PENDING, sizeof(Pending));
  if (!pool) {
    pool  = (Packet*)ps_calloc(DNS_RX_SLOTS, sizeof(Packet));
    freeQ = xQueueCreate(DNS_RX_SLOTS, sizeof(uint8_t));
    workQ = xQueueCreate(DNS_RX_SLOTS, sizeof(uint8_t));
    for (uint8_t i = 0; pool && i < DNS_RX_SLOTS; i++) xQueueSend(freeQ, &i, 0);
  }
  dnscache::begin(DNS_CACHE_SLOTS);
}

bool begin() {
  dns1Ip = parseV4(g_settings.dns1);
  dns2Ip = parseV4(g_settings.dns2);
  if (started) return true;
  if (!pend || !pool) prealloc();
  if (!pend || !pool || !freeQ || !workQ) {
    Serial.println("[dns] no memory for the pending table or receive pool");
    return false;
  }

  // One endpoint answers IPv4 and IPv6 alike when IPv6 is on.
  clientPcb = rawListen(g_settings.ipv6 ? IPADDR_TYPE_ANY : IPADDR_TYPE_V4, DNS_PORT, SRC_CLIENT);
  if (!clientPcb) {
    Serial.println("[dns] port 53 bind failed");
    return false;
  }
  upPcb = rawListen(IPADDR_TYPE_V4, 0, SRC_UPSTREAM);
  tcp4 = listenTcp(AF_INET);
  if (g_settings.ipv6) tcp6 = listenTcp(AF_INET6);

  if (!upPcb ||
      xTaskCreatePinnedToCore(udpTask, "dns", DNS_TASK_STACK, nullptr, DNS_TASK_PRIORITY,
                              nullptr, 1) != pdPASS) {
    Serial.println("[dns] worker not started");
    return false;
  }
  if (tcp4 >= 0) {
    xTaskCreatePinnedToCore(tcpTask, "dnstcp", DNS_TASK_STACK, nullptr, 1, nullptr, 1);
  }
  started = true;
  Serial.printf("[dns] serving on %s:%d (udp%s, tcp%s), %d-packet receive queue, upstream %s / %s\n",
                WiFi.localIP().toString().c_str(), DNS_PORT, g_settings.ipv6 ? "+v6" : "",
                tcp4 >= 0 ? (tcp6 >= 0 ? "+v6" : "") : " off", DNS_RX_SLOTS, g_settings.dns1.c_str(),
                g_settings.dns2.c_str());
  return true;
}

bool running() { return started; }

void setRouter(uint32_t ipv4) { routerIp = ipv4; }

Stats stats() {
  Stats s = counters;
  s.dropped = dropped;
  return s;
}

bool fromDot(const uint8_t* data, int len) {
  uint8_t idx;
  if (!pool || len > DNS_MAX_PACKET || xQueueReceive(freeQ, &idx, 0) != pdTRUE) {
    dropped = dropped + 1;
    return false;
  }
  Packet& k = pool[idx];
  k.src = SRC_DOT;
  k.len = (uint16_t)len;
  memcpy(k.data, data, len);
  if (xQueueSend(workQ, &idx, 0) != pdTRUE) {
    xQueueSend(freeQ, &idx, 0);
    return false;
  }
  return true;
}

String recentBlocked() {
  String out;
  char copy[BL_RECENT_BLOCKED][BL_MAX_DOMAIN_LEN];
  portENTER_CRITICAL(&recentMux);
  memcpy(copy, recent, sizeof(copy));
  int next = recentNext;
  portEXIT_CRITICAL(&recentMux);

  for (int i = 1; i <= BL_RECENT_BLOCKED; i++) {
    const char* name = copy[(next - i + BL_RECENT_BLOCKED) % BL_RECENT_BLOCKED];
    if (!name[0]) break;
    if (!out.isEmpty()) out += "\n";
    out += name;
  }
  return out;
}

bool resolves(const char* host) {
  uint32_t server = dns1Ip ? dns1Ip : parseV4(g_settings.dns1);
  if (!server) return false;
  uint8_t q[300], r[DNS_MAX_PACKET];
  uint16_t qid = (uint16_t)esp_random();
  int qlen = dnsmsg::makeQuery(q, sizeof(q), qid, host, dnsmsg::T_A);
  if (!qlen) return false;

  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) return false;
  struct timeval tv = {1, 500 * 1000};
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  struct sockaddr_in to = {};
  to.sin_family = AF_INET;
  to.sin_port = htons(DNS_PORT);
  to.sin_addr.s_addr = server;
  bool ok = false;
  if (sendto(fd, q, qlen, 0, (struct sockaddr*)&to, sizeof(to)) == qlen) {
    int n = recv(fd, r, sizeof(r), 0);
    uint8_t ip[4];
    ok = n >= dnsmsg::HEADER && dnsmsg::id(r) == qid && dnsmsg::rcode(r) == dnsmsg::RC_OK &&
         dnsmsg::firstA(r, n, ip);
  }
  close(fd);
  return ok;
}

String upstreamStatus() {
  String plain = g_settings.dns1 + (g_settings.dns2.isEmpty() ? String("") : " / " + g_settings.dns2);
  if (!g_settings.dotEnabled) return plain + " (plain)";
  if (dot::ready()) return "DNS-over-TLS, " + dot::status() + "; fallback " + plain;
  return plain + " (plain) -- DNS-over-TLS " + dot::status();
}

}  // namespace sinkhole
