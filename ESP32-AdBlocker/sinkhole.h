#pragma once

#include <Arduino.h>

// The DNS server, on UDP and TCP port 53, IPv4 and (optionally) IPv6.
//
// Blocked names get 0.0.0.0 / :: / NODATA. Everything else is relayed:
// the upstream server's reply goes back to the client byte for byte (apart
// from the ID), so every record type, every address, CNAME chains and real
// TTLs come through. Many lookups run at once; replies are cached in PSRAM.
//
// Upstreams in order: DNS-over-TLS (when connected), then dns1, then dns2.
// Local names go to the router instead.
//
// Started from s60sc/ESP32_AdBlocker externalDNS.cpp (AGPL-3.0, dateno1 and
// s60sc); the relay, cache, parallel lookups and TCP are new.

namespace sinkhole {

struct Stats {
  uint32_t queries;
  uint32_t blocked;    // blocklist and CNAME hits
  uint32_t forwarded;  // answered by an upstream server
  uint32_t cached;
  uint32_t local;      // localhost, local records, canaries, router
  uint32_t failed;     // no upstream answered
  uint32_t inFlight;   // waiting on upstream right now
  uint32_t tcp;        // queries that came over TCP
  uint32_t dropped;    // packets that arrived with the receive pool full
};

// Allocates the pending-query table and the cache in PSRAM. Call before the
// blocklist claims the rest of PSRAM.
void prealloc();

// Binds the sockets and starts the UDP and TCP tasks. Safe to call again.
bool begin();
bool running();

// The router's address, for local names. 0 to forget it.
void setRouter(uint32_t ipv4);

Stats stats();

// Most recent blocked names, newest first, up to BL_RECENT_BLOCKED.
String recentBlocked();

// Synchronous upstream A lookup, used to reject typos before adding a custom
// block. Not for the DNS tasks' own use.
bool resolves(const char* host);

// A reply from the DoT proxy, queued for the DNS task like any other
// upstream reply. Returns false if the receive pool is full.
bool fromDot(const uint8_t* data, int len);

// Where allowed lookups are going right now, for the status report.
String upstreamStatus();

}  // namespace sinkhole
