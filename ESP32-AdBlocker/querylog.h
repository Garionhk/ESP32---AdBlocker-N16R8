#pragma once

#include <Arduino.h>

// Every DNS query and what happened to it, in a ring in PSRAM, plus hourly
// totals for the last week in RTC memory. The ring is lost on any reboot,
// the daily one included; the hourly totals survive a software restart but
// not a power cut.

namespace querylog {

enum class Kind : uint8_t {
  Forwarded,     // answered by the upstream server
  Cached,        // answered from the cache
  Blocked,       // on the blocklist
  BlockedCname,  // allowed name, but its CNAME target is blocked
  Local,         // localhost, a local record, or a canary
  Router,        // local name, answered by the router
  Failed,        // upstream timed out or failed (SERVFAIL)
};

const int NAME_LEN = 72;   // longer names are cut for display

struct Entry {
  uint32_t when;       // epoch seconds; 0 if the clock was not set
  uint8_t  family;     // 4 or 6
  uint8_t  addr[16];   // client address
  uint16_t qtype;
  Kind     kind;
  uint8_t  rcode;
  uint16_t ms;         // time to answer
  char     name[NAME_LEN];
};

struct Hour {
  uint32_t hour;       // epoch / 3600
  uint32_t queries;
  uint32_t blocked;
};

// Allocates the ring in PSRAM. Call early, before the blocklist takes the
// rest of PSRAM.
bool begin(size_t entries);

// Called by the DNS tasks for every answered query.
void record(const Entry& e);

// Copies up to `max` entries, newest first, that pass `filter` (may be null).
// Returns how many were copied.
typedef bool (*Filter)(const Entry& e, void* ctx);
int recent(Entry* out, int max, Filter filter = nullptr, void* ctx = nullptr);

// Walks every entry in the ring, oldest first, under the lock. Keep fn fast.
void forEach(void (*fn)(const Entry& e, void* ctx), void* ctx);

uint32_t size();      // entries currently held
uint32_t capacity();

// Most frequent names or clients in the ring.
enum class TopOf : uint8_t { BlockedNames, AllowedNames, Clients };
struct TopRow {
  char     key[NAME_LEN];
  uint32_t count;
};
int top(TopOf what, TopRow* out, int max);

// Hourly totals, newest first, up to `max` (the RTC ring holds 168).
int hours(Hour* out, int max);

// "1.2.3.4" or an IPv6 address.
String clientStr(const Entry& e);

const char* kindName(Kind k);
bool isBlockedKind(Kind k);

}  // namespace querylog
