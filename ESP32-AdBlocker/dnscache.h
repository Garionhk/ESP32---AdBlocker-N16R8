#pragma once

#include <stddef.h>
#include <stdint.h>

#include "dnsmsg.h"

// Cache of whole upstream replies, keyed by question, in PSRAM. Each entry
// lives as long as its smallest TTL, and TTLs are counted down when served,
// so clients see the same freshness they would from the upstream server.
//
// Thread-safe: the UDP and TCP DNS tasks share it.

namespace dnscache {

struct Stats {
  uint32_t hits;
  uint32_t misses;
  uint32_t slots;
};

// Allocates `slots` fixed-size entries in PSRAM. Returns false if it cannot.
bool begin(size_t slots);

// Copies a fresh reply for `q` into out (ID untouched -- the caller sets it)
// and returns its length, or 0 on a miss. `generation` must match what the
// entry was stored with; bumping it invalidates everything at once.
int get(const dnsmsg::Question& q, uint32_t generation, uint8_t* out, int cap);

// Stores a NOERROR or NXDOMAIN reply. Truncated, oversize and zero-TTL replies
// are skipped.
void put(const dnsmsg::Question& q, uint32_t generation, const uint8_t* reply, int len);

Stats stats();

}  // namespace dnscache
