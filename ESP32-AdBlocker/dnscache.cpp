#include <Arduino.h>
#include <freertos/semphr.h>

#include "config.h"
#include "dnscache.h"

namespace dnscache {
namespace {

struct Slot {
  uint32_t hash;        // 0 = empty
  uint32_t generation;
  uint32_t storedAt;    // seconds since boot
  uint32_t ttl;
  uint16_t len;
  uint8_t  reply[DNS_CACHE_MAX_REPLY];
};

Slot*    slots = nullptr;
uint32_t count = 0;
uint32_t hits = 0, misses = 0;
SemaphoreHandle_t lock = nullptr;

uint32_t nowS() { return millis() / 1000; }

uint32_t hashOf(const dnsmsg::Question& q) {
  uint32_t h = 2166136261u;
  for (const char* p = q.name; *p; p++) h = (h ^ (uint8_t)*p) * 16777619u;
  h = (h ^ (q.type & 0xFF)) * 16777619u;
  h = (h ^ (q.type >> 8)) * 16777619u;
  h = (h ^ q.cls) * 16777619u;
  return h ? h : 1;
}

bool fresh(const Slot& s, uint32_t now) { return s.hash && now - s.storedAt < s.ttl; }

}  // namespace

bool begin(size_t n) {
  slots = (Slot*)ps_calloc(n, sizeof(Slot));
  if (!slots) {
    Serial.println("[cache] PSRAM allocation failed -- caching off");
    return false;
  }
  count = n;
  lock = xSemaphoreCreateMutex();
  Serial.printf("[cache] %u replies, %u KB PSRAM\n", (unsigned)n,
                (unsigned)(n * sizeof(Slot) / 1024));
  return true;
}

int get(const dnsmsg::Question& q, uint32_t generation, uint8_t* out, int cap) {
  if (!slots) return 0;
  uint32_t h = hashOf(q), now = nowS();
  int len = 0;
  xSemaphoreTake(lock, portMAX_DELAY);
  for (uint32_t i = 0; i < DNS_CACHE_PROBE; i++) {
    Slot& s = slots[(h + i) % count];
    if (s.hash != h || s.generation != generation || !fresh(s, now)) continue;
    // The hash is only a hint; the stored question is the real key.
    if (!dnsmsg::sameQuestion(s.reply, s.len, q) || s.len > cap) continue;
    memcpy(out, s.reply, s.len);
    len = s.len;
    dnsmsg::ageTtls(out, len, now - s.storedAt);
    break;
  }
  if (len) hits++;
  else misses++;
  xSemaphoreGive(lock);
  return len;
}

void put(const dnsmsg::Question& q, uint32_t generation, const uint8_t* reply, int len) {
  if (!slots || len > DNS_CACHE_MAX_REPLY || len < dnsmsg::HEADER) return;
  if (dnsmsg::truncated(reply)) return;
  uint8_t rc = dnsmsg::rcode(reply);
  if (rc != dnsmsg::RC_OK && rc != dnsmsg::RC_NXDOMAIN) return;
  uint32_t ttl = dnsmsg::cacheTtl(reply, len, DNS_CACHE_NEGATIVE_TTL_S);
  if (ttl == 0) return;
  if (ttl > DNS_CACHE_MAX_TTL_S) ttl = DNS_CACHE_MAX_TTL_S;

  uint32_t h = hashOf(q), now = nowS();
  xSemaphoreTake(lock, portMAX_DELAY);
  // Same question, an empty or expired slot, or else the oldest of the probe
  // window.
  Slot *same = nullptr, *spare = nullptr, *oldest = nullptr;
  for (uint32_t i = 0; i < DNS_CACHE_PROBE; i++) {
    Slot& s = slots[(h + i) % count];
    if (s.hash == h && dnsmsg::sameQuestion(s.reply, s.len, q)) { same = &s; break; }
    if (!fresh(s, now)) { if (!spare) spare = &s; }
    else if (!oldest || s.storedAt < oldest->storedAt) oldest = &s;
  }
  Slot* victim = same ? same : spare ? spare : oldest;
  victim->hash = h;
  victim->generation = generation;
  victim->storedAt = now;
  victim->ttl = ttl;
  victim->len = (uint16_t)len;
  memcpy(victim->reply, reply, len);
  xSemaphoreGive(lock);
}

Stats stats() {
  return {hits, misses, count};
}

}  // namespace dnscache
