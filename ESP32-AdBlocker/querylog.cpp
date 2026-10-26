#include <Arduino.h>
#include <esp_attr.h>
#include <freertos/semphr.h>
#include <lwip/inet.h>
#include <lwip/sockets.h>

#include "querylog.h"

namespace querylog {
namespace {

Entry*   ring = nullptr;
uint32_t cap  = 0;
uint32_t head = 0;     // next slot to write
uint32_t used = 0;
SemaphoreHandle_t lock = nullptr;

// RTC memory survives the daily software restart. The marker says whether
// what is there was written by us or is power-on noise.
const uint32_t HOURS_MAGIC = 0xADB1A0A1;
const int      HOURS = 168;
RTC_NOINIT_ATTR uint32_t hoursMagic;
RTC_NOINIT_ATTR Hour     hourRing[HOURS];

Hour& slotFor(uint32_t hour) { return hourRing[hour % HOURS]; }

}  // namespace

bool begin(size_t entries) {
  lock = xSemaphoreCreateMutex();
  if (hoursMagic != HOURS_MAGIC) {
    memset(hourRing, 0, sizeof(hourRing));
    hoursMagic = HOURS_MAGIC;
  }
  ring = (Entry*)ps_calloc(entries, sizeof(Entry));
  if (!ring) {
    Serial.println("[log] PSRAM allocation failed -- query log off");
    return false;
  }
  cap = entries;
  Serial.printf("[log] %u entries, %u KB PSRAM\n", (unsigned)entries,
                (unsigned)(entries * sizeof(Entry) / 1024));
  return true;
}

void record(const Entry& e) {
  if (!lock) return;
  xSemaphoreTake(lock, portMAX_DELAY);
  if (ring) {
    ring[head] = e;
    head = (head + 1) % cap;
    if (used < cap) used++;
  }
  if (e.when > 1704067200UL) {   // only once the clock is real
    uint32_t hour = e.when / 3600;
    Hour& h = slotFor(hour);
    if (h.hour != hour) h = {hour, 0, 0};
    h.queries++;
    if (isBlockedKind(e.kind)) h.blocked++;
  }
  xSemaphoreGive(lock);
}

int recent(Entry* out, int max, Filter filter, void* ctx) {
  if (!ring) return 0;
  int n = 0;
  xSemaphoreTake(lock, portMAX_DELAY);
  for (uint32_t i = 0; i < used && n < max; i++) {
    const Entry& e = ring[(head + cap - 1 - i) % cap];
    if (!filter || filter(e, ctx)) out[n++] = e;
  }
  xSemaphoreGive(lock);
  return n;
}

void forEach(void (*fn)(const Entry& e, void* ctx), void* ctx) {
  if (!ring) return;
  xSemaphoreTake(lock, portMAX_DELAY);
  for (uint32_t i = 0; i < used; i++) fn(ring[(head + cap - used + i) % cap], ctx);
  xSemaphoreGive(lock);
}

namespace {

struct Tally {
  uint32_t hash;
  uint32_t count;
  char     key[NAME_LEN];
};

uint32_t fnv(const char* s) {
  uint32_t h = 2166136261u;
  while (*s) h = (h ^ (uint8_t)*s++) * 16777619u;
  return h ? h : 1;
}

}  // namespace

int top(TopOf what, TopRow* out, int max) {
  if (!ring || used == 0) return 0;
  // Open-addressed tally. 2048 distinct keys is plenty for a household; a
  // name that finds no free slot in 16 probes is simply not counted.
  const uint32_t SLOTS = 2048;
  Tally* t = (Tally*)ps_calloc(SLOTS, sizeof(Tally));
  if (!t) return 0;

  xSemaphoreTake(lock, portMAX_DELAY);
  for (uint32_t i = 0; i < used; i++) {
    const Entry& e = ring[i];
    bool blocked = isBlockedKind(e.kind);
    if (what == TopOf::BlockedNames && !blocked) continue;
    if (what == TopOf::AllowedNames && (blocked || e.kind == Kind::Failed)) continue;
    char key[NAME_LEN];
    if (what == TopOf::Clients) {
      String c = clientStr(e);
      strncpy(key, c.c_str(), sizeof(key) - 1);
      key[sizeof(key) - 1] = 0;
    } else {
      strcpy(key, e.name);
    }
    uint32_t h = fnv(key);
    for (uint32_t k = 0; k < 16; k++) {
      Tally& s = t[(h + k) % SLOTS];
      if (s.hash == 0) { s.hash = h; strcpy(s.key, key); s.count = 1; break; }
      if (s.hash == h && !strcmp(s.key, key)) { s.count++; break; }
    }
  }
  xSemaphoreGive(lock);

  int n = 0;
  for (uint32_t i = 0; i < SLOTS; i++) {
    if (!t[i].hash) continue;
    // Insertion into a short sorted list of the best `max`.
    int pos = n;
    while (pos > 0 && out[pos - 1].count < t[i].count) pos--;
    if (pos >= max) continue;
    int last = n < max ? n : max - 1;
    for (int j = last; j > pos; j--) out[j] = out[j - 1];
    strcpy(out[pos].key, t[i].key);
    out[pos].count = t[i].count;
    if (n < max) n++;
  }
  free(t);
  return n;
}

uint32_t size() { return used; }
uint32_t capacity() { return cap; }

int hours(Hour* out, int max) {
  if (!lock) return 0;
  uint32_t now = (uint32_t)(time(nullptr) / 3600);
  int n = 0;
  xSemaphoreTake(lock, portMAX_DELAY);
  for (int i = 0; i < HOURS && n < max; i++) {
    uint32_t hour = now - i;
    const Hour& h = slotFor(hour);
    out[n++] = h.hour == hour ? h : Hour{hour, 0, 0};
  }
  xSemaphoreGive(lock);
  return n;
}

String clientStr(const Entry& e) {
  char buf[48];
  if (e.family == 6) inet_ntop(AF_INET6, e.addr, buf, sizeof(buf));
  else snprintf(buf, sizeof(buf), "%u.%u.%u.%u", e.addr[0], e.addr[1], e.addr[2], e.addr[3]);
  return buf;
}

const char* kindName(Kind k) {
  switch (k) {
    case Kind::Forwarded:    return "forwarded";
    case Kind::Cached:       return "cached";
    case Kind::Blocked:      return "blocked";
    case Kind::BlockedCname: return "blocked (CNAME)";
    case Kind::Local:        return "local";
    case Kind::Router:       return "router";
    case Kind::Failed:       return "failed";
  }
  return "?";
}

bool isBlockedKind(Kind k) { return k == Kind::Blocked || k == Kind::BlockedCname; }

}  // namespace querylog
