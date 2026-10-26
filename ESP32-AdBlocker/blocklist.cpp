// Blocklist storage, download and snapshot.
//
// Ported from s60sc/ESP32_AdBlocker appSpecific.cpp (AGPL-3.0).
// dateno1 2026, s60sc 2020-2026.

#include <Arduino.h>
#include <FS.h>
#include <HTTPClient.h>
#include <LittleFS.h>
#include <NetworkClientSecure.h>
#include <WiFi.h>
#include <esp_heap_caps.h>
#include <freertos/semphr.h>
#include <time.h>

#include "blocklist.h"
#include "blparse.h"
#include "config.h"
#include "dot.h"
#include "localdns.h"
#include "sinkhole.h"
#include "settings.h"
#include "util.h"

// The IDF certificate bundle linked into every Arduino-ESP32 build. Blocklists
// are hosted anywhere, so a fixed set of roots like ntfy's certs.h is no good
// here.
extern const uint8_t x509_crt_bundle_start[] asm("_binary_x509_crt_bundle_start");
extern const uint8_t x509_crt_bundle_end[]   asm("_binary_x509_crt_bundle_end");

namespace blocklist {
namespace {

// Names packed end to end, NUL-terminated, in the order they arrived. `ptrs`
// holds their offsets, sorted by the name they point at, so lookups are a
// binary search. Removing a name only drops its pointer; the bytes stay until
// the next rebuild.
char*     arena     = nullptr;
size_t    arenaSize = 0;
size_t    arenaUsed = 0;
uint32_t* ptrs      = nullptr;
uint32_t  count     = 0;

// Names you unblocked. Checked before the blocklist at every level of a name,
// so allowing "cdn.example.com" wins over a blocked "example.com". Small and
// fixed-size: it only ever holds what you typed.
typedef char AllowName[BL_MAX_DOMAIN_LEN];
AllowName* allow      = nullptr;
uint32_t   allowCount = 0;

// Bumped whenever an answer could change: a new list, an edit, on/off. The
// DNS cache drops entries stored under an older generation.
volatile uint32_t gen = 1;

volatile State   state    = State::Empty;
volatile bool    saving   = false;   // snapshot being written; no edits
volatile bool    on       = true;
volatile uint8_t progress = 0;
bool   fromSnapshot = false;
time_t loadedAt     = 0;
volatile bool     reloading     = false;   // requested, until runReload returns
volatile Result   lastResult    = Result::None;
volatile uint32_t lastAttemptMs = 0;

// Held by the DNS task for each lookup and by anything that changes `ptrs`.
// The loader does NOT hold it while building: it flips state to Loading
// first, and isBlocked() never touches the arena unless state is Ready.
SemaphoreHandle_t lock = nullptr;

struct Guard {
  Guard()  { xSemaphoreTake(lock, portMAX_DELAY); }
  ~Guard() { xSemaphoreGive(lock); }
};

TaskHandle_t loader = nullptr;
char reloadReason[32] = "";

// Messages for the main loop to publish.
const int EVENT_SLOTS = 4;
String events[EVENT_SLOTS];
int    eventHead = 0, eventCount = 0;
SemaphoreHandle_t eventLock = nullptr;

void postEvent(const String& msg) {
  Serial.printf("[blocklist] %s\n", msg.c_str());
  xSemaphoreTake(eventLock, portMAX_DELAY);
  events[(eventHead + eventCount) % EVENT_SLOTS] = msg;
  if (eventCount < EVENT_SLOTS) eventCount++;
  else eventHead = (eventHead + 1) % EVENT_SLOTS;   // drop the oldest
  xSemaphoreGive(eventLock);
}

bool clockValid() { return time(nullptr) > (time_t)NTP_MIN_VALID_EPOCH; }

// ---- sorted table ---------------------------------------------------------

// First index whose name is >= `name`.
uint32_t lowerBound(const char* name) {
  uint32_t lo = 0, hi = count;
  while (lo < hi) {
    uint32_t mid = lo + (hi - lo) / 2;
    if (strcmp(arena + ptrs[mid], name) < 0) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

bool find(const char* name, uint32_t& idx) {
  idx = lowerBound(name);
  return idx < count && strcmp(arena + ptrs[idx], name) == 0;
}

// Appends without sorting -- the download path sorts once at the end.
bool append(const char* name, size_t len) {
  if (arenaUsed + len + 1 > arenaSize || count >= BL_MAX_DOMAINS) return false;
  memcpy(arena + arenaUsed, name, len);
  arena[arenaUsed + len] = 0;
  ptrs[count++] = (uint32_t)arenaUsed;
  arenaUsed += len + 1;
  return true;
}

// Caller holds the lock (or owns the table during a build).
Edit insertSorted(const char* name, size_t len) {
  uint32_t idx;
  if (find(name, idx)) return Edit::Duplicate;
  if (arenaUsed + len + 1 > arenaSize || count >= BL_MAX_DOMAINS) return Edit::Full;
  memcpy(arena + arenaUsed, name, len);
  arena[arenaUsed + len] = 0;
  memmove(&ptrs[idx + 1], &ptrs[idx], (count - idx) * sizeof(uint32_t));
  ptrs[idx] = (uint32_t)arenaUsed;
  arenaUsed += len + 1;
  count++;
  return Edit::Ok;
}

bool removeSorted(const char* name) {
  uint32_t idx;
  if (!find(name, idx)) return false;
  memmove(&ptrs[idx], &ptrs[idx + 1], (count - idx - 1) * sizeof(uint32_t));
  count--;
  return true;
}

int compareNames(const void* a, const void* b) {
  return strcmp(arena + *(const uint32_t*)a, arena + *(const uint32_t*)b);
}

// One sort for the whole list. Upstream insertion-sorted each line as it
// arrived, which costs a memmove of the pointer table per name and is what
// made a first load take minutes.
uint32_t sortAndDedupe() {
  qsort(ptrs, count, sizeof(uint32_t), compareNames);
  uint32_t kept = 0;
  for (uint32_t i = 0; i < count; i++) {
    if (kept == 0 || strcmp(arena + ptrs[i], arena + ptrs[kept - 1]) != 0) {
      ptrs[kept++] = ptrs[i];
    }
  }
  uint32_t dups = count - kept;
  count = kept;
  return dups;
}

void resetStorage() {
  count = 0;
  arenaUsed = 0;
}

uint32_t allowLowerBound(const char* name) {
  uint32_t lo = 0, hi = allowCount;
  while (lo < hi) {
    uint32_t mid = lo + (hi - lo) / 2;
    if (strcmp(allow[mid], name) < 0) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

bool allowFind(const char* name) {
  uint32_t i = allowLowerBound(name);
  return i < allowCount && strcmp(allow[i], name) == 0;
}

bool allowInsert(const char* name) {
  if (!allow) return false;
  uint32_t i = allowLowerBound(name);
  if (i < allowCount && strcmp(allow[i], name) == 0) return true;
  if (allowCount >= BL_MAX_ALLOW) return false;
  memmove(&allow[i + 1], &allow[i], (allowCount - i) * sizeof(AllowName));
  strncpy(allow[i], name, BL_MAX_DOMAIN_LEN - 1);
  allow[i][BL_MAX_DOMAIN_LEN - 1] = 0;
  allowCount++;
  return true;
}

void allowRemove(const char* name) {
  uint32_t i = allowLowerBound(name);
  if (i >= allowCount || strcmp(allow[i], name) != 0) return;
  memmove(&allow[i], &allow[i + 1], (allowCount - i - 1) * sizeof(AllowName));
  allowCount--;
}

// The decision for one normalized name, most specific label first: an
// allowed name stops the walk, a blocked one ends it. With subdomain matching
// off only the full name is looked at. `matched` gets the entry that decided,
// or "" when nothing did. Caller holds the lock and has checked Ready.
bool decide(const char* name, const char** matched) {
  bool subdomains = g_settings.blockSubdomains;
  const char* p = name;
  for (;;) {
    uint32_t idx;
    if (allow && allowFind(p)) { if (matched) *matched = p; return false; }
    if (find(p, idx)) { if (matched) *matched = arena + ptrs[idx]; return true; }
    if (!subdomains) break;
    const char* dot = strchr(p, '.');
    // Stop before a bare TLD: "com" on its own is never the answer.
    if (!dot || !strchr(dot + 1, '.')) break;
    p = dot + 1;
  }
  if (matched) *matched = "";
  return false;
}

// ---- custom list ----------------------------------------------------------
//
// One name per line, applied on top of every load. A leading '#' means
// unblock. Lines are only ever appended, so replaying the file in order gives
// the latest decision for each name.

bool appendCustom(const char* name, bool unblockIt) {
  File f = LittleFS.open(BL_CUSTOM_PATH, FILE_APPEND);
  if (!f) {
    Serial.printf("[blocklist] cannot open %s\n", BL_CUSTOM_PATH);
    return false;
  }
  if (unblockIt) f.print('#');
  f.println(name);
  f.close();
  return true;
}

// Caller owns the table (loader, before Ready).
void applyCustom() {
  allowCount = 0;   // rebuilt from the file every time, like the blocks
  File f = LittleFS.open(BL_CUSTOM_PATH, FILE_READ);
  if (!f) return;

  uint32_t added = 0, removed = 0;
  char name[BL_MAX_DOMAIN_LEN + 8];
  while (f.available()) {
    String line = f.readStringUntil('\n');
    line.trim();
    if (line.isEmpty()) continue;
    bool unblockIt = line[0] == '#';
    strncpy(name, line.c_str() + (unblockIt ? 1 : 0), sizeof(name) - 1);
    name[sizeof(name) - 1] = 0;
    size_t len = normalize(name);
    if (!len) continue;
    if (unblockIt) {
      removeSorted(name);
      if (allowInsert(name)) removed++;
    } else {
      allowRemove(name);
      if (insertSorted(name, len) == Edit::Ok) added++;
    }
  }
  f.close();
  if (added || removed) {
    Serial.printf("[blocklist] custom list: +%lu blocked, %lu allowed\n",
                  (unsigned long)added, (unsigned long)removed);
  }
}

// ---- snapshot -------------------------------------------------------------
//
// Same encoding as upstream: entries in sorted order, each stored as
// (bytes shared with the previous name, suffix length, suffix), CRC32 at the
// end. Sorted neighbours share long prefixes, so this roughly halves the size.

#pragma pack(push, 1)
struct SnapHdr {
  uint32_t magic;
  uint16_t ver;
  uint32_t items;
  uint32_t rawLen;     // arena bytes the entries decode to
  int64_t  loadedAt;   // epoch of the download it came from
};
#pragma pack(pop)

const uint32_t SNAP_MAGIC = 0x31424441;   // "ADB1"
const uint16_t SNAP_VER   = 1;
const char*    SNAP_TMP   = BL_SNAPSHOT_PATH ".tmp";

uint32_t crc32Update(uint32_t c, const uint8_t* d, size_t n) {
  while (n--) {
    c ^= *d++;
    for (int k = 0; k < 8; k++) c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1u)));
  }
  return c;
}

void saveSnapshot() {
  uint32_t rawLen = 0;
  for (uint32_t i = 0; i < count; i++) rawLen += strlen(arena + ptrs[i]) + 1;

  size_t freeFs = LittleFS.totalBytes() - LittleFS.usedBytes();
  // Worst case: no shared prefixes at all. The old snapshot is still there
  // while the new one is written, so this must fit alongside it.
  if (freeFs < rawLen + count * 2 + 8192) {
    Serial.printf("[blocklist] snapshot skipped: %s free in flash, need %s\n",
                  fmtBytes(freeFs).c_str(), fmtBytes(rawLen + count * 2).c_str());
    return;
  }

  File f = LittleFS.open(SNAP_TMP, FILE_WRITE);
  if (!f) {
    Serial.println("[blocklist] snapshot: cannot create file");
    return;
  }

  uint32_t t0 = millis();
  SnapHdr h = {SNAP_MAGIC, SNAP_VER, count, rawLen, (int64_t)loadedAt};
  bool ok = f.write((const uint8_t*)&h, sizeof(h)) == sizeof(h);

  uint32_t crc = 0xFFFFFFFFu;
  uint8_t  buf[512];
  size_t   used = 0;
  const char* prev = "";
  size_t prevLen = 0;

  size_t written = sizeof(h) + 4;   // header and trailing CRC
  auto put = [&](const uint8_t* d, size_t n) {
    crc = crc32Update(crc, d, n);
    written += n;
    while (n > 0 && ok) {
      if (used == sizeof(buf)) {
        ok = f.write(buf, used) == used;
        used = 0;
      }
      size_t chunk = min(n, sizeof(buf) - used);
      memcpy(buf + used, d, chunk);
      used += chunk; d += chunk; n -= chunk;
    }
  };

  for (uint32_t i = 0; i < count && ok; i++) {
    if ((i & 0x7FF) == 0) vTaskDelay(1);
    const char* cur = arena + ptrs[i];
    size_t len = strlen(cur);
    size_t shared = 0;
    while (shared < len && shared < prevLen && shared < 255 && cur[shared] == prev[shared]) shared++;
    uint8_t lens[2] = {(uint8_t)shared, (uint8_t)(len - shared)};   // len < 256
    put(lens, 2);
    put((const uint8_t*)cur + shared, len - shared);
    prev = cur;
    prevLen = len;
  }
  if (ok && used) ok = f.write(buf, used) == used;
  uint32_t finalCrc = crc ^ 0xFFFFFFFFu;
  if (ok) ok = f.write((const uint8_t*)&finalCrc, 4) == 4;
  f.close();

  if (!ok) {
    Serial.println("[blocklist] snapshot write failed");
    LittleFS.remove(SNAP_TMP);
    return;
  }
  LittleFS.remove(BL_SNAPSHOT_PATH);
  if (!LittleFS.rename(SNAP_TMP, BL_SNAPSHOT_PATH)) {
    Serial.println("[blocklist] snapshot rename failed");
    LittleFS.remove(SNAP_TMP);
    return;
  }
  Serial.printf("[blocklist] snapshot saved: %s domains, %s in %lu ms\n",
                withCommas(count).c_str(), fmtBytes(written).c_str(),
                (unsigned long)(millis() - t0));
}

// Caller owns the table. Leaves it empty on any failure.
bool restoreSnapshot() {
  File f = LittleFS.open(BL_SNAPSHOT_PATH, FILE_READ);
  if (!f) {
    Serial.println("[blocklist] no snapshot in flash yet");
    return false;
  }

  uint32_t t0 = millis();
  SnapHdr h;
  const char* why = nullptr;
  if (f.read((uint8_t*)&h, sizeof(h)) != sizeof(h)) why = "short header";
  else if (h.magic != SNAP_MAGIC || h.ver != SNAP_VER) why = "unknown format";
  else if (h.items > BL_MAX_DOMAINS) why = "too many entries";
  else if (h.rawLen > arenaSize) why = "larger than PSRAM arena";
  if (why) {
    Serial.printf("[blocklist] snapshot rejected: %s\n", why);
    f.close();
    return false;
  }

  uint8_t buf[512];
  size_t  have = 0, at = 0;
  auto get = [&](uint8_t* d, size_t n) -> bool {
    while (n > 0) {
      if (at == have) {
        int r = f.read(buf, sizeof(buf));
        if (r <= 0) return false;
        have = (size_t)r;
        at = 0;
      }
      size_t chunk = min(n, have - at);
      memcpy(d, buf + at, chunk);
      at += chunk; d += chunk; n -= chunk;
    }
    return true;
  };

  resetStorage();
  uint32_t crc = 0xFFFFFFFFu;
  size_t prevLen = 0;
  bool ok = true;

  for (uint32_t i = 0; i < h.items && ok; i++) {
    if ((i & 0x7FF) == 0) vTaskDelay(1);
    uint8_t lens[2];
    if (!get(lens, 2)) { ok = false; break; }
    crc = crc32Update(crc, lens, 2);
    size_t shared = lens[0], suffix = lens[1];
    if (shared > prevLen || arenaUsed + shared + suffix + 1 > h.rawLen) { ok = false; break; }

    char* dst = arena + arenaUsed;
    if (shared) memcpy(dst, arena + ptrs[count - 1], shared);   // i > 0 here
    if (suffix && !get((uint8_t*)dst + shared, suffix)) { ok = false; break; }
    crc = crc32Update(crc, (const uint8_t*)dst + shared, suffix);
    dst[shared + suffix] = 0;

    ptrs[count++] = (uint32_t)arenaUsed;
    arenaUsed += shared + suffix + 1;
    prevLen = shared + suffix;
  }

  uint32_t fileCrc = 0;
  if (ok) ok = get((uint8_t*)&fileCrc, 4);
  f.close();

  if (!ok || arenaUsed != h.rawLen || (crc ^ 0xFFFFFFFFu) != fileCrc) {
    Serial.println("[blocklist] snapshot rejected: corrupt");
    resetStorage();
    return false;
  }

  loadedAt = (time_t)h.loadedAt;
  fromSnapshot = true;
  Serial.printf("[blocklist] restored %s domains from flash in %lu ms\n",
                withCommas(count).c_str(), (unsigned long)(millis() - t0));
  return true;
}

// ---- download -------------------------------------------------------------

void setState(State s);

// Streams the configured URL into the arena, one line at a time. Fills
// `error` and returns false on any failure.
//
// The current list is left alone until the server has answered 200: only
// then does this switch to Loading and wipe the arena (`started`). A dead
// connection therefore costs nothing -- the old list keeps blocking.
// `offline` marks failures that look like no internet rather than a bad list.
bool download(const String& url, String& error, bool& truncated, bool& started,
              bool& offline) {
  offline = false;
  bool tls = url.startsWith("https://");

  NetworkClientSecure secure;
  NetworkClient       plain;
  if (tls) {
    secure.setCACertBundle(x509_crt_bundle_start,
                           x509_crt_bundle_end - x509_crt_bundle_start);
  }
  NetworkClient& client = tls ? (NetworkClient&)secure : plain;

  HTTPClient http;
  // HTTP/1.0 means no chunked encoding, so the stream is the raw file.
  http.useHTTP10(true);
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);
  http.setTimeout(BL_READ_TIMEOUT_MS);
  http.setUserAgent("esp32-adblocker/" APP_VERSION);

  if (!http.begin(client, url)) {
    error = "bad URL";
    return false;
  }
  int code = http.GET();
  if (code != HTTP_CODE_OK) {
    error = code > 0 ? "HTTP " + String(code) : http.errorToString(code);
    offline = code < 0;   // connection refused, DNS failure, TLS, timeout
    http.end();
    return false;
  }

  if (!started) {
    setState(State::Loading);   // from here the DNS task passes everything through
    resetStorage();
    started = true;
  }

  int total = http.getSize();   // -1 when the server sends no length
  Serial.printf("[blocklist] downloading %s (%s)\n", url.c_str(),
                total > 0 ? fmtBytes(total).c_str() : "size unknown");

  NetworkClient* stream = http.getStreamPtr();
  static char line[BL_MAX_LINE + 1];
  size_t   lineLen  = 0;
  bool     longLine = false;
  uint32_t got      = 0;
  uint32_t lastRead = millis();
  uint8_t  buf[1024];
  truncated = false;

  auto endLine = [&]() {
    line[lineLen] = 0;
    if (!longLine) {
      char* dom = blparse::extractDomain(line);
      size_t len = dom ? normalize(dom) : 0;
      if (len && !append(dom, len)) truncated = true;
    }
    lineLen = 0;
    longLine = false;
  };

  while (!truncated) {
    int avail = stream->available();
    if (avail <= 0) {
      if (!stream->connected()) break;            // HTTP/1.0: close ends the body
      if (total > 0 && got >= (uint32_t)total) break;
      if (millis() - lastRead > BL_READ_TIMEOUT_MS) {
        error = "download stalled after " + fmtBytes(got);
        offline = true;
        http.end();
        return false;
      }
      vTaskDelay(pdMS_TO_TICKS(5));
      continue;
    }

    int n = stream->read(buf, min((size_t)avail, sizeof(buf)));
    if (n <= 0) continue;
    for (int i = 0; i < n; i++) {
      char c = (char)buf[i];
      if (c == '\n') endLine();
      else if (c == '\r') continue;
      else if (lineLen < BL_MAX_LINE) line[lineLen++] = c;
      else longLine = true;
    }
    got += n;
    lastRead = millis();
    if (total > 0) progress = (uint8_t)min(99UL, (unsigned long)got * 100UL / (unsigned long)total);
  }
  if (lineLen) endLine();
  http.end();

  if (got == 0) {
    error = "empty response";
    return false;
  }
  return true;
}

// Splits the URL setting on newlines and spaces.
int listUrls(String urls[BL_MAX_LISTS]) {
  int n = 0;
  String all = g_settings.blocklistUrl;
  all.replace("\r", "\n");
  all.replace(" ", "\n");
  int start = 0;
  while (start <= (int)all.length() && n < BL_MAX_LISTS) {
    int nl = all.indexOf('\n', start);
    if (nl < 0) nl = all.length();
    String u = all.substring(start, nl);
    u.trim();
    if (!u.isEmpty()) urls[n++] = u;
    start = nl + 1;
  }
  return n;
}

// Every configured list, one after another into the same arena. One that
// fails is reported and skipped; the load only fails if none worked.
bool downloadAll(String& error, bool& truncated, bool& started, bool& offline,
                 String& partial) {
  String urls[BL_MAX_LISTS];
  int n = listUrls(urls);
  started = false;
  truncated = false;
  if (n == 0) {
    error = "no blocklist URL configured";
    return false;
  }

  int good = 0;
  bool anyOffline = false;
  for (int i = 0; i < n && !truncated; i++) {
    String err;
    bool off = false;
    uint32_t before = count;
    if (download(urls[i], err, truncated, started, off)) {
      good++;
      Serial.printf("[blocklist] list %d: %s domains\n", i + 1,
                    withCommas(count - before).c_str());
    } else {
      anyOffline = anyOffline || off;
      if (!partial.isEmpty()) partial += "\n";
      partial += "list " + String(i + 1) + " failed: " + err;
      error = err;
    }
  }
  offline = good == 0 && anyOffline;
  if (good == 0) return false;
  if (count == 0) {
    error = "no domains found -- are they HOSTS or Adblock lists?";
    return false;
  }
  if (n > 1) error = String(good) + " of " + String(n) + " lists";
  return true;
}

// ---- loader task ----------------------------------------------------------

void setState(State s) {
  Guard g;
  state = s;
  gen = gen + 1;
}

// Each outcome is published once: retries while the internet is down would
// otherwise post the same failure every few minutes.
void finish(Result r, const String& msg) {
  bool repeat = r != Result::Ok && r == lastResult;
  lastResult = r;
  lastAttemptMs = millis();
  if (!repeat) postEvent(msg);
  else Serial.printf("[blocklist] %s\n", msg.c_str());
}

void runReload(const char* reason) {
  Serial.printf("[blocklist] reload (%s), heap %u\n", reason, (unsigned)ESP.getFreeHeap());
  progress = 0;

  uint32_t t0 = millis();
  String error, partial;
  bool truncated = false, started = false, offline = false;

  // RAM holds only so many TLS sessions: the DoT link steps aside while the
  // list downloads, and lookups use plain DNS for those seconds.
  dot::pause(true);
  bool ok = downloadAll(error, truncated, started, offline, partial);
  dot::pause(false);

  if (ok) {
    uint32_t dups = sortAndDedupe();
    applyCustom();
    loadedAt = time(nullptr);
    fromSnapshot = false;
    progress = 100;
    setState(State::Ready);

    String msg = "Blocklist loaded: " + withCommas(count) + " domains (" +
                 withCommas(dups) + " duplicates dropped, " + fmtBytes(arenaUsed) +
                 " of " + fmtBytes(arenaSize) + ", " +
                 String((millis() - t0) / 1000) + " s)";
    if (!partial.isEmpty()) msg += "\n" + partial;
    if (truncated) msg += "\nTRUNCATED -- the lists are larger than PSRAM; use fewer or smaller ones.";
    finish(Result::Ok, msg);

    {
      Guard g;
      saving = true;
    }
    saveSnapshot();
    saving = false;
    return;
  }

  Result r = offline ? Result::NoInternet : Result::Failed;
  String why = "Blocklist download failed (" + error + "). ";

  if (!started) {
    // Never touched the list, so whatever was blocking still is.
    if (state == State::Ready) {
      finish(r, why + "Still blocking with the current " + withCommas(count) +
                    " domains; retrying every few minutes.");
    } else {
      setState(State::Failed);
      finish(r, why + "No list yet -- NOT blocking; retrying every few minutes.");
    }
    return;
  }

  // Failed mid-transfer. The old list was wiped to make room, so bring it
  // back from flash.
  resetStorage();
  if (restoreSnapshot()) {
    applyCustom();
    setState(State::Ready);
    finish(r, why + "Still blocking with the previous " + withCommas(count) +
                  " domains from flash; retrying every few minutes.");
  } else {
    setState(State::Failed);
    finish(r, why + "No list to fall back on -- NOT blocking; retrying every few minutes.");
  }
}

void loaderMain(void*) {
  for (;;) {
    ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
    char reason[sizeof(reloadReason)];
    strncpy(reason, reloadReason, sizeof(reason));
    runReload(reason);
    reloading = false;
  }
}

}  // namespace

// ---- public ---------------------------------------------------------------

bool begin() {
  if (!psramFound()) {
    Serial.println("[blocklist] no PSRAM -- build with PSRAM=opi for an N16R8");
    return false;
  }

  lock = xSemaphoreCreateMutex();
  eventLock = xSemaphoreCreateMutex();

  allow = (AllowName*)ps_calloc(BL_MAX_ALLOW, sizeof(AllowName));
  ptrs = (uint32_t*)ps_malloc(BL_MAX_DOMAINS * sizeof(uint32_t));
  size_t largest = heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM);
  if (!ptrs || largest < BL_PSRAM_RESERVE + BL_MIN_ARENA) {
    Serial.printf("[blocklist] not enough PSRAM (largest block %s)\n", fmtBytes(largest).c_str());
    state = State::Failed;
    return false;
  }
  arenaSize = largest - BL_PSRAM_RESERVE;
  arena = (char*)ps_malloc(arenaSize);
  if (!arena) {
    Serial.println("[blocklist] arena allocation failed");
    state = State::Failed;
    return false;
  }
  Serial.printf("[blocklist] arena %s, room for ~%s domains\n", fmtBytes(arenaSize).c_str(),
                withCommas(min((uint32_t)(arenaSize / 26), (uint32_t)BL_MAX_DOMAINS)).c_str());

  // Formats on first use. A large partition takes a while the first time.
  if (!LittleFS.begin(/*formatOnFail=*/true)) {
    Serial.println("[blocklist] LittleFS unavailable -- no snapshot, no custom list");
  } else {
    Serial.printf("[blocklist] flash %s used of %s\n", fmtBytes(LittleFS.usedBytes()).c_str(),
                  fmtBytes(LittleFS.totalBytes()).c_str());
    localdns::begin();
  }

  if (restoreSnapshot()) {
    applyCustom();
    state = State::Ready;
  }

  if (xTaskCreatePinnedToCore(loaderMain, "blLoader", BL_TASK_STACK, nullptr, 1,
                              &loader, 1) != pdPASS) {
    Serial.println("[blocklist] loader task not started");
    return false;
  }
  return true;
}

size_t normalize(char* name) { return blparse::normalize(name, BL_MAX_DOMAIN_LEN); }

bool isBlocked(const char* name) {
  if (!on || state != State::Ready) return false;
  // Never stall a query for long: worst case it is answered unblocked.
  if (xSemaphoreTake(lock, pdMS_TO_TICKS(20)) != pdTRUE) return false;
  bool hit = state == State::Ready && decide(name, nullptr);
  xSemaphoreGive(lock);
  return hit;
}

uint32_t generation() { return gen; }

bool requestReload(const char* reason) {
  // The state only turns Loading once the server answers, so the flag is
  // what stops a second request queueing behind one still connecting.
  if (!loader || reloading || state == State::Loading || saving) return false;
  reloading = true;
  strncpy(reloadReason, reason, sizeof(reloadReason) - 1);
  xTaskNotifyGive(loader);
  return true;
}

bool snapshotStale() {
  if (!clockValid()) return false;
  if (state != State::Ready || loadedAt == 0) return true;
  return time(nullptr) - loadedAt > (time_t)BL_SNAPSHOT_MAX_AGE_S;
}

bool explain(const String& domain, String& matched) {
  matched = "";
  char name[BL_MAX_DOMAIN_LEN + 8];
  strncpy(name, domain.c_str(), sizeof(name) - 1);
  name[sizeof(name) - 1] = 0;
  if (!normalize(name) || state != State::Ready) return false;
  Guard g;
  if (state != State::Ready) return false;
  const char* m = "";
  bool hit = decide(name, &m);
  matched = m;
  return hit;
}

bool contains(const String& domain) {
  String ignored;
  return explain(domain, ignored);
}

Edit block(const String& domain) {
  char name[BL_MAX_DOMAIN_LEN + 8];
  strncpy(name, domain.c_str(), sizeof(name) - 1);
  name[sizeof(name) - 1] = 0;
  size_t len = normalize(name);
  if (!len) return Edit::Invalid;
  if (state != State::Ready || saving) return Edit::Busy;
  if (contains(name)) return Edit::Duplicate;

  // Outside the lock: an upstream lookup can take a second or more, and the
  // DNS task must not wait on it.
  if (!sinkhole::resolves(name)) return Edit::Unresolvable;

  Guard g;
  if (state != State::Ready || saving) return Edit::Busy;
  if (!appendCustom(name, false)) return Edit::IoError;
  allowRemove(name);
  gen = gen + 1;
  Edit r = insertSorted(name, len);
  return r == Edit::Duplicate ? Edit::Ok : r;   // was only allowed; now blocked
}

Edit unblock(const String& domain) {
  char name[BL_MAX_DOMAIN_LEN + 8];
  strncpy(name, domain.c_str(), sizeof(name) - 1);
  name[sizeof(name) - 1] = 0;
  if (!normalize(name)) return Edit::Invalid;

  Guard g;
  if (state != State::Ready || saving) return Edit::Busy;
  // Blocked directly or through a parent: either way an allow entry for this
  // exact name lets it through.
  if (!decide(name, nullptr)) return Edit::NotFound;
  if (!appendCustom(name, true)) return Edit::IoError;
  removeSorted(name);
  if (!allowInsert(name)) return Edit::Full;
  gen = gen + 1;
  return Edit::Ok;
}

bool clearCustom() {
  if (reloading || state == State::Loading || saving) return false;
  LittleFS.remove(BL_CUSTOM_PATH);
  return requestReload("custom list cleared");
}

void forgetSnapshot() {
  LittleFS.remove(BL_SNAPSHOT_PATH);
  Serial.println("[blocklist] snapshot deleted");
}

void setEnabled(bool enable) {
  on = enable;
  gen = gen + 1;
}
bool enabled() { return on; }

Stats stats() {
  Stats s;
  s.state        = state;
  s.lastResult   = lastResult;
  s.lastAttemptMs = lastAttemptMs;
  s.domains      = state == State::Ready ? count : 0;
  s.allowed      = allowCount;
  s.arenaUsed    = arenaUsed;
  s.arenaSize    = arenaSize;
  s.progress     = progress;
  s.fromSnapshot = fromSnapshot;
  s.loadedAt     = loadedAt;
  s.enabled      = on;
  return s;
}

const char* stateName(State s) {
  switch (s) {
    case State::Empty:   return "empty";
    case State::Loading: return "downloading";
    case State::Ready:   return "ready";
    case State::Failed:  return "failed";
  }
  return "?";
}

const char* editMessage(Edit e) {
  switch (e) {
    case Edit::Ok:           return "done";
    case Edit::Duplicate:    return "already blocked";
    case Edit::NotFound:     return "not in the blocklist";
    case Edit::Invalid:      return "not a valid domain name";
    case Edit::Busy:         return "the blocklist is reloading -- try again in a minute";
    case Edit::Full:         return "the blocklist is full";
    case Edit::Unresolvable: return "it does not resolve (typo?) so it was not added";
    case Edit::IoError:      return "could not write the custom list to flash";
  }
  return "?";
}

bool takeEvent(String& message) {
  if (!eventLock) return false;
  xSemaphoreTake(eventLock, portMAX_DELAY);
  bool any = eventCount > 0;
  if (any) {
    message = events[eventHead];
    events[eventHead] = String();
    eventHead = (eventHead + 1) % EVENT_SLOTS;
    eventCount--;
  }
  xSemaphoreGive(eventLock);
  return any;
}

}  // namespace blocklist
