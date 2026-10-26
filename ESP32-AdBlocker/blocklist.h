#pragma once

#include <Arduino.h>

// The blocklist: every blocked domain, sorted, in PSRAM.
//
// Ported from s60sc/ESP32_AdBlocker (appSpecific.cpp, AGPL-3.0). The storage
// layout is the same -- names packed end to end in one arena, plus a table of
// offsets kept in sorted order for binary search -- but the build sorts once
// at the end instead of insertion-sorting every line, and lookups never race a
// rebuild.
//
// A copy is kept in LittleFS so a reboot restores the list in seconds instead
// of downloading it again. The daily reboot depends on that.

namespace blocklist {

enum class State : uint8_t { Empty, Loading, Ready, Failed };

enum class Edit : uint8_t {
  Ok,
  Duplicate,     // already blocked
  NotFound,      // not in the list, so nothing to unblock
  Invalid,       // not a usable domain name
  Busy,          // a download or snapshot write is running
  Full,          // arena or pointer table exhausted
  Unresolvable,  // the name does not resolve, so probably a typo
  IoError,       // custom list file could not be written
};

// How the most recent download attempt ended.
enum class Result : uint8_t {
  None,        // no attempt yet this boot
  Ok,
  NoInternet,  // could not reach the server, or the transfer stalled
  Failed,      // reached it, but bad URL, HTTP error, or not a blocklist
};

struct Stats {
  State    state;
  Result   lastResult;
  uint32_t lastAttemptMs;   // millis() when the last attempt finished
  uint32_t domains;
  uint32_t allowed;         // names you unblocked
  uint32_t arenaUsed;
  uint32_t arenaSize;
  uint8_t  progress;        // 0-100 while Loading
  bool     fromSnapshot;    // current list came from flash, not a download
  time_t   loadedAt;        // epoch of the download behind the current list
  bool     enabled;
};

// Allocates PSRAM, mounts LittleFS, restores the snapshot if there is one and
// starts the loader task. Returns false if there is not enough PSRAM.
bool begin();

// Called from the DNS tasks. `name` must already be normalized (see
// normalize()). With subdomain matching on, "ads.tracker.example.com" is
// blocked by an entry for "tracker.example.com"; allowed names win at every
// level. Answers false whenever the list is not Ready, so a reload passes
// queries through rather than stalling them.
bool isBlocked(const char* name);

// Lowercases, strips one trailing dot and a leading "www.". Returns the new
// length, 0 if the result is not a plausible domain name.
size_t normalize(char* name);

// Queues a download. Returns false if one is already running.
bool requestReload(const char* reason);

// True once the snapshot is old enough that a download is due. Needs a valid
// clock; answers false without one.
bool snapshotStale();

bool contains(const String& domain);

// Like contains(), and says which entry decided: the domain itself, a parent
// it is a subdomain of, or an allow entry. `matched` is "" when nothing did.
bool explain(const String& domain, String& matched);

// Changes whenever an answer could: a new list, an edit, on/off. The DNS
// cache keys on it.
uint32_t generation();
Edit block(const String& domain);
Edit unblock(const String& domain);

// Deletes the custom list and reloads, since the snapshot has those entries
// baked in.
bool clearCustom();

// Deletes the snapshot so the next boot downloads afresh. Used when the
// blocklist URL changes: the stored copy came from the old one.
void forgetSnapshot();

void setEnabled(bool on);
bool enabled();

Stats stats();
const char* stateName(State s);
const char* editMessage(Edit e);

// Loader-task results ("loaded 162,431 domains", "download failed ...") for
// the main loop to publish. The loader never talks to ntfy itself.
bool takeEvent(String& message);

}  // namespace blocklist
