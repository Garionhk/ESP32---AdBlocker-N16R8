#pragma once

#include <stdint.h>
#include <time.h>

// Pure timing decisions for scheduler.cpp, kept free of hardware calls so the
// native tests can drive them with any clock they like.

namespace schedule {

// A planned reboot this recent means the one being considered is the same
// day's, seen again: the hour repeats when DST ends, and a reboot that lands
// a second early can still be inside the configured minute.
const int64_t REBOOT_REPEAT_GUARD_S = 20 * 3600;

// True when the configured daily reboot should happen now.
//
//   local          current local time (localtime_r with the configured TZ)
//   now            the same instant as epoch seconds
//   lastPlanned    epoch of the previous planned reboot, 0 if none known
//   uptimeMs       millis() -- a reboot never fires in its own first minutes
//
// The match is on the hour and minute only. On the spring-forward day a time
// inside the skipped hour never occurs, so that day has no reboot.
inline bool rebootDue(const struct tm& local, int64_t now, bool enabled,
                      uint8_t hour, uint8_t minute, int64_t lastPlanned,
                      uint32_t uptimeMs, uint32_t minUptimeMs) {
  if (!enabled) return false;
  if (uptimeMs < minUptimeMs) return false;
  if (local.tm_hour != hour || local.tm_min != minute) return false;
  if (lastPlanned > 0 && now - lastPlanned < REBOOT_REPEAT_GUARD_S) return false;
  return true;
}

// True once per local day, in the first minute of `hour`. `lastYday` carries
// the day it last fired; -1 means never.
inline bool refreshDue(const struct tm& local, uint8_t hour, int lastYday) {
  return local.tm_hour == hour && local.tm_min == 0 && local.tm_yday != lastYday;
}

}  // namespace schedule
