// Host-side tests for schedule.h: when the daily reboot and the daily
// blocklist refresh fire, driven through real POSIX TZ rules so the DST days
// behave as they will on the device.
#include <cstdio>
#include <cstdlib>
#include <ctime>

#include "schedule.h"

static int failures = 0, checks = 0;

static void ok(bool cond, const char* what) {
  checks++;
  if (!cond) { failures++; printf("  FAIL: %s\n", what); }
}

static const uint32_t MIN_UP = 120000;
static const uint32_t UP     = 3600000;   // an hour of uptime: past the guard

static void useTz(const char* tz) {
  setenv("TZ", tz, 1);
  tzset();
}

// Epoch for a local wall-clock time in the current TZ.
static time_t at(int y, int mo, int d, int h, int mi) {
  struct tm t = {};
  t.tm_year = y - 1900; t.tm_mon = mo - 1; t.tm_mday = d;
  t.tm_hour = h; t.tm_min = mi; t.tm_isdst = -1;
  return mktime(&t);
}

static struct tm local(time_t t) {
  struct tm out;
  localtime_r(&t, &out);
  return out;
}

static bool due(time_t now, uint8_t h, uint8_t m, int64_t lastPlanned,
                uint32_t uptime = UP, bool enabled = true) {
  struct tm l = local(now);
  return schedule::rebootDue(l, now, enabled, h, m, lastPlanned, uptime, MIN_UP);
}

// Counts the minutes in [from, from + hours) at which the reboot would fire,
// recording each one as the last planned reboot -- what the device does.
static int firingsOver(time_t from, int hours, uint8_t h, uint8_t m) {
  int fired = 0;
  int64_t lastPlanned = 0;
  for (time_t t = from; t < from + hours * 3600; t += 60) {
    if (due(t, h, m, lastPlanned)) { fired++; lastPlanned = t; }
  }
  return fired;
}

int main() {
  useTz("EST5EDT,M3.2.0,M11.1.0");

  // --- the basic match ---
  time_t four = at(2026, 10, 25, 4, 0);
  ok(due(four, 4, 0, 0), "fires at 04:00");
  ok(!due(four + 60, 4, 0, 0), "not at 04:01");
  ok(!due(four - 60, 4, 0, 0), "not at 03:59");
  ok(due(four + 59, 4, 0, 0), "anywhere inside the minute");
  ok(!due(four, 4, 0, 0, UP, /*enabled=*/false), "never when disabled");
  ok(!due(four, 4, 0, 0, 30000), "not in the first two minutes of uptime");
  ok(due(four, 4, 0, 0, MIN_UP), "fires once uptime reaches the minimum");

  // --- the repeat guard ---
  ok(!due(four + 30, 4, 0, four), "same minute after a reboot is suppressed");
  ok(due(four + 86400, 4, 0, four), "next day fires again");
  ok(due(four + 21 * 3600, (uint8_t)local(four + 21 * 3600).tm_hour, 0, four),
     "21 h later is past the guard");
  ok(!due(four + 19 * 3600, (uint8_t)local(four + 19 * 3600).tm_hour, 0, four),
     "19 h later is inside the guard");

  // --- a normal day fires exactly once ---
  ok(firingsOver(at(2026, 10, 25, 0, 0), 24, 4, 0) == 1, "ordinary day: exactly one reboot");
  ok(firingsOver(at(2026, 10, 1, 0, 0), 24 * 7, 4, 0) == 7, "a week: seven reboots");

  // --- DST starts 2026-03-08: 02:00-02:59 local does not exist ---
  ok(firingsOver(at(2026, 3, 8, 0, 0), 24, 2, 30) == 0,
     "spring forward: a time in the skipped hour never fires");
  ok(firingsOver(at(2026, 3, 8, 0, 0), 24, 4, 0) == 1,
     "spring forward: 04:00 still fires once");

  // --- DST ends 2026-11-01: 01:00-01:59 local happens twice ---
  ok(firingsOver(at(2026, 11, 1, 0, 0), 25, 1, 30) == 1,
     "fall back: a repeated time fires once, not twice");
  ok(firingsOver(at(2026, 11, 1, 0, 0), 25, 4, 0) == 1,
     "fall back: 04:00 fires once");

  // --- another zone, no DST ---
  useTz("HKT-8");
  ok(due(at(2026, 6, 1, 4, 0), 4, 0, 0), "HKT 04:00 fires");
  ok(firingsOver(at(2026, 6, 1, 0, 0), 24, 4, 0) == 1, "HKT day: exactly one");

  // --- refresh: first minute of the hour, once a day ---
  useTz("EST5EDT,M3.2.0,M11.1.0");
  time_t three = at(2026, 10, 25, 3, 0);
  struct tm l3 = local(three);
  ok(schedule::refreshDue(l3, 3, -1), "refresh fires at 03:00");
  ok(!schedule::refreshDue(l3, 3, l3.tm_yday), "but not twice the same day");
  struct tm l301 = local(three + 60);
  ok(!schedule::refreshDue(l301, 3, -1), "only in the first minute");
  struct tm lnext = local(three + 86400);
  ok(schedule::refreshDue(lnext, 3, l3.tm_yday), "fires again the next day");

  printf("%d/%d checks passed\n", checks - failures, checks);
  return failures ? 1 : 0;
}
