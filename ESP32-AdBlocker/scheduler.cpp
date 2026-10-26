#include <Arduino.h>
#include <esp_attr.h>
#include <esp_system.h>
#include <time.h>

#include "blocklist.h"
#include "config.h"
#include "ntfy.h"
#include "schedule.h"
#include "scheduler.h"
#include "settings.h"

namespace scheduler {
namespace {

// RTC memory survives a software restart but not a power cut, which is what
// tells a planned reboot apart from everything else.
const uint32_t PLANNED_MAGIC = 0xADB10C42;
RTC_NOINIT_ATTR uint32_t plannedMagic;
RTC_NOINIT_ATTR char     plannedWhy[24];
RTC_NOINIT_ATTR uint32_t plannedAtMagic;
RTC_NOINIT_ATTR int64_t  plannedAt;   // epoch of the last planned reboot

String   resetReason;
int64_t  lastPlannedAt = 0;
uint32_t lastCheckMs   = 0;
int      lastRefreshYday = -1;
bool     rebootPending = false;

bool clockValid() { return time(nullptr) > (time_t)NTP_MIN_VALID_EPOCH; }

const char* hardwareReason(esp_reset_reason_t r) {
  switch (r) {
    case ESP_RST_POWERON:   return "power on";
    case ESP_RST_EXT:       return "reset pin";
    case ESP_RST_SW:        return "software restart";
    case ESP_RST_PANIC:     return "crash (panic)";
    case ESP_RST_INT_WDT:   return "crash (interrupt watchdog)";
    case ESP_RST_TASK_WDT:  return "crash (task watchdog)";
    case ESP_RST_WDT:       return "crash (watchdog)";
    case ESP_RST_DEEPSLEEP: return "deep sleep wake";
    case ESP_RST_BROWNOUT:  return "brownout (power supply too weak?)";
    case ESP_RST_USB:       return "USB reset";
    default:                return "unknown";
  }
}

}  // namespace

void begin() {
  esp_reset_reason_t r = esp_reset_reason();
  bool planned = plannedMagic == PLANNED_MAGIC;
  if (planned) plannedWhy[sizeof(plannedWhy) - 1] = 0;
  resetReason = (planned && r == ESP_RST_SW) ? String(plannedWhy) : String(hardwareReason(r));
  plannedMagic = 0;

  // plannedAt has its own marker and is never cleared, so a crash soon after
  // a daily reboot cannot set up a second one inside the guard window. Only
  // a power cut, which wipes RTC memory, forgets it.
  lastPlannedAt = plannedAtMagic == PLANNED_MAGIC ? plannedAt : 0;
  Serial.printf("[sched] last reset: %s\n", resetReason.c_str());
}

void restart(const char* why) {
  ntfy::publish(String("Rebooting (") + why + ")", "Reboot");
  strncpy(plannedWhy, why, sizeof(plannedWhy) - 1);
  plannedWhy[sizeof(plannedWhy) - 1] = 0;
  plannedAt = clockValid() ? (int64_t)time(nullptr) : 0;
  plannedAtMagic = PLANNED_MAGIC;
  plannedMagic = PLANNED_MAGIC;
  Serial.printf("[sched] restarting: %s\n", why);
  delay(1500);   // let the notice and the serial line get out
  ESP.restart();
}

// A failed download is retried every few minutes, and a stale or missing
// list is fetched as soon as the clock is valid -- covering a boot that had no
// internet yet. Neither waits for the nightly refresh.
static void retryDownload() {
  blocklist::Stats b = blocklist::stats();
  if (b.state == blocklist::State::Loading) return;
  bool failed = b.lastResult == blocklist::Result::NoInternet ||
                b.lastResult == blocklist::Result::Failed;
  bool due = b.lastResult == blocklist::Result::None ||
             millis() - b.lastAttemptMs >= BL_RETRY_INTERVAL_MS;
  if (due && (failed || blocklist::snapshotStale())) {
    blocklist::requestReload(failed ? "retry" : "stale list");
  }
}

void tick() {
  if (millis() - lastCheckMs < 1000) return;
  lastCheckMs = millis();
  if (!clockValid()) return;
  retryDownload();

  time_t now = time(nullptr);
  struct tm local;
  localtime_r(&now, &local);
  const Settings& s = g_settings;

  if (schedule::refreshDue(local, s.refreshHour, lastRefreshYday)) {
    lastRefreshYday = local.tm_yday;
    if (blocklist::requestReload("daily refresh")) {
      Serial.println("[sched] daily blocklist refresh");
    }
  }

  if (!rebootPending &&
      schedule::rebootDue(local, now, s.rebootEnabled, s.rebootHour, s.rebootMinute,
                          lastPlannedAt, millis(), REBOOT_MIN_UPTIME_MS)) {
    rebootPending = true;
  }
  // Never cut a download off halfway; it only takes a minute or so.
  if (rebootPending && blocklist::stats().state != blocklist::State::Loading) {
    restart("daily reboot");
  }
}

String lastResetReason() { return resetReason; }

String nextReboot() {
  const Settings& s = g_settings;
  if (!s.rebootEnabled) return "off";
  char buf[24];
  snprintf(buf, sizeof(buf), "%02u:%02u", s.rebootHour, s.rebootMinute);
  String out = buf;
  if (clockValid()) {
    time_t now = time(nullptr);
    struct tm local;
    localtime_r(&now, &local);
    char zone[8];
    if (strftime(zone, sizeof(zone), "%Z", &local)) out += String(" ") + zone;
  }
  return out;
}

String localTimeStr() {
  if (!clockValid()) return "clock not set";
  time_t now = time(nullptr);
  struct tm local;
  localtime_r(&now, &local);
  char buf[32];
  strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M %Z", &local);
  return buf;
}

}  // namespace scheduler
