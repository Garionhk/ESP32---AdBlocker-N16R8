#pragma once

#include <Arduino.h>

// Daily reboot and daily blocklist refresh, both in local time.

namespace scheduler {

// Reads why the previous run ended. Call once, early in setup().
void begin();

// Checks the clock about once a second. Call every loop() while online.
void tick();

// Publishes a notice, records the reason so the next boot can report it, and
// restarts. Used by the daily reboot and by the "reboot" command.
void restart(const char* why);

// "daily reboot", "power on", "crash (panic)" ...
String lastResetReason();

// "04:00 EST", or "off".
String nextReboot();

// Local time now, "2026-10-25 14:03 EDT", or "clock not set".
String localTimeStr();

}  // namespace scheduler
