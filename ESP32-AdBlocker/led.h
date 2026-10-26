#pragma once

#include "ledstate.h"

// Status LED: a WS2812 (the RGB LED on most S3 dev boards) or a plain
// single-colour LED, configured on the settings page. Runs its own small task
// so blinking never depends on the main loop.

namespace led {

// Reads pin, type and brightness from g_settings. A pin of 0 leaves the LED
// off and starts nothing.
void begin();

// Switches pattern. Cheap to call every loop; only changes are acted on.
void show(Pattern p);

Pattern current();

}  // namespace led
