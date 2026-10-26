// Status LED task. Patterns and colours from s60sc/ESP32_AdBlocker
// appSpecific.cpp (AGPL-3.0, dateno1 2026).

#include <Arduino.h>

#include "led.h"
#include "settings.h"

namespace led {
namespace {

volatile Pattern wanted = Pattern::Off;
uint8_t pin = 0;
bool    rgb = true;
bool    activeLow = false;
uint8_t bright = 16;

void write(uint8_t r, uint8_t g, uint8_t b) {
  if (rgb) {
    // Brightness scales every channel; full 255 on a WS2812 is blinding.
    rgbLedWrite(pin, (uint16_t)r * bright / 255, (uint16_t)g * bright / 255,
                (uint16_t)b * bright / 255);
    return;
  }
  // Single colour: any lit channel means on.
  bool lit = r || g || b;
  uint8_t level = lit ? bright : 0;
  analogWrite(pin, activeLow ? 255 - level : level);
}

void ledTask(void*) {
  Pattern shown = Pattern::Off;
  bool     on = false;
  uint32_t lastToggle = 0;
  uint32_t lastRefresh = 0;

  write(0, 0, 0);
  for (;;) {
    Pattern p = wanted;
    Look l = look(p);
    uint32_t now = millis();

    if (p != shown) {
      shown = p;
      on = true;
      lastToggle = lastRefresh = now;
      write(l.r, l.g, l.b);
    } else if (l.blinkMs && now - lastToggle >= l.blinkMs) {
      on = !on;
      lastToggle = now;
      if (on) write(l.r, l.g, l.b);
      else write(0, 0, 0);
    } else if (!l.blinkMs && now - lastRefresh >= 1000) {
      // Rewrite a steady colour now and then; a WS2812 that glitched on a
      // noisy edge would otherwise stay wrong until the next change.
      lastRefresh = now;
      write(l.r, l.g, l.b);
    }
    vTaskDelay(pdMS_TO_TICKS(20));
  }
}

}  // namespace

void begin() {
  pin       = g_settings.ledPin;
  rgb       = g_settings.ledRgb;
  activeLow = g_settings.ledActiveLow;
  bright    = g_settings.ledBright ? g_settings.ledBright : 1;
  if (pin == 0) {
    Serial.println("[led] disabled");
    return;
  }
  if (!rgb) pinMode(pin, OUTPUT);
  xTaskCreatePinnedToCore(ledTask, "led", 2048, nullptr, 1, nullptr, 1);
  Serial.printf("[led] %s on GPIO %u, brightness %u\n", rgb ? "WS2812" : "single colour",
                pin, bright);
}

void show(Pattern p) {
  if (p == wanted) return;
  wanted = p;
  if (pin) Serial.printf("[led] %s\n", name(p));
}

Pattern current() { return wanted; }

}  // namespace led
