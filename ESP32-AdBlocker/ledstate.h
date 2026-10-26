#pragma once

#include <stdint.h>

// Which pattern the status LED shows, decided from device state alone so the
// native tests can check every case. Colours and blink rates follow
// s60sc/ESP32_AdBlocker:
//
//   ApMode       slow blink yellow     setup portal or WiFi fallback
//   Active       steady green          list loaded, last download fine
//   Offline      very slow blink teal  serving a list, last download failed
//   Failure      fast blink red        no list at all
//   Downloading  medium blink blue     download in progress (not blocking)
//   NoInternet   flashing purple       last download could not reach the server

namespace led {

enum class Pattern : uint8_t { Off, ApMode, Active, Offline, Failure, Downloading, NoInternet };

struct Look {
  uint8_t  r, g, b;
  uint16_t blinkMs;   // half-period; 0 = steady
};

inline Look look(Pattern p) {
  switch (p) {
    case Pattern::ApMode:      return {255, 255,   0,  600};
    case Pattern::Active:      return {  0, 255,   0,    0};
    case Pattern::Offline:     return {  0, 255, 255, 1000};
    case Pattern::Failure:     return {255,   0,   0,  150};
    case Pattern::Downloading: return {  0,   0, 255,  300};
    case Pattern::NoInternet:  return {160,   0, 255,   75};
    case Pattern::Off:         break;
  }
  return {0, 0, 0, 0};
}

// apMode       setup portal or WiFi fallback is up
// loading      a download is streaming into the list
// haveList     a list is loaded and being used
// lastResult   0 none, 1 ok, 2 no internet, 3 failed -- blocklist::Result
inline Pattern choose(bool apMode, bool loading, bool haveList, uint8_t lastResult) {
  if (apMode)          return Pattern::ApMode;
  if (loading)         return Pattern::Downloading;
  if (lastResult == 2) return Pattern::NoInternet;
  if (!haveList)       return Pattern::Failure;
  if (lastResult == 3) return Pattern::Offline;
  return Pattern::Active;
}

inline const char* name(Pattern p) {
  switch (p) {
    case Pattern::Off:         return "off";
    case Pattern::ApMode:      return "AP mode (yellow, slow blink)";
    case Pattern::Active:      return "active (green)";
    case Pattern::Offline:     return "offline (teal, very slow blink)";
    case Pattern::Failure:     return "failure (red, fast blink)";
    case Pattern::Downloading: return "downloading (blue, medium blink)";
    case Pattern::NoInternet:  return "no internet (purple, flashing)";
  }
  return "?";
}

}  // namespace led
