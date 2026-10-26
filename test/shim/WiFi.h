// Enough of the WiFi/ESP surface for commands.cpp to build on the host.
#pragma once

#include "Arduino.h"

struct FakeIP {
  const char* text;
  String toString() const { return String(text); }
};

struct FakeWiFi {
  FakeIP localIP() const { return FakeIP{"192.168.1.50"}; }
  FakeIP gatewayIP() const { return FakeIP{"192.168.1.1"}; }
  FakeIP globalIPv6() const { return FakeIP{"::"}; }
  String macAddress() const { return String("AA:BB:CC:DD:EE:FF"); }
  String SSID() const { return String("test-net"); }
  int    RSSI() const { return -55; }
};
extern FakeWiFi WiFi;

extern bool g_restarted;

struct FakeESP {
  unsigned getFreeHeap() const { return 220 * 1024; }
  unsigned getFreePsram() const { return 3 * 1024 * 1024; }
  // Records the reboot instead of taking one, so factoryreset is testable.
  void restart() const { g_restarted = true; }
};
extern FakeESP ESP;

inline void delay(unsigned long) {}

// Test-controlled clock.
extern unsigned long fakeMillis;
inline unsigned long millis() { return fakeMillis; }
