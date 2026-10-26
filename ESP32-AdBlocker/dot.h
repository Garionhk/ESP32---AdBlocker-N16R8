#pragma once

#include <Arduino.h>

// DNS-over-TLS upstream. A small proxy listens on 127.0.0.1:DOT_PROXY_PORT
// and relays each UDP query over one long-lived TLS connection to
// Settings::dotHost (RFC 7858), so the sinkhole treats it as just another
// UDP server and never blocks on TLS itself.

namespace dot {

// Starts the proxy task if DoT is enabled. Safe to call more than once.
void begin();

// True while the TLS connection is up and not paused; the sinkhole only
// routes queries here when it is.
bool ready();

// Drops the TLS connection and keeps it down until resumed. The blocklist
// download pauses it: RAM only fits so many TLS sessions at once.
void pause(bool paused);

// "connected to one.one.one.one", "connecting", "off" ...
String status();

}  // namespace dot
