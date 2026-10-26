#pragma once

#include <Arduino.h>

// Runtime configuration, held in NVS and edited from the web portal.
//
// Nothing user-specific is baked into the binary, so a build can be shared
// without leaking a WiFi password.

struct Settings {
  // WiFi
  String   wifiSsid;
  String   wifiPass;

  // Optional static address. All three blank means DHCP. A DNS server has to
  // stay put, so either this or a DHCP reservation on the router is needed.
  String   staticIp;
  String   staticGw;
  String   staticMask;

  // Upstream resolvers -- where allowed queries are forwarded, and what the
  // device itself uses for ntfy, NTP and the blocklist download.
  String   dns1 = "1.1.1.1";
  String   dns2 = "1.0.0.1";

  // ntfy server
  String   ntfyHost = "ntfy.sh";
  uint16_t ntfyPort = 443;
  bool     ntfyTls  = true;
  String   ntfyTopic;

  // ntfy login -- token wins over user/password; all blank means an open server
  String   ntfyUser;
  String   ntfyPass;
  String   ntfyToken;

  // Command passphrase: prefixes every command sent over ntfy. REQUIRED for
  // block / unblock / reload / reboot / factoryreset.
  String   cmdPass;

  // Login for the settings page. Deliberately separate from cmdPass: that one
  // travels through the ntfy topic, and it should not also unlock the config.
  String   adminPass;

  // Encrypted upstream: DNS-over-TLS to this host. When the connection is
  // down, lookups fall back to dns1 / dns2 in the clear.
  bool     dotEnabled = true;
  String   dotHost    = "one.one.one.one";
  uint16_t dotPort    = 853;

  // Blocklist sources, HOSTS or Adblock format, one URL per line (up to
  // BL_MAX_LISTS), and the local hour they are re-downloaded each day.
  String   blocklistUrl = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts";
  uint8_t  refreshHour  = 3;

  // Blocking an entry also blocks its subdomains (ads.example.com for
  // example.com), as Pi-hole does for Adblock-style lists.
  bool     blockSubdomains = true;

  // Firefox's DoH canary and iCloud Private Relay's, answered NXDOMAIN so
  // those features switch themselves off and queries stay here.
  bool     blockCanaries = true;

  // Single-label names, .lan / .home / .home.arpa, and reverse lookups of
  // private addresses go to the router instead of the public resolver.
  bool     localForward = true;

  // Answer DNS over IPv6 too.
  bool     ipv6 = true;

  // Daily reboot, in local time. tz is a POSIX TZ string so DST is handled.
  String   tz            = "EST5EDT,M3.2.0,M11.1.0";
  bool     rebootEnabled = true;
  uint8_t  rebootHour    = 4;
  uint8_t  rebootMinute  = 0;

  // Status LED. Pin 0 means none. GPIO 48 is the RGB LED on an
  // ESP32-S3-DevKitC-1 v1.0; v1.1 boards moved it to 38.
  uint8_t  ledPin       = 48;
  bool     ledRgb       = true;    // WS2812; false = single-colour LED
  bool     ledActiveLow = false;   // single-colour only
  uint8_t  ledBright    = 16;      // 1-255

  bool     provisioned = false;   // the "ok" sentinel
};

extern Settings g_settings;

// Loads from NVS into g_settings. Leaves the defaults above in place if the
// device has never been provisioned.
void settings_begin();

bool settings_save();

// Wipes the config namespace. The blocklist snapshot and custom list live on
// LittleFS and are untouched.
void settings_clear();

// True when no static address is configured.
bool settings_useDhcp(const Settings& s);

// Dotted-quad parse with no surprises: exactly four 0-255 parts, digits only.
bool parseIPv4(const String& text, uint32_t& out);

// Checks the static-address trio: all blank (DHCP) or all valid, a contiguous
// netmask, and the address inside the gateway's subnet. Fills `error` with a
// sentence for the settings page when it returns false.
bool settings_validStaticIp(const String& ip, const String& gw,
                            const String& mask, String& error);

// GPIOs safe to drive an LED from on an N16R8: not the flash / octal PSRAM
// pins (26-37), not native USB (19-20), not UART0 (43-44), not the strapping
// pins 0, 45 and 46. 0 itself is allowed and means "no LED".
bool settings_validLedPin(int pin);

// "HH:MM" -> hour and minute. Rejects anything outside 00:00-23:59.
bool parseHhMm(const String& text, uint8_t& hour, uint8_t& minute);

// Username paired with Settings::adminPass on the settings page.
static const char* const ADMIN_USER = "admin";
