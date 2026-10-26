// ESP32-S3 DNS ad blocker with ntfy status and commands.
//
// Point your router's DNS at this device. Names in the blocklist get 0.0.0.0;
// everything else is forwarded upstream. The blocklist engine and DNS
// responder are ported from s60sc/ESP32_AdBlocker (AGPL-3.0); WiFi setup,
// settings and ntfy follow the same pattern as ESP32 WOL-NTFY.
//
// All configuration lives in NVS and is edited from the built-in web portal --
// nothing user-specific is compiled in. See README.md.

#include <Arduino.h>
#include <WiFi.h>
#include <time.h>

#include "blocklist.h"
#include "commands.h"
#include "config.h"
#include "dot.h"
#include "querylog.h"
#include "led.h"
#include "sinkhole.h"
#include "ntfy.h"
#include "scheduler.h"
#include "settings.h"
#include "webconfig.h"

// What the device is currently doing. WiFi can come and go while the portal
// stays up, so the transitions need to be explicit.
enum class Mode { SetupPortal, ApFallback, Online };
static Mode mode = Mode::SetupPortal;

static uint32_t lastWifiAttemptMs = 0;

// Picks the LED pattern from the mode and the blocklist's state.
static void updateLed() {
  blocklist::Stats b = blocklist::stats();
  led::show(led::choose(mode != Mode::Online,
                        b.state == blocklist::State::Loading,
                        b.state == blocklist::State::Ready,
                        (uint8_t)b.lastResult));
}
static bool     announced = false;   // boot message sent

static const char* wifiStatusName(wl_status_t s) {
  switch (s) {
    case WL_IDLE_STATUS:     return "IDLE";
    case WL_NO_SSID_AVAIL:   return "NO_SSID_AVAIL (network not seen)";
    case WL_SCAN_COMPLETED:  return "SCAN_COMPLETED";
    case WL_CONNECTED:       return "CONNECTED";
    case WL_CONNECT_FAILED:  return "CONNECT_FAILED (usually a wrong password)";
    case WL_CONNECTION_LOST: return "CONNECTION_LOST";
    case WL_DISCONNECTED:    return "DISCONNECTED";
    default:                 return "UNKNOWN";
  }
}

// Runs when the join fails. The ESP32 is 2.4 GHz only, so the single most
// useful fact is whether it can even see the configured SSID -- a 5 GHz-only
// network is invisible here and looks identical to a typo.
static void diagnoseWifi() {
  Serial.println("[wifi] scanning to see what is actually in range...");

  // The radio must be idle to scan. Scanning while the station is still trying
  // to associate returns 0 networks and looks exactly like a dead antenna.
  WiFi.disconnect(false, false);
  delay(200);

  int n = WiFi.scanNetworks();
  if (n <= 0) {
    Serial.printf("[wifi] scan returned %d networks. If this persists, suspect "
                  "the antenna or an underpowered USB port rather than the "
                  "credentials.\n", n);
    return;
  }

  bool found = false;
  Serial.printf("[wifi] %d network(s) visible on 2.4 GHz:\n", n);
  for (int i = 0; i < n; i++) {
    bool isOurs = (WiFi.SSID(i) == g_settings.wifiSsid);
    if (isOurs) found = true;
    Serial.printf("  %-32s ch%-3d %4d dBm  %s%s\n",
                  WiFi.SSID(i).c_str(), WiFi.channel(i), WiFi.RSSI(i),
                  WiFi.encryptionType(i) == WIFI_AUTH_OPEN ? "open" : "secured",
                  isOurs ? "   <== configured SSID" : "");
  }
  WiFi.scanDelete();

  if (found) {
    Serial.println("[wifi] SSID is in range, so the password is the likely problem");
  } else {
    Serial.printf("[wifi] \"%s\" was NOT found. It is probably 5 GHz-only "
                  "(the ESP32 cannot see 5 GHz), hidden, or misspelled.\n",
                  g_settings.wifiSsid.c_str());
  }
}

static IPAddress ipOf(const String& text) {
  IPAddress a;
  a.fromString(text);
  return a;
}

// Static address if one is configured, DHCP otherwise. Either way the device
// itself resolves through the upstream servers: once the router hands this
// device's address out as everyone's DNS, a DHCP lease would point it at
// itself.
static void applyAddressing() {
  const Settings& s = g_settings;
  if (settings_useDhcp(s)) return;
  if (!WiFi.config(ipOf(s.staticIp), ipOf(s.staticGw), ipOf(s.staticMask),
                   ipOf(s.dns1), ipOf(s.dns2))) {
    Serial.println("[wifi] static address rejected, falling back to DHCP");
  }
}

static bool connectWifi(uint32_t timeoutMs) {
  Serial.printf("[wifi] joining %s (%s)\n", g_settings.wifiSsid.c_str(),
                settings_useDhcp(g_settings) ? "DHCP" : g_settings.staticIp.c_str());

  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);          // DNS answers and the ntfy socket stay snappy
  WiFi.setAutoReconnect(true);
  if (g_settings.ipv6) WiFi.enableIPv6();   // before begin(), or no SLAAC address
  applyAddressing();
  WiFi.begin(g_settings.wifiSsid.c_str(), g_settings.wifiPass.c_str());

  uint32_t start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < timeoutMs) {
    delay(250);
    Serial.print(".");
  }
  Serial.println();

  if (WiFi.status() != WL_CONNECTED) {
    Serial.printf("[wifi] failed to join: %s\n", wifiStatusName(WiFi.status()));
    diagnoseWifi();
    return false;
  }

  if (settings_useDhcp(g_settings)) {
    WiFi.setDNS(ipOf(g_settings.dns1), ipOf(g_settings.dns2));
  }
  Serial.printf("[wifi] ip %s  mask %s  gw %s  rssi %d dBm\n",
                WiFi.localIP().toString().c_str(),
                WiFi.subnetMask().toString().c_str(),
                WiFi.gatewayIP().toString().c_str(),
                WiFi.RSSI());
  return true;
}

// Local time matters here -- it is what the daily reboot runs on -- and TLS
// certificate validation needs the date. Skipping this is the classic cause
// of handshakes that fail for no visible reason.
static bool syncClock() {
  Serial.printf("[time] syncing (TZ %s)", g_settings.tz.c_str());
  configTzTime(g_settings.tz.c_str(), NTP_SERVER_1, NTP_SERVER_2);

  uint32_t start = millis();
  while (millis() - start < NTP_SYNC_TIMEOUT_MS) {
    if (time(nullptr) > (time_t)NTP_MIN_VALID_EPOCH) {
      Serial.printf("\n[time] %s\n", scheduler::localTimeStr().c_str());
      return true;
    }
    delay(250);
    Serial.print(".");
  }

  Serial.println("\n[time] NTP sync failed -- TLS will likely reject certs, "
                 "and the daily reboot waits for a clock");
  return false;
}

// Pressing BOOT (GPIO0) just after a reset forces the setup portal on an
// already-provisioned device -- the way back from a forgotten admin password
// or a moved network. It has to be pressed AFTER releasing EN: GPIO0 held low
// through the reset itself puts the ESP32 into its serial bootloader instead.
static bool bootButtonPressed() {
  pinMode(0, INPUT_PULLUP);
  Serial.println("[boot] press BOOT now to open the setup portal");
  uint32_t start = millis();
  while (millis() - start < BOOT_WINDOW_MS) {
    if (digitalRead(0) == LOW) return true;
    delay(20);
  }
  return false;
}

// Portal with no WiFi behind it. Deliberately has no timeout: an unprovisioned
// device has no useful fallback state, so a page telling you how to fix that
// is the most useful thing it can be doing.
static void runSetupPortal() {
  mode = Mode::SetupPortal;

  // Deliberately open. Only reached when the device is unprovisioned (nothing
  // to protect yet) or when someone pressed the BOOT button, which already
  // implies physical access.
  webconfig::beginAP(/*requireAuth=*/false);
  led::show(led::Pattern::ApMode);

  Serial.println("\n=== SETUP MODE ===");
  uint32_t lastNag = 0;
  while (!webconfig::saved()) {
    webconfig::tick();
    if (millis() - lastNag > 5000) {
      lastNag = millis();
      Serial.printf("[setup] join wifi \"%s\" then open %s\n",
                    webconfig::apSsid().c_str(),
                    webconfig::settingsUrl().c_str());
    }
    delay(5);
  }
  // handleSave() restarts the device, so this is never reached.
}

static void goOnline() {
  mode = Mode::Online;

  // The portal first: switching it to STA releases the captive DNS, if the
  // AP fallback had it, so the sinkhole can bind port 53. Then DNS before
  // anything slow -- the moment the router hands this address out, clients
  // start asking. Until the blocklist is ready queries just pass through.
  webconfig::beginSTA();
  sinkhole::setRouter(settings_useDhcp(g_settings) ? (uint32_t)WiFi.gatewayIP()
                                                   : (uint32_t)ipOf(g_settings.staticGw));
  sinkhole::begin();
  bool timeOk = syncClock();
  dot::begin();   // needs the clock for its certificate check
  ntfy::begin(commands::handle);

  if (!announced) {
    announced = true;
    ntfy::publish("AdBlocker online\n" + commands::statusReport(), "Online");
  } else {
    ntfy::publish("WiFi is back.\n" + commands::statusReport(), "Reconnected");
  }

  // A snapshot older than a day, or none at all, means download now rather
  // than wait for the nightly refresh.
  if (timeOk && blocklist::snapshotStale()) blocklist::requestReload("startup");

  Serial.printf("[boot] online, heap %u bytes free, psram %u\n",
                (unsigned)ESP.getFreeHeap(), (unsigned)ESP.getFreePsram());
}

// WiFi is configured but unreachable. Bring the portal up so the settings can
// be fixed, while the station side keeps retrying in the background -- a router
// coming back should not need a reboot.
static void startApFallback() {
  mode = Mode::ApFallback;
  // Once the sinkhole owns port 53 the captive DNS cannot bind; the portal
  // still answers at 192.168.4.1.
  webconfig::beginAP(/*requireAuth=*/true, /*captive=*/!sinkhole::running());
  Serial.printf("[wifi] unreachable; portal at %s while retrying in background\n",
                webconfig::settingsUrl().c_str());
}

void setup() {
  Serial.begin(SERIAL_BAUD);
  delay(200);
  Serial.println("\n\n=== " APP_NAME " v" APP_VERSION " ===");

  scheduler::begin();
  settings_begin();
  led::begin();

  // Only worth waiting for on a provisioned board; otherwise setup is next anyway.
  bool forced = g_settings.provisioned && bootButtonPressed();
  if (forced) Serial.println("[boot] BOOT pressed -- forcing setup portal");

  if (!g_settings.provisioned || forced) {
    runSetupPortal();
    return;
  }

  // The query log and DNS tables take their PSRAM first; the blocklist arena
  // gets what is left. Restored from flash before WiFi is even up, so
  // blocking starts the moment DNS does.
  querylog::begin(QUERYLOG_ENTRIES);
  sinkhole::prealloc();
  blocklist::begin();

  if (!connectWifi(WIFI_CONNECT_TIMEOUT_MS)) {
    startApFallback();
  } else {
    goOnline();
  }
}

void loop() {
  webconfig::tick();          // the portal answers in every mode
  if (mode != Mode::SetupPortal) updateLed();

  switch (mode) {
    case Mode::SetupPortal:
      break;                  // runSetupPortal() blocks; nothing to do here

    case Mode::ApFallback:
      // WIFI_AP_STA means the station side is still trying underneath us.
      if (WiFi.status() == WL_CONNECTED) {
        Serial.println("[wifi] back up, leaving AP mode");
        WiFi.softAPdisconnect(true);
        WiFi.mode(WIFI_STA);
        if (settings_useDhcp(g_settings)) {
          WiFi.setDNS(ipOf(g_settings.dns1), ipOf(g_settings.dns2));
        }
        goOnline();
      } else if (millis() - lastWifiAttemptMs > WIFI_RETRY_INTERVAL_MS) {
        lastWifiAttemptMs = millis();
        Serial.printf("[wifi] retrying (%s)\n", wifiStatusName(WiFi.status()));
        WiFi.begin(g_settings.wifiSsid.c_str(), g_settings.wifiPass.c_str());
      }
      break;

    case Mode::Online: {
      if (WiFi.status() != WL_CONNECTED) {
        Serial.println("[wifi] link lost");
        startApFallback();
        break;
      }
      ntfy::poll();
      scheduler::tick();

      String event;
      while (blocklist::takeEvent(event)) ntfy::publish(event, "Blocklist");
      break;
    }
  }

  delay(10);   // yields to the WiFi stack; nothing above blocks
}
