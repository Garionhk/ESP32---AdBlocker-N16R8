#pragma once

#include <Arduino.h>

// Configuration portal. Runs in every mode:
//
//   setup   -- SoftAP + captive portal, before the device is provisioned
//   AP      -- SoftAP + STA, after a WiFi failure, so it stays reachable
//   STA     -- on the LAN, so settings can be changed without a reboot dance
//
// The settings page requires the admin login except in setup mode, where no
// credential exists yet (or someone pressed the BOOT button). With no admin
// password stored, the authenticated modes answer "Settings locked".
//
// On the LAN it also serves /status: the live report plus check / block /
// unblock / reload / on / off.

namespace webconfig {

// SoftAP + portal. Used for first-boot setup and the WiFi fallback.
// requireAuth is false only in setup mode. captive starts the catch-all DNS
// that makes phones pop the page; it has to be false once the AdBlocker's own
// DNS server owns port 53.
void beginAP(bool requireAuth, bool captive = true);

// Server on the LAN address. No catch-all DNS -- the sinkhole answers there.
void beginSTA();

void stop();

// Pump the server (and the captive DNS in AP mode). Call every loop().
void tick();

bool   isAP();
String apSsid();      // "AdBlocker-Setup-A1B2", last 4 of the MAC
String ip();          // current address the portal answers on
String settingsUrl(); // "http://<ip>"

// True once a save has been accepted; the setup loop watches this.
bool saved();

}  // namespace webconfig
