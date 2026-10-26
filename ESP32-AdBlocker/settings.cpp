#include <Arduino.h>
#include <Preferences.h>

#include "config.h"
#include "settings.h"

Settings g_settings;

namespace {

Preferences prefs;

const char* NS = "adbcfg";

// All well inside the 15-character NVS key limit.
const char* K_SSID    = "ssid";
const char* K_PASS    = "pass";
const char* K_SIP     = "sip";
const char* K_SGW     = "sgw";
const char* K_SMASK   = "smask";
const char* K_DNS1    = "dns1";
const char* K_DNS2    = "dns2";
const char* K_HOST    = "host";
const char* K_PORT    = "port";
const char* K_TLS     = "tls";
const char* K_TOPIC   = "topic";
const char* K_USER    = "user";
const char* K_NPASS   = "npass";
const char* K_TOKEN   = "token";
const char* K_CMD     = "cmdpass";
const char* K_ADMIN   = "admpass";
const char* K_BLURL   = "blurl";
const char* K_REFRESH = "refresh";
const char* K_TZ      = "tz";
const char* K_REBOOT  = "reboot";
const char* K_RHOUR   = "rhour";
const char* K_RMIN    = "rmin";
const char* K_DOT     = "dot";
const char* K_DOTHOST = "dothost";
const char* K_DOTPORT = "dotport";
const char* K_SUBDOM  = "subdom";
const char* K_CANARY  = "canary";
const char* K_LOCALFW = "localfw";
const char* K_IPV6    = "ipv6";
const char* K_LEDPIN  = "ledpin";
const char* K_LEDRGB  = "ledrgb";
const char* K_LEDLOW  = "ledlow";
const char* K_LEDBRT  = "ledbrt";
const char* K_OK      = "ok";

}  // namespace

void settings_begin() {
  // Opened read-write even though this only reads: on a never-written
  // namespace a read-only open fails.
  if (!prefs.begin(NS, /*readOnly=*/false)) {
    Serial.println("[settings] could not open NVS, using defaults");
    return;
  }

  g_settings.provisioned = prefs.getBool(K_OK, false);
  if (!g_settings.provisioned) {
    Serial.println("[settings] no stored config -- first boot");
    prefs.end();
    return;
  }

  const Settings d;   // compiled defaults, for keys added after first save
  g_settings.wifiSsid      = prefs.getString(K_SSID, "");
  g_settings.wifiPass      = prefs.getString(K_PASS, "");
  g_settings.staticIp      = prefs.getString(K_SIP, "");
  g_settings.staticGw      = prefs.getString(K_SGW, "");
  g_settings.staticMask    = prefs.getString(K_SMASK, "");
  g_settings.dns1          = prefs.getString(K_DNS1, d.dns1);
  g_settings.dns2          = prefs.getString(K_DNS2, d.dns2);
  g_settings.ntfyHost      = prefs.getString(K_HOST, d.ntfyHost);
  g_settings.ntfyPort      = (uint16_t)prefs.getUInt(K_PORT, d.ntfyPort);
  g_settings.ntfyTls       = prefs.getBool(K_TLS, d.ntfyTls);
  g_settings.ntfyTopic     = prefs.getString(K_TOPIC, "");
  g_settings.ntfyUser      = prefs.getString(K_USER, "");
  g_settings.ntfyPass      = prefs.getString(K_NPASS, "");
  g_settings.ntfyToken     = prefs.getString(K_TOKEN, "");
  g_settings.cmdPass       = prefs.getString(K_CMD, "");
  g_settings.adminPass     = prefs.getString(K_ADMIN, "");
  g_settings.blocklistUrl  = prefs.getString(K_BLURL, d.blocklistUrl);
  g_settings.refreshHour   = (uint8_t)prefs.getUInt(K_REFRESH, d.refreshHour);
  g_settings.tz            = prefs.getString(K_TZ, d.tz);
  g_settings.rebootEnabled = prefs.getBool(K_REBOOT, d.rebootEnabled);
  g_settings.rebootHour    = (uint8_t)prefs.getUInt(K_RHOUR, d.rebootHour);
  g_settings.rebootMinute  = (uint8_t)prefs.getUInt(K_RMIN, d.rebootMinute);
  g_settings.dotEnabled    = prefs.getBool(K_DOT, d.dotEnabled);
  g_settings.dotHost       = prefs.getString(K_DOTHOST, d.dotHost);
  g_settings.dotPort       = (uint16_t)prefs.getUInt(K_DOTPORT, d.dotPort);
  g_settings.blockSubdomains = prefs.getBool(K_SUBDOM, d.blockSubdomains);
  g_settings.blockCanaries = prefs.getBool(K_CANARY, d.blockCanaries);
  g_settings.localForward  = prefs.getBool(K_LOCALFW, d.localForward);
  g_settings.ipv6          = prefs.getBool(K_IPV6, d.ipv6);
  g_settings.ledPin        = (uint8_t)prefs.getUInt(K_LEDPIN, d.ledPin);
  g_settings.ledRgb        = prefs.getBool(K_LEDRGB, d.ledRgb);
  g_settings.ledActiveLow  = prefs.getBool(K_LEDLOW, d.ledActiveLow);
  g_settings.ledBright     = (uint8_t)prefs.getUInt(K_LEDBRT, d.ledBright);

  prefs.end();

  // A record flagged complete but missing essentials is worse than no record:
  // it would skip the setup portal and then fail forever.
  if (g_settings.wifiSsid.isEmpty() || g_settings.ntfyTopic.isEmpty()) {
    Serial.println("[settings] stored config is incomplete -- forcing setup");
    g_settings.provisioned = false;
    return;
  }

  Serial.printf("[settings] loaded: ssid=%s ip=%s host=%s:%u topic set=%d\n",
                g_settings.wifiSsid.c_str(),
                settings_useDhcp(g_settings) ? "dhcp" : g_settings.staticIp.c_str(),
                g_settings.ntfyHost.c_str(), (unsigned)g_settings.ntfyPort,
                g_settings.ntfyTopic.isEmpty() ? 0 : 1);
}

bool settings_save() {
  if (!prefs.begin(NS, /*readOnly=*/false)) {
    Serial.println("[settings] could not open NVS for write");
    return false;
  }

  // Cleared first and set last, so a power cut mid-save reads back as
  // unprovisioned rather than as a mix of old and new values.
  prefs.putBool(K_OK, false);
  prefs.putString(K_SSID,    g_settings.wifiSsid);
  prefs.putString(K_PASS,    g_settings.wifiPass);
  prefs.putString(K_SIP,     g_settings.staticIp);
  prefs.putString(K_SGW,     g_settings.staticGw);
  prefs.putString(K_SMASK,   g_settings.staticMask);
  prefs.putString(K_DNS1,    g_settings.dns1);
  prefs.putString(K_DNS2,    g_settings.dns2);
  prefs.putString(K_HOST,    g_settings.ntfyHost);
  prefs.putUInt(K_PORT,      g_settings.ntfyPort);
  prefs.putBool(K_TLS,       g_settings.ntfyTls);
  prefs.putString(K_TOPIC,   g_settings.ntfyTopic);
  prefs.putString(K_USER,    g_settings.ntfyUser);
  prefs.putString(K_NPASS,   g_settings.ntfyPass);
  prefs.putString(K_TOKEN,   g_settings.ntfyToken);
  prefs.putString(K_CMD,     g_settings.cmdPass);
  prefs.putString(K_ADMIN,   g_settings.adminPass);
  prefs.putString(K_BLURL,   g_settings.blocklistUrl);
  prefs.putUInt(K_REFRESH,   g_settings.refreshHour);
  prefs.putString(K_TZ,      g_settings.tz);
  prefs.putBool(K_REBOOT,    g_settings.rebootEnabled);
  prefs.putUInt(K_RHOUR,     g_settings.rebootHour);
  prefs.putUInt(K_RMIN,      g_settings.rebootMinute);
  prefs.putBool(K_DOT,       g_settings.dotEnabled);
  prefs.putString(K_DOTHOST, g_settings.dotHost);
  prefs.putUInt(K_DOTPORT,   g_settings.dotPort);
  prefs.putBool(K_SUBDOM,    g_settings.blockSubdomains);
  prefs.putBool(K_CANARY,    g_settings.blockCanaries);
  prefs.putBool(K_LOCALFW,   g_settings.localForward);
  prefs.putBool(K_IPV6,      g_settings.ipv6);
  prefs.putUInt(K_LEDPIN,    g_settings.ledPin);
  prefs.putBool(K_LEDRGB,    g_settings.ledRgb);
  prefs.putBool(K_LEDLOW,    g_settings.ledActiveLow);
  prefs.putUInt(K_LEDBRT,    g_settings.ledBright);

  bool ok = prefs.putBool(K_OK, true) == 1;
  prefs.end();
  if (!ok) {
    Serial.println("[settings] write failed");
    return false;
  }

  g_settings.provisioned = true;
  Serial.println("[settings] saved");
  return true;
}

void settings_clear() {
  if (!prefs.begin(NS, /*readOnly=*/false)) return;
  prefs.clear();
  prefs.end();
  g_settings = Settings();   // back to compiled defaults
  Serial.println("[settings] cleared");
}

bool settings_useDhcp(const Settings& s) {
  return s.staticIp.isEmpty() && s.staticGw.isEmpty() && s.staticMask.isEmpty();
}

bool parseIPv4(const String& text, uint32_t& out) {
  uint32_t value = 0;
  int parts = 0, digits = 0, part = 0;

  for (unsigned int i = 0; i <= text.length(); i++) {
    char c = (i < text.length()) ? text[i] : '.';
    if (c >= '0' && c <= '9') {
      part = part * 10 + (c - '0');
      if (++digits > 3 || part > 255) return false;
    } else if (c == '.') {
      if (digits == 0 || parts == 4) return false;
      value = (value << 8) | (uint32_t)part;
      parts++;
      part = 0;
      digits = 0;
    } else {
      return false;
    }
  }
  if (parts != 4) return false;
  out = value;
  return true;
}

bool settings_validStaticIp(const String& ip, const String& gw,
                            const String& mask, String& error) {
  bool any = !ip.isEmpty() || !gw.isEmpty() || !mask.isEmpty();
  if (!any) return true;   // DHCP
  if (ip.isEmpty() || gw.isEmpty() || mask.isEmpty()) {
    error = "Static IP needs the address, gateway and subnet -- or leave all three "
            "blank for DHCP.";
    return false;
  }

  uint32_t a, g, m;
  if (!parseIPv4(ip, a))   { error = "Static IP address is not a valid IPv4 address."; return false; }
  if (!parseIPv4(gw, g))   { error = "Gateway is not a valid IPv4 address."; return false; }
  if (!parseIPv4(mask, m)) { error = "Subnet is not a valid IPv4 mask."; return false; }

  // Contiguous ones then zeros, e.g. 255.255.255.0. ~m + 1 is a power of two
  // exactly when that holds.
  uint32_t inv = ~m;
  if (m == 0 || (inv & (inv + 1)) != 0) {
    error = "Subnet must be a mask such as 255.255.255.0.";
    return false;
  }
  if ((a & m) != (g & m)) {
    error = "Static IP and gateway are not in the same subnet.";
    return false;
  }
  if (a == g) { error = "Static IP cannot be the gateway's address."; return false; }
  uint32_t host = a & ~m;
  if (host == 0 || host == ~m) {
    error = "Static IP cannot be the subnet's network or broadcast address.";
    return false;
  }
  return true;
}

bool settings_validLedPin(int pin) {
  if (pin == 0) return true;
  if (pin < 0 || pin > 48) return false;
  if (pin >= 19 && pin <= 20) return false;
  if (pin >= 22 && pin <= 37) return false;   // 22-25 do not exist on the S3
  if (pin >= 43 && pin <= 46) return false;
  return true;
}

bool parseHhMm(const String& text, uint8_t& hour, uint8_t& minute) {
  if (text.length() != 5 || text[2] != ':') return false;
  for (int i : {0, 1, 3, 4}) {
    if (text[i] < '0' || text[i] > '9') return false;
  }
  int h = (text[0] - '0') * 10 + (text[1] - '0');
  int m = (text[3] - '0') * 10 + (text[4] - '0');
  if (h > 23 || m > 59) return false;
  hour = (uint8_t)h;
  minute = (uint8_t)m;
  return true;
}
