// Host-side tests for settings.cpp: the NVS round-trip and the static-IP,
// address and time validation behind the settings form.
#include <cstdio>
#include <map>
#include <string>

#include "Arduino.h"
#include "Preferences.h"
#include "settings.h"

SerialShim Serial;
std::map<std::string, std::string> Preferences::backing;

static int failures = 0, checks = 0;

static void ok(bool cond, const char* what) {
  checks++;
  if (!cond) { failures++; printf("  FAIL: %s\n", what); }
}

static bool staticOk(const char* ip, const char* gw, const char* mask) {
  String err;
  return settings_validStaticIp(String(ip), String(gw), String(mask), err);
}

int main() {
  // --- parseIPv4 ---
  uint32_t v = 0;
  ok(parseIPv4("192.168.1.50", v) && v == 0xC0A80132, "parses a plain address");
  ok(parseIPv4("0.0.0.0", v) && v == 0, "parses all-zero");
  ok(!parseIPv4("192.168.1", v), "three parts rejected");
  ok(!parseIPv4("192.168.1.1.1", v), "five parts rejected");
  ok(!parseIPv4("192.168.1.256", v), "part over 255 rejected");
  ok(!parseIPv4("192.168..1", v), "empty part rejected");
  ok(!parseIPv4("192.168.1.1 ", v), "trailing space rejected");
  ok(!parseIPv4("1921.168.1.1", v), "four-digit part rejected");
  ok(!parseIPv4("", v), "empty rejected");

  // --- static IP trio ---
  ok(staticOk("", "", ""), "all blank means DHCP");
  ok(staticOk("192.168.1.53", "192.168.1.1", "255.255.255.0"), "valid trio accepted");
  ok(staticOk("10.0.5.2", "10.0.0.1", "255.255.0.0"), "/16 accepted");
  ok(!staticOk("192.168.1.53", "", ""), "IP alone rejected");
  ok(!staticOk("192.168.1.53", "192.168.1.1", ""), "missing subnet rejected");
  ok(!staticOk("192.168.2.53", "192.168.1.1", "255.255.255.0"), "different subnet rejected");
  ok(!staticOk("192.168.1.53", "192.168.1.1", "255.0.255.0"), "non-contiguous mask rejected");
  ok(!staticOk("192.168.1.53", "192.168.1.1", "0.0.0.0"), "zero mask rejected");
  ok(!staticOk("192.168.1.1", "192.168.1.1", "255.255.255.0"), "IP equal to gateway rejected");
  ok(!staticOk("192.168.1.0", "192.168.1.1", "255.255.255.0"), "network address rejected");
  ok(!staticOk("192.168.1.255", "192.168.1.1", "255.255.255.0"), "broadcast rejected");
  ok(!staticOk("192.168.1.x", "192.168.1.1", "255.255.255.0"), "garbage rejected");
  {
    String err;
    settings_validStaticIp("192.168.1.53", "", "", err);
    ok(err.indexOf("all three") >= 0, "partial entry explains the all-or-nothing rule");
  }

  // --- HH:MM ---
  uint8_t h = 99, m = 99;
  ok(parseHhMm("04:00", h, m) && h == 4 && m == 0, "04:00");
  ok(parseHhMm("23:59", h, m) && h == 23 && m == 59, "23:59");
  ok(parseHhMm("00:00", h, m) && h == 0 && m == 0, "00:00");
  ok(!parseHhMm("24:00", h, m), "24:00 rejected");
  ok(!parseHhMm("12:60", h, m), "minute 60 rejected");
  ok(!parseHhMm("4:00", h, m), "single-digit hour rejected");
  ok(!parseHhMm("04-00", h, m), "wrong separator rejected");
  ok(!parseHhMm("", h, m), "empty rejected");

  // --- LED pins ---
  ok(settings_validLedPin(0), "0 means no LED");
  ok(settings_validLedPin(48), "48 (DevKitC-1 v1.0 RGB)");
  ok(settings_validLedPin(38), "38 (DevKitC-1 v1.1 RGB)");
  ok(settings_validLedPin(2), "a plain GPIO");
  ok(settings_validLedPin(21), "21");
  ok(!settings_validLedPin(19) && !settings_validLedPin(20), "USB pins rejected");
  ok(!settings_validLedPin(26) && !settings_validLedPin(35) && !settings_validLedPin(37),
     "flash / PSRAM pins rejected");
  ok(!settings_validLedPin(43) && !settings_validLedPin(44), "UART0 rejected");
  ok(!settings_validLedPin(45) && !settings_validLedPin(46), "strapping pins rejected");
  ok(!settings_validLedPin(49) && !settings_validLedPin(-1), "out of range rejected");

  // --- NVS round trip, including a simulated reboot ---
  settings_begin();
  ok(!g_settings.provisioned, "fresh NVS is unprovisioned");
  ok(settings_useDhcp(g_settings), "defaults use DHCP");

  g_settings.wifiSsid      = "home";
  g_settings.wifiPass      = "wifipass";
  g_settings.staticIp      = "192.168.1.53";
  g_settings.staticGw      = "192.168.1.1";
  g_settings.staticMask    = "255.255.255.0";
  g_settings.dns1          = "9.9.9.9";
  g_settings.dns2          = "";
  g_settings.ntfyTopic     = "adb-topic";
  g_settings.cmdPass       = "sekret";
  g_settings.adminPass     = "adminpw";
  g_settings.blocklistUrl  = "https://example.com/hosts";
  g_settings.refreshHour   = 2;
  g_settings.tz            = "HKT-8";
  g_settings.rebootEnabled = false;
  g_settings.rebootHour    = 5;
  g_settings.rebootMinute  = 30;
  g_settings.ledPin        = 38;
  g_settings.ledRgb        = false;
  g_settings.ledActiveLow  = true;
  g_settings.ledBright     = 200;
  ok(settings_save(), "save succeeds");

  g_settings = Settings();   // "reboot"
  settings_begin();
  ok(g_settings.provisioned, "provisioned after reload");
  ok(g_settings.staticIp == "192.168.1.53", "static IP survives");
  ok(g_settings.staticMask == "255.255.255.0", "subnet survives");
  ok(!settings_useDhcp(g_settings), "static config is not DHCP");
  ok(g_settings.dns1 == "9.9.9.9" && g_settings.dns2.isEmpty(), "upstream DNS survives");
  ok(g_settings.blocklistUrl == "https://example.com/hosts", "blocklist URL survives");
  ok(g_settings.refreshHour == 2, "refresh hour survives");
  ok(g_settings.tz == "HKT-8", "timezone survives");
  ok(!g_settings.rebootEnabled && g_settings.rebootHour == 5 && g_settings.rebootMinute == 30,
     "reboot schedule survives");
  ok(g_settings.ledPin == 38 && !g_settings.ledRgb && g_settings.ledActiveLow &&
         g_settings.ledBright == 200,
     "LED settings survive");

  // A record whose ok flag is set but which lost its topic must not boot.
  Preferences::backing["adbcfg/topic"] = "";
  g_settings = Settings();
  settings_begin();
  ok(!g_settings.provisioned, "incomplete record forces setup");

  settings_clear();
  ok(g_settings.dns1 == "1.1.1.1" && g_settings.rebootHour == 4, "clear restores defaults");

  printf("%d/%d checks passed\n", checks - failures, checks);
  return failures ? 1 : 0;
}
