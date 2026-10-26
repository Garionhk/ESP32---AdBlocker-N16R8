#include <Arduino.h>
#include <WiFi.h>
#include <time.h>

#include "blocklist.h"
#include "commands.h"
#include "config.h"
#include "sinkhole.h"
#include "ntfy.h"
#include "querylog.h"
#include "scheduler.h"
#include "settings.h"
#include "util.h"
#include "webconfig.h"

namespace commands {
namespace {

const int MAX_TOKENS = 6;

int tokenize(const String& input, String out[MAX_TOKENS]) {
  int    n = 0;
  String current;

  for (unsigned int i = 0; i <= input.length() && n < MAX_TOKENS; i++) {
    char c = (i < input.length()) ? input[i] : ' ';
    if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
      if (current.length() > 0) {
        out[n++] = current;
        current  = "";
      }
    } else {
      current += c;
    }
  }
  return n;
}

// Compares without an early exit, so response time does not leak how many
// leading characters were right. Case-insensitive, so phone
// auto-capitalisation doesn't lock you out.
bool passphraseOk(const String& given, const String& expected) {
  String a = given, b = expected;
  a.toLowerCase();
  b.toLowerCase();

  uint32_t diff = (uint32_t)(a.length() ^ b.length());
  for (unsigned int i = 0; i < b.length(); i++) {
    char g = (i < a.length()) ? a[i] : '\0';
    diff |= (uint32_t)(g ^ b[i]);
  }
  return diff == 0;
}

// State-changing commands ALWAYS need a passphrase to be set, even though the
// gate in handle() lets everything through when none is -- ntfy.sh topics are
// public, so an ungated topic stays read-only.
bool requireSecret(const String& secret, const char* what, const char* title) {
  if (!secret.isEmpty()) return true;
  ntfy::publish(String("Set a command passphrase before ") + what + ".", title);
  return false;
}

String blocklistLine() {
  blocklist::Stats b = blocklist::stats();
  String out = "blocklist ";
  switch (b.state) {
    case blocklist::State::Ready:
      out += withCommas(b.domains) + " domains";
      if (b.loadedAt > 0 && time(nullptr) > (time_t)NTP_MIN_VALID_EPOCH) {
        out += ", downloaded " + fmtDuration((uint32_t)(time(nullptr) - b.loadedAt)) + " ago";
      }
      if (b.fromSnapshot) out += " (from flash)";
      break;
    case blocklist::State::Loading:
      out += "downloading " + String(b.progress) + "% -- not blocking until done";
      break;
    case blocklist::State::Failed:
      out += "FAILED to load -- not blocking";
      break;
    case blocklist::State::Empty:
      out += "not loaded yet";
      break;
  }
  return out;
}

String queriesLine() {
  sinkhole::Stats d = sinkhole::stats();
  String out = "queries " + withCommas(d.queries) + ", blocked " + withCommas(d.blocked);
  if (d.queries > 0) out += " (" + String((unsigned long)(d.blocked * 100ULL / d.queries)) + "%)";
  out += ", cached " + withCommas(d.cached);
  if (d.failed > 0) out += ", upstream failures " + withCommas(d.failed);
  if (d.dropped > 0) out += ", dropped (queue full) " + withCommas(d.dropped);
  return out;
}

String topLines(querylog::TopOf what, int n) {
  querylog::TopRow rows[5];
  int got = querylog::top(what, rows, n < 5 ? n : 5);
  String out;
  for (int i = 0; i < got; i++) out += "\n  " + String(rows[i].count) + "  " + rows[i].key;
  return got ? out : String("\n  (nothing yet)");
}

void replyHelp() {
  String help =
      "AdBlocker -- commands\n"
      "\n"
      "Start every command with your passphrase:\n"
      "<passphrase> <command>\n"
      "\n"
      "status             address, blocklist, schedule, memory\n"
      "stats              query counts and recently blocked names\n"
      "top                most blocked names and busiest devices\n"
      "check <domain>     is it blocked, and by which entry?\n"
      "block <domain>     add to your custom blocklist\n"
      "unblock <domain>   allow it through\n"
      "on / off           turn blocking on or off until reboot\n"
      "reload             download the blocklist again now\n"
      "clearcustom        forget every block / unblock you added\n"
      "reboot             restart now\n"
      "factoryreset       wipe settings, reboot into setup\n"
      "help               this message\n"
      "\n"
      "A leading www. is ignored, so check example.com covers both.";
  ntfy::publish(help, "Help");
}

void replyStats() {
  String out = queriesLine() + "\n" + blocklistLine();
  String recent = sinkhole::recentBlocked();
  out += recent.isEmpty() ? "\n\nNothing blocked yet." : "\n\nRecently blocked:\n" + recent;
  ntfy::publish(out, "Stats");
}

void doCheck(const String& domain) {
  if (blocklist::stats().state != blocklist::State::Ready) {
    ntfy::publish("The blocklist is not loaded right now, so nothing is blocked.", "Check");
    return;
  }
  String via;
  bool hit = blocklist::explain(domain, via);
  String msg = domain + (hit ? " IS blocked" : " is NOT blocked");
  if (!via.isEmpty() && via != domain) {
    msg += hit ? " (via " + via + ")" : " (you allowed " + via + ")";
  }
  msg += ".";
  if (hit && !blocklist::enabled()) msg += " (Blocking is off at the moment.)";
  ntfy::publish(msg, "Check");
}

void doEdit(const String& secret, const String& verb, String tokens[MAX_TOKENS], int count) {
  bool isBlock = verb == "block";
  const char* title = isBlock ? "Block" : "Unblock";
  if (!requireSecret(secret, "changing the blocklist", title)) return;
  if (count < 2) {
    ntfy::publish("Usage: <passphrase> " + verb + " <domain>", title);
    return;
  }
  blocklist::Edit r = isBlock ? blocklist::block(tokens[1]) : blocklist::unblock(tokens[1]);
  if (r == blocklist::Edit::Ok) {
    ntfy::publish(tokens[1] + (isBlock ? " is now blocked." : " is now allowed."), title);
  } else {
    ntfy::publish(tokens[1] + ": " + blocklist::editMessage(r) + ".", title);
  }
}

void doEnable(const String& secret, bool on) {
  if (!requireSecret(secret, "turning blocking on or off", "Blocking")) return;
  blocklist::setEnabled(on);
  ntfy::publish(on ? "Blocking is ON."
                   : "Blocking is OFF until you send \"on\" or the device reboots.",
                "Blocking");
}

void doReload(const String& secret) {
  if (!requireSecret(secret, "reloading the blocklist", "Reload")) return;
  if (blocklist::requestReload("ntfy request")) {
    ntfy::publish("Downloading the blocklist. Queries pass through unblocked until it "
                  "finishes; you will get a message when it is done.",
                  "Reload");
  } else {
    ntfy::publish("A download is already running.", "Reload");
  }
}

void doClearCustom(const String& secret) {
  if (!requireSecret(secret, "clearing the custom list", "Custom list")) return;
  if (blocklist::clearCustom()) {
    ntfy::publish("Custom blocks and unblocks deleted. Reloading the blocklist without them.",
                  "Custom list");
  } else {
    ntfy::publish("The blocklist is busy -- try again in a minute.", "Custom list");
  }
}

void doReboot(const String& secret) {
  if (!requireSecret(secret, "rebooting", "Reboot")) return;
  scheduler::restart("ntfy request");
}

void doFactoryReset(const String& secret) {
  if (!requireSecret(secret, "using factoryreset", "Factory reset")) return;
  ntfy::publish("Clearing settings. Rebooting into setup mode -- join the \"" +
                    webconfig::apSsid() + "\" network to reconfigure. The blocklist "
                    "and custom list stay in flash.",
                "Factory reset");
  settings_clear();
  delay(1500);          // let the reply actually reach the server
  ESP.restart();
}

}  // namespace

String statusReport() {
  const Settings& s = g_settings;
  bool dhcp = settings_useDhcp(s);

  String out =
      String(APP_NAME " v" APP_VERSION) + "\n" +
      "ip " + WiFi.localIP().toString() + (dhcp ? " (DHCP)" : " (static)") + "\n";
  if (dhcp) {
    out += "mac " + WiFi.macAddress() + " -- reserve this IP for it in your router\n";
  }
  if (s.ipv6) {
    String v6 = WiFi.globalIPv6().toString();
    if (v6 != "::" && !v6.isEmpty()) out += "ipv6 " + v6 + "\n";
  }
  out += "gw " + WiFi.gatewayIP().toString() + "\n" +
         "upstream " + sinkhole::upstreamStatus() + "\n" +
         "wifi " + WiFi.SSID() + " (" + String(WiFi.RSSI()) + " dBm)\n" +
         "settings " + webconfig::settingsUrl() + "\n" +
         blocklistLine() + "\n" +
         "blocking " + String(blocklist::enabled() ? "on" : "OFF") + "\n" +
         queriesLine() + "\n" +
         "up " + fmtDuration(millis() / 1000) + ", last reset: " +
         scheduler::lastResetReason() + "\n" +
         "time " + scheduler::localTimeStr() + "\n" +
         "next reboot " + scheduler::nextReboot() + ", list refresh " +
         (s.refreshHour < 10 ? "0" : "") + String(s.refreshHour) + ":00\n" +
         "ntfy " + String(ntfy::connected() ? "connected" : "reconnecting") + "\n" +
         "heap " + fmtBytes(ESP.getFreeHeap()) + ", psram " + fmtBytes(ESP.getFreePsram()) +
         " free";
  return out;
}

void handle(const String& message) {
  String tokens[MAX_TOKENS];
  int    n = tokenize(message, tokens);
  if (n == 0) return;

  // --- passphrase gate --------------------------------------------------
  // The passphrase prefixes every command. Anything else is ignored without a
  // reply, so a stranger on the topic gets no hint the device is listening.
  String secret = g_settings.cmdPass;
  secret.trim();
  if (!secret.isEmpty()) {
    if (!passphraseOk(tokens[0], secret)) return;
    for (int i = 1; i < n; i++) tokens[i - 1] = tokens[i];
    tokens[--n] = "";
    if (n == 0) return;
  }

  String verb = tokens[0];
  verb.toLowerCase();

  if (verb == "help" || verb == "?" || verb == "commands") {
    replyHelp();

  } else if (verb == "status" || verb == "stat") {
    ntfy::publish(statusReport(), "Status");

  } else if (verb == "stats") {
    replyStats();

  } else if (verb == "top") {
    ntfy::publish("Most blocked:" + topLines(querylog::TopOf::BlockedNames, 5) +
                      "\n\nBusiest devices:" + topLines(querylog::TopOf::Clients, 5) +
                      "\n\nSince the last reboot.",
                  "Top");

  } else if (verb == "check") {
    if (n < 2) {
      ntfy::publish("Usage: <passphrase> check <domain>", "Check");
      return;
    }
    doCheck(tokens[1]);

  } else if (verb == "block" || verb == "unblock") {
    doEdit(secret, verb, tokens, n);

  } else if (verb == "allow" || verb == "whitelist") {
    doEdit(secret, "unblock", tokens, n);

  } else if (verb == "on" || verb == "enable") {
    doEnable(secret, true);

  } else if (verb == "off" || verb == "disable") {
    doEnable(secret, false);

  } else if (verb == "reload" || verb == "refresh") {
    doReload(secret);

  } else if (verb == "clearcustom") {
    doClearCustom(secret);

  } else if (verb == "reboot" || verb == "restart") {
    doReboot(secret);

  } else if (verb == "factoryreset") {
    doFactoryReset(secret);

  } else {
    ntfy::publish("Unknown command \"" + tokens[0] + "\". Send \"<passphrase> help\" "
                  "for the list.",
                  "Unknown command");
  }
}

}  // namespace commands
