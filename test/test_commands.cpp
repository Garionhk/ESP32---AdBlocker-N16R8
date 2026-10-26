// Host-side tests for the real commands.cpp. The transport, the blocklist,
// the DNS server and the scheduler are stubbed so the replies and the calls
// made can be inspected; settings.cpp is the genuine article.
#include <cstdio>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "Arduino.h"
#include "Preferences.h"
#include "WiFi.h"
#include "blocklist.h"
#include "commands.h"
#include "config.h"
#include "querylog.h"
#include "scheduler.h"
#include "settings.h"
#include "sinkhole.h"
#include "webconfig.h"

#define COMMAND_PASSPHRASE "test-passphrase"

SerialShim Serial;
FakeWiFi   WiFi;
FakeESP    ESP;
unsigned long fakeMillis = 1000;
bool g_restarted = false;
std::map<std::string, std::string> Preferences::backing;

// ---- stubs ----------------------------------------------------------------

static std::vector<std::string> sent;
static std::string restartReason;
static std::set<std::string> blocked = {"ads.example.com"};
static bool blockingOn = true;
static int  reloads = 0;
static bool reloadBusy = false;
static blocklist::State listState = blocklist::State::Ready;

namespace ntfy {
bool publish(const String& message, const String& title) {
  sent.push_back(std::string(title.s) + "|" + message.s);
  return true;
}
bool connected() { return true; }
}  // namespace ntfy

namespace webconfig {
String settingsUrl() { return String("http://192.168.1.50"); }
String apSsid()      { return String("AdBlocker-Setup-TEST"); }
}  // namespace webconfig

namespace scheduler {
void   restart(const char* why) { restartReason = why; }
String lastResetReason() { return String("daily reboot"); }
String nextReboot()      { return String("04:00 EST"); }
String localTimeStr()    { return String("2026-10-25 14:00 EDT"); }
}  // namespace scheduler

namespace sinkhole {
Stats  stats() { return Stats{200, 50, 148, 2}; }
String recentBlocked() { return String("ads.example.com\ntrack.example.net"); }
String upstreamStatus() { return String("DNS-over-TLS, connected to one.one.one.one"); }
}  // namespace sinkhole

namespace blocklist {
Stats stats() {
  Stats s = {};
  s.state = listState;
  s.domains = 162431;
  s.enabled = blockingOn;
  return s;
}
bool enabled() { return blockingOn; }
void setEnabled(bool on) { blockingOn = on; }
bool contains(const String& d) { return blocked.count(d.s) > 0; }
bool explain(const String& d, String& via) {
  // Mimics subdomain matching: x.ads.example.com is blocked via its parent.
  for (std::string n = d.s;;) {
    if (blocked.count(n)) { via = String(n); return true; }
    size_t dot = n.find('.');
    if (dot == std::string::npos) break;
    n = n.substr(dot + 1);
  }
  via = String("");
  return false;
}
Edit block(const String& d) {
  if (blocked.count(d.s)) return Edit::Duplicate;
  blocked.insert(d.s);
  return Edit::Ok;
}
Edit unblock(const String& d) {
  if (!blocked.erase(d.s)) return Edit::NotFound;
  return Edit::Ok;
}
const char* editMessage(Edit e) { return e == Edit::Duplicate ? "already blocked" : "not in the blocklist"; }
bool requestReload(const char*) { if (reloadBusy) return false; reloads++; return true; }
bool clearCustom() { return requestReload("clear"); }
}  // namespace blocklist

namespace querylog {
int top(TopOf what, TopRow* out, int max) {
  if (max < 1) return 0;
  strcpy(out[0].key, what == TopOf::Clients ? "192.168.1.20" : "ads.example.com");
  out[0].count = 42;
  return 1;
}
}  // namespace querylog

// ---- harness --------------------------------------------------------------

static int failures = 0, checks = 0;

static void ok(bool cond, const char* what) {
  checks++;
  if (!cond) { failures++; printf("  FAIL: %s\n", what); }
}

static std::string lastReply() { return sent.empty() ? "" : sent.back(); }

static bool replyHas(const char* needle) {
  return lastReply().find(needle) != std::string::npos;
}

static void send(const char* msg) {
  sent.clear();
  restartReason.clear();
  g_restarted = false;
  commands::handle(String(msg));
}

#define P COMMAND_PASSPHRASE " "

static bool anyReplyLeaks() {
  for (auto& m : sent) if (m.find(COMMAND_PASSPHRASE) != std::string::npos) return true;
  return false;
}

int main() {
  g_settings.cmdPass   = COMMAND_PASSPHRASE;
  g_settings.ntfyTopic = "t";
  g_settings.wifiSsid  = "w";

  // --- the gate ---
  send("status");
  ok(sent.empty(), "no passphrase: silent");
  send("wrong-pass status");
  ok(sent.empty(), "wrong passphrase: silent");
  send("test-passphrasex status");
  ok(sent.empty(), "passphrase with extra chars: silent");
  send(COMMAND_PASSPHRASE);
  ok(sent.empty(), "passphrase alone: silent");
  send("TEST-Passphrase help");
  ok(replyHas("Help|"), "passphrase is case-insensitive");
  ok(!anyReplyLeaks(), "help does not echo the passphrase");

  // --- read-only commands ---
  send(P "status");
  ok(replyHas("Status|"), "status replies");
  ok(replyHas("192.168.1.50 (DHCP)"), "status shows IP and DHCP mode");
  ok(replyHas("AA:BB:CC:DD:EE:FF"), "DHCP status shows the MAC to reserve");
  ok(replyHas("162,431 domains"), "status shows list size with separators");
  ok(replyHas("next reboot 04:00 EST"), "status shows next reboot");
  ok(replyHas("upstream DNS-over-TLS"), "status shows the upstream path");
  ok(replyHas("last reset: daily reboot"), "status shows last reset reason");
  ok(replyHas("blocked 50 (25%)"), "status shows block rate");
  ok(!anyReplyLeaks(), "status does not echo the passphrase");

  g_settings.staticIp = "192.168.1.50";
  g_settings.staticGw = "192.168.1.1";
  g_settings.staticMask = "255.255.255.0";
  send(P "status");
  ok(replyHas("(static)") && !replyHas("reserve"), "static mode: no reservation hint");
  g_settings.staticIp = g_settings.staticGw = g_settings.staticMask = "";

  send(P "STATS");
  ok(replyHas("Stats|") && replyHas("track.example.net"), "stats lists recent blocks");

  send(P "check ads.example.com");
  ok(replyHas("IS blocked"), "check: blocked");
  send(P "check x.ads.example.com");
  ok(replyHas("IS blocked (via ads.example.com)"), "check names the parent that blocks it");
  send(P "top");
  ok(replyHas("Top|") && replyHas("42  ads.example.com") && replyHas("192.168.1.20"),
     "top lists names and clients");
  send(P "check good.example.com");
  ok(replyHas("NOT blocked"), "check: allowed");
  send(P "check");
  ok(replyHas("Usage"), "check without a domain shows usage");

  listState = blocklist::State::Loading;
  send(P "check ads.example.com");
  ok(replyHas("not loaded"), "check while loading says nothing is blocked");
  listState = blocklist::State::Ready;

  // --- editing ---
  send(P "block new.example.com");
  ok(replyHas("now blocked") && blocked.count("new.example.com"), "block adds");
  send(P "block new.example.com");
  ok(replyHas("already blocked"), "block twice reports duplicate");
  send(P "unblock new.example.com");
  ok(replyHas("now allowed") && !blocked.count("new.example.com"), "unblock removes");
  send(P "allow ads.example.com");
  ok(replyHas("now allowed"), "allow is an alias for unblock");
  send(P "unblock nothere.example.com");
  ok(replyHas("not in the blocklist"), "unblock of unknown name");
  send(P "block");
  ok(replyHas("Usage"), "block without a domain shows usage");

  send(P "off");
  ok(!blockingOn && replyHas("OFF"), "off disables blocking");
  send(P "on");
  ok(blockingOn && replyHas("ON"), "on enables blocking");

  send(P "reload");
  ok(reloads == 1 && replyHas("Downloading"), "reload queues a download");
  reloadBusy = true;
  send(P "reload");
  ok(reloads == 1 && replyHas("already running"), "reload while busy is refused");
  reloadBusy = false;

  send(P "clearcustom");
  ok(reloads == 2 && replyHas("deleted"), "clearcustom reloads");

  send(P "reboot");
  ok(restartReason == "ntfy request", "reboot restarts with a reason");

  send(P "frobnicate");
  ok(replyHas("Unknown command \"frobnicate\""), "unknown command");
  ok(!anyReplyLeaks(), "unknown-command reply does not echo the passphrase");

  // --- with no passphrase configured, state changes are refused ---
  g_settings.cmdPass = "";
  send("status");
  ok(replyHas("Status|"), "no passphrase set: read-only commands answer");
  send("block x.example.com");
  ok(replyHas("Set a command passphrase") && !blocked.count("x.example.com"),
     "no passphrase set: block refused");
  send("off");
  ok(blockingOn && replyHas("Set a command passphrase"), "no passphrase set: off refused");
  send("reboot");
  ok(restartReason.empty(), "no passphrase set: reboot refused");
  send("factoryreset");
  ok(!g_restarted, "no passphrase set: factoryreset refused");

  // --- factoryreset ---
  g_settings.cmdPass = COMMAND_PASSPHRASE;
  settings_save();
  send(P "factoryreset");
  ok(g_restarted, "factoryreset restarts");
  ok(replyHas("AdBlocker-Setup-TEST"), "factoryreset names the setup network");
  ok(!anyReplyLeaks(), "factoryreset does not echo the passphrase");
  g_settings = Settings();
  settings_begin();
  ok(!g_settings.provisioned, "factoryreset cleared the stored settings");

  printf("%d/%d checks passed\n", checks - failures, checks);
  return failures ? 1 : 0;
}
