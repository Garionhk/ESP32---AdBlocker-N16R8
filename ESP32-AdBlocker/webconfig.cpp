#include <Arduino.h>
#include <DNSServer.h>
#include <WebServer.h>
#include <WiFi.h>

#include "blocklist.h"
#include "commands.h"
#include "localdns.h"
#include "querylog.h"
#include "sinkhole.h"
#include "config.h"
#include "scheduler.h"
#include "settings.h"
#include "webconfig.h"

namespace webconfig {
namespace {

WebServer server(80);
DNSServer captiveDns;

bool apMode      = false;
bool captiveOn   = false;
bool authNeeded  = true;
bool running     = false;
bool savedFlag   = false;

// POSIX TZ strings for the picker. Anything else goes in the custom field.
struct Zone { const char* label; const char* tz; };
const Zone ZONES[] = {
  {"Eastern (Toronto, New York)",      "EST5EDT,M3.2.0,M11.1.0"},
  {"Central (Winnipeg, Chicago)",      "CST6CDT,M3.2.0,M11.1.0"},
  {"Mountain (Calgary, Denver)",       "MST7MDT,M3.2.0,M11.1.0"},
  {"Arizona / Saskatchewan-style MST", "MST7"},
  {"Pacific (Vancouver, LA)",          "PST8PDT,M3.2.0,M11.1.0"},
  {"Atlantic (Halifax)",               "AST4ADT,M3.2.0,M11.1.0"},
  {"Newfoundland",                     "NST3:30NDT,M3.2.0,M11.1.0"},
  {"Alaska",                           "AKST9AKDT,M3.2.0,M11.1.0"},
  {"Hawaii",                           "HST10"},
  {"UK / Ireland",                     "GMT0BST,M3.5.0/1,M10.5.0"},
  {"Central Europe",                   "CET-1CEST,M3.5.0,M10.5.0/3"},
  {"Eastern Europe",                   "EET-2EEST,M3.5.0/3,M10.5.0/4"},
  {"India",                            "IST-5:30"},
  {"Hong Kong",                        "HKT-8"},
  {"China",                            "CST-8"},
  {"Singapore",                        "<+08>-8"},
  {"Japan",                            "JST-9"},
  {"Korea",                            "KST-9"},
  {"Sydney / Melbourne",               "AEST-10AEDT,M10.1.0,M4.1.0/3"},
  {"New Zealand",                      "NZST-12NZDT,M9.5.0,M4.1.0/3"},
  {"UTC",                              "UTC0"},
};

String htmlEscape(const String& in) {
  String out;
  out.reserve(in.length());
  for (unsigned int i = 0; i < in.length(); i++) {
    char c = in[i];
    switch (c) {
      case '&':  out += "&amp;";  break;
      case '<':  out += "&lt;";   break;
      case '>':  out += "&gt;";   break;
      case '"':  out += "&quot;"; break;
      case '\'': out += "&#39;";  break;
      default:   out += c;
    }
  }
  return out;
}

const char PAGE_HEAD[] PROGMEM =
    "<!doctype html><meta charset=utf-8>"
    "<meta name=viewport content='width=device-width,initial-scale=1'>"
    "<title>AdBlocker</title><style>"
    "body{font-family:system-ui,sans-serif;margin:0;padding:1rem;max-width:34rem;"
    "background:#111;color:#eee}"
    "h1{font-size:1.2rem}h2{font-size:.95rem;margin:1.4rem 0 .4rem;color:#8bd}"
    "label{display:block;margin:.6rem 0 .15rem;font-size:.85rem;color:#bbb}"
    "input[type=text],input[type=password],input[type=number],input[type=time],select{"
    "width:100%;box-sizing:border-box;padding:.5rem;border:1px solid #444;"
    "border-radius:4px;background:#1c1c1c;color:#eee;font-size:1rem}"
    "small{color:#888;font-size:.75rem}"
    "button{margin-top:1.2rem;width:100%;padding:.7rem;font-size:1rem;border:0;"
    "border-radius:4px;background:#2a7;color:#022;font-weight:600}"
    ".row{display:flex;gap:.6rem}.row>div{flex:1}"
    ".btns{display:flex;flex-wrap:wrap;gap:.4rem}.btns button{flex:1;min-width:6rem;"
    "margin-top:.6rem;background:#357;color:#eef}"
    ".err{background:#833;padding:.5rem;border-radius:4px;margin-bottom:.8rem}"
    ".ok{background:#264;padding:.5rem;border-radius:4px;margin-bottom:.8rem}"
    "pre{white-space:pre-wrap;background:#1c1c1c;padding:.6rem;border-radius:4px;"
    "font-size:.8rem}nav a{color:#8bd;margin-right:1rem;white-space:nowrap}"
    "textarea{width:100%;box-sizing:border-box;min-height:6rem;padding:.5rem;border:1px solid #444;"
    "border-radius:4px;background:#1c1c1c;color:#eee;font:.85rem ui-monospace,monospace}"
    "table{border-collapse:collapse;width:100%;font-size:.75rem}td,th{padding:.2rem .3rem;"
    "border-bottom:1px solid #222;text-align:left;word-break:break-all}th{color:#8bd}"
    ".b{color:#e77}.c{color:#7c7}.f{color:#ea5}.mini{margin:0;padding:.1rem .4rem;width:auto;"
    "font-size:.7rem;background:#333;color:#ddd}.tiles{display:flex;flex-wrap:wrap;gap:.5rem}"
    ".tile{flex:1;min-width:7rem;background:#1c1c1c;border-radius:4px;padding:.5rem}"
    ".tile b{display:block;font-size:1.2rem}body.wide{max-width:60rem}"
    "</style>";

String nav() {
  if (apMode) return "";
  return "<nav><a href=/status>Status</a><a href=/stats>Dashboard</a><a href=/log>Query log</a>"
         "<a href=/local>Local DNS</a><a href=/>Settings</a></nav>";
}

// Returns false and sends the challenge if the request should be rejected.
bool authorized() {
  if (!authNeeded) return true;

  // No admin password stored. Leaving the page open would let anyone on the
  // LAN (or anyone in range of the fallback AP) repoint the device, so it stays
  // shut until one is set -- which needs the BOOT button, i.e. physical access.
  if (g_settings.adminPass.isEmpty()) {
    String p = FPSTR(PAGE_HEAD);
    p += "<h1>Settings locked</h1><p>No admin password is set yet. Press "
         "<b>EN</b> (reset) on the board, then immediately press and hold "
         "<b>BOOT</b> for two seconds. It opens the <b>" + htmlEscape(apSsid()) +
         "</b> network, where you can set one.</p>";
    server.send(403, "text/html", p);
    return false;
  }

  if (server.authenticate(ADMIN_USER, g_settings.adminPass.c_str())) return true;
  server.requestAuthentication();
  return false;
}

void handleScan() {
  if (!authorized()) return;

  int n = WiFi.scanNetworks();
  String j = "[";
  for (int i = 0; i < n && i < 30; i++) {
    if (i) j += ",";
    j += "\"" + htmlEscape(WiFi.SSID(i)) + "\"";
  }
  WiFi.scanDelete();
  server.send(200, "application/json", j + "]");
}

String textField(const char* label, const char* name, const String& value,
                 const String& placeholder = "") {
  return String("<label>") + label + "</label><input type=text name=" + name +
         " value='" + htmlEscape(value) + "' placeholder='" + htmlEscape(placeholder) + "'>";
}

void sendForm(const String& error) {
  const Settings& s = g_settings;

  // Hints for the static fields: what DHCP handed out, when we have a lease.
  bool lease = !apMode && WiFi.status() == WL_CONNECTED;
  String hintIp   = lease ? WiFi.localIP().toString()   : "blank = DHCP";
  String hintGw   = lease ? WiFi.gatewayIP().toString() : "e.g. 192.168.0.1";
  String hintMask = lease ? WiFi.subnetMask().toString(): "e.g. 255.255.255.0";

  String p = FPSTR(PAGE_HEAD);
  p += nav();
  p += "<h1>AdBlocker setup</h1>";
  if (!error.isEmpty()) p += "<div class=err>" + htmlEscape(error) + "</div>";
  p += "<form method=POST action=/save>";

  p += "<h2>WiFi</h2>";
  p += "<label>Network (2.4 GHz only)</label>";
  p += "<input type=text name=ssid list=nets value='" + htmlEscape(s.wifiSsid) +
       "' required><datalist id=nets></datalist>";
  p += "<label>Password</label><input type=password name=wpass>";
  p += "<small>Leave blank to keep the stored password.</small>";

  p += "<h2>Address <small>(blank = DHCP)</small></h2>";
  p += "<small>Your router hands this device's IP to everyone as their DNS server, so "
       "it must never change. Either reserve it in the router (DHCP reservation) or "
       "fill in all three fields below.</small>";
  p += textField("Static IP", "sip", s.staticIp, hintIp);
  p += "<div class=row><div>" + textField("Gateway", "sgw", s.staticGw, hintGw) +
       "</div><div>" + textField("Subnet", "smask", s.staticMask, hintMask) + "</div></div>";

  p += "<h2>Upstream DNS</h2>";
  p += "<div class=row><div>" + textField("Primary", "dns1", s.dns1) +
       "</div><div>" + textField("Secondary", "dns2", s.dns2) + "</div></div>";
  p += "<small>Allowed lookups are forwarded here. Not your router -- it will point "
       "back at this device.</small>";
  p += "<label><input type=checkbox name=dot" + String(s.dotEnabled ? " checked" : "") +
       "> encrypt with DNS-over-TLS (falls back to the servers above if it is down)</label>";
  p += "<div class=row><div>" + textField("DoT server", "dothost", s.dotHost) +
       "</div><div><label>Port</label><input type=number name=dotport min=1 max=65535 value='" +
       String(s.dotPort) + "'></div></div>";
  p += "<small>one.one.one.one (Cloudflare), dns.quad9.net (Quad9), dns.google.</small>";
  p += "<label><input type=checkbox name=localfw" + String(s.localForward ? " checked" : "") +
       "> send local names (printer, nas.lan, reverse lookups) to the router</label>";
  p += "<label><input type=checkbox name=ipv6" + String(s.ipv6 ? " checked" : "") +
       "> answer DNS over IPv6 too</label>";

  p += "<h2>Blocklist</h2>";
  p += "<label>URLs, one per line, up to " + String(BL_MAX_LISTS) +
       " (HOSTS, Adblock or plain lists)</label><textarea name=blurl>" +
       htmlEscape(s.blocklistUrl) + "</textarea>";
  p += "<label><input type=checkbox name=subdom" + String(s.blockSubdomains ? " checked" : "") +
       "> blocking a domain also blocks its subdomains</label>";
  p += "<label><input type=checkbox name=canary" + String(s.blockCanaries ? " checked" : "") +
       "> switch off Firefox DNS-over-HTTPS and iCloud Private Relay (they would bypass "
       "blocking)</label>";
  p += "<label>Re-download daily at hour (0-23)</label>"
       "<input type=number name=refresh min=0 max=23 value='" + String(s.refreshHour) + "'>";

  p += "<h2>Daily reboot</h2>";
  p += "<label><input type=checkbox name=reboot" + String(s.rebootEnabled ? " checked" : "") +
       "> reboot every day</label>";
  char hhmm[6];
  snprintf(hhmm, sizeof(hhmm), "%02u:%02u", s.rebootHour, s.rebootMinute);
  p += "<label>At (local time)</label><input type=time name=rtime value='" + String(hhmm) + "'>";
  p += "<small>DNS is down for a few seconds while it restarts. Avoid 01:00-03:00 -- "
       "DST changes skip or repeat that hour.</small>";

  p += "<label>Timezone</label><select name=tzsel>";
  bool known = false;
  for (const Zone& z : ZONES) {
    bool sel = s.tz == z.tz;
    known = known || sel;
    p += "<option value='" + htmlEscape(z.tz) + "'" + (sel ? " selected" : "") + ">" +
         htmlEscape(z.label) + "</option>";
  }
  p += "</select>";
  p += textField("or custom POSIX TZ string", "tzcustom", known ? String("") : s.tz,
                 "e.g. EST5EDT,M3.2.0,M11.1.0");

  p += "<h2>Status LED</h2>";
  p += "<div class=row><div><label>GPIO (0 = none)</label>"
       "<input type=number name=ledpin min=0 max=48 value='" + String(s.ledPin) + "'></div>";
  p += "<div><label>Brightness (1-255)</label>"
       "<input type=number name=ledbrt min=1 max=255 value='" + String(s.ledBright) + "'></div></div>";
  p += "<label>Type</label><select name=ledtype>"
       "<option value=rgb" + String(s.ledRgb ? " selected" : "") + ">WS2812 RGB</option>"
       "<option value=mono" + String(s.ledRgb ? "" : " selected") + ">single colour</option></select>";
  p += "<label><input type=checkbox name=ledlow" + String(s.ledActiveLow ? " checked" : "") +
       "> single colour LED is active-low</label>";
  p += "<small>ESP32-S3-DevKitC-1: GPIO 48 (v1.0) or 38 (v1.1). Yellow = setup / no WiFi, "
       "green = blocking, blue = downloading list, purple = no internet, teal = old list, "
       "red = no list.</small>";

  p += "<h2>ntfy server</h2>";
  p += "<label>Host</label><input type=text name=host value='" +
       htmlEscape(s.ntfyHost) + "' required>";
  p += "<div class=row><div><label>Port</label>"
       "<input type=number name=port min=1 max=65535 value='" +
       String(s.ntfyPort) + "' required></div>";
  p += "<div><label>TLS</label><input type=checkbox name=tls" +
       String(s.ntfyTls ? " checked" : "") + "> https</div></div>";
  p += "<label>Topic</label><input type=text name=topic value='" +
       htmlEscape(s.ntfyTopic) + "' required>";
  p += "<small>Status messages, commands and replies share this topic. Make it long "
       "and unguessable.</small>";

  p += "<h2>ntfy login <small>(blank for an open server)</small></h2>";
  p += "<label>Username</label><input type=text name=nuser value='" +
       htmlEscape(s.ntfyUser) + "'>";
  p += "<label>Password</label><input type=password name=npass>";
  p += "<label>or Token</label><input type=password name=token>";
  p += "<small>A token wins over username and password. Blank keeps stored "
       "values; tick below to remove them.</small>";
  p += "<label><input type=checkbox name=nclear> clear stored ntfy login</label>";

  p += "<h2>Passphrases</h2>";
  p += "<label>Command passphrase</label><input type=password name=cmdpass>";
  p += "<small>Prefix for every command sent from the ntfy app "
       "(<i>passphrase status</i>). Required for block / unblock / reboot.</small>";
  p += "<label>Admin password (this page)</label><input type=password name=admpass>";
  p += "<small>Login is <b>admin</b>. Keep it different from the command "
       "passphrase. Blank keeps the stored ones.</small>";

  p += "<button type=submit>Save &amp; restart</button></form>";

  // Populates the network picker. Typing a network name by hand is how the
  // SSID typo happened once already.
  p += "<script>fetch('/scan').then(r=>r.json()).then(a=>{"
       "document.getElementById('nets').innerHTML="
       "a.map(s=>'<option value=\"'+s+'\">').join('')}).catch(()=>{});</script>";

  server.send(200, "text/html", p);
}

void handleRoot() {
  if (!authorized()) return;
  sendForm("");
}

// ntfy topics are [-_A-Za-z0-9]{1,64}; anything else would also break the URL.
bool validTopic(const String& t) {
  if (t.isEmpty() || t.length() > 64) return false;
  for (unsigned int i = 0; i < t.length(); i++) {
    char c = t[i];
    if (!isalnum((unsigned char)c) && c != '-' && c != '_') return false;
  }
  return true;
}

bool validTz(const String& tz) {
  if (tz.isEmpty() || tz.length() > 60) return false;
  for (unsigned int i = 0; i < tz.length(); i++) {
    if (!isprint((unsigned char)tz[i]) || tz[i] == ' ') return false;
  }
  return true;
}

String trimmedArg(const char* name) {
  String v = server.arg(name);
  v.trim();
  return v;
}

void handleSave() {
  if (!authorized()) return;

  String ssid  = trimmedArg("ssid");
  String host  = trimmedArg("host");
  String topic = trimmedArg("topic");
  String nuser = trimmedArg("nuser");
  String sip   = trimmedArg("sip");
  String sgw   = trimmedArg("sgw");
  String smask = trimmedArg("smask");
  String dns1  = trimmedArg("dns1");
  String dns2  = trimmedArg("dns2");
  String blurl = trimmedArg("blurl");
  String tz    = trimmedArg("tzcustom");
  if (tz.isEmpty()) tz = trimmedArg("tzsel");
  long   port    = server.arg("port").toInt();
  long   refresh = server.arg("refresh").toInt();
  long   ledPin  = server.arg("ledpin").toInt();
  long   ledBrt  = server.arg("ledbrt").toInt();

  if (ssid.isEmpty())               { sendForm("WiFi network is required."); return; }
  if (host.isEmpty())               { sendForm("ntfy host is required."); return; }
  if (!validTopic(topic)) {
    sendForm("ntfy topic must be 1-64 letters, digits, - or _.");
    return;
  }
  if (port < 1 || port > 65535)     { sendForm("Port must be 1-65535."); return; }

  String ipError;
  if (!settings_validStaticIp(sip, sgw, smask, ipError)) { sendForm(ipError); return; }

  uint32_t scratch;
  if (!parseIPv4(dns1, scratch)) { sendForm("Primary upstream DNS must be an IPv4 address."); return; }
  if (!dns2.isEmpty() && !parseIPv4(dns2, scratch)) {
    sendForm("Secondary upstream DNS must be an IPv4 address, or blank.");
    return;
  }
  if (!sip.isEmpty() && (dns1 == sip || dns2 == sip)) {
    sendForm("Upstream DNS cannot be this device's own address.");
    return;
  }
  {
    // One URL per line; blank lines dropped.
    String clean;
    int lists = 0, start = 0;
    blurl.replace("\r", "");
    while (start <= (int)blurl.length()) {
      int nl = blurl.indexOf('\n', start);
      if (nl < 0) nl = blurl.length();
      String u = blurl.substring(start, nl);
      u.trim();
      start = nl + 1;
      if (u.isEmpty()) continue;
      if (!u.startsWith("https://") && !u.startsWith("http://")) {
        sendForm("Each blocklist URL must start with https:// or http://.");
        return;
      }
      if (++lists > BL_MAX_LISTS) {
        sendForm("At most " + String(BL_MAX_LISTS) + " blocklist URLs.");
        return;
      }
      if (!clean.isEmpty()) clean += "\n";
      clean += u;
    }
    if (lists == 0) { sendForm("Enter at least one blocklist URL."); return; }
    blurl = clean;
  }
  String dothost = trimmedArg("dothost");
  long dotport = server.arg("dotport").toInt();
  if (server.hasArg("dot") && dothost.isEmpty()) {
    sendForm("Enter a DNS-over-TLS server, or untick encryption.");
    return;
  }
  if (dotport < 1 || dotport > 65535) { sendForm("DoT port must be 1-65535."); return; }
  if (refresh < 0 || refresh > 23) { sendForm("Refresh hour must be 0-23."); return; }

  uint8_t rh = 0, rm = 0;
  if (!parseHhMm(server.arg("rtime"), rh, rm)) {
    sendForm("Reboot time must be HH:MM.");
    return;
  }
  if (!validTz(tz)) { sendForm("Timezone must be a POSIX TZ string without spaces."); return; }
  if (!settings_validLedPin((int)ledPin)) {
    sendForm("LED GPIO can't be used: 19-20 are USB, 26-37 flash and PSRAM, 43-46 serial "
             "and strapping pins. Use 0 for no LED.");
    return;
  }
  if (ledBrt < 1 || ledBrt > 255) { sendForm("LED brightness must be 1-255."); return; }

  // Blank password fields mean "keep what is stored" -- the form never renders
  // a stored password back to the browser, so blank is the normal state.
  String wpass   = server.arg("wpass");
  String npass   = server.arg("npass");
  String token   = server.arg("token");
  String cmdpass = server.arg("cmdpass");
  String admpass = server.arg("admpass");
  cmdpass.trim();

  // Work on a copy so a rejected form leaves the running config untouched.
  Settings s = g_settings;

  if (!wpass.isEmpty())   s.wifiPass  = wpass;
  if (!cmdpass.isEmpty()) s.cmdPass   = cmdpass;
  if (!admpass.isEmpty()) s.adminPass = admpass;

  // On a first-time setup there is nothing to keep, so this must be supplied.
  if (!g_settings.provisioned && wpass.isEmpty()) {
    sendForm("WiFi password is required.");
    return;
  }
  if (s.cmdPass.isEmpty())   { sendForm("Command passphrase is required."); return; }
  if (s.adminPass.isEmpty()) { sendForm("Admin password is required."); return; }
  // Commands match the passphrase case-insensitively, so compare that way too.
  if (s.cmdPass.equalsIgnoreCase(s.adminPass)) {
    sendForm("Use a different admin password from the command passphrase.");
    return;
  }

  bool urlChanged = s.blocklistUrl != blurl;

  s.wifiSsid      = ssid;
  s.staticIp      = sip;
  s.staticGw      = sgw;
  s.staticMask    = smask;
  s.dns1          = dns1;
  s.dns2          = dns2;
  s.blocklistUrl  = blurl;
  s.dotEnabled    = server.hasArg("dot");
  s.dotHost       = dothost;
  s.dotPort       = (uint16_t)dotport;
  s.blockSubdomains = server.hasArg("subdom");
  s.blockCanaries = server.hasArg("canary");
  s.localForward  = server.hasArg("localfw");
  s.ipv6          = server.hasArg("ipv6");
  s.refreshHour   = (uint8_t)refresh;
  s.rebootEnabled = server.hasArg("reboot");
  s.rebootHour    = rh;
  s.rebootMinute  = rm;
  s.tz            = tz;
  s.ledPin        = (uint8_t)ledPin;
  s.ledBright     = (uint8_t)ledBrt;
  s.ledRgb        = server.arg("ledtype") != "mono";
  s.ledActiveLow  = server.hasArg("ledlow");
  s.ntfyHost      = host;
  s.ntfyPort      = (uint16_t)port;
  s.ntfyTls       = server.hasArg("tls");
  s.ntfyTopic     = topic;
  s.ntfyUser      = nuser;
  if (server.hasArg("nclear")) {
    s.ntfyUser  = "";
    s.ntfyPass  = "";
    s.ntfyToken = "";
  }
  if (!npass.isEmpty()) s.ntfyPass  = npass;
  if (!token.isEmpty()) s.ntfyToken = token;

  // settings_save() persists g_settings, so swap the copy in and roll back if
  // the write fails.
  Settings previous = g_settings;
  g_settings = s;
  if (!settings_save()) {
    g_settings = previous;
    sendForm("Could not write to flash.");
    return;
  }
  savedFlag = true;
  // The stored copy came from the old URL; make the next boot download.
  if (urlChanged) blocklist::forgetSnapshot();

  String where = sip.isEmpty() ? String("its DHCP address") : "<b>" + htmlEscape(sip) + "</b>";
  String p = FPSTR(PAGE_HEAD);
  p += "<h1>Saved</h1><p>Restarting. The device will join <b>" + htmlEscape(ssid) +
       "</b> on " + where + " and announce itself on your ntfy topic.</p>";
  server.send(200, "text/html", p);

  delay(1500);       // let the response actually reach the browser
  ESP.restart();
}

void sendStatus(const String& note, bool good) {
  String p = FPSTR(PAGE_HEAD);
  p += nav();
  p += "<h1>AdBlocker status</h1>";
  if (!note.isEmpty()) p += String("<div class=") + (good ? "ok" : "err") + ">" +
                            htmlEscape(note) + "</div>";
  p += "<pre>" + htmlEscape(commands::statusReport()) + "</pre>";

  p += "<form method=POST action=/action>";
  p += "<label>Domain</label><input type=text name=domain placeholder='ads.example.com'>";
  p += "<div class=btns><button name=op value=check>Check</button>"
       "<button name=op value=block>Block</button>"
       "<button name=op value=unblock>Unblock</button></div>";
  p += "<div class=btns><button name=op value=reload>Reload list</button>";
  p += blocklist::enabled() ? "<button name=op value=off>Turn blocking off</button>"
                            : "<button name=op value=on>Turn blocking on</button>";
  p += "<button name=op value=reboot onclick=\"return confirm('Reboot now?')\">Reboot</button>"
       "</div></form>";
  p += "<p><small>Blocks and unblocks are kept in a custom list in flash and survive "
       "reloads and reboots.</small></p>";
  server.send(200, "text/html", p);
}

void handleStatus() {
  if (!authorized()) return;
  sendStatus("", true);
}

void handleAction() {
  if (!authorized()) return;
  String op = server.arg("op");
  String domain = trimmedArg("domain");

  if (op == "check" || op == "block" || op == "unblock") {
    if (domain.isEmpty()) { sendStatus("Enter a domain first.", false); return; }
    if (op == "check") {
      String via;
      bool hit = blocklist::explain(domain, via);
      String msg = domain + (hit ? " IS blocked" : " is NOT blocked");
      if (!via.isEmpty() && via != domain) msg += hit ? " (via " + via + ")" : " (you allowed " + via + ")";
      sendStatus(msg + ".", true);
      return;
    }
    blocklist::Edit r = op == "block" ? blocklist::block(domain) : blocklist::unblock(domain);
    bool ok = r == blocklist::Edit::Ok;
    sendStatus(ok ? domain + (op == "block" ? " is now blocked." : " is now allowed.")
                  : domain + ": " + blocklist::editMessage(r) + ".",
               ok);
  } else if (op == "reload") {
    bool ok = blocklist::requestReload("web request");
    sendStatus(ok ? "Downloading. Refresh this page to follow progress."
                  : "A download is already running.", ok);
  } else if (op == "on" || op == "off") {
    blocklist::setEnabled(op == "on");
    sendStatus(op == "on" ? "Blocking is on." : "Blocking is off until turned on or reboot.", true);
  } else if (op == "reboot") {
    String p = FPSTR(PAGE_HEAD);
    p += "<h1>Rebooting</h1><p>Back in a few seconds.</p>";
    server.send(200, "text/html", p);
    delay(500);
    scheduler::restart("web request");
  } else {
    sendStatus("Unknown action.", false);
  }
}

// ---- dashboard, query log, local DNS --------------------------------------

String tile(const String& label, const String& value) {
  return "<div class=tile>" + htmlEscape(label) + "<b>" + htmlEscape(value) + "</b></div>";
}

String topTable(const char* title, querylog::TopOf what, bool linkNames) {
  querylog::TopRow rows[10];
  int n = querylog::top(what, rows, 10);
  String p = String("<h2>") + title + "</h2>";
  if (!n) return p + "<small>nothing yet</small>";
  p += "<table>";
  for (int i = 0; i < n; i++) {
    String key = htmlEscape(rows[i].key);
    String cell = linkNames ? "<a href='/log?q=" + key + "'>" + key + "</a>"
                            : "<a href='/log?client=" + key + "'>" + key + "</a>";
    p += "<tr><td>" + cell + "</td><td>" + String(rows[i].count) + "</td></tr>";
  }
  return p + "</table>";
}

// Last 24 hours as an inline SVG bar chart: total queries, blocked on top.
String hourChart() {
  querylog::Hour h[24];
  int n = querylog::hours(h, 24);
  uint32_t peak = 1;
  for (int i = 0; i < n; i++) peak = max(peak, h[i].queries);
  String svg = "<svg viewBox='0 0 240 80' width='100%' preserveAspectRatio='none' "
               "style='background:#1c1c1c;border-radius:4px'>";
  for (int i = 0; i < n; i++) {
    int x = (n - 1 - i) * 10;   // oldest on the left
    int hq = (int)(h[i].queries * 76 / peak);
    int hb = (int)(h[i].blocked * 76 / peak);
    svg += "<rect x='" + String(x + 1) + "' y='" + String(78 - hq) + "' width='8' height='" +
           String(hq) + "' fill='#357'/>";
    svg += "<rect x='" + String(x + 1) + "' y='" + String(78 - hb) + "' width='8' height='" +
           String(hb) + "' fill='#c55'/>";
  }
  return svg + "</svg><small>Last 24 h, one bar per hour: blue all queries, red blocked. "
               "Peak " + String(peak) + "/h.</small>";
}

void handleStats() {
  if (!authorized()) return;
  sinkhole::Stats d = sinkhole::stats();
  String p = FPSTR(PAGE_HEAD);
  p += "<body class=wide>" + nav() + "<h1>Dashboard</h1>";
  uint32_t pct = d.queries ? (uint32_t)((uint64_t)d.blocked * 100 / d.queries) : 0;
  p += "<div class=tiles>" + tile("Queries", String(d.queries)) +
       tile("Blocked", String(d.blocked) + " (" + String(pct) + "%)") +
       tile("Cached", String(d.cached)) + tile("Forwarded", String(d.forwarded)) +
       tile("Local", String(d.local)) + tile("Failed", String(d.failed)) + "</div>";
  p += "<small>Since the last reboot. Upstream: " + htmlEscape(sinkhole::upstreamStatus()) +
       "</small>";
  p += "<h2>Today</h2>" + hourChart();
  p += topTable("Top blocked", querylog::TopOf::BlockedNames, true);
  p += topTable("Top allowed", querylog::TopOf::AllowedNames, true);
  p += topTable("Top clients", querylog::TopOf::Clients, false);
  p += "<p><small>Top lists cover the last " + String(querylog::size()) +
       " queries. They reset on every reboot, the daily one included.</small></p>";
  server.send(200, "text/html", p);
}

struct LogFilter {
  String client;
  String q;
  bool   blockedOnly;
};

bool logMatch(const querylog::Entry& e, void* ctx) {
  const LogFilter& f = *(const LogFilter*)ctx;
  if (f.blockedOnly && !querylog::isBlockedKind(e.kind)) return false;
  if (!f.q.isEmpty() && strstr(e.name, f.q.c_str()) == nullptr) return false;
  if (!f.client.isEmpty() && querylog::clientStr(e) != f.client) return false;
  return true;
}

const char* typeName(uint16_t t) {
  switch (t) {
    case 1: return "A"; case 2: return "NS"; case 5: return "CNAME"; case 6: return "SOA";
    case 12: return "PTR"; case 15: return "MX"; case 16: return "TXT"; case 28: return "AAAA";
    case 33: return "SRV"; case 64: return "SVCB"; case 65: return "HTTPS";
  }
  return "?";
}

void handleLog() {
  if (!authorized()) return;
  LogFilter f;
  f.client = trimmedArg("client");
  f.q = trimmedArg("q");
  f.q.toLowerCase();
  f.blockedOnly = server.arg("blocked") == "1";

  const int MAX = 200;
  querylog::Entry* rows = (querylog::Entry*)ps_malloc(MAX * sizeof(querylog::Entry));
  int n = rows ? querylog::recent(rows, MAX, logMatch, &f) : 0;

  String p = FPSTR(PAGE_HEAD);
  p += "<body class=wide>" + nav() + "<h1>Query log</h1>";
  p += "<form method=GET action=/log class=row><div><input type=text name=q placeholder='name contains' "
       "value='" + htmlEscape(f.q) + "'></div><div><input type=text name=client placeholder='client IP' "
       "value='" + htmlEscape(f.client) + "'></div><div><label><input type=checkbox name=blocked value=1" +
       String(f.blockedOnly ? " checked" : "") + "> blocked only</label></div>"
       "<div><button class=mini>Filter</button></div></form>";
  p += "<small>Newest first, " + String(n) + " shown of " + String(querylog::size()) +
       " kept. Cleared on reboot.</small><table><tr><th>time</th><th>client</th><th>type</th>"
       "<th>name</th><th>result</th><th>ms</th><th></th></tr>";
  for (int i = 0; i < n; i++) {
    const querylog::Entry& e = rows[i];
    char when[12] = "-";
    if (e.when) {
      time_t t = e.when;
      struct tm l;
      localtime_r(&t, &l);
      strftime(when, sizeof(when), "%H:%M:%S", &l);
    }
    bool blocked = querylog::isBlockedKind(e.kind);
    const char* cls = blocked ? "b" : e.kind == querylog::Kind::Failed ? "f" : "c";
    String name = htmlEscape(e.name);
    String client = htmlEscape(querylog::clientStr(e));
    p += String("<tr><td>") + when + "</td><td><a href='/log?client=" + client + "'>" + client +
         "</a></td><td>" + typeName(e.qtype) + "</td><td>" + name + "</td><td class=" + cls + ">" +
         querylog::kindName(e.kind) + "</td><td>" + String(e.ms) + "</td><td>"
         "<form method=POST action=/action style=margin:0><input type=hidden name=domain value='" +
         name + "'><button class=mini name=op value=" + (blocked ? "unblock>allow" : "block>block") +
         "</button></form></td></tr>";
  }
  p += "</table>";
  free(rows);
  server.send(200, "text/html", p);
}

void sendLocal(const String& note, bool good) {
  String p = FPSTR(PAGE_HEAD);
  p += nav() + "<h1>Local DNS</h1>";
  if (!note.isEmpty()) p += String("<div class=") + (good ? "ok" : "err") + ">" + htmlEscape(note) + "</div>";
  p += "<form method=POST action=/local><label>One IPv4 address and one or more names per line"
       "</label><textarea name=hosts rows=12 placeholder='192.168.0.10  nas  nas.lan'>" +
       htmlEscape(localdns::text()) + "</textarea><button>Save</button></form>";
  p += "<small>Answered by this device directly, including the reverse (PTR) lookup. "
       "Up to " + String(DNS_LOCAL_RECORDS) + " names. # starts a comment.</small>";
  server.send(200, "text/html", p);
}

void handleLocal() {
  if (!authorized()) return;
  sendLocal("", true);
}

void handleLocalSave() {
  if (!authorized()) return;
  String t = server.arg("hosts");
  t.replace("\r", "");
  int records = 0, bad = 0;
  if (!localdns::save(t, records, bad)) { sendLocal("Could not write to flash.", false); return; }
  sendLocal(String(records) + " names saved" + (bad ? ", " + String(bad) + " lines skipped (not \"IP name\")" : String("")) + ".",
            bad == 0);
}

// Captive-portal probes (/generate_204, /hotspot-detect.html, /ncsi.txt ...)
// all land here. Answering them with a redirect is what makes phones pop the
// setup page on their own. AP mode only.
void handleNotFound() {
  if (!apMode) { handleStatus(); return; }
  server.sendHeader("Location", "http://" + WiFi.softAPIP().toString() + "/", true);
  server.send(302, "text/plain", "");
}

// Once only: the device can move between AP and STA several times per boot,
// and WebServer::on() appends rather than replaces.
void routes() {
  static bool done = false;
  if (done) return;
  server.on("/", HTTP_GET, handleRoot);
  server.on("/scan", HTTP_GET, handleScan);
  server.on("/save", HTTP_POST, handleSave);
  server.on("/status", HTTP_GET, handleStatus);
  server.on("/action", HTTP_POST, handleAction);
  server.on("/stats", HTTP_GET, handleStats);
  server.on("/log", HTTP_GET, handleLog);
  server.on("/local", HTTP_GET, handleLocal);
  server.on("/local", HTTP_POST, handleLocalSave);
  server.onNotFound(handleNotFound);
  done = true;
}

}  // namespace

void beginAP(bool requireAuth, bool captive) {
  stop();
  apMode     = true;
  authNeeded = requireAuth;

  // AP_STA rather than AP: in the fallback case the station side keeps
  // retrying in the background, so a router coming back brings the device
  // online without a reboot.
  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP(apSsid().c_str());
  delay(100);

  captiveOn = captive;
  if (captive) {
    captiveDns.setErrorReplyCode(DNSReplyCode::NoError);
    captiveDns.start(DNS_PORT, "*", WiFi.softAPIP());
  }

  routes();
  server.begin();
  running = true;

  Serial.printf("[web] AP \"%s\" up, portal at http://%s (auth %s)\n",
                apSsid().c_str(), WiFi.softAPIP().toString().c_str(),
                requireAuth ? "on" : "off");
}

void beginSTA() {
  stop();
  apMode     = false;
  authNeeded = true;

  routes();
  server.begin();
  running = true;

  Serial.printf("[web] settings page at http://%s\n",
                WiFi.localIP().toString().c_str());
}

void stop() {
  if (!running) return;
  server.stop();
  if (captiveOn) captiveDns.stop();
  captiveOn = false;
  running = false;
}

void tick() {
  if (!running) return;
  if (captiveOn) captiveDns.processNextRequest();
  server.handleClient();
}

bool isAP() { return apMode; }

String apSsid() {
  uint8_t mac[6];
  WiFi.macAddress(mac);
  char buf[28];
  snprintf(buf, sizeof(buf), "AdBlocker-Setup-%02X%02X", mac[4], mac[5]);
  return String(buf);
}

String ip() {
  return apMode ? WiFi.softAPIP().toString() : WiFi.localIP().toString();
}

String settingsUrl() { return "http://" + ip(); }

bool saved() { return savedFlag; }

}  // namespace webconfig
