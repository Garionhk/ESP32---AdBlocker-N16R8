# ESP32 AdBlocker (ESP32-S3 N16R8)

**English** | [繁體中文](README.zh-HK.md)

A Pi-hole-style, network-wide ad blocker on a single ESP32-S3 N16R8 board. Point your
router's DNS at it, and ads and trackers are blocked for every device on the network: phones,
TVs, consoles, anything that can't run an ad blocker of its own.

Allowed lookups are encrypted with **DNS-over-TLS**, and the upstream reply is passed back
unchanged: every record type, every address, CNAME chains and real TTLs. It reports to your
phone over [ntfy](https://ntfy.sh), takes commands from it, and reboots itself every night.

```
$ dig @192.168.0.254 doubleclick.net +short
0.0.0.0
$ dig @192.168.0.254 x.y.doubleclick.net +short
0.0.0.0
$ dig @192.168.0.254 example.com +short
172.66.147.243
104.20.23.154
```

## Features

| | |
|---|---|
| **Blocking** | up to 4 merged blocklists (HOSTS, Adblock `\|\|domain^` or plain), about 250,000 domains; the default Hagezi Pro list is 210,000. Subdomains are blocked with their parent, CNAME-cloaked trackers are caught, and your own block / allow list wins over the lists |
| **Resolving** | DNS-over-TLS to Cloudflare (or Quad9 / Google), falling back to plain DNS. Full relay of every record type, a 768-entry cache that honours TTLs, up to 64 lookups in flight, DNS over TCP, IPv4 and IPv6 |
| **Local network** | local names (`printer`, `nas.lan`, private reverse lookups) go to your router; a Local DNS page for your own `IP name` records |
| **Bypass guards** | switches off Firefox's DNS-over-HTTPS and iCloud Private Relay automatically, using their canary names |
| **Visibility** | web dashboard (24-hour chart, top blocked / allowed / clients), query log with filters and one-click block/allow, live status page |
| **Phone control** | ntfy messages with IP and status after boot, plus passphrase-protected commands: `status`, `top`, `check`, `block`, `unblock`, `reload`, `reboot` … |
| **Self-care** | daily reboot at a time and timezone you choose; blocklist re-downloaded daily and restored from flash in about 2 seconds after a reboot; failed downloads retried every 5 minutes |
| **Status LED** | the on-board WS2812 shows setup, blocking, downloading, no internet and failure at a glance |
| **No secrets in the binary** | WiFi, ntfy and passwords are set from a captive-portal web page and kept in NVS, so the same firmware file works for everyone |

## How it compares to Pi-hole

It covers what most households use Pi-hole for. What it can't match is scale.

| | Pi-hole on a Raspberry Pi | This board |
|---|---|---|
| Cost / power | a Pi, an SD card, ~3 W | a ~$10 board, under 1 W, no SD card |
| Blocklist size | millions of domains | ~250,000 |
| Regex rules | yes | no: exact names and subdomains |
| Query history | long-term database | last 6,000 queries, cleared on reboot; hourly totals kept for a week |
| DHCP server, DNSSEC validation | yes | no (the router does DHCP; Cloudflare validates) |
| Encrypted upstream | add-on (cloudflared / unbound) | built in |
| Phone notifications and commands | add-on | built in |

## Hardware

- **ESP32-S3 N16R8**: 16 MB flash, 8 MB octal PSRAM. The PSRAM is required; the blocklist,
  cache and query log live there. Tested on an ESP32-S3-DevKitC-1-style board.
- **2.4 GHz WiFi.** The ESP32 has no 5 GHz radio.
- **A fixed IP address** for the board, set as a static IP or a DHCP reservation, because every
  device will send its DNS queries to it.

## Quick start

### 1. Flash

Download from the [latest release](https://github.com/Garionhk/ESP32-AdBlocker-N16R8/releases/latest):

| File | Use it when |
|---|---|
| `adblocker-v1.0.3-esp32s3-n16r8.bin` | first install, connected through the board's **UART** port or a USB-serial adapter (CP2102, CH343, FTDI) |
| `adblocker-v1.0.3-esp32s3-n16r8-usbcdc.bin` | first install, connected through the board's **native USB** port |
| `…-app.bin` / `…-usbcdc-app.bin` | updating a board that already runs it. Keeps settings and the blocklist |

The two builds differ only in which port the serial log comes out of. Both block the same.

```bash
pip install esptool
```

First install (writes the whole flash):

```bash
esptool --port /dev/cu.usbserial-XXXX --baud 921600 write-flash 0x0 adblocker-v1.0.3-esp32s3-n16r8.bin
```

Update (application only):

```bash
esptool --port /dev/cu.usbserial-XXXX --baud 921600 write-flash 0x10000 adblocker-v1.0.3-esp32s3-n16r8-app.bin
```

To build it yourself instead, see [Building](#building).

### 2. Set it up

1. Join the WiFi network **`AdBlocker-Setup-XXXX`** from your phone. **Turn mobile data off
   first**, or the phone may leave a network with no internet before the page loads.
2. The setup page opens by itself, or go to **http://192.168.4.1**.
3. Fill in your WiFi, ntfy topic and two passwords, then tap **Save & restart**.

| Section | Fields |
|---|---|
| WiFi | network (from a live scan) and password |
| Address | static IP, gateway, subnet. Leave all three blank for DHCP |
| Upstream DNS | plain servers (default `1.1.1.1` / `1.0.0.1`), DNS-over-TLS and its server, local names to the router, IPv6 |
| Blocklist | up to 4 URLs, daily refresh hour, subdomain blocking, Firefox / iCloud switch-off |
| Daily reboot | on/off, time, timezone |
| Status LED | GPIO (0 = none), WS2812 or single colour, brightness |
| ntfy | server, port, TLS, topic, and an optional login or token |
| Passwords | a command passphrase for ntfy, and an admin password for the web pages (user `admin`) |

### 3. It reports in

Your ntfy topic gets:

```
AdBlocker online
ESP32 AdBlocker v1.0.0
ip 192.168.0.254 (static)
gw 192.168.0.1
upstream DNS-over-TLS, connected to one.one.one.one; fallback 1.1.1.1 / 1.0.0.1
wifi home (-57 dBm)
settings http://192.168.0.254
blocklist 53,172 domains, downloaded 1h 10m ago (from flash)
blocking on
queries 243, blocked 109 (44%), cached 19
up 5m, last reset: power on
time 2026-10-25 17:27 PDT
next reboot 04:00 PDT, list refresh 03:00
ntfy connected
heap 109 KB, psram 136 KB free
```

On a DHCP address it also shows the MAC to reserve in your router. On the first boot the
blocklist downloads in the background (about 20 seconds for the default Hagezi Pro list), and a
second message reports the result.

### 4. Point your network at it

In your router's DHCP settings, set the **DNS server** to the board's IP, as the **only** DNS
server. A second one such as `8.8.8.8` would let devices skip the blocker. Devices pick it up
when they reconnect.

Test from a computer before changing anything:

```bash
dig @192.168.0.254 doubleclick.net
```

`0.0.0.0` means it's blocking.

Then read [How well it blocks](#how-well-it-blocks) for what to expect and how to tighten it.

## How well it blocks

It blocks as well as Pi-hole does with the same list, because both work the same way: by
refusing to look up ad and tracker domains. How much that catches depends on **which list you
use** and on **what can go around DNS**, not on the board.

### What it blocks well, and what it can't

| Blocks well | Can't block (no DNS blocker can) |
|---|---|
| third-party ad networks and trackers (DoubleClick, ad exchanges, analytics) | **YouTube ads**: they come from the same servers as the videos |
| in-app ads in many free apps and games | **Facebook, Instagram, TikTok** sponsored posts, **Twitch** and **Spotify** ads |
| smart TV, console and IoT telemetry; ad tiles on TV home screens | any ad served from the site's own domain |
| malware, phishing and scam domains (with the default list) | the empty box a blocked ad can leave behind |

Rough expectations: **smart TVs, apps and games** see the biggest difference, since they can't run
an ad blocker of their own. **Web browsing** loses most banner and tracker ads; with a browser
blocker on top, nearly all. **YouTube and social feeds** barely change.

### Your options

None of these need code changes. Pick what suits your household.

| Option | Where | Effect |
|---|---|---|
| **Choose a list** | Settings → Blocklist | Hagezi Multi PRO (default) is strong with few false positives. Hagezi Multi NORMAL is gentler; StevenBlack is conservative. See [Blocklists](#blocklists) |
| **Block encrypted-DNS bypass** | add a second URL in Settings → Blocklist | stops apps and browsers going around the board with their own encrypted DNS (see below) |
| **Turn off Chrome's "Use secure DNS"** | Chrome settings on each device | or set it to "your current provider". Firefox's equivalent and iCloud Private Relay are switched off for you |
| **Android "Private DNS"** | phone settings | leave it on *Automatic* or *Off*. A named provider (e.g. `dns.google`) goes around the board |
| **Close the DNS back door** | router firewall, if it has one | block outgoing ports 53 and 853 from every device except the board. Catches devices with hard-coded DNS, such as some Chromecasts, Android TVs and apps |
| **IPv6 DNS** | router | hand out the board's IPv6 address as the IPv6 DNS server, or turn IPv6 DNS off, so devices can't fall back to another server |
| **A browser blocker** | each computer's browser | uBlock Origin handles what DNS can't: YouTube, cosmetic clean-up, same-site ads |
| **Unblock what breaks** | ntfy `unblock <domain>`, or **allow** in the Query log | the most specific entry wins, so one exception doesn't open up the whole domain |

**Encrypted-DNS bypass lists** (paste one as an extra line under Blocklist URLs):

| List | Entries | Blocks |
|---|---|---|
| `https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/doh.txt` | ~3,300 | public DNS-over-HTTPS / DNS-over-TLS servers only |
| `https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/doh-vpn-proxy-bypass.txt` | ~16,000 | the above **plus VPNs, Tor and proxies**. Skip it if anyone at home needs a VPN |

These lists include Cloudflare's `one.one.one.one`, the board's own DoT server, but that's
fine. The board looks up its upstream directly, not through its own blocklist, so only your
devices lose the ability to go around it.

### Measure it

Open **https://d3ward.github.io/toolz/adblock** on a device that uses the board, with the
browser's own ad blocker turned off. It gives a score you can compare before and after
changing lists.

## Capacity

**About 1–10 people, or 50–80 devices, without noticeable delays.** A household averages under
one query a second, with page-load bursts of 10–30 lookups at once; the board has a wide margin
on both. These numbers come from `tools/dnsload.py` run against the test board over WiFi, with
Hagezi Pro loaded and DNS-over-TLS on (v1.0.3):

| Load | Clean (no loss) up to | Beyond that |
|---|---|---|
| Burst, all arriving at once | **20 queries** (blocked, cached and upstream alike) | 50 at once: 6–24% lost; 100+: 30–50% |
| Steady, blocked names | **800 / s** | 1,600 / s: 34% lost |
| Steady, cached names | **400 / s** | 800 / s: 4% lost |
| Steady, upstream lookups | **400 / s** without loss | above ~200 / s, about 5% fall back to plain DNS after 0.9 s |

Typical answer times: **7 ms** blocked or cached, **20–25 ms** upstream.

Where the limits come from:
- **Bursts above ~50 at once** are lost in the ESP32 core's own network buffers (its 32-deep
  input queue and the WiFi driver's receive buffers). They're compiled into the core, so this
  firmware can't raise them. A single home rarely sends that many at the same instant.
- **DNS-over-TLS** is one encrypted connection. Above ~200 new lookups a second it can't keep
  up, and the overflow is answered over plain DNS a moment later.

Versions before 1.0.3 received through ordinary sockets, whose queue holds only **6 packets**.
There, a burst of 10 lost 4 and a burst of 20 lost 14, so a busy page could stall for a second
while lookups retried. Upgrade if you're on 1.0.2 or earlier.

**Measure your own** (it sends real queries; use it only on your own network):

```bash
python3 tools/dnsload.py 192.168.0.254 burst blocked
```

```bash
python3 tools/dnsload.py 192.168.0.254 rate cached --rates 100,200,400
```

`burst` sends N queries back to back; `rate` holds a steady rate for 5 s. `blocked`, `cached`
and `uncached` (fresh names that must go upstream) choose what's being asked. Run the same burst
against your router for comparison.

## Using it

### Web pages

Browse to the board's IP and log in as `admin`.

| Page | What's on it |
|---|---|
| **Status** | the status report; check, block, unblock, reload, on/off, reboot |
| **Dashboard** | totals, a 24-hour chart, top blocked, top allowed, top clients |
| **Query log** | the last 6,000 queries: time, device, type, name, result, latency. Filter by name, device or blocked only; block or allow from any row |
| **Local DNS** | your own `IP name` records, with reverse lookups |
| **Settings** | everything from the setup form |

The query log and top lists are kept in RAM and start empty after every reboot, the daily one
included. The hourly totals behind the chart survive the daily reboot (RTC memory), but not a
power cut.

### ntfy commands

Send them to your topic, each starting with your command passphrase, e.g. `sekret status`.

| Command | Aliases | What it does |
|---|---|---|
| `help` | `?` | the command list |
| `status` | `stat` | the report shown above |
| `stats` | | counts and the last 10 blocked names |
| `top` | | the most blocked names and the busiest devices |
| `check <domain>` | | is it blocked, and by which entry (`via doubleclick.net`) |
| `block <domain>` | | add to your own list (it must resolve, which catches typos) |
| `unblock <domain>` | `allow` | let it through, even when a parent is blocked |
| `on` / `off` | | pause blocking until `on` or the next reboot |
| `reload` | `refresh` | download the blocklists now |
| `clearcustom` | | forget everything you blocked or allowed |
| `reboot` | `restart` | restart now |
| `factoryreset` | | wipe settings and reboot into setup (keeps the blocklist) |

A message without the right passphrase gets no reply at all, and no reply ever repeats the
passphrase. Use a long, random topic name: on public ntfy.sh, the topic name is the only
thing keeping strangers out.

### Status LED

The on-board WS2812 is on **GPIO 48** on ESP32-S3-DevKitC-1 v1.0 boards and **GPIO 38** on
v1.1; set it on the settings page (0 = no LED). A single-colour LED also works.

| Colour | Pattern | Meaning |
|---|---|---|
| Yellow | slow blink | setup portal, or WiFi down |
| Green | steady | blocking normally |
| Blue | medium blink | downloading the blocklist (not blocking for those seconds) |
| Purple | fast flashing | last download couldn't reach the internet; retrying every 5 minutes |
| Teal | very slow blink | last download failed; still blocking with the previous list |
| Red | fast blink | no blocklist at all, nothing is blocked |

## How it works

### Name matching

- **Subdomains go with their parent** (on by default): with `doubleclick.net` listed,
  `ads.doubleclick.net` is blocked too. A leading `www.` is always ignored. Turn it off for
  exact, hosts-file-style matching.
- **The most specific entry wins.** `unblock cdn.example.com` allows that name even while
  `example.com` stays blocked.
- **CNAMEs are checked.** An allowed name that turns out to be an alias for a blocked one is
  blocked too. The log shows `blocked (CNAME)`.
- **Local names go to your router** (`printer`, `*.lan`, `*.home`, `*.home.arpa`,
  `*.internal`, private reverse lookups), never to the public resolver. Queries from the
  router itself are never sent back to it, so there's no loop.
- **`.local`** is never forwarded (it's mDNS), and **`localhost`** is always `127.0.0.1`.

### Upstream

Allowed lookups try DNS-over-TLS first. If it's down or doesn't answer within 0.9 s, they go
to the plain servers, so DNS keeps working, just unencrypted for those lookups. The status
report always says which path is in use.

- The TLS connection is kept open with a tiny query every 7 s, because Cloudflare drops idle
  connections after about 10 s.
- DoT steps aside for the ~20 s daily blocklist download: the chip's internal RAM only fits
  so many TLS connections at once.
- Replies too big for UDP are sent with the truncated flag, and the client retries over TCP.

### Blocklists

Each list can be HOSTS (`0.0.0.0 ads.example.com`), Adblock (`||ads.example.com^`) or one
name per line. Adblock rules with options, paths, wildcards or `@@` exceptions are skipped,
since DNS can't apply them.

| List | Size | URL |
|---|---|---|
| **Hagezi Multi PRO** (default) | 210,000, 3.8 MB | `https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt` |
| Hagezi Multi NORMAL (gentler) | smaller | `https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/multi.txt` |
| StevenBlack unified (conservative) | 53,000, 1.3 MB | `https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts` |
| StevenBlack + fakenews + gambling | larger | `https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling/hosts` |

The board has about 4.9 MB for names, roughly 250,000 domains at a typical 18 characters.
Combined lists that need more are truncated, and the load message says `TRUNCATED`.

**Hagezi lists need subdomain matching** (on by default). They list
`g.doubleclick.net`, not each of `pubads.g.doubleclick.net`, `securepubads.g.doubleclick.net` …
With matching off, most of Google's ad hosts would get through.

**Google click-through links are left open by Hagezi on purpose.** `ad.doubleclick.net` and
`googleadservices.com` are what you pass through when you *tap* a sponsored Google result or an
ad link in an email, so blocking them breaks those links. The ads themselves still don't load.
StevenBlack does block them. To block them anyway:
`<passphrase> block ad.doubleclick.net`, then `block googleadservices.com`.

**Upgrading from v1.0.0?** The default only applies to new installs and factory resets. A board
that's already set up keeps its saved URL, so change it on the Settings page.

- **Lists are fetched daily** at the refresh hour (03:00 by default), and at boot if the saved
  copy is over 24 h old.
- **A download only replaces the list once the server has answered,** so an attempt with no
  internet changes nothing. A failure partway through restores the previous list from flash.
- **Nothing is blocked while a download is sorting,** which takes about 20 seconds for Hagezi Pro.

### Daily reboot

On by default at 04:00 local time. Any POSIX TZ string works.

- **Short outage:** DNS is down for a few seconds while it restarts; devices retry and don't
  notice.
- **Reason recorded:** `last reset` reads `daily reboot` after a planned restart, and the
  hardware reason (`crash (panic)`, `brownout`, `power on`) after anything else.
- **Never mid-download:** it won't reboot during a download.
- **Clock required:** it needs the clock from NTP before it can reboot on schedule.
- **Avoid 01:00–03:00:** daylight-saving changes skip or repeat that hour.

## Changing settings later

| Situation | What to do |
|---|---|
| Board is online | browse to its IP, log in as `admin` |
| WiFi is down | it opens `AdBlocker-Setup-XXXX` (http://192.168.4.1, admin login) and keeps retrying every 10 s |
| Moved house, or forgot the admin password | press **EN**, release, then **hold BOOT** for 2 s: the setup portal opens with no login |
| From anywhere | `<passphrase> factoryreset` over ntfy |

If it won't join WiFi, the serial log (115200 baud) lists every 2.4 GHz network in range and
says whether yours is among them, which separates a typo, a 5 GHz-only network and a wrong
password.

## Building

[arduino-cli](https://arduino.github.io/arduino-cli/) with the ESP32 core 3.1.1 or newer
(tested with 3.3.10) and ArduinoJson:

```bash
arduino-cli core install esp32:esp32
```

```bash
arduino-cli lib install ArduinoJson
```

```bash
arduino-cli compile --fqbn "esp32:esp32:esp32s3:FlashSize=16M,PSRAM=opi,PartitionScheme=custom" --export-binaries ESP32-AdBlocker
```

Add `,CDCOnBoot=cdc` to the FQBN for a board on its native USB port.
`PartitionScheme=custom` uses the sketch's own [`partitions.csv`](ESP32-AdBlocker/partitions.csv):
a 4 MB app slot and 12 MB of LittleFS for the saved blocklist, your lists and local records.
[flash.md](flash.md) covers building shareable binaries and flashing them.

### Tests

The pure logic is covered by 265 native checks that need no board. They cover DNS packet
handling (compression, pointer loops, overruns, TTL ageing, CNAMEs), blocklist parsing, the
settings round-trip and validation, reboot timing across both DST changes, LED states, local
DNS parsing, and every ntfy command, including the passphrase gate.

```bash
./test/run.sh
```

### Source map

| File | Role |
|---|---|
| `ESP32-AdBlocker.ino` | boot flow; setup / fallback / online states |
| `sinkhole.cpp` | the DNS server: decide, answer or relay; UDP and TCP, IPv4 and IPv6 |
| `dnsmsg.h` | DNS wire format: parse, walk records, build replies, classify names |
| `dnscache.cpp` | reply cache in PSRAM |
| `dot.cpp` | DNS-over-TLS proxy on the loopback interface |
| `blocklist.cpp`, `blparse.h` | PSRAM blocklist, downloads, flash snapshot, your block / allow list |
| `querylog.cpp` | query log, hourly totals, top lists |
| `localdns.cpp`, `localrec.h` | local DNS records |
| `webconfig.cpp` | setup portal and web pages |
| `ntfy.cpp`, `commands.cpp` | ntfy stream, publishing, command handling |
| `scheduler.cpp`, `schedule.h` | daily reboot, daily refresh, reset reason |
| `led.cpp`, `ledstate.h` | status LED |
| `settings.cpp`, `config.h` | settings in NVS; tunables |
| `tools/dnsload.py` | load tester (runs on your computer) |

## Credits and license

The blocklist engine and the original DNS responder come from
[s60sc/ESP32_AdBlocker](https://github.com/s60sc/ESP32_AdBlocker) (s60sc and dateno1), under the
AGPL-3.0. This project is therefore released under the **[AGPL-3.0](LICENSE)** too. If you run
a modified version as a network service, you must offer its source to its users.

Default blocklist: [Hagezi DNS blocklists](https://github.com/hagezi/dns-blocklists). Also
supported: [StevenBlack/hosts](https://github.com/StevenBlack/hosts).
