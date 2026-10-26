#pragma once

// Tunables. Credentials live in NVS (settings.cpp), not here.

#define APP_NAME           "ESP32 AdBlocker"
#define APP_VERSION        "1.0.0"

// ---- Blocklist ----------------------------------------------------------
// Pointer table and domain arena both live in PSRAM. 400k pointers is 1.6 MB;
// a consolidated hosts file such as StevenBlack's is well under half that.
#define BL_MAX_DOMAINS        400000UL
#define BL_MAX_DOMAIN_LEN     100     // longer names in a list are skipped
#define BL_MAX_LINE           1024    // longest blocklist line processed
#define BL_PSRAM_RESERVE      (128 * 1024)   // left free after the arena
#define BL_MIN_ARENA          (2 * 1024 * 1024)
#define BL_READ_TIMEOUT_MS    10000UL  // download stalls longer than this abort
#define BL_SNAPSHOT_MAX_AGE_S (24UL * 3600)  // older snapshots trigger a download
#define BL_RETRY_INTERVAL_MS  (5UL * 60 * 1000)  // after a failed download
#define BL_MAX_LISTS          4       // blocklist URLs merged into one list
#define BL_MAX_ALLOW          1000    // names you can unblock (~100 KB PSRAM)
#define BL_RECENT_BLOCKED     10      // recently blocked names kept for "stats"
#define BL_SNAPSHOT_PATH      "/blsnap.bin"
#define BL_CUSTOM_PATH        "/custom.txt"
#define BL_TASK_STACK         (8 * 1024)
#define QUERYLOG_ENTRIES      6000    // ~100 B each in PSRAM; lost on reboot

// ---- DNS server ---------------------------------------------------------
#define DNS_PORT              53
#define DNS_CACHE_SLOTS       768     // whole replies, PSRAM
#define DNS_CACHE_MAX_REPLY   700     // bigger replies are relayed but not cached
#define DNS_CACHE_PROBE       4       // slots searched per lookup
#define DNS_CACHE_NEGATIVE_TTL_S 60   // NXDOMAIN with no SOA
#define DNS_CACHE_MAX_TTL_S   86400
#define DNS_MAX_PENDING       64      // upstream lookups in flight at once
#define DNS_UPSTREAM_TIMEOUT_MS 900   // per server attempt, then the next one
#define DNS_BLOCKED_TTL_S     10      // short, so an unblock takes effect fast
#define DNS_LOCAL_TTL_S       300     // localhost and local records
#define DNS_MAX_PACKET        1500    // client or upstream, UDP
#define DNS_TASK_STACK        (8 * 1024)
#define DNS_TASK_PRIORITY     3
#define DNS_TCP_CLIENTS       3       // concurrent TCP connections served
#define DNS_TCP_IDLE_MS       5000UL
#define DNS_LOCAL_RECORDS     128     // entries in your local DNS list
#define DNS_LOCAL_PATH        "/hosts.txt"

// ---- DNS-over-TLS -------------------------------------------------------
// A local proxy on the loopback interface turns the sinkhole's UDP queries
// into one long-lived TLS stream, so the sinkhole itself never blocks on TLS.
#define DOT_PROXY_PORT        5300
#define DOT_MIN_HEAP          90000   // bytes free before a TLS connect is tried
#define DOT_KEEPALIVE_MS      7000UL  // Cloudflare drops DoT idle for ~10 s
#define DOT_RECONNECT_MS      10000UL
#define DOT_TASK_STACK        (8 * 1024)

// ---- ntfy ---------------------------------------------------------------
// Server host, port, TLS, login and topic live in NVS -- they describe your
// deployment. Only behaviour tuning belongs here.

// ntfy sends a keepalive about every 45 s. If nothing at all arrives for this
// long the socket is presumed dead -- the usual failure mode for an always-on
// device is a TLS connection that stays "open" but never delivers again.
#define NTFY_STREAM_TIMEOUT_MS   90000UL

#define NTFY_RECONNECT_MIN_MS     1000UL   // first retry delay
#define NTFY_RECONNECT_MAX_MS    30000UL   // ceiling for exponential backoff

// Read timeout for the subscribe socket, in MILLISECONDS.
// NetworkClientSecure does not override setTimeout(), so this lands on
// Stream::setTimeout(), which is milliseconds -- not the seconds that
// NetworkClient::setTimeout() and setHandshakeTimeout() take. Passing seconds
// here means the header read gives up in ~15 ms and the status line comes back
// empty.
#define NTFY_SOCKET_TIMEOUT_MS    15000UL

// Tag stamped on every message this device publishes. Because commands and
// replies share one topic, the receive path uses this tag to ignore its own
// output and avoid a feedback loop.
#define NTFY_SELF_TAG      "adblock"

#define NTFY_DEDUP_SLOTS      8   // recently-seen message IDs remembered

// Longest incoming message body accepted. Anything larger is dropped rather
// than parsed, so a huge publish cannot exhaust the heap.
#define NTFY_MAX_LINE      2048

// ---- Scheduler ----------------------------------------------------------
// The daily reboot only fires once the device has been up this long, so the
// boot that follows a 04:00 reboot cannot match 04:00 again and loop.
#define REBOOT_MIN_UPTIME_MS     120000UL

// ---- Networking ---------------------------------------------------------
#define WIFI_CONNECT_TIMEOUT_MS  30000UL
#define WIFI_RETRY_INTERVAL_MS   10000UL
#define NTP_SERVER_1       "pool.ntp.org"
#define NTP_SERVER_2       "time.nist.gov"
#define NTP_SYNC_TIMEOUT_MS      30000UL

// How long after a reset the BOOT button is watched for, to force the setup
// portal. It has to be pressed AFTER releasing EN: GPIO0 held low through the
// reset itself puts the ESP32 into its serial bootloader instead.
#define BOOT_WINDOW_MS            2000UL

// TLS certificate validation compares against the clock, so the device must
// know roughly what year it is before the first connection. Anything past
// 2024-01-01 means NTP has replied.
#define NTP_MIN_VALID_EPOCH   1704067200UL

// ---- Debug --------------------------------------------------------------
#define SERIAL_BAUD        115200

// Log every DNS decision to serial. Noisy: a household makes several queries
// a second.
// #define DNS_VERBOSE

// Uncomment to skip TLS certificate verification. Debugging only -- the
// passphrase travels over this connection.
// #define NTFY_TLS_INSECURE
