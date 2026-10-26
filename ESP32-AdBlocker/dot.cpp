#include <Arduino.h>
#include <NetworkClientSecure.h>
#include <WiFi.h>
#include <freertos/idf_additions.h>

#include "config.h"
#include "dnsmsg.h"
#include "dot.h"
#include "settings.h"
#include "sinkhole.h"

extern const uint8_t x509_crt_bundle_start[] asm("_binary_x509_crt_bundle_start");
extern const uint8_t x509_crt_bundle_end[]   asm("_binary_x509_crt_bundle_end");

namespace dot {
namespace {

TaskHandle_t task = nullptr;
volatile bool connectedFlag = false;
volatile bool pausedFlag = false;
volatile uint32_t lastConnectMs = 0;
volatile int  failures = 0;

// Queries from the sinkhole, waiting to go out on the TLS stream. In PSRAM:
// each slot holds a whole packet.
struct Query {
  uint16_t len;
  uint8_t  data[DNS_MAX_PACKET];
};
QueueHandle_t queries = nullptr;

// Reads exactly n bytes from the TLS stream, or gives up after timeoutMs.
bool readExact(NetworkClientSecure& c, uint8_t* buf, size_t n, uint32_t timeoutMs) {
  size_t got = 0;
  uint32_t start = millis();
  while (got < n) {
    if (!c.connected()) return false;
    int a = c.available();
    if (a > 0) {
      int r = c.read(buf + got, min((size_t)a, n - got));
      if (r > 0) got += r;
      continue;
    }
    if (millis() - start > timeoutMs) return false;
    vTaskDelay(1);
  }
  return true;
}

bool writeFrame(NetworkClientSecure& c, const uint8_t* q, int len) {
  uint8_t frame[2 + DNS_MAX_PACKET];
  if (len > DNS_MAX_PACKET) return false;
  dnsmsg::wr16(frame, (uint16_t)len);
  memcpy(frame + 2, q, len);
  return c.write(frame, len + 2) == (size_t)(len + 2);
}

void proxyTask(void*) {
  NetworkClientSecure* tls = new NetworkClientSecure();
  tls->setCACertBundle(x509_crt_bundle_start, x509_crt_bundle_end - x509_crt_bundle_start);
  tls->setHandshakeTimeout(8);

  uint8_t  buf[DNS_MAX_PACKET];
  uint32_t lastActivity = millis();
  uint16_t keepaliveId = 0;
  uint32_t connectedAt = 0, framesOut = 0, framesIn = 0;

  for (;;) {
    bool want = g_settings.dotEnabled && !pausedFlag && WiFi.status() == WL_CONNECTED &&
                time(nullptr) > (time_t)NTP_MIN_VALID_EPOCH;   // TLS needs the date

    if (connectedFlag && (!want || !tls->connected())) {
      tls->stop();
      connectedFlag = false;
      if (want) {
        Serial.printf("[dot] connection closed after %lu s, %lu queries / %lu replies\n",
                      (unsigned long)((millis() - connectedAt) / 1000), (unsigned long)framesOut,
                      (unsigned long)framesIn);
      } else {
        Serial.println("[dot] paused");
      }
    }

    if (want && !connectedFlag && millis() - lastConnectMs > DOT_RECONNECT_MS &&
        ESP.getFreeHeap() > DOT_MIN_HEAP) {
      lastConnectMs = millis();
      if (tls->connect(g_settings.dotHost.c_str(), g_settings.dotPort)) {
        connectedFlag = true;
        connectedAt = millis();
        framesOut = framesIn = 0;
        failures = 0;
        lastActivity = millis();
        Serial.printf("[dot] connected to %s:%u, heap %u\n", g_settings.dotHost.c_str(),
                      (unsigned)g_settings.dotPort, (unsigned)ESP.getFreeHeap());
      } else {
        failures = failures + 1;
        char err[80] = "";
        tls->lastError(err, sizeof(err));
        Serial.printf("[dot] connect to %s failed (%s) -- using plain DNS\n",
                      g_settings.dotHost.c_str(), err);
        tls->stop();
      }
    }

    // Queries from the sinkhole. One that can't go out is dropped; the
    // sinkhole times out and moves on to the plain servers.
    static Query q;
    for (int i = 0; i < 16 && xQueueReceive(queries, &q, 0) == pdTRUE; i++) {
      if (!connectedFlag) continue;
      framesOut++;
      if (!writeFrame(*tls, q.data, q.len)) {
        Serial.println("[dot] write failed");
        tls->stop();
        connectedFlag = false;
        break;
      }
      lastActivity = millis();
    }

    // Replies, in whatever order the server sends them; the IDs match them up.
    while (connectedFlag && tls->available() >= 2) {
      uint8_t lenb[2];
      if (!readExact(*tls, lenb, 2, 2000)) { tls->stop(); connectedFlag = false; break; }
      uint16_t len = dnsmsg::rd16(lenb);
      if (len > sizeof(buf) || !readExact(*tls, buf, len, 2000)) {
        Serial.println("[dot] bad frame, reconnecting");
        tls->stop();
        connectedFlag = false;
        break;
      }
      lastActivity = millis();
      framesIn++;
      if (len >= dnsmsg::HEADER && dnsmsg::id(buf) == keepaliveId && keepaliveId) continue;
      sinkhole::fromDot(buf, len);
    }

    // Servers hang up idle connections. A tiny query now and then keeps it
    // open, so a real query never waits for a fresh handshake.
    if (connectedFlag && millis() - lastActivity > DOT_KEEPALIVE_MS) {
      uint8_t q[64];
      keepaliveId = (uint16_t)(esp_random() | 1);
      int n = dnsmsg::makeQuery(q, sizeof(q), keepaliveId, g_settings.dotHost.c_str(), dnsmsg::T_A);
      if (n && !writeFrame(*tls, q, n)) { tls->stop(); connectedFlag = false; }
      lastActivity = millis();
    }

    vTaskDelay(pdMS_TO_TICKS(2));
  }
}

}  // namespace

void begin() {
  if (task || !g_settings.dotEnabled) return;
  queries = xQueueCreateWithCaps(DOT_QUEUE_SLOTS, sizeof(Query), MALLOC_CAP_SPIRAM);
  if (!queries) {
    Serial.println("[dot] no memory for the query queue -- DoT off");
    return;
  }
  xTaskCreatePinnedToCore(proxyTask, "dot", DOT_TASK_STACK, nullptr, 2, &task, 1);
}

bool submit(const uint8_t* data, int len) {
  if (!queries || !connectedFlag || pausedFlag || len > DNS_MAX_PACKET) return false;
  static Query q;   // only the DNS task calls this
  q.len = (uint16_t)len;
  memcpy(q.data, data, len);
  return xQueueSend(queries, &q, 0) == pdTRUE;
}

bool ready() { return connectedFlag && !pausedFlag; }

void pause(bool p) { pausedFlag = p; }

String status() {
  if (!g_settings.dotEnabled) return "off";
  if (pausedFlag) return "paused for blocklist download";
  if (connectedFlag) return "connected to " + g_settings.dotHost;
  return failures ? "not connected (" + String(failures) + " failures) -- using plain DNS"
                  : "connecting";
}

}  // namespace dot
