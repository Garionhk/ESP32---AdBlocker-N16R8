#include <Arduino.h>
#include <LittleFS.h>
#include <freertos/semphr.h>

#include "config.h"
#include "localdns.h"
#include "localrec.h"

namespace localdns {
namespace {

localrec::Record rows[DNS_LOCAL_RECORDS];
localrec::Table  table = {rows, DNS_LOCAL_RECORDS, 0};
SemaphoreHandle_t lock = nullptr;

void ensureLock() {
  if (!lock) lock = xSemaphoreCreateMutex();
}

}  // namespace

void begin() {
  ensureLock();
  String t = text();
  int bad = 0;
  xSemaphoreTake(lock, portMAX_DELAY);
  localrec::parse(t.c_str(), table, bad);
  xSemaphoreGive(lock);
  if (table.count || bad) {
    Serial.printf("[local] %d records, %d unusable lines\n", table.count, bad);
  }
}

bool lookup(const char* name, uint8_t ip[4]) {
  if (!lock) return false;
  xSemaphoreTake(lock, portMAX_DELAY);
  const localrec::Record* r = localrec::byName(table, name);
  if (r) memcpy(ip, r->ip, 4);
  xSemaphoreGive(lock);
  return r != nullptr;
}

bool reverse(const uint8_t ip[4], char* name, size_t cap) {
  if (!lock) return false;
  xSemaphoreTake(lock, portMAX_DELAY);
  const localrec::Record* r = localrec::byIp(table, ip);
  if (r) {
    strncpy(name, r->name, cap - 1);
    name[cap - 1] = 0;
  }
  xSemaphoreGive(lock);
  return r != nullptr;
}

String text() {
  File f = LittleFS.open(DNS_LOCAL_PATH, FILE_READ);
  if (!f) return "";
  String t = f.readString();
  f.close();
  return t;
}

bool save(const String& t, int& records, int& bad) {
  ensureLock();
  File f = LittleFS.open(DNS_LOCAL_PATH, FILE_WRITE);
  if (!f) return false;
  f.print(t);
  f.close();
  xSemaphoreTake(lock, portMAX_DELAY);
  records = localrec::parse(t.c_str(), table, bad);
  xSemaphoreGive(lock);
  Serial.printf("[local] saved: %d records, %d unusable lines\n", records, bad);
  return true;
}

int count() { return table.count; }

}  // namespace localdns
