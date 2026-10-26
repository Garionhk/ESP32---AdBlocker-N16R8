#pragma once

#include <Arduino.h>

// Your local DNS records (Pi-hole's "Local DNS"), stored in LittleFS and
// edited from the settings page. Answered directly, never forwarded.

namespace localdns {

// Loads the file. Call after LittleFS is mounted.
void begin();

// Answers for an A query / a PTR query of an IPv4 address. Thread-safe.
bool lookup(const char* name, uint8_t ip[4]);
bool reverse(const uint8_t ip[4], char* name, size_t cap);

// The stored text, as typed.
String text();

// Replaces the records. Returns how many lines were unusable via `bad`.
bool save(const String& text, int& records, int& bad);

int count();

}  // namespace localdns
