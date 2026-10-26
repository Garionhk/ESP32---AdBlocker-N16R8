#pragma once

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Your own name -> IPv4 records, in hosts-file syntax:
//
//   192.168.0.10  nas  nas.lan
//   192.168.0.20  printer
//
// Pure parsing and lookup over a fixed table, so the native tests can drive
// it; localdns.cpp adds the file and the lock.

namespace localrec {

const int NAME_LEN = 64;

struct Record {
  uint8_t ip[4];
  char    name[NAME_LEN];   // lowercase, no trailing dot
};

struct Table {
  Record* rows;
  int     cap;
  int     count;
};

inline bool parseIp(const char* s, uint8_t ip[4]) {
  int parts = 0;
  const char* p = s;
  while (parts < 4) {
    if (!isdigit((unsigned char)*p)) return false;
    char* end;
    long v = strtol(p, &end, 10);
    if (v < 0 || v > 255 || end - p > 3) return false;
    ip[parts++] = (uint8_t)v;
    p = end;
    if (parts < 4) {
      if (*p != '.') return false;
      p++;
    }
  }
  return *p == 0;
}

inline bool validName(const char* n) {
  size_t len = strlen(n);
  if (len == 0 || len >= (size_t)NAME_LEN || n[0] == '.' || n[len - 1] == '.') return false;
  for (const char* p = n; *p; p++) {
    char c = *p;
    if (!(isalnum((unsigned char)c) || c == '-' || c == '.' || c == '_')) return false;
  }
  return true;
}

// Parses the whole text into `t`, replacing what was there. Lines that do not
// parse are skipped and counted in `bad`. Returns the number of records.
inline int parse(const char* text, Table& t, int& bad) {
  t.count = 0;
  bad = 0;
  const char* p = text;
  while (*p) {
    const char* eol = strchr(p, '\n');
    size_t n = eol ? (size_t)(eol - p) : strlen(p);
    char line[256];
    if (n >= sizeof(line)) n = sizeof(line) - 1;
    memcpy(line, p, n);
    line[n] = 0;
    p += n + (eol ? 1 : 0);

    char* hash = strchr(line, '#');
    if (hash) *hash = 0;
    char* save = nullptr;
    char* tok = strtok_r(line, " \t\r", &save);
    if (!tok) continue;                       // blank or comment
    uint8_t ip[4];
    if (!parseIp(tok, ip)) { bad++; continue; }
    bool any = false;
    while ((tok = strtok_r(nullptr, " \t\r", &save))) {
      for (char* c = tok; *c; c++) *c = (char)tolower((unsigned char)*c);
      size_t len = strlen(tok);
      if (len && tok[len - 1] == '.') tok[--len] = 0;
      if (!validName(tok)) { bad++; continue; }
      if (t.count >= t.cap) { bad++; continue; }
      Record& r = t.rows[t.count++];
      memcpy(r.ip, ip, 4);
      strcpy(r.name, tok);
      any = true;
    }
    if (!any) bad++;
  }
  return t.count;
}

inline const Record* byName(const Table& t, const char* name) {
  for (int i = 0; i < t.count; i++) {
    if (strcmp(t.rows[i].name, name) == 0) return &t.rows[i];
  }
  return nullptr;
}

// First record for an address, for PTR answers.
inline const Record* byIp(const Table& t, const uint8_t ip[4]) {
  for (int i = 0; i < t.count; i++) {
    if (memcmp(t.rows[i].ip, ip, 4) == 0) return &t.rows[i];
  }
  return nullptr;
}

}  // namespace localrec
