#pragma once

#include <Arduino.h>

// Small formatting helpers shared by the status page and the ntfy replies.

// 162431 -> "162,431"
inline String withCommas(uint32_t n) {
  char raw[12];
  snprintf(raw, sizeof(raw), "%lu", (unsigned long)n);
  String out;
  int len = (int)strlen(raw);
  for (int i = 0; i < len; i++) {
    if (i > 0 && (len - i) % 3 == 0) out += ',';
    out += raw[i];
  }
  return out;
}

// 3276800 -> "3.1 MB"
inline String fmtBytes(uint32_t n) {
  char buf[16];
  if (n >= 1024UL * 1024UL) snprintf(buf, sizeof(buf), "%.1f MB", n / 1048576.0);
  else if (n >= 1024UL)     snprintf(buf, sizeof(buf), "%lu KB", (unsigned long)(n / 1024));
  else                      snprintf(buf, sizeof(buf), "%lu B", (unsigned long)n);
  return String(buf);
}

// 93784 s -> "1d 2h 3m"
inline String fmtDuration(uint32_t s) {
  uint32_t d = s / 86400;
  uint32_t h = (s % 86400) / 3600;
  uint32_t m = (s % 3600) / 60;

  String out;
  if (d > 0) out += String(d) + "d ";
  if (d > 0 || h > 0) out += String(h) + "h ";
  out += String(m) + "m";
  return out;
}
