// Host-side tests for localrec.h: the local DNS list parser and lookups.
#include <cstdio>
#include <cstring>

#include "localrec.h"

static int failures = 0, checks = 0;

static void ok(bool cond, const char* what) {
  checks++;
  if (!cond) { failures++; printf("  FAIL: %s\n", what); }
}

int main() {
  localrec::Record rows[8];
  localrec::Table t = {rows, 8, 0};
  int bad = 0;

  int n = localrec::parse(
      "# my network\n"
      "192.168.0.10  nas  NAS.lan.\n"
      "\n"
      "192.168.0.20\tprinter   # the laser one\n"
      "not-an-ip  thing\n"
      "192.168.0.30\n"
      "192.168.0.256 broken\n"
      "192.168.0.40 bad!name ok-name\r\n",
      t, bad);

  ok(n == 4, "four names parsed");
  ok(bad == 4, "four unusable entries counted");

  uint8_t ip[4];
  const localrec::Record* r = localrec::byName(t, "nas");
  ok(r && r->ip[3] == 10, "nas");
  r = localrec::byName(t, "nas.lan");
  ok(r && r->ip[3] == 10, "second name, lowercased, trailing dot dropped");
  r = localrec::byName(t, "printer");
  ok(r && r->ip[3] == 20, "tab separated, comment stripped");
  r = localrec::byName(t, "ok-name");
  ok(r && r->ip[3] == 40, "good name kept on a line with a bad one");
  ok(!localrec::byName(t, "bad!name"), "bad name skipped");
  ok(!localrec::byName(t, "thing"), "line with a bad IP skipped");
  ok(!localrec::byName(t, "NAS"), "lookups expect lowercase");

  uint8_t want[4] = {192, 168, 0, 10};
  r = localrec::byIp(t, want);
  ok(r && !strcmp(r->name, "nas"), "reverse gives the first name");
  uint8_t none[4] = {10, 0, 0, 1};
  ok(!localrec::byIp(t, none), "unknown address");

  ok(localrec::parseIp("10.0.0.1", ip) && ip[0] == 10, "parseIp");
  ok(!localrec::parseIp("10.0.0", ip), "three parts");
  ok(!localrec::parseIp("10.0.0.1.", ip), "trailing dot");

  // Capacity: extra names are counted as unusable, not written past the end.
  localrec::Record two[2];
  localrec::Table small = {two, 2, 0};
  n = localrec::parse("1.1.1.1 a b c d\n", small, bad);
  ok(n == 2 && bad == 2, "table full: extras counted, not overflowed");

  printf("%d/%d checks passed\n", checks - failures, checks);
  return failures ? 1 : 0;
}
