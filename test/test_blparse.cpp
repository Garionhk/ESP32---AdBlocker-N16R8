// Host-side tests for blparse.h: which blocklist lines yield a domain, and
// how names are normalized for storage and lookup.
#include <cstdio>
#include <cstring>
#include <string>

#include "blparse.h"

static int failures = 0, checks = 0;

static void ok(bool cond, const char* what) {
  checks++;
  if (!cond) { failures++; printf("  FAIL: %s\n", what); }
}

// Runs one line through both steps, as the download does. "" means skipped.
static std::string domainOf(const char* line) {
  char buf[256];
  strncpy(buf, line, sizeof(buf) - 1);
  buf[sizeof(buf) - 1] = 0;
  char* d = blparse::extractDomain(buf);
  if (!d || !blparse::normalize(d, 100)) return "";
  return d;
}

static std::string norm(const char* name) {
  char buf[256];
  strncpy(buf, name, sizeof(buf) - 1);
  buf[sizeof(buf) - 1] = 0;
  return blparse::normalize(buf, 100) ? std::string(buf) : std::string();
}

int main() {
  // --- HOSTS format ---
  ok(domainOf("0.0.0.0 ads.example.com") == "ads.example.com", "0.0.0.0 line");
  ok(domainOf("127.0.0.1 ads.example.com") == "ads.example.com", "127.0.0.1 line");
  ok(domainOf("0.0.0.0\ttabbed.example.com") == "tabbed.example.com", "tab separated");
  ok(domainOf("0.0.0.0 ads.example.com # tracker") == "ads.example.com", "trailing comment");
  ok(domainOf("0.0.0.0 ads.example.com#x") == "ads.example.com", "comment with no space");
  ok(domainOf("  0.0.0.0 indented.example.com") == "indented.example.com", "leading whitespace");
  ok(domainOf("0.0.0.0 WWW.Shouty.Example.COM") == "shouty.example.com", "www. and case");

  // --- the junk at the top of a hosts file ---
  ok(domainOf("# Title: StevenBlack/hosts") == "", "comment line");
  ok(domainOf("127.0.0.1 localhost") == "", "localhost");
  ok(domainOf("127.0.0.1 localhost.localdomain") == "", "localhost.localdomain");
  ok(domainOf("0.0.0.0 printer.local") == "", ".local names");
  ok(domainOf("255.255.255.255 broadcasthost") == "", "broadcast line");
  ok(domainOf("::1 localhost") == "", "IPv6 loopback");
  ok(domainOf("fe80::1%lo0 localhost") == "", "link-local");
  ok(domainOf("0.0.0.0 0.0.0.0") == "", "0.0.0.0 0.0.0.0");
  ok(domainOf("0.0.0.0") == "", "bare address");
  ok(domainOf("") == "", "blank line");
  ok(domainOf("   ") == "", "whitespace line");

  // --- Adblock format ---
  ok(domainOf("||ads.example.com^") == "ads.example.com", "plain domain rule");
  ok(domainOf("||ads.example.com^  ") == "ads.example.com", "trailing spaces");
  ok(domainOf("||ads.example.com^$third-party") == "", "rule with options skipped");
  ok(domainOf("||example.com/ads/*") == "", "path rule skipped");
  ok(domainOf("||*.example.com^") == "", "wildcard skipped");
  ok(domainOf("! Adblock comment") == "", "! comment");
  ok(domainOf("[Adblock Plus 2.0]") == "", "header");
  ok(domainOf("@@||allowed.example.com^") == "", "exception rule skipped");

  // --- plain list ---
  ok(domainOf("tracker.example.net") == "tracker.example.net", "plain domain");
  ok(domainOf("tracker.example.net # why") == "tracker.example.net", "plain with comment");
  ok(domainOf("address=/x.com/0.0.0.0") == "", "dnsmasq syntax skipped");

  // --- normalize on its own ---
  ok(norm("example.com.") == "example.com", "trailing dot stripped");
  ok(norm("www.example.com") == "example.com", "www. stripped");
  ok(norm("WWW.EXAMPLE.COM.") == "example.com", "both, any case");
  ok(norm("www2.example.com") == "www2.example.com", "only an exact www. label");
  ok(norm("under_score.example.com") == "under_score.example.com", "underscore allowed");
  ok(norm("router") == "", "single label rejected");
  ok(norm("www.") == "", "www. alone rejected");
  ok(norm("192.168.1.1") == "", "IP literal rejected");
  ok(norm(".example.com") == "", "leading dot rejected");
  ok(norm("exa mple.com") == "", "space rejected");
  ok(norm("exämple.com") == "", "non-ASCII rejected");
  ok(norm("") == "", "empty rejected");
  {
    std::string longName(99, 'a');
    longName += ".com";
    ok(norm(longName.c_str()) == "", "longer than the limit rejected");
  }

  printf("%d/%d checks passed\n", checks - failures, checks);
  return failures ? 1 : 0;
}
