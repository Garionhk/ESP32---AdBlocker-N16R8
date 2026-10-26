// Host-side tests for ledstate.h: which pattern each device state shows, and
// that the colours and blink rates match the documented table.
#include <cstdio>

#include "ledstate.h"

using led::Pattern;

static int failures = 0, checks = 0;

static void ok(bool cond, const char* what) {
  checks++;
  if (!cond) { failures++; printf("  FAIL: %s\n", what); }
}

// Mirrors blocklist::Result.
enum { NONE = 0, OK = 1, NO_INTERNET = 2, FAILED = 3 };

int main() {
  // --- AP mode wins over everything ---
  ok(led::choose(true, false, false, NONE) == Pattern::ApMode, "setup portal: yellow");
  ok(led::choose(true, true, true, OK) == Pattern::ApMode, "WiFi fallback during download: yellow");
  ok(led::choose(true, false, true, NO_INTERNET) == Pattern::ApMode, "fallback beats no internet");

  // --- online ---
  ok(led::choose(false, false, true, OK) == Pattern::Active, "list loaded, download ok: green");
  ok(led::choose(false, false, true, NONE) == Pattern::Active,
     "restored from flash, no download needed: green");
  ok(led::choose(false, true, false, OK) == Pattern::Downloading, "downloading: blue");
  ok(led::choose(false, true, false, NO_INTERNET) == Pattern::Downloading,
     "a retry that got through shows blue, not purple");
  ok(led::choose(false, false, true, NO_INTERNET) == Pattern::NoInternet,
     "no internet with a list: purple");
  ok(led::choose(false, false, false, NO_INTERNET) == Pattern::NoInternet,
     "no internet without a list: purple");
  ok(led::choose(false, false, true, FAILED) == Pattern::Offline, "bad download, old list: teal");
  ok(led::choose(false, false, false, FAILED) == Pattern::Failure, "bad download, no list: red");
  ok(led::choose(false, false, false, NONE) == Pattern::Failure, "no list, no attempt yet: red");

  // --- the documented colours ---
  led::Look y = led::look(Pattern::ApMode);
  ok(y.r && y.g && !y.b && y.blinkMs, "AP mode is blinking yellow");
  led::Look g = led::look(Pattern::Active);
  ok(!g.r && g.g && !g.b && g.blinkMs == 0, "active is steady green");
  led::Look t = led::look(Pattern::Offline);
  ok(!t.r && t.g && t.b, "offline is teal");
  led::Look r = led::look(Pattern::Failure);
  ok(r.r && !r.g && !r.b, "failure is red");
  led::Look b = led::look(Pattern::Downloading);
  ok(!b.r && !b.g && b.b, "downloading is blue");
  led::Look p = led::look(Pattern::NoInternet);
  ok(p.r && !p.g && p.b, "no internet is purple");
  led::Look off = led::look(Pattern::Off);
  ok(!off.r && !off.g && !off.b, "off is dark");

  // --- blink speeds keep their order: flashing < fast < medium < slow < very slow ---
  ok(p.blinkMs < r.blinkMs, "purple flashes faster than red");
  ok(r.blinkMs < b.blinkMs, "red faster than blue");
  ok(b.blinkMs < y.blinkMs, "blue faster than yellow");
  ok(y.blinkMs < t.blinkMs, "yellow faster than teal");

  printf("%d/%d checks passed\n", checks - failures, checks);
  return failures ? 1 : 0;
}
