#!/usr/bin/env bash
# Compiles the sketch's pure logic natively and runs the assertions. No board
# required.
#
# The real source files are compiled in -- nothing is copied or reimplemented --
# against the small Arduino shim in shim/. The transport (ntfy), the blocklist
# engine, the DNS server and the scheduler are stubbed inside test_commands.cpp
# so replies can be inspected.
#
#     ./test/run.sh

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKETCH="$HERE/../ESP32-AdBlocker"

OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

FLAGS=(-std=gnu++17 -w -I "$HERE/shim" -I "$SKETCH")

echo "=== settings ==="
g++ "${FLAGS[@]}" -o "$OUT/test_settings" "$HERE/test_settings.cpp" "$SKETCH/settings.cpp"
"$OUT/test_settings"

echo
echo "=== schedule ==="
g++ "${FLAGS[@]}" -o "$OUT/test_schedule" "$HERE/test_schedule.cpp"
"$OUT/test_schedule"

echo
echo "=== DNS messages ==="
g++ "${FLAGS[@]}" -o "$OUT/test_dnsmsg" "$HERE/test_dnsmsg.cpp"
"$OUT/test_dnsmsg"

echo
echo "=== local DNS records ==="
g++ "${FLAGS[@]}" -o "$OUT/test_localrec" "$HERE/test_localrec.cpp"
"$OUT/test_localrec"

echo
echo "=== status LED ==="
g++ "${FLAGS[@]}" -o "$OUT/test_led" "$HERE/test_led.cpp"
"$OUT/test_led"

echo
echo "=== blocklist parsing ==="
g++ "${FLAGS[@]}" -o "$OUT/test_blparse" "$HERE/test_blparse.cpp"
"$OUT/test_blparse"

echo
echo "=== commands ==="
g++ "${FLAGS[@]}" -o "$OUT/test_commands" \
    "$HERE/test_commands.cpp" "$SKETCH/commands.cpp" "$SKETCH/settings.cpp"
"$OUT/test_commands"
