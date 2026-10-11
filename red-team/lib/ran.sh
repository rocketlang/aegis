#!/usr/bin/env bash
# aegis red-team — a battery is green only if its cases RAN.
#
#   lib/ran.sh <least number of cases> <battery> [args…]
#
# Every battery hands itself to this file in its first lines. Until 11 October 2026 a battery believed its
# probe's exit code and nothing else: with a `bun` or `python3` that did nothing and exited 0, 19 of the 22
# batteries printed their banner and exited 0. A probe that returns early, or whose cases sit in a promise
# nobody waited for, would have been green the same way.
#
# This runs the battery, shows its output as it comes, and then counts what ran:
#   - lines that begin with a verdict in brackets: [safe] [GAP ] [ok] [PASS] [held] [FAIL]
#   - tests a `bun test` run reports as passed or failed
#   - or, when the battery sets RAN_MARK, lines that match that pattern
# Exit 0 or 1 with fewer cases than the battery names is BROKE (3). So is exit 0 with a skipped test: a skipped
# test proved nothing. Any other exit is passed on as it is.
set -u
MIN="$1"; BATTERY="$2"; shift 2
OUT="$(mktemp "${TMPDIR:-/tmp}/ran.XXXXXX")"; trap 'rm -f "$OUT"' EXIT
RAN_INNER=1 bash "$BATTERY" "$@" 2>&1 | tee "$OUT"; rc=${PIPESTATUS[0]}
if [ -n "${RAN_MARK:-}" ]; then
  cases="$(grep -cE -- "$RAN_MARK" "$OUT")"
else
  cases="$(grep -cE '^[[:space:]]*\[(safe|GAP ?|ok|PASS|held|FAIL)[[:space:]]*\]' "$OUT")"
  tests="$(sed -n 's/^ *\([0-9][0-9]*\) \(pass\|fail\)$/\1/p' "$OUT" | awk '{ n += $1 } END { print n + 0 }')"
  cases=$(( cases + ${tests:-0} ))
fi
skipped="$(sed -n 's/^ *\([0-9][0-9]*\) skip$/\1/p' "$OUT" | awk '{ n += $1 } END { print n + 0 }')"
if [ "$rc" = 0 ] || [ "$rc" = 1 ]; then
  if [ "$cases" -lt "$MIN" ]; then
    echo "BROKE — $(basename "$BATTERY") ran $cases case(s), and it has at least $MIN; exit $rc proves nothing"; rc=3
  elif [ "$rc" = 0 ] && [ "${skipped:-0}" -gt 0 ]; then
    echo "BROKE — $(basename "$BATTERY") skipped ${skipped} test(s); a skipped test proves nothing"; rc=3
  fi
fi
echo "ran: $cases case(s), exit $rc"
exit "$rc"
