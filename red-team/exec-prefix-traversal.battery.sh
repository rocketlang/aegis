#!/usr/bin/env bash
# aegis red-team — exec allowlist prefix rule vs traversal and symlinks (review point 2, 2026-10-16).
# A prefix rule passes only a normal-form path whose real path is also under the prefix.
# Hermetic, against the real _auto_decide_exec; executes nothing. Runs vs repo source.
set -u
[ -n "${RAN_INNER:-}" ] || exec "$(cd "$(dirname "$0")" && pwd)/lib/ran.sh" 3 "$0" "$@"   # green only if the cases ran
HERE="$(cd "$(dirname "$0")" && pwd)"
echo "=== aegis red-team · exec prefix traversal ==="
command -v python3 >/dev/null || { echo "BROKE — python3 not found"; exit 3; }
python3 "$HERE/exec-prefix-traversal.probe.py"; rc=$?
echo "EXIT=$rc   (0 = a prefix rule only passes paths inside it · 1 = a path escapes a prefix rule · 3 = broke)"
exit $rc
