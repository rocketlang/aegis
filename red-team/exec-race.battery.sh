#!/usr/bin/env bash
# aegis red-team — exec-check race (TOCTOU) on strict-exec (review finding, 2026-10-08).
# Proves the ALLOW verdict (answered via seccomp CONTINUE, which re-reads the path pointer) does NOT
# bind the executed binary: an agent thread can swap the path between the supervisor's check and the
# kernel's re-read. Deterministic model against the real check_exec; the live race is disposable-host.
# GAP = an un-allowlisted binary would run under ALLOW. Runs vs repo source.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
echo "=== aegis red-team · exec-check race (TOCTOU) ==="
command -v python3 >/dev/null || { echo "BROKE — python3 not found"; exit 3; }
python3 "$HERE/exec-race.probe.py"; rc=$?
echo "EXIT=$rc   (0 = exec decision binds what runs · 1 = TOCTOU open, RED until fixed · 3 = broke)"
exit $rc
