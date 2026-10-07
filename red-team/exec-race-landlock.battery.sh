#!/usr/bin/env bash
# aegis red-team — exec-race closure via Landlock exec confinement (review finding, 2026-10-08).
# A child applies the real _apply_landlock_exec_confinement (allowlisting only `true`) and proves the
# KERNEL denies a non-allowlisted execve (EACCES) while the allowlisted one runs — the TOCTOU boundary
# the pointer swap cannot cross. Per-process Landlock, so it only confines the probe's own children.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
echo "=== aegis red-team · exec-race closure (Landlock) ==="
command -v python3 >/dev/null || { echo "BROKE — python3 not found"; exit 3; }
python3 "$HERE/exec-race-landlock.probe.py"; rc=$?
echo "EXIT=$rc   (0 = allowlist binds the real file · 1 = non-allowlisted ran, RED · 3 = Landlock unavailable here)"
exit $rc
