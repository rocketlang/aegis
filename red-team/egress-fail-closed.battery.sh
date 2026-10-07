#!/usr/bin/env bash
# aegis red-team — EGRESS fail-closed (review finding, 2026-10-08). Proves the launcher refuses to
# exec an agent when it cannot join the egress cgroup (was: logged + ran unconstrained), with an
# explicit --allow-unconstrained-egress opt-out. Hermetic — drives the real _join_egress_cgroup(),
# no root/BPF/profile. GAP = it proceeded (fail open). Runs vs repo source.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
echo "=== aegis red-team · egress fail-closed ==="
command -v python3 >/dev/null || { echo "BROKE — python3 not found"; exit 3; }
python3 "$HERE/egress-fail-closed.probe.py"; rc=$?
echo "EXIT=$rc   (0 = failed join refuses to exec · 1 = fail-open reproduced, RED until fixed · 3 = broke)"
exit $rc
