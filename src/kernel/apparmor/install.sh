#!/usr/bin/env bash
# Install/refresh the kavachos-agent AppArmor profile.
# Additive: loading confines nothing until runner.ts attaches it via aa-exec.
set -euo pipefail

SRC="$(dirname "$0")/kavachos-agent.profile"
DST="/etc/apparmor.d/kavachos.agent"

command -v apparmor_parser >/dev/null || { echo "apparmor_parser not found — AppArmor not installed" >&2; exit 1; }
aa-status --enabled 2>/dev/null || { echo "AppArmor not enabled in kernel" >&2; exit 1; }

cp "$SRC" "$DST"
apparmor_parser -r "$DST"

grep -q '^kavachos-agent ' /sys/kernel/security/apparmor/profiles \
  && echo "kavachos-agent profile loaded (enforce)" \
  || { echo "profile load FAILED" >&2; exit 1; }
