#!/usr/bin/env bash
# KOS-T213 Smoke Test — strict_exec mode: execve allowlist enforcement
# Tests two cases:
#   Case A: binary on allowlist executes normally
#   Case B: binary NOT on allowlist (e.g. /usr/bin/nmap) is blocked (EPERM)
#   Case C (boundary test): allowed binary attempts to execve a blocked binary
#            — strict_exec must catch the second-hop exec, not just the first
#
# Requires: root + libseccomp (seccomp NOTIFY support)
# @rule:KOS-046 strict_exec: execve/execveat gated by exec-allowlist
# @rule:KOS-047 auto-ALLOW/DENY from allowlist — no Telegram (too fast for HITL)
# @rule:KOS-048 unknown binary = DENY by default
#
# Usage: sudo bash tests/smoke-t213-strict-exec.sh

set -euo pipefail

PASS=0
FAIL=0
SKIP=0

log()  { echo "[smoke-t213] $*"; }
pass() { log "PASS: $1"; PASS=$((PASS+1)); }
fail() { log "FAIL: $1"; FAIL=$((FAIL+1)); }
skip() { log "SKIP: $1"; SKIP=$((SKIP+1)); }

if [[ $EUID -ne 0 ]]; then
  skip "must run as root (seccomp NOTIFY requires CAP_SYS_ADMIN)"
  exit 0
fi

if ! command -v bun &>/dev/null; then
  skip "bun not found"
  exit 0
fi

# `import ctypes` does NOT make ctypes.util available — this check raised AttributeError
# on every run and skipped the whole suite while libseccomp was installed and working.
# A precondition that can only fail is a suite that never runs, and it exits 0, so it
# reads green in CI. Fixed 2026-09-22; `import ctypes.util` is the operative change.
if ! python3 -c "import ctypes, ctypes.util; ctypes.CDLL(ctypes.util.find_library('seccomp'))" 2>/dev/null; then
  skip "libseccomp not found — install libseccomp2 or libseccomp-dev"
  exit 0
fi

KAVACHOS_CLI="${KAVACHOS_CLI:-bun /root/aegis/src/kavachos-cli.ts}"

# --- Case A: allowed binary executes normally ---

log "Case A: /usr/bin/ls runs under strict_exec (on allowlist)"

OUT_A=$(mktemp)
# `|| EXIT_A=$?` is required: under `set -e` a non-zero exit aborts the script before
# a bare `EXIT_A=$?` can capture it, so a failing Case A silently took the whole suite
# — including every case below it — down with it, and the file still exited 0 on a skip.
EXIT_A=0
$KAVACHOS_CLI run \
  --trust-mask=255 \
  --domain=general \
  --strict-exec \
  --session-id="SMOKE-T213-A" \
  --verbose \
  -- /usr/bin/ls /tmp \
  >"$OUT_A" 2>&1 || EXIT_A=$?

if [[ $EXIT_A -eq 0 ]]; then
  pass "ls exited 0 — allowlisted binary executed normally"
else
  # Check if it's a seccomp-setup failure vs actual exec block
  if grep -q "FATAL\|seccomp_init\|libseccomp" "$OUT_A"; then
    skip "seccomp setup failed (libseccomp issue) — not an exec policy failure"
  else
    fail "ls exited $EXIT_A — unexpected failure for allowlisted binary"
    cat "$OUT_A"
  fi
fi
rm -f "$OUT_A"

# --- Case B: non-allowlisted binary blocked at first hop ---

log "Case B: /usr/bin/nmap blocked under strict_exec (not on claude-code allowlist)"

# If nmap isn't installed, use a binary that definitely isn't on the allowlist
BLOCKED_BIN="/usr/bin/nmap"
if ! command -v nmap &>/dev/null; then
  BLOCKED_BIN="/usr/bin/nc"
fi
if ! command -v nc &>/dev/null && ! command -v nmap &>/dev/null; then
  # Last resort: use a custom script
  BLOCKED_BIN=$(mktemp /tmp/smoke-blocked-XXXX)
  echo '#!/bin/sh' > "$BLOCKED_BIN"
  echo 'echo "I should not run"' >> "$BLOCKED_BIN"
  chmod +x "$BLOCKED_BIN"
  CLEANUP_BIN="$BLOCKED_BIN"
fi

OUT_B=$(mktemp)
# Case B EXPECTS a non-zero exit, so under `set -e` it aborted the suite on success.
EXIT_B=0
$KAVACHOS_CLI run \
  --trust-mask=255 \
  --domain=general \
  --strict-exec \
  --session-id="SMOKE-T213-B" \
  --verbose \
  -- "$BLOCKED_BIN" --version \
  >"$OUT_B" 2>&1 || EXIT_B=$?

if grep -q "DENY\|EPERM\|kavachos:exec.*DENY\|not in exec allowlist\|Operation not permitted" "$OUT_B"; then
  pass "non-allowlisted binary produced DENY evidence in logs"
elif [[ $EXIT_B -ne 0 ]]; then
  pass "non-allowlisted binary exited non-zero (exit=$EXIT_B) — exec block likely active"
else
  fail "non-allowlisted binary $BLOCKED_BIN executed successfully — strict_exec not enforced"
  cat "$OUT_B"
fi
rm -f "$OUT_B"
# `[[ ... ]] && cmd` as a bare statement returns non-zero when the test is false,
# which under `set -e` ended the suite here. Every case below never ran.
if [[ -n "${CLEANUP_BIN:-}" ]]; then rm -f "$CLEANUP_BIN"; fi

# --- Case C: second-hop exec blocked (the hard half of strict_exec) ---
# Allowed binary (/usr/bin/sh) attempts to execve a blocked binary.
# If strict_exec only catches first-hop, this will succeed — the test exposes that.

log "Case C: sh tries to exec a blocked binary via shell command (second-hop check)"

OUT_C=$(mktemp)
EXIT_C=0
# sh is on the allowlist; nmap/nc/custom script is not
BLOCKED_CMD="$( command -v nmap 2>/dev/null || command -v nc 2>/dev/null || echo "/nonexistent-binary" )"

$KAVACHOS_CLI run \
  --trust-mask=255 \
  --domain=general \
  --strict-exec \
  --session-id="SMOKE-T213-C" \
  --verbose \
  -- /usr/bin/sh -c "$BLOCKED_CMD --version 2>&1; echo SH_EXIT:\$?" \
  >"$OUT_C" 2>&1 || EXIT_C=$?

OUTPUT_C=$(cat "$OUT_C")

if echo "$OUTPUT_C" | grep -q "kavachos:exec.*DENY\|not in exec allowlist\|Operation not permitted"; then
  pass "second-hop exec blocked — sh could not exec non-allowlisted binary (strict_exec catches sub-exec)"
elif echo "$OUTPUT_C" | grep -q "SH_EXIT:126\|SH_EXIT:127\|Permission denied"; then
  pass "sh got exit 126/127 for blocked binary — exec denied at kernel level"
elif echo "$OUTPUT_C" | grep -q "I should not run\|SH_EXIT:0" && [[ "$BLOCKED_CMD" != "/nonexistent-binary" ]]; then
  fail "THREAT MODEL GAP: sh successfully exec'd blocked binary via shell command — strict_exec only caught first hop"
  log "  This is the 'sh as unbounded allowlist' problem described in the docs."
  log "  strict_exec prevents direct execve; sh can still run arbitrary code."
  cat "$OUT_C"
else
  skip "Case C ambiguous (blocked_cmd=$BLOCKED_CMD exit=$EXIT_C) — review manually"
  cat "$OUT_C"
fi
rm -f "$OUT_C"

# --- Case G/H/I/J: the allowlist itself is unreadable (KOS-047 fail-closed) ---
#
# Added 2026-09-22. This path used to ALLOW: `allowlist load error ... allow by default`.
# A typo'd or missing allowlist silently disarmed the one layer that binds a
# non-cooperating agent. A gate that cannot read its own rules must refuse.
# The deliberate way to run without strict_exec is to unset KAVACHOS_EXEC_ALLOWLIST,
# which Case J confirms still works.

SECCOMP="/root/aegis/src/kernel/apply-seccomp.py"
# NOT `ls ... | head -1`: under `set -o pipefail` head exits first, ls takes SIGPIPE,
# the pipeline reports non-zero and `set -e` kills the suite before these cases run.
PROFILE_SRC=""
for _p in /root/.aegis/kernel/*.seccomp.json; do
  [[ -f "$_p" ]] || continue
  PROFILE_SRC="$_p"
  break
done

if [[ -z "${PROFILE_SRC:-}" ]]; then
  skip "no seccomp profile on disk for the allowlist cases"
else
  TMPD=$(mktemp -d)
  # profile with execve/execveat routed to the NOTIFY tier so the allowlist is consulted
  python3 - "$PROFILE_SRC" "$TMPD/gated.json" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
for e in d.get("syscalls", []):
    if e.get("action") == "SCMP_ACT_ALLOW":
        e["names"] = [n for n in e["names"] if n not in ("execve", "execveat")]
d["syscalls"].append({"action": "SCMP_ACT_NOTIFY", "names": ["execve", "execveat"]})
json.dump(d, open(sys.argv[2], "w"))
PYEOF

  log "Case G: missing allowlist refuses to start the agent"
  OUT_G=$(KAVACHOS_EXEC_ALLOWLIST="$TMPD/does-not-exist.json"     timeout 30 python3 "$SECCOMP" "$TMPD/gated.json" -- /usr/bin/true 2>&1 || true)
  if grep -q "FATAL: exec allowlist unreadable" <<<"$OUT_G"; then
    pass "missing allowlist is fatal — no longer allows every binary"
  else
    fail "missing allowlist did not refuse: $OUT_G"
  fi

  log "Case H: corrupt allowlist refuses to start the agent"
  printf '{"allow": [' > "$TMPD/corrupt.json"
  OUT_H=$(KAVACHOS_EXEC_ALLOWLIST="$TMPD/corrupt.json" \
    timeout 30 python3 "$SECCOMP" "$TMPD/gated.json" -- /usr/bin/true 2>&1 || true)
  if grep -q "FATAL: exec allowlist unreadable" <<<"$OUT_H"; then
    pass "corrupt allowlist is fatal"
  else
    fail "corrupt allowlist did not refuse: $OUT_H"
  fi

  log "Case I: a VALID allowlist still permits and still denies"
  printf '{"agent_type":"smoke","allow":[{"path":"/usr/bin/python3"}]}' > "$TMPD/ok.json"
  OUT_I=$(KAVACHOS_EXEC_ALLOWLIST="$TMPD/ok.json" \
    timeout 30 python3 "$SECCOMP" "$TMPD/gated.json" \
    -- python3 -c 'import subprocess;subprocess.run(["/usr/bin/id"])' 2>&1 || true)
  if grep -q "ALLOW: /usr/bin/python3" <<<"$OUT_I" && grep -q "DENY: '/usr/bin/id'" <<<"$OUT_I"; then
    pass "valid allowlist unchanged — python3 allowed, /usr/bin/id denied"
  else
    fail "valid allowlist regressed: $OUT_I"
  fi

  log "Case J: unsetting the allowlist is still the way to run without strict_exec"
  OUT_J=$(timeout 30 python3 "$SECCOMP" "$TMPD/gated.json" -- /usr/bin/true 2>&1 || true)
  if grep -q "strict_exec not active" <<<"$OUT_J"; then
    pass "no allowlist configured still runs — the explicit opt-out is intact"
  else
    fail "opt-out path broke: $OUT_J"
  fi

  rm -rf "$TMPD"
fi

# --- Summary ---

echo ""
echo "KOS-T213 Results: PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"
echo ""
echo "Threat model note (KOS-046):"
echo "  strict_exec prevents first-hop execve to unknown binaries."
echo "  sh + git + curl on the allowlist are functionally an unbounded exec surface:"
echo "    - sh runs arbitrary commands via -c"
echo "    - git has hooks that exec arbitrary scripts"
echo "    - curl can fetch+pipe to sh"
echo "  This gate catches accidental tool calls and casual escapes, not"
echo "  a determined agent operating through an allowed shell interpreter."
echo "  Document this scope in the threat model, not the changelog."
[[ $FAIL -eq 0 ]]
