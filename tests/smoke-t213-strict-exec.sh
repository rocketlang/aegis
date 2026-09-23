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
RUN_TAG="$$-$(date +%s)"
EXIT_A=0
$KAVACHOS_CLI run \
  --trust-mask=255 \
  --domain=general \
  --strict-exec \
  --session-id="SMOKE-T213-A-$RUN_TAG" \
  --verbose \
  -- /usr/bin/ls /tmp \
  >"$OUT_A" 2>&1 || EXIT_A=$?

if [[ $EXIT_A -eq 0 ]]; then
  pass "ls exited 0 — allowlisted binary executed normally"
else
  # NO SKIP BRANCH, deliberately. This used to downgrade ANY fatal — seccomp_init,
  # libseccomp, or a genuine policy regression — into a skip, and the suite still
  # exited 0. Proven 2026-09-23 by pointing this case at a binary that does not
  # exist: it reported "SKIP: seccomp setup failed" with PASS=6 FAIL=0 SKIP=1 and
  # exit 0. A real break was indistinguishable from an environment quirk.
  # A check that cannot run FAILS. It never skips.
  fail "ls exited $EXIT_A — an allowlisted binary must execute normally"
  cat "$OUT_A"
fi
rm -f "$OUT_A"

# --- Case A2: the agent really ran, and its exit status came back ---
#
# Case A asserting exit 0 is weak: a launch that quietly did nothing also exits 0.
# A distinctive status can only be produced by the agent itself actually running and
# the runner propagating what it returned, so this is the case that proves an exec
# happened rather than inferring it from the absence of an error.
log "Case A2: an allowlisted binary's exit status propagates (exit 7)"
# A UNIQUE session id per run, never a fixed one. A fixed id leaves a pinned BPF
# object at /sys/fs/bpf/kavachos/<sid>/connect4, and the NEXT run fails to pin with
# "already exists" — the suite poisoning itself, which has bitten this file before.
A2_SID="SMOKE-T213-A2-$RUN_TAG"
OUT_A2=$(mktemp)
EXIT_A2=0
$KAVACHOS_CLI run \
  --trust-mask=255 \
  --domain=general \
  --strict-exec \
  --session-id="$A2_SID" \
  -- /bin/sh -c 'exit 7' \
  >"$OUT_A2" 2>&1 || EXIT_A2=$?

if [[ $EXIT_A2 -eq 7 ]]; then
  pass "exit 7 propagated — the agent ran and its status came back intact"
else
  fail "expected exit 7 from the agent, got $EXIT_A2"
  cat "$OUT_A2"
fi
rm -f "$OUT_A2" /root/.aegis/kernel/"$A2_SID".*.json 2>/dev/null
rm -rf /sys/fs/bpf/kavachos/"$A2_SID" 2>/dev/null || true

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
  --session-id="SMOKE-T213-B-$RUN_TAG" \
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
  --session-id="SMOKE-T213-C-$RUN_TAG" \
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
  # An unrecognised shape FAILS. This branch used to skip and say "review manually",
  # which meant nobody did: the suite exited 0 and the second-hop question went
  # unanswered. Case C asks whether sh can exec a binary the allowlist denies — the
  # answer is either "it was blocked" or "the threat model has a gap", and an output
  # matching none of the known shapes means the case did not answer its own question.
  # That is a failure of the test, and a test that cannot answer must say so.
  fail "Case C answered nothing (blocked_cmd=$BLOCKED_CMD exit=$EXIT_C) — output matched no known shape"
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
  # Do not skip four cases because an input was missing — SYNTHESISE the input. Every
  # launch above writes a profile, so an empty directory here means either the suite is
  # being run in a fresh environment or the earlier cases did not do what they claim.
  # One throwaway launch settles which, and only a still-empty directory is fatal.
  log "  no profile on disk — synthesising one with a throwaway launch"
  SYN_SID="SMOKE-T213-SYN-$$-$(date +%s)"
  $KAVACHOS_CLI run --trust-mask=255 --domain=general --session-id="$SYN_SID" \
    -- /bin/sh -c 'exit 0' >/dev/null 2>&1 || true
  for _p in /root/.aegis/kernel/*.seccomp.json; do
    [[ -f "$_p" ]] || continue
    PROFILE_SRC="$_p"
    break
  done
  rm -f /root/.aegis/kernel/"$SYN_SID".*.json 2>/dev/null || true
  rm -rf /sys/fs/bpf/kavachos/"$SYN_SID" 2>/dev/null || true
fi

if [[ -z "${PROFILE_SRC:-}" ]]; then
  # Still nothing after a launch that should have written one. The allowlist cases
  # cannot run, and four unrun cases must never read as a green suite.
  fail "no seccomp profile on disk even after a launch — cases G/H/I/J could not run"
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
