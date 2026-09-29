#!/bin/sh
# Does the TypeScript half of the stack run on aarch64 at all?
#
# §14.4 of the design doc names this as unmeasured, and says that until it is, "mount
# AEGIS on the edge" is an intention rather than a claim. It is decision-relevant, not
# curiosity: if the TS layer will not start on the target, the component that produces a
# runtime receipt has to be written in something else, and that is a different design.
#
# Only the dependency-light modules are under test — the ones that stopped importing a
# database when merkle-tree was split out. That is deliberate: those are exactly the
# modules an edge device would need.
echo "arch:   $(uname -m)"
echo "kernel: $(uname -r)"
echo

fails=0
say() { if [ "$2" = "0" ]; then echo "  [ok  ] $1${3:+ — $3}"; else echo "  [FAIL] $1${3:+ — $3}"; fails=$((fails+1)); fi; }

# Bun ships an aarch64 build; whether it runs here is the question, not whether it exists.
if command -v bun >/dev/null; then
  say "bun already present" 0 "$(bun --version)"
else
  # bun's installer unpacks a zip. Missing unzip made the install fail with a message
  # that said so plainly — worth noting, because a runtime that cannot install is
  # indistinguishable from a runtime that cannot run unless the failure names itself.
  command -v unzip >/dev/null || {
    echo "  … unzip absent; installing it first"
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq unzip >/dev/null 2>&1
  }
  command -v unzip >/dev/null; say "unzip available for the installer" $?
  echo "  … installing bun (aarch64) over user-mode NAT"
  export BUN_INSTALL=/usr/local
  if curl -fsSL https://bun.sh/install 2>/dev/null | bash >/tmp/bun-install.log 2>&1; then
    export PATH="/usr/local/bin:$PATH"
    command -v bun >/dev/null; say "bun installed and on PATH" $? "$(bun --version 2>/dev/null)"
  else
    say "bun installed" 1 "install script failed — see /tmp/bun-install.log"
    tail -5 /tmp/bun-install.log 2>/dev/null | sed 's/^/          /'
  fi
fi
export PATH="/usr/local/bin:$PATH"
command -v bun >/dev/null || { echo; echo "RESULT: $fails failure(s) — no runtime, nothing measured"; exit 1; }

# Does it actually EXECUTE aarch64 code, or merely unpack?
bun -e 'console.log("exec-ok", process.arch, process.platform)' > /tmp/bunexec 2>&1
say "bun executes on this architecture" $? "$(cat /tmp/bunexec)"
grep -q "arm64" /tmp/bunexec; say "bun reports arm64, not an emulated x64 build" $?

cp -r /hostshare/edge-ts /tmp/edge-ts 2>/dev/null || { echo "  [FAIL] no edge-ts payload"; exit 1; }
cd /tmp/edge-ts

echo
echo "  running the dependency-light modules' own suites on ARM:"
bun test tests/ > /tmp/ts.out 2>&1
rc=$?
grep -E "^ *[0-9]+ (pass|fail)|Ran [0-9]+ tests" /tmp/ts.out | sed 's/^/    /'
say "the TypeScript layer's tests pass on aarch64" $rc
[ "$rc" -eq 0 ] || tail -20 /tmp/ts.out | sed 's/^/        /'

echo
echo "RESULT: $fails failure(s)"
exit $([ "$fails" -eq 0 ] && echo 0 || echo 1)
