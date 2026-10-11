#!/usr/bin/env bash
# aegis red-team — @xshieldai/agent-kernel: the published package holds the files its own code reaches for.
#
# Through 2.6.0 the bundle left out two things the launcher uses:
#   - dns-proxy.py, which the egress supervisor loads from beside itself. Without it the supervisor leaves name
#     lookups denied (the safe direction), so an agent under egress enforcement could resolve nothing at all;
#   - the AppArmor profile and its install script, which the launcher's own warning tells the user to run. The
#     warning named a path inside the source repository.
#
# Reads an INSTALLED copy. Nothing is launched and nothing is installed into the system.
#
#   ./red-team/kavachos-bundle-files.battery.sh                   the copy packed from this repository
#   AK_VERSION=2.6.0 ./red-team/kavachos-bundle-files.battery.sh   that version from the npm registry
#
# Red on 2.6.0, green from 2.6.1. Exit: 0 no gap · 1 a gap · 3 broke.
set -u
[ -n "${RAN_INNER:-}" ] || exec "$(cd "$(dirname "$0")" && pwd)/lib/ran.sh" 5 "$0" "$@"   # green only if the cases ran
HERE="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$HERE/.." && pwd)"
BUN="$(command -v bun || echo /root/.bun/bin/bun)"
echo "=== aegis red-team · agent-kernel: the package holds the files its code reaches for ==="
for c in node npm python3; do command -v "$c" >/dev/null || { echo "BROKE — $c not found"; exit 3; }; done
T="$(mktemp -d "${TMPDIR:-/tmp}/ak-files.XXXXXX")"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/app"; echo '{"name":"t","private":true}' > "$T/app/package.json"
if [ -n "${AK_VERSION:-}" ]; then WHAT="@xshieldai/agent-kernel@$AK_VERSION"; SRC="the npm registry"
else
  [ -x "$BUN" ] || { echo "BROKE — bun not found"; exit 3; }
  ( cd "$REPO/packages/kavachos" && "$BUN" run build >/dev/null 2>"$T/build.err" && npm pack --ignore-scripts --pack-destination "$T" >/dev/null 2>&1 ) || { echo "BROKE — could not build and pack packages/kavachos: $(tail -1 "$T/build.err")"; exit 3; }
  WHAT="$(ls "$T"/*.tgz 2>/dev/null | head -1)"; SRC="packed from this repository"; [ -n "$WHAT" ] || { echo "BROKE — no tarball"; exit 3; }
fi
( cd "$T/app" && npm i --ignore-scripts --no-fund --no-audit "$WHAT" >/dev/null 2>&1 ) || { echo "BROKE — install failed ($WHAT)"; exit 3; }
D="$T/app/node_modules/@xshieldai/agent-kernel/dist"; [ -f "$D/kavachos.js" ] && [ -f "$D/cgroup-egress.py" ] || { echo "BROKE — the bundle or the egress supervisor is missing from the install"; exit 3; }
echo "version: $(node -p "require('$T/app/node_modules/@xshieldai/agent-kernel/package.json').version") ($SRC)"
fail=0; ok() { echo "  [safe] $1"; }; gap() { echo "  [GAP]  $1"; fail=1; }

# The supervisor names the helper it loads; that name must be a file beside it, and it must load.
want="$(grep -o '"[a-z-]*proxy\.py"' "$D/cgroup-egress.py" | head -1 | tr -d '"')"
[ -n "$want" ] || { echo "BROKE — could not find which helper the egress supervisor loads"; exit 3; }
[ -f "$D/$want" ] && ok "the name-resolver helper the supervisor loads ($want) is in the package" || gap "the egress supervisor loads $want from beside itself, and the package does not hold it: under egress enforcement the agent gets no name lookups"
r="$(python3 -I - "$D/$want" <<'PY' 2>&1
import importlib.util, sys
try:
    s = importlib.util.spec_from_file_location("kavachos_dns_proxy", sys.argv[1]); m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
    print("loads" if all(hasattr(m, n) for n in ("ResolvingProxy", "allowed_names", "first_upstream")) else "loads-but-incomplete")
except Exception as e:
    print("does-not-load")
PY
)"
[ "$r" = loads ] && ok "the helper loads the way the supervisor loads it, with the three things it uses" || gap "the helper $r"
# The path jail: profile and install script, where the launcher will say they are.
[ -f "$D/apparmor/kavachos-agent.profile" ] && grep -q 'profile kavachos-agent' "$D/apparmor/kavachos-agent.profile" && ok "the AppArmor profile is in the package" || gap "the AppArmor profile is not in the package"
[ -f "$D/apparmor/install.sh" ] && grep -q 'kavachos-agent.profile' "$D/apparmor/install.sh" && ok "its install script is in the package, beside the profile it installs" || gap "the install script the launcher tells the user to run is not in the package"
if grep -q 'src/kernel/apparmor/install.sh' "$D/kavachos.js"; then gap "the launcher's warning names a path inside the source repository (src/kernel/apparmor/install.sh), which an installed package does not have"
else ok "the launcher's warning no longer names a path that exists only in the source repository"; fi
echo "EXIT=$fail   (0 = no gap · 1 = a gap · 3 = broke)"
exit $fail
