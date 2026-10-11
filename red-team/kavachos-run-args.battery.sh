#!/usr/bin/env bash
# aegis red-team — @xshieldai/agent-kernel: the agent's arguments must not be read as kavachos options.
#
# Through 2.4.0 `kavachos run` read every word starting with "--" as its own option, wherever it stood. A caller
# that passed on arguments it did not write (a workflow node, a wrapper) let those arguments choose the session,
# the trust mask, a dry run, or an unconstrained launch. From 2.5.0 a bare "--" ends kavachos's options.
#
# Every case here is a DRY RUN in a temporary home: a profile is generated and printed, nothing is launched and
# nothing is enforced, so this is safe on any box. It runs an INSTALLED copy of the package.
#
#   ./red-team/kavachos-run-args.battery.sh                  the copy packed from this repository
#   AK_VERSION=2.4.0 ./red-team/kavachos-run-args.battery.sh  that version from the npm registry
#
# Red on 2.4.0, green from 2.5.0. Exit: 0 no gap · 1 a gap · 3 broke.
set -u
[ -n "${RAN_INNER:-}" ] || exec "$(cd "$(dirname "$0")" && pwd)/lib/ran.sh" 9 "$0" "$@"   # green only if the cases ran
HERE="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$HERE/.." && pwd)"
BUN="$(command -v bun || echo /root/.bun/bin/bun)"
echo "=== aegis red-team · kavachos run: the agent's arguments are the agent's ==="
[ -x "$BUN" ] && command -v npm >/dev/null && command -v node >/dev/null || { echo "BROKE — bun, node or npm not found"; exit 3; }
T="$(mktemp -d "${TMPDIR:-/tmp}/ak-args.XXXXXX")"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/app" "$T/home"; echo '{"name":"t","private":true}' > "$T/app/package.json"
if [ -n "${AK_VERSION:-}" ]; then WHAT="@xshieldai/agent-kernel@$AK_VERSION"; SRC="the npm registry"
else
  ( cd "$REPO/packages/kavachos" && "$BUN" run build >/dev/null 2>"$T/build.err" && npm pack --ignore-scripts --pack-destination "$T" >/dev/null 2>&1 ) || { echo "BROKE — could not build and pack packages/kavachos: $(tail -1 "$T/build.err")"; exit 3; }
  WHAT="$(ls "$T"/*.tgz 2>/dev/null | head -1)"; SRC="packed from this repository"; [ -n "$WHAT" ] || { echo "BROKE — no tarball"; exit 3; }
fi
( cd "$T/app" && npm i --ignore-scripts --no-fund --no-audit "$WHAT" >/dev/null 2>&1 ) || { echo "BROKE — install failed ($WHAT)"; exit 3; }
CLI="$T/app/node_modules/@xshieldai/agent-kernel/dist/kavachos.js"; [ -f "$CLI" ] || { echo "BROKE — no dist/kavachos.js in the installed package"; exit 3; }
echo "version: $(node -p "require('$T/app/node_modules/@xshieldai/agent-kernel/package.json').version") ($SRC)"
fail=0
# k <args…> — run `kavachos run <args…>` in the temporary home; stdout in $T/out, stderr in $T/err, status in $rc.
k() { ( cd "$T/home" && env -u KAVACHOS_TRUST_MASK -u KAVACHOS_DOMAIN -u KAVACHOS_DELEGATION_DEPTH -u KAVACHOS_PROXY_URL HOME="$T/home" AEGIS_HOME="$T/home/.aegis" ANKR_STATE_DIR="$T/home/state" timeout 60 "$BUN" "$CLI" run "$@" >"$T/out" 2>"$T/err" ); rc=$?; }
# j <dotted.path> — a value from the JSON a dry run prints ("" when absent or when no JSON was printed).
j() { node -e 'let s=require("fs").readFileSync(process.argv[1],"utf8");const a=s.indexOf("{");let o;try{o=JSON.parse(s.slice(a))}catch{o=undefined}for(const k of process.argv[2].split("."))o=o?.[k];console.log(o===undefined?"":typeof o==="object"?JSON.stringify(o):String(o))' "$T/out" "$1"; }
ok() { echo "  [safe] $1"; }; gap() { echo "  [GAP]  $1"; fail=1; }

# The control: an option written BEFORE the agent's command is honoured, and a dry run launches nothing.
k --dry-run --session-id=CONTROL-1 --trust-mask=0xFF -- echo hello
[ "$rc" = 0 ] && [ "$(j dryRun)" = true ] || { echo "BROKE — a plain dry run did not work (exit $rc): $(head -c 200 "$T/err")"; exit 3; }
[ "$(j sessionId)" = CONTROL-1 ] && ok "control: kavachos's own options, written first, are honoured — session $(j sessionId)" || gap "control: --session-id before the command was not honoured (got '$(j sessionId)')"
BASE="$(j syscallCount)"
k --dry-run -- echo hello; MIN="$(j syscallCount)"
[ -n "$BASE" ] && [ -n "$MIN" ] && [ "$BASE" != "$MIN" ] || { echo "BROKE — trust masks 0xFF and the default give the same profile size ($BASE, $MIN); the next case could not tell them apart"; exit 3; }

# The agent's arguments name a session. It must not become the session.
k --dry-run --trust-mask=0xFF -- echo --session-id=FROM-THE-AGENTS-ARGUMENTS
[ "$(j sessionId)" != FROM-THE-AGENTS-ARGUMENTS ] && [ -n "$(j sessionId)" ] && ok "a session id among the agent's arguments is not taken as the session" || gap "the session was named by the agent's arguments: $(j sessionId)"
# The agent's arguments name a trust mask. The profile must stay the default one.
k --dry-run -- echo --trust-mask=0xFF
[ "$(j syscallCount)" = "$MIN" ] && ok "a trust mask among the agent's arguments does not widen the profile ($MIN syscalls, the default)" || gap "the agent's arguments widened the profile: $(j syscallCount) syscalls, the default is $MIN"
# The agent's arguments say --dry-run. That is the agent's word: this is NOT a dry run, so no profile JSON is
# printed by kavachos for it. Asked with kavachos's own --dry-run in front, so nothing is launched either way:
# the agent's --dry-run must come back among the agent's words.
k --dry-run --trust-mask=0xFF -- echo --dry-run --port 4900 --allow-unconstrained-egress --needs=22 --depth=9
[ "$(j agentCommand)" = '["echo","--dry-run","--port","4900","--allow-unconstrained-egress","--needs=22","--depth=9"]' ] && ok "every word after -- reaches the agent, its own options included" || gap "the agent's command as kavachos would launch it: '$(j agentCommand)' (its options were taken or dropped)"
[ "$(j options.allowUnconstrainedEgress)" = false ] && ok "--allow-unconstrained-egress among the agent's arguments does not loosen the launch" || gap "allowUnconstrainedEgress reads '$(j options.allowUnconstrainedEgress)' with the flag only among the agent's arguments"
[ "$(j options.delegationDepth)" = 1 ] && [ "$(j options.loopbackPorts)" = '[]' ] && ok "--depth and --needs among the agent's arguments are not taken" || gap "depth '$(j options.delegationDepth)', loopback ports '$(j options.loopbackPorts)' with the flags only among the agent's arguments"

# A line that cannot be read is refused, not guessed at.
k --dry-run echo -- hello
[ "$rc" = 2 ] && grep -q 'before "--"' "$T/err" && ok "a command word before -- is refused (exit 2) and the right form is shown" || gap "a command word before -- was accepted (exit $rc)"
k --dry-run --
[ "$rc" != 0 ] && ok "-- with nothing after it is refused (exit $rc)" || gap "-- with nothing after it was accepted"

# Without --, old launch lines keep working, and the words taken from the agent are named aloud.
k --dry-run echo hello --session-id=OLD-FORM
[ "$(j sessionId)" = OLD-FORM ] && grep -q 'NOT passed to the agent' "$T/err" && ok "without -- the old reading holds, with a warning that names the words taken" || gap "without --: session '$(j sessionId)', warning $(grep -c 'NOT passed to the agent' "$T/err")"
echo "EXIT=$fail   (0 = no gap · 1 = a gap · 3 = broke)"
exit $fail
