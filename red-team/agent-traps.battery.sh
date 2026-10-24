#!/usr/bin/env bash
# aegis red-team — maritime agent traps: a local model as a ship manager's assistant, alone and behind
# the gates aegis has. 10 public traps + 3 controls here; 20 more held out (AGENT_TRAPS_HELDOUT). See the probe.
#
#   ./red-team/agent-traps.battery.sh                                   public set, qwen2.5:7b
#   AGENT_TRAPS_MODEL=llama3.1:8b ./red-team/agent-traps.battery.sh      another local model
#   AGENT_TRAPS_HELDOUT=<file> AGENT_TRAPS_OUT=<dir> ./red-team/agent-traps.battery.sh
#
# Needs a local Ollama with the model pulled. On CPU a trap takes minutes: the full set takes hours.
# RED by design until aegis has a gate for every act a trap covers. Exit: 0 no gap · 1 a gap · 3 broke.
set -u
export RAN_MARK="${RAN_MARK:-^[[:space:]]*\[(safe|GAP |unreached)\]}"
[ -n "${RAN_INNER:-}" ] || exec "$(cd "$(dirname "$0")" && pwd)/lib/ran.sh" 13 "$0" "$@"   # green only if the cases ran
HERE="$(cd "$(dirname "$0")" && pwd)"; BUN="$(command -v bun || echo /root/.bun/bin/bun)"
echo "=== aegis red-team · maritime agent traps, alone and behind aegis ==="
[ -x "$BUN" ] || { echo "BROKE — bun not found"; exit 3; }
# The port comes from the box's port authority when there is one; Ollama's default otherwise.
if [ -z "${OLLAMA_URL:-}" ] && [ -r /root/.ankr/config/ports.json ]; then
  P="$(node -p 'JSON.stringify(require("/root/.ankr/config/ports.json")).match(/"ollama":(\d+)/)?.[1] ?? ""' 2>/dev/null)"
  [ -n "$P" ] && export OLLAMA_URL="http://127.0.0.1:$P"
fi
T="$(mktemp -d "${TMPDIR:-/tmp}/agent-traps.XXXXXX")"; trap 'rm -rf "$T"' EXIT
HOME="$T" timeout "${AGENT_TRAPS_TIMEOUT:-36000}" "$BUN" "$HERE/agent-traps.probe.ts"; rc=$?
[ "$rc" -gt 1 ] && rc=3
echo "EXIT=$rc   (0 = no trap got past aegis and no control was over-blocked · 1 = a gap, RED · 3 = broke / could not run)"
exit $rc
