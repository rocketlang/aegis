# AF-T-703 — external honeypot manifest: the two exposure switches (founder-applied)

Everything is built and committed: `src/dashboard/routes/tripwire-mcp.ts` serves the MCP
JSON-RPC surface (initialize / tools/list / tools/call) with the inert decoys, WATCH
ledgering to `~/.aegis/tripwire.jsonl`, and staged containment per source IP
(`ext:<ip>`). The route registers in `server.ts` but is DARK until the two switches
below are applied — each one is deliberately a human action (the auto-mode classifier
also refused to let a session apply switch 1, correctly).

## Switch 1 — session-guard pass-through (`src/dashboard/server.ts`)

In the public pass-through list of the session guard (around the `"/demo"` line), add:

```ts
      url === "/mcp" ||          // AF-T-703 external honeypot manifest — bait only, must be reachable (AGT-018)
```

Without it, POST /mcp answers 401 and the surface catches nothing.

## Switch 2 — nginx location (`/etc/nginx/sites-enabled/aegis.xshieldai.com`)

Inside the 443 server block (next to the /dashboard locations):

```nginx
    # ── AF-T-703 Agent Tripwire — external MCP manifest (bait only) ──────────
    location = /mcp {
        proxy_pass http://localhost:4850/mcp;
        proxy_buffering off;
        client_max_body_size 64k;
    }
```

Then: `nginx -t && nginx -s reload` (never the systemd unit — nginx runs under ankr-watch).

## Bring-up + verification

1. Restart the dashboard service so the new route loads (ankr-ctl, the service that owns :4850).
2. Local first (bypasses nginx, proves the route + guard line):
   `curl -s -X POST localhost:4850/mcp -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'`
   → must return the 5 decoy tools.
3. Public: same POST against `https://aegis.xshieldai.com/mcp`.
4. Trip it once from outside: `tools/call` with `db_dump_all_databases` → response is the
   inert `{status:"accepted",ref:...}`; `~/.aegis/tripwire.jsonl` gains a `via:"external-mcp"`
   WATCH entry attributed to `ext:<your ip>`; `aegis tripwire-stage ext:<your ip>` shows the stage.
5. Clear your own test evidence: `aegis tripwire-clear ext:<your ip> --reason "founder deploy test"`.

## Standing properties (do not change casually)

- The endpoint is UNAUTHENTICATED BY DESIGN and serves bait only — no real tool, no real
  state is reachable through it (AGT-018; internal manifests stay clean, INF-AFW-005).
- The handshake name is deliberately plausible (`ankr-ops-tools`) — announcing "tripwire"
  would tip the prober and catch nobody.
- Containment runs in OBSERVE until `aegis tripwire-mode enforce` (AFW-006).
