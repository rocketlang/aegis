# @rocketlang/aegis-suite

**Meta-package.** Installs the full open-source AEGIS / KavachOS / xShieldAI agent governance stack in one shot.

```bash
npm install @rocketlang/aegis-suite
# or
bun add @rocketlang/aegis-suite
```

That's it. You now have all six primitives. Import from each sub-package by name (this meta-package does not re-export — keep your imports honest about which primitive you're using).

## What's bundled (6 packages)

| Package | Role | Phase |
|---|---|---|
| [`@rocketlang/aegis`](https://www.npmjs.com/package/@rocketlang/aegis) | Agent **spend** governance: budget caps, kill-switch, DAN gate, HanumanG 7-axis spawn check | v2.1.0 stable |
| [`@rocketlang/kavachos`](https://www.npmjs.com/package/@rocketlang/kavachos) | Agent **behavior**: seccomp-bpf, Falco, syscall mediation, exec allowlist, egress firewall | v2.0.2 stable |
| [`@rocketlang/aegis-guard`](https://www.npmjs.com/package/@rocketlang/aegis-guard) | Five Locks SDK: approval-token, nonce, idempotency, SENSE, quality-evidence | v0.1.0 |
| [`@rocketlang/chitta-detect`](https://www.npmjs.com/package/@rocketlang/chitta-detect) | Memory poisoning detection: trust / imperative / tool-output / capability-expansion / fingerprint scanners | v0.1.0 |
| [`@rocketlang/lakshmanrekha`](https://www.npmjs.com/package/@rocketlang/lakshmanrekha) | LLM endpoint probe suite: 8 deterministic attack probes + replayable refusal classifier + multi-provider runner | v0.1.0 |
| [`@rocketlang/hanumang-mandate`](https://www.npmjs.com/package/@rocketlang/hanumang-mandate) | Mudrika delegation-credential verifier + 7-axis posture scorer | v0.1.0 |

## Deliberately NOT bundled

| Package | Why excluded |
|---|---|
| `@rocketlang/n8n-nodes-kavachos` | n8n-specific integration — `npm install @rocketlang/n8n-nodes-kavachos` separately if you use n8n. Excluded so non-n8n users don't pull n8n-shaped deps. |
| `@rocketlang/kavachos-ee` | BSL-1.1 Enterprise Edition (PRAMANA Merkle ledger, HanumanG EE posture registry, dual-control approvals, multi-tenant isolation). Not published to npm. Contact [captain@ankr.in](mailto:captain@ankr.in) for design partner access. |

## Why a meta-package and not a fused single package?

The 6 primitives are **deliberately separate** — each addresses a different governance moment (spend / behavior / approval / memory / LLM probing / delegation). Forcing them into one fused package would:

- Multiply per-primitive deps for users who only need one
- Bundle SQLite + Postgres + fastify + bun-specific code for users running in browsers/edge
- Conflate the "stop bad spend" concern with the "verify mandate credentials" concern when neither needs the other

This meta-package is the **convenience installer**, not a re-architected mono-product. You get them all at once; you still import from each by name.

## The unified workflow (after install)

### Day-1: Aegis CLI sets up the spend gate

```bash
# Installed globally via @rocketlang/aegis bin
aegis init
aegis-monitor &
aegis-dashboard &
# → http://localhost:4850 (KAVACH DAN Gate dashboard)
```

### Day-1: Probe your LLM endpoint with lakshmanrekha

```typescript
import { runAllProbes, computeRefusalRate } from '@rocketlang/lakshmanrekha';

const results = await runAllProbes(
  'https://api.openai.com/v1',
  process.env.OPENAI_API_KEY!,
  'openai',
  { model: 'gpt-4o-mini' }
);
console.log(`Refusal rate: ${computeRefusalRate(results.map(r => r.verdict))}%`);
```

### Day-2: Scan persistent memory writes with chitta-detect

```typescript
import { scan } from '@rocketlang/chitta-detect';

const result = scan.evaluate(suspiciousMemoryContent, { agent_id: 'agent-001' });
if (result.verdict === 'BLOCK') {
  throw new Error(`memory write blocked: ${result.rules_fired.join(', ')}`);
}
```

### Day-3: Verify agent mandates with hanumang-mandate

```typescript
import { verifyMudrika, scoreAxis, computePostureScore } from '@rocketlang/hanumang-mandate';

const mandate = verifyMudrika(receivedMudrika, expectedAgentId);
if (mandate.outcome !== 'PASS') {
  throw new Error(`mandate rejected: ${mandate.failure_reason}`);
}
```

### Day-4: Wire Five Locks with aegis-guard

```typescript
import { verifyApprovalToken, emitAegisSenseEvent, checkIdempotency } from '@rocketlang/aegis-guard';

// LOCK_1 — verify approval token before irreversible action
const payload = verifyApprovalToken(token, 'my-service', 'settle', 'record_settle');

// LOCK_3 — emit SENSE event with before/after delta
emitAegisSenseEvent({ event_type: 'allowance.settle', /* ... */ });
```

### Day-N: Kernel-enforce behavior with kavachos (when ready)

```bash
# Installed via @rocketlang/kavachos bin (note: bin name collision with aegis's
# bundled kavachos shim — use whichever is on your PATH first; both point at
# the same kernel-enforcement primitives)
kavachos audit ./my-agent.config.json
kavachos generate seccomp ./policy.bpf
```

## Why this matters — the open primitive vs the hosted product

[Fin Operator](https://www.fin.ai/) launched 2026-05-15 as a Pro-tier subscription product whose "proposal system" puts a human gate between AI agents and the systems they change. The same primitives — pull-request-shaped intercepts, agent-managing-agent, attestation chains — are open and self-hostable here. `aegis` was born 17 April 2026, about a month before Fin Operator's launch, from a real $200 incident with an unmonitored Claude Code session.

| | Fin Operator (2026-05-15) | @rocketlang/aegis-suite (2026-05-16) |
|---|---|---|
| Distribution | Pro-tier subscription, vendor-hosted | `npm install @rocketlang/aegis-suite`, self-hosted |
| License | Proprietary | AGPL-3.0-only (suite) + BSL-1.1 → AGPL-3.0 in 4 years (EE) |
| Scope | Bound to the Fin platform | Vendor-neutral (Claude Code, OpenAI Codex, Cursor, custom) |
| Self-host | No | Yes — local-first by default |
| Audit | Trust the vendor | `grep -rn "fetch(" node_modules/@rocketlang/*/src/` |
| Pricing | Pro tier + usage blocks | $0 OSS · BSL-1.1 EE free up to 3 concurrent sessions |

## License

AGPL-3.0-only (the meta-package itself + all 6 bundled packages). Any modified version run as a network service must publish source per AGPL clause 13.

EE packages (BSL-1.1) are separate — see boundary doc at [OPEN-CORE-BOUNDARY.md](https://github.com/rocketlang/aegis/blob/main/OPEN-CORE-BOUNDARY.md).

For commercial dual-licensing: [captain@ankr.in](mailto:captain@ankr.in).

---

## v0.2.0 — `wireAllToBus()` + Agentic Control Center event bus

Added 2026-05-17. One call wires all 4 OSS primitives (aegis-guard,
chitta-detect, lakshmanrekha, hanumang-mandate) to a single event bus
+ persists every event to SQLite at `~/.aegis/acc-events.db`. The
aegis dashboard (v2.2.0+, ships same release wave) reads from this
file to render the **Agentic Control Center** page at
`http://localhost:4850/control-center`.

### Quick start

```typescript
import { wireAllToBus } from '@rocketlang/aegis-suite';

// One call — wires all 4 primitives + sets up SQLite writer
const handle = wireAllToBus();

console.log('Events persisting to:', handle.sqlitePath);
// → /home/you/.aegis/acc-events.db

// Now use any of the @rocketlang primitives normally — every operation
// emits a receipt that lands in the SQLite file:
import { verifyApprovalToken } from '@rocketlang/aegis-guard';
import { scan } from '@rocketlang/chitta-detect';

verifyApprovalToken(token, 'svc', 'cap', 'op');     // → emits lock.approval.verified
scan.evaluate(content, { agent_id: 'agent-1' });    // → emits scan.evaluated
```

### View live in the Agentic Control Center

If you also have `@rocketlang/aegis` v2.2.0+ installed and the dashboard
running (`aegis-dashboard &`), visit:

- **`http://localhost:4850/control-center`** — single-page grid with 6
  zones (one per primitive + PRAMANA panel)
- **`http://localhost:4850/agent/:id`** — per-agent timeline across all
  primitives, ordered by emission time
- **`http://localhost:4850/api/acc/events`** — JSON query API
- **`http://localhost:4850/api/acc/health`** — counts by primitive

All routes are gated by the dashboard's session auth when
`dashboard.auth.enabled: true` in `~/.aegis/config.json` (the default
after `aegis init`).

### Subscribe to events live (custom processing)

```typescript
const handle = wireAllToBus();
const unsub = handle.subscribe!((receipt) => {
  if (receipt.verdict === 'BLOCK' || receipt.verdict === 'FAIL') {
    notifyOps(receipt);  // your custom alerting
  }
});
// later: unsub() to detach
```

### Bring your own bus

```typescript
import type { EventBus, AccReceipt } from '@rocketlang/aegis-suite';

const myBus: EventBus = {
  emit: (r: AccReceipt) => sendToRedis(r),  // your transport
};

wireAllToBus({ bus: myBus });  // no SQLite, no in-memory fan-out — fully delegated
```

### Detach when done

```typescript
import { unwireAll } from '@rocketlang/aegis-suite';
unwireAll();  // all 4 primitives revert to v0.1.0 (no emission)
```

### Architecture

```
consumer process
  ├─ wireAllToBus() ──┬─ setEventBus on aegis-guard
  │                   ├─ setEventBus on chitta-detect
  │                   ├─ setEventBus on lakshmanrekha
  │                   └─ setEventBus on hanumang-mandate
  │
  ├─ InMemoryBus ──┬─ fan-out to subscribers (your live listeners)
  │                └─ SqliteEventWriter ──> ~/.aegis/acc-events.db
  │
  └─ (your code calls primitives normally)

aegis-dashboard (separate process, v2.2.0+)
  └─ reads ~/.aegis/acc-events.db
     └─ /control-center, /agent/:id, /api/acc/*
```

### Phase-1 limits (v0.2.0)

- **Same-process vs cross-process visibility.** When the consumer
  process and dashboard process are different (typical: your app + the
  aegis-dashboard service), the consumer writes to SQLite via WAL.
  Reader-side visibility lags slightly because WAL pages are not
  automatically checkpointed back to the main DB file until
  ~1000 writes accumulate. **If you want immediate cross-process
  visibility, call `handle.checkpoint!()`** after a batch of activity
  (e.g., end-of-request handler) or periodically (e.g., every 30s).
  Single-process (consumer == dashboard) needs no checkpointing.
- **`@rocketlang/aegis` v2.2.0 required for the cockpit UI.** The
  dashboard at port 4850 needs aegis v2.2.0 (which ships in this same
  release wave) to expose the `/control-center` route. Events still
  persist to SQLite with any aegis version; only the rendering layer
  needs v2.2.0.
- **Default bus is in-process only.** Multi-process buses (Redis,
  Kafka, NATS) are a consumer choice — implement the `EventBus`
  interface and pass via `wireAllToBus({ bus: yourBus })`.
- **WAL files (`-wal`, `-shm`) accompany `acc-events.db`.** If you
  move/copy the SQLite file, take all three together or call
  `checkpoint()` first to consolidate into the main file.
- **`@rocketlang/n8n-nodes-kavachos` is NOT wired.** It's an n8n
  integration, not a primitive — its event-bus story is the consumer's
  n8n workflow, not `wireAllToBus`.

### SQLite schema (for direct query access)

```sql
CREATE TABLE acc_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  receipt_id  TEXT NOT NULL,
  primitive   TEXT NOT NULL,      -- 'aegis-guard' | 'chitta-detect' | etc.
  event_type  TEXT NOT NULL,      -- 'lock.approval.verified' | 'scan.evaluated' | etc.
  emitted_at  TEXT NOT NULL,      -- ISO 8601
  agent_id    TEXT,
  verdict     TEXT,               -- PASS | FAIL | BLOCK | etc.
  rules_fired TEXT,               -- JSON array, e.g. '["AEG-E-016"]'
  summary     TEXT,
  payload     TEXT,               -- JSON object
  ingested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
-- Indexes on (primitive, emitted_at), (agent_id, emitted_at), event_type, id
```

Schema is forward-compatible-additive only (ACC-YK-006) — fields added,
never removed or renamed. Direct SQL queries from external tools
(Grafana, datadog-agent, custom scripts) are supported and stable.
