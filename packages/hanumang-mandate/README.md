# @rocketlang/hanumang-mandate

Agent delegation credential verifier + 7-axis posture scorer. Pure primitives extracted from the internal **xshieldai-hanumang** Fastify service.

**Two primitives. No DB. No HTTP. Install and use.**

## What this is

`hanumang-mandate` is the credential + posture-scoring layer of HanumanG, the agent-delegation-posture monitor inside xShieldAI. The full service has SQLite-backed attestations, regression alerts, revocation-URL polling, and Forja endpoints — that lives in the closed product. This package is the two primitives the rest of the service is built on: **Mudrika credential verification** and **7-axis posture scoring**.

## Complementary to `@rocketlang/aegis` HanumanG

The aegis package and this package are **different governance moments**, both named "HanumanG":

| | `@rocketlang/aegis` HanumanG | `@rocketlang/hanumang-mandate` |
|---|---|---|
| Question | *Can this agent SPAWN?* | *Is this agent's MANDATE valid? What's its posture?* |
| When | PreToolUse hook (spawn-time) | Continuous (per-action) |
| Output | Binary PASS/FAIL | A/B/C/D/F grade + per-axis score |
| Axes (7) | identity / authorization / scope / budget / depth / purpose / revocability | mudrika_integrity / identity_broadcast / mandate_bounds / proportional_force / return_with_proof / no_overreach / truthful_report |

Use both. They are **not duplicates** — they cover different governance concerns.

## Install

```bash
npm install @rocketlang/hanumang-mandate
# or
bun add @rocketlang/hanumang-mandate
```

## Mudrika — the delegation credential

A Mudrika is a JWT-shaped credential that a principal issues to an agent. It declares: who is acting, on whose behalf, for what task, with what trust mask, in what scope, for how long, with what proof of provenance.

```typescript
import { verifyMudrika } from '@rocketlang/hanumang-mandate';

const mudrika = {
  mudrika_version: 'v1',
  mudrika_id: 'mdr-001-2026-05-16',
  principal_id: 'user:capt-anil',
  agent_id: 'agent:codex-001',
  task_id: 'task:refactor-routes',
  trust_mask: 0b00011111,         // 5 bits set
  scope_key: 'aegis/packages/aegis-guard',
  issued_at: '2026-05-16T12:00:00Z',
  ttl_seconds: 3600,
  required_return_proof: 'pramana_receipt',
  revocation_url: 'https://aegis.rocketlang.dev/mudrika/revoke',
  pramana_chain: ['root', 'pramana:abc123'],
};

const result = verifyMudrika(mudrika, 'agent:codex-001');
// {
//   outcome: 'PASS',                       // or 'FAIL' / 'EXPIRED' / 'REVOKED'
//   failure_reason: null,
//   expires_at: '2026-05-16T13:00:00Z',
//   trust_mask: 31,
//   scope_key: 'aegis/packages/aegis-guard',
//   principal_id: 'user:capt-anil',
//   ...
// }
```

### Phase-1 limit — signature is NOT cryptographically verified

`verifyMudrika()` validates structure + TTL + trust_mask range. It does **not** verify the `signature` field cryptographically. The `signature` is in the payload schema for forward compatibility; today, callers must establish provenance themselves (e.g., authenticated transport, internal trust boundary).

Phase 2 will add signature verification. If you need it now, wrap `verifyMudrika()` with your own crypto check.

## 7-axis posture scorer

The scorer assesses an agent's per-action behaviour across seven axes. Each axis returns 0–100 + an outcome (`PASS` / `WARN` / `FAIL`). The aggregate `PostureScore` uses a **worst-axis floor** (`HNG-YK-001`) — a single FAIL caps the grade at D regardless of how high the average is.

```typescript
import { scoreAxis, computePostureScore } from '@rocketlang/hanumang-mandate';

const axisScores = [
  scoreAxis({
    axis: 'mudrika_integrity',
    mudrika_verified: true,
    mudrika_ttl_remaining_s: 600,
    pramana_chain_depth: 2,
  }),
  scoreAxis({
    axis: 'identity_broadcast',
    self_declared: true,
    declared_fields: ['agentId', 'agentType', 'officerRole', 'scopeKey', 'taskId', 'delegatedBy'],
  }),
  scoreAxis({
    axis: 'mandate_bounds',
    trust_mask_granted: 0b11111,
    trust_mask_requested: 0b01111,
    scope_key_match: true,
    ttl_respected: true,
  }),
  scoreAxis({
    axis: 'proportional_force',
    response_mode: 1,
  }),
  scoreAxis({
    axis: 'return_with_proof',
    receipt_filed: true,
    receipt_signed: true,
    actions_listed: true,
    deviations_reported: true,
  }),
  scoreAxis({
    axis: 'no_overreach',
    trust_mask_granted: 0b11111,
    trust_mask_used: 0b00111,
  }),
  scoreAxis({
    axis: 'truthful_report',
    before_state_present: true,
    after_state_present: true,
    errors_reported: true,
    human_modified_flagged: true,
  }),
];

const posture = computePostureScore(axisScores);
// {
//   overall_score: 100,
//   overall_grade: 'A',
//   violation_count: 0,
//   warn_count: 0,
//   axes: { mudrika_integrity: {...}, identity_broadcast: {...}, ... }
// }
```

### The 7 axes

| Axis | Rule | What it checks |
|---|---|---|
| `mudrika_integrity` | HNG-S-001 | Credential present + verified + non-expiring |
| `identity_broadcast` | HNG-S-002 | Agent self-declared with required fields |
| `mandate_bounds` | HNG-S-003 | Requested mask ≤ granted mask, scope match, TTL respected |
| `proportional_force` | HNG-S-004 | Response mode (1/2/3) properly routed |
| `return_with_proof` | HNG-S-005 | Task closed with signed receipt + actions list |
| `no_overreach` | HNG-S-006 | Used bits ⊆ granted bits + utilisation signal |
| `truthful_report` | HNG-S-007 | before/after state present, errors + human-modification declared |

### Grade thresholds

| Grade | Condition |
|---|---|
| A | overall_score ≥ 90, no violations |
| B | overall_score ≥ 80, no violations |
| C | overall_score ≥ 60, no violations |
| D | overall_score < 60, OR 1–2 violations |
| F | 3+ violations |

## What this package does NOT do

- **No DB.** No persistence. The full xshieldai-hanumang service stores attestations to SQLite — you'd need to write your own store on top of these primitives.
- **No HTTP.** `revocation_url` is in the mudrika payload but `verifyMudrika()` does not call it. The full service does (HNG-S-011, EE feature).
- **No signature crypto.** See Phase-1 limit above.
- **No regression alerting.** The full service tracks posture over time and routes alerts; not here.
- **No registry / fleet view.** That's the EE layer.

## Honest discipline

`hanumang-mandate` was extracted from a service that runs internally at `trust_mask=1`, `claude_ankr_mask=29`, `claw_mask=14255`. Those scores describe the **full service**, not this primitives-only SDK. The package itself is v0.1.0 — a first OSS surface of the credential + scoring primitives, audited in extraction but not independently CA-audited as a standalone artifact.

The Phase-1 signature limit is real. Use this for structural verification in trusted-transport environments, not for crypto-attested mandates over untrusted channels.

## Related

- [`@rocketlang/aegis`](https://www.npmjs.com/package/@rocketlang/aegis) — spawn-time HanumanG + DAN gate + budget caps (complementary to this)
- [`@rocketlang/kavachos`](https://www.npmjs.com/package/@rocketlang/kavachos) — seccomp-bpf + Falco behavior governance
- [`@rocketlang/chitta-detect`](https://www.npmjs.com/package/@rocketlang/chitta-detect) — memory poisoning detection
- [`@rocketlang/lakshmanrekha`](https://www.npmjs.com/package/@rocketlang/lakshmanrekha) — LLM endpoint probe suite
- [`@rocketlang/aegis-guard`](https://www.npmjs.com/package/@rocketlang/aegis-guard) — Five Locks SDK

## License

AGPL-3.0-only. See [LICENSE](LICENSE). Any modified version run as a network service must publish source per AGPL clause 13.

The full xshieldai-hanumang service is internal (port 4255) and not currently distributed.

For commercial dual-licensing or partnership: [captain@ankr.in](mailto:captain@ankr.in).

---

## v0.2.0 — Opt-in Agentic Control Center (ACC) event bus

Added 2026-05-17. `verifyMudrika()`, `scoreAxis()`, and
`computePostureScore()` now emit `AccReceipt` events, **but only when
you wire a bus**. Without `setEventBus`, v0.2.0 behaves identically to
v0.1.0 — no emission, no state, no side effect.

### Wire it in 3 lines

```typescript
import { setEventBus, type EventBus, type AccReceipt } from '@rocketlang/hanumang-mandate';

const myBus: EventBus = {
  emit: (r: AccReceipt) => console.log(`[ACC] ${r.event_type} ${r.verdict} ${r.summary}`),
};
setEventBus(myBus);
```

### Receipt events emitted

| Primitive | event_type | verdict |
|---|---|---|
| `verifyMudrika` (PASS) | `mudrika.verified` | PASS |
| `verifyMudrika` (FAIL / EXPIRED) | `mudrika.rejected` | FAIL |
| `scoreAxis` (per axis) | `posture.axis_scored` | PASS / WARN / FAIL |
| `computePostureScore` (aggregate) | `posture.scored` | `{grade}-{verdict}` (e.g. `A-PASS`, `D-FAIL`) |

### Receipt shape

```typescript
interface AccReceipt {
  receipt_id: string;       // primitive-prefixed: 'hanumang-mudrika-{mudrikaId}' etc.
  primitive: string;        // always 'hanumang-mandate'
  event_type: string;       // 'mudrika.verified' | 'mudrika.rejected' | 'posture.axis_scored' | 'posture.scored'
  emitted_at: string;       // ISO 8601
  agent_id?: string;        // populated from mudrika.agent_id on verifyMudrika; not yet on scoreAxis
  verdict?: string;
  rules_fired?: string[];   // HNG-* rule IDs
  summary?: string;
  payload?: Record<string, unknown>;
}
```

Strict subset of EE PRAMANA receipt format — EE consumers ingest without translation.

### Phase-1 limits (v0.2.0)

- **agent_id is populated on `mudrika.verified` only** — scoreAxis and
  computePostureScore don't currently receive an agent_id parameter. Future
  versions may add an optional `agent_id` field to `AxisInput`; today,
  post-process receipts in the bus to add agent context from your own tracking.
- **scoreAxis emits per call** — if you score 7 axes for one agent, that's
  7 `posture.axis_scored` events + 1 `posture.scored` aggregate = 8 receipts.
  Cockpit consumers may want to collapse these for display.
- **Mudrika signature crypto NOT verified** (unchanged from v0.1.0) —
  emission says `mudrika.verified` based on structural + TTL + trust_mask
  range checks only. Phase-2 will add cryptographic signature verification.
- **Default bus is in-process only.** Multi-process buses are a consumer choice.

### Use with `@rocketlang/aegis-suite`

```typescript
import { wireAllToBus } from '@rocketlang/aegis-suite';  // suite v0.2.0+
wireAllToBus();  // wires aegis-guard + chitta-detect + lakshmanrekha + hanumang-mandate at once
```
