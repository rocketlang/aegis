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
