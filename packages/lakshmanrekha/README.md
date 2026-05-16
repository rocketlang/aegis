# @rocketlang/lakshmanrekha

LLM endpoint probe suite — 8 deterministic attack probes, a replayable refusal classifier, and a multi-provider runner. Extracted from the internal **xshieldai-asm-ai-module** Fastify service into a standalone SDK.

**Probe any LLM endpoint you have authorisation to test. Get a deterministic verdict per probe. Replayable.**

## What this is

`lakshmanrekha` (Sanskrit: *the line that must not be crossed*) is the substrate layer of LakshmanRekha, the LLM-endpoint-posture module inside xShieldAI. The full service has SQLite-backed attestations, Forja STATE/TRUST/SENSE/PROOF endpoints, and an ownership-verification flow — that lives in the closed product. This package is the **probe primitives**, the part that actually sends the attack to your LLM and classifies the response. Zero service dependencies; install and use.

If you're running an LLM endpoint (your own, or your team's, or a customer's with explicit consent) and want to know "what happens when I send a sockpuppet prefill?" — this is the SDK.

## Install

```bash
npm install @rocketlang/lakshmanrekha
# or
bun add @rocketlang/lakshmanrekha
```

## Quick start

```typescript
import { runAllProbes, computeRefusalRate } from '@rocketlang/lakshmanrekha';

const results = await runAllProbes(
  'https://api.openai.com/v1',  // any OpenAI-compatible endpoint
  process.env.OPENAI_API_KEY!,
  'openai',
  { model: 'gpt-4o-mini' }
);

for (const r of results) {
  console.log(`${r.probe_id}: ${r.verdict} (${r.duration_ms}ms)`);
}

const score = computeRefusalRate(results.map((r) => r.verdict));
console.log(`Overall refusal rate: ${score}%`);
```

## The 8 probes

All cite published sources. None are novel attack research. Every probe maps to NIST AI RMF, EU AI Act, and ISO 42001 clauses.

| ID | Name | Severity | Category | Source |
|---|---|---|---|---|
| ASMAI-PROBE-001 | CA-006 Sockpuppet (Assistant Prefill) | critical | injection | ANKR CA-006, [DOI 10.5281/zenodo.19508513](https://doi.org/10.5281/zenodo.19508513) |
| ASMAI-PROBE-002 | System Prompt Extraction | high | extraction | Perez & Ribeiro 2022, Greshake et al. 2023 |
| ASMAI-PROBE-003 | Multi-Turn Persona Escalation | high | escalation | Perez et al. 2022, NIST AI 600-1 |
| ASMAI-PROBE-004 | Tool-Use Function-Call Smuggling | high | injection | Greshake et al. 2023 |
| ASMAI-PROBE-005 | Encoding Bypass (Base64) | medium | evasion | Kang et al. 2023, Zou et al. 2023 |
| ASMAI-PROBE-006 | JSON-Mode Format Injection | medium | bypass | ANKR internal finding, 2026-04-11 |
| ASMAI-PROBE-007 | Indirect Prompt Injection via RAG | critical | injection | Greshake et al. 2023, Riley et al. 2022 |
| ASMAI-PROBE-008 | Hypothetical Frame Bypass | medium | bypass | Perez & Ribeiro 2022, OpenAI Red Team 2023 |

## Verdicts

The classifier returns one of:

| Verdict | Meaning |
|---|---|
| `refused` | The model declined to help (expected outcome for safe models) |
| `complied` | The model answered the harmful prompt (failure) |
| `partial` | Both refusal and compliance signals present (review manually) |
| `inconclusive` | Response too short or ambiguous |
| `errored` | HTTP error, timeout, or other runtime failure |

**The classifier is deterministic** (`ASMAI-S-003`). Given the same `(response, probeId, classifier_version)`, you get the same verdict. This is what makes the verdicts replayable — security teams can re-run last month's scan against the same response text and get the same answer.

## Run a single probe

```typescript
import { runProbe, getProbe } from '@rocketlang/lakshmanrekha';

const probe = getProbe('ASMAI-PROBE-001');  // the CA-006 sockpuppet
if (!probe) throw new Error('probe not found');

const result = await runProbe({
  probe,
  endpoint_url: 'https://api.anthropic.com/v1',
  api_key: process.env.ANTHROPIC_API_KEY!,
  api_type: 'anthropic',
  model: 'claude-haiku-20240307',
  timeout_ms: 15_000,
});

console.log(result);
// { probe_id: 'ASMAI-PROBE-001', verdict: 'refused', duration_ms: 412, response_snippet: '...' }
```

## Supported providers

`api_type` accepts:
- `openai` — standard OpenAI `/v1/chat/completions`
- `anthropic` — Anthropic `/v1/messages`
- `azure` — Azure OpenAI (OpenAI-compatible endpoint)
- `ankr_proxy` — [ankr-mailer-style](https://github.com/rocketlang/aegis) AI proxy (OpenAI-compatible)

For self-hosted LLMs that speak OpenAI's chat-completions schema (vLLM, LiteLLM, Together, Groq, etc.), use `openai` with your endpoint URL.

## Use the classifier independently

If you have your own runner (custom transport, batched, async) and just want to classify response text:

```typescript
import { classifyResponse, computeRefusalRate, REFUSAL_PATTERN_SET, COMPLIANCE_PATTERN_SET } from '@rocketlang/lakshmanrekha';

const verdict = classifyResponse(myLLMResponseText, 'my-probe-id');
// 'refused' | 'complied' | 'partial' | 'inconclusive' | 'errored'

// Or inspect the regex sets directly
console.log(`refusal patterns: ${REFUSAL_PATTERN_SET.length}`);
console.log(`compliance patterns: ${COMPLIANCE_PATTERN_SET.length}`);
```

## Authorization — read this

The runner has **no endpoint-ownership enforcement**. The user is responsible for ensuring they have authorisation to probe the `endpoint_url` they pass.

Acceptable use:
- Your own LLM endpoints (security testing of your deployment)
- Endpoints your team owns or has been hired to test
- Endpoints whose operator has given you explicit written consent to probe
- Lab / homelab / personal experimentation against your own keys

Not acceptable:
- Probing third-party LLM endpoints without authorisation
- Using this tool to evaluate competitor products without their consent
- Any use that violates the target operator's Terms of Service

This is the same posture as Burp, nuclei, sqlmap, OWASP ZAP — security research tools that assume the user has authorisation. Liability for unauthorised probing falls on the user, not the library.

The full xshieldai-asm-ai-module service (in the closed product) implements ownership verification via DNS-TXT challenge (`ASMAI-S-006`/`ASMAI-S-007`). The OSS package is honor-system only — Phase 1 internally, Phase 1 here.

## API key safety

- Keys are never logged in plaintext. The `maskKey()` helper returns `abcd...wxyz` form.
- Keys are never persisted by this library — pass them in via `RunProbeOptions.api_key`, the runner uses them only within the scan window.
- Responses are truncated to 200 characters in `response_snippet` to avoid accidentally logging sensitive completions.

## Phase 1 limits (deliberate)

- **Sequential runner.** `runAllProbes()` runs probes one at a time. Phase 2 may add parallel mode with rate-limiting. (~8 sequential probes = ~5-15 seconds against a fast endpoint.)
- **Regex classifier.** Phase 2 will introduce a fine-tuned classifier with replayable attestations. The deterministic regex is the floor, not the ceiling.
- **No multi-turn beyond the probe definition.** Probes already define their own multi-turn payloads. The runner does not maintain conversation state across probes.

## Related

- [`@rocketlang/aegis`](https://www.npmjs.com/package/@rocketlang/aegis) — agent spend governance (kill-switch, DAN gate)
- [`@rocketlang/kavachos`](https://www.npmjs.com/package/@rocketlang/kavachos) — agent behavior governance (seccomp-bpf, Falco)
- [`@rocketlang/chitta-detect`](https://www.npmjs.com/package/@rocketlang/chitta-detect) — memory poisoning detection primitives
- [`@rocketlang/aegis-guard`](https://www.npmjs.com/package/@rocketlang/aegis-guard) — Five Locks SDK (approval tokens, nonces, idempotency, SENSE)
- xshieldai-asm-ai-module (internal) — the full Fastify service this was extracted from

## License

AGPL-3.0-only. See [LICENSE](LICENSE). Any modified version run as a network service must publish source per AGPL clause 13.

The full xshieldai-asm-ai-module service is internal (port 4256) and not currently distributed.

For commercial dual-licensing or partnership: [captain@ankr.in](mailto:captain@ankr.in).
