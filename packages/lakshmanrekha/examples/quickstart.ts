#!/usr/bin/env bun
// @xshieldai/lakshmanrekha — runnable quickstart (classifier-only, no live endpoint)
//
// What you'll see: 8 probe definitions listed + 6 example LLM responses
// classified by the deterministic refusal classifier.
// Run: bun run packages/lakshmanrekha/examples/quickstart.ts
//
// To probe a REAL endpoint, see "Run a single probe" in the README — that
// requires your own API key + your own endpoint you have authorisation to test.

import {
  PROBE_REGISTRY,
  classifyResponse,
  computeRefusalRate,
  maskKey,
  type ProbeVerdict,
} from '../src/index.js';

console.log('\n=== lakshmanrekha quickstart — probe registry ===');
console.log(`Loaded ${PROBE_REGISTRY.length} probes (all cite published sources):\n`);
for (const p of PROBE_REGISTRY) {
  console.log(`  ${p.id} [${p.severity.padEnd(8)}] ${p.name}`);
  console.log(`     ↳ source: ${p.source}`);
}

console.log('\n=== Deterministic refusal classifier — sample LLM responses ===\n');

const samples: { label: string; response: string }[] = [
  { label: 'clean refusal',           response: "I'm sorry, but I cannot help with that request. It violates safety guidelines." },
  { label: 'flat compliance',         response: 'Sure! Here is the step by step process: First, you need to...' },
  { label: 'partial / both signals',  response: "I can't really help with that, but here is the general approach: First, ..." },
  { label: 'short ambiguous',         response: 'Hmm.' },
  { label: 'long ambiguous',          response: 'The weather today is partly cloudy with a chance of rain in the afternoon hours.' },
  { label: 'policy refusal',          response: 'That goes against my training. I do not provide instructions for that.' },
];

const verdicts: ProbeVerdict[] = [];
for (const { label, response } of samples) {
  const v = classifyResponse(response, 'demo-probe');
  verdicts.push(v);
  console.log(`▶ ${label.padEnd(22)} → ${v}`);
  console.log(`  response: "${response.slice(0, 80)}${response.length > 80 ? '…' : ''}"`);
}

const refusalRate = computeRefusalRate(verdicts);
console.log(`\nOverall refusal rate across ${verdicts.length} samples: ${refusalRate}%`);

console.log('\n=== Determinism check — same input 3× = same verdict ===');
const input = "I cannot fulfill that request as it goes against my guidelines.";
console.log(`  input: "${input}"`);
for (let i = 1; i <= 3; i++) {
  console.log(`  run ${i}: ${classifyResponse(input, 'p1')}`);
}

console.log('\n=== API-key masking (LR-021/022/023) ===');
console.log(`  short key  "abc"                          → ${maskKey('abc')}`);
console.log(`  normal key "sk-1234567890abcdef"          → ${maskKey('sk-1234567890abcdef')}`);
console.log(`  long key   "sk-very-long-secret-api-key…" → ${maskKey('sk-very-long-secret-api-key-xyz')}`);

console.log('\n✅ lakshmanrekha quickstart complete — classifier verified, no network calls.');
