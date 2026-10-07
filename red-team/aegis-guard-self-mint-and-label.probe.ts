// atma-pariksha — ADVERSARIAL battery for @xshieldai/aegis-guard.
// Reproduces an independent security review's findings (Oct 2026) as red tests against the PUBLISHED
// package: the self-mint (approval authority at the agent's own uid) and label-not-act (a token binds to
// a label, not the concrete arguments). A "GAP" line means the exploit SUCCEEDED — the battery is RED
// until the code is fixed, then these flip to "safe".
//
// Our earlier batteries tested the happy/property paths and the signature lock (a verifier given only a
// public key cannot mint). They did NOT test the case where the attacker runs at the SAME uid as the
// signer — which is the real deployment. That is the gap this battery closes in our own testing.
//
// Usage: bun adversarial-aegis-guard-probe.ts   (run with HOME pointed at a throwaway; @xshieldai/aegis-guard installed)
import { ensureSigningKeypair, mintApprovalToken, verifyApprovalToken } from '@xshieldai/aegis-guard';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

let gaps = 0;
const R = (id: string, exploitWorked: boolean, detail: string) => {
  console.log(`  [${exploitWorked ? 'GAP ' : 'safe'}] ${id} — ${detail}`);
  if (exploitWorked) gaps++;
};
const now = Date.now(); // ms — verifyApprovalToken compares expires_at against Date.now()
const approval = (op: string) => ({ service_id: 'db', capability: 'schema', operation: op, issued_at: now, expires_at: now + 300_000, status: 'approved' as const });

// ── P1: self-mint — the approver lives at the agent's own uid (review point 1, RAN) ───────────────
// The "operator/dashboard" provisions the signing key. An agent at the SAME uid can read that key and
// mint its own approval; mintApprovalToken reads the same key, so calling it IS the exploit.
ensureSigningKeypair();
const keyPath = join(process.env.HOME || '/root', '.aegis', 'approval-signing.key');
let keyReadable = false;
try { readFileSync(keyPath, 'utf8'); keyReadable = true; } catch { /* not readable */ }
const selfMinted = mintApprovalToken(approval('drop_table'));
let accepted = false;
try { verifyApprovalToken(selfMinted, 'db', 'schema', 'drop_table'); accepted = true; } catch { /* rejected */ }
R('P1 self-mint', keyReadable && accepted,
  `agent at the same uid reads the signing key (${keyReadable ? 'READABLE' : 'not readable'}) and mints its own 'drop_table' approval → verify ${accepted ? 'ACCEPTS it — no operator took part' : 'rejects'}`);

// ── P4: label-not-act — a token binds to a label, not the concrete arguments (review point 4) ─────
// One 'drop_table' approval carries no field naming WHICH table. So it authorises dropping any table.
const tok = mintApprovalToken(approval('drop_table'));
const payload = verifyApprovalToken(tok, 'db', 'schema', 'drop_table') as Record<string, unknown>;
const argFields = ['table', 'target', 'arguments', 'args', 'action_digest', 'payload_digest', 'resource'];
const bindsToAct = argFields.some((f) => f in payload);
R('P4 label-not-act', !bindsToAct,
  `the verified 'drop_table' token carries no concrete-argument field (${argFields.join('/')}) — one approval drops ANY table; a digest of the action would bind it`);

console.log(`\n  adversarial-aegis-guard: ${gaps} gap(s) reproduced${gaps === 0 ? ' — all closed ✓' : ' (RED until fixed)'}`);
process.exit(gaps > 0 ? 1 : 0);
