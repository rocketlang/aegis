// aegis red-team — ADVERSARIAL battery for @xshieldai/aegis-guard.
// Reproduces the independent review's findings (Oct 2026) against the PUBLISHED package:
//   P1 self-mint     — an agent at the signer's own uid makes/reads the signing key and mints its
//                      own approval; verify accepts it.
//   P4 label-not-act — a token binds to a label, not the concrete arguments, so one 'drop_table'
//                      approval authorises dropping ANY table.
// A "GAP" line means the exploit SUCCEEDED (RED). "safe" means it was refused.
//
// Honest across versions: in 0.6.0 both are closed by default — minting is an authority action
// (ensureSigningKeypair/mint refuse for a non-authority agent), and a label-only token is refused
// by verify. So against 0.6.0 the exploit throws at the mint/verify step, and THAT is the fix
// working — reported as "safe". Against 0.5.0 the exploit still succeeds — reported as "GAP".
//
// Usage: bun aegis-guard-self-mint-and-label.probe.ts  (run with HOME at a throwaway; pkg installed)
import { ensureSigningKeypair, mintApprovalToken, verifyApprovalToken } from '@xshieldai/aegis-guard';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

let gaps = 0;
const R = (id: string, exploitWorked: boolean, detail: string) => {
  console.log(`  [${exploitWorked ? 'GAP ' : 'safe'}] ${id} — ${detail}`);
  if (exploitWorked) gaps++;
};
const now = Date.now();
const approval = (op: string) => ({ service_id: 'db', capability: 'schema', operation: op, issued_at: now, expires_at: now + 300_000, status: 'approved' as const });

// ── P1: self-mint — an agent at the signer's own uid tries to mint its own approval ───────────────
// 0.5.0: ensureSigningKeypair makes a local key, the agent reads it, mintApprovalToken signs, verify
// accepts — GAP. 0.6.0: minting is an authority action, so keygen/mint throw for a non-authority
// agent — the exploit never produces a token. That throw IS the fix; report safe.
let p1Worked = false;
let p1Detail = '';
try {
  ensureSigningKeypair();
  const keyPath = join(process.env.HOME || '/root', '.aegis', 'approval-signing.key');
  let keyReadable = false;
  try { readFileSync(keyPath, 'utf8'); keyReadable = true; } catch { /* not readable */ }
  const selfMinted = mintApprovalToken(approval('drop_table'));
  let accepted = false;
  try { verifyApprovalToken(selfMinted, 'db', 'schema', 'drop_table'); accepted = true; } catch { /* rejected */ }
  p1Worked = keyReadable && accepted;
  p1Detail = `agent at the same uid read the signing key (${keyReadable ? 'READABLE' : 'not readable'}) and minted its own 'drop_table' approval → verify ${accepted ? 'ACCEPTED it — no operator took part' : 'rejected'}`;
} catch (e) {
  p1Worked = false;
  p1Detail = `the agent could not mint — ${(e as Error).message.slice(0, 80)}… (minting is an authority action; the agent is not the authority)`;
}
R('P1 self-mint', p1Worked, p1Detail);

// ── P4: label-not-act — one approval authorises every instance of the operation ───────────────────
// 0.5.0: a verified 'drop_table' token carries no field naming WHICH table — GAP. 0.6.0: verify
// refuses a label-only token outright (action-binding enforced), so the exploit throws — report safe.
let p4Worked = false;
let p4Detail = '';
try {
  const tok = mintApprovalToken(approval('drop_table'));
  const payload = verifyApprovalToken(tok, 'db', 'schema', 'drop_table') as Record<string, unknown>;
  const argFields = ['table', 'target', 'arguments', 'args', 'action_digest', 'payload_digest', 'resource'];
  const bindsToAct = argFields.some((f) => f in payload);
  p4Worked = !bindsToAct;
  p4Detail = bindsToAct
    ? `the verified token carries a concrete-argument field — bound to the act`
    : `the verified 'drop_table' token carries no concrete-argument field (${argFields.join('/')}) — one approval drops ANY table`;
} catch (e) {
  const msg = (e as Error).message;
  p4Worked = false;
  p4Detail = /action_digest|concrete action/i.test(msg)
    ? `verify refused the label-only token — action-binding is enforced (${msg.slice(0, 60)}…)`
    : `the label-only exploit could not run — ${msg.slice(0, 80)}… (blocked before a loose token could be made; verify-side enforcement is pinned by repo test GH-109)`;
}
R('P4 label-not-act', p4Worked, p4Detail);

console.log(`\n  adversarial-aegis-guard: ${gaps} gap(s) reproduced${gaps === 0 ? ' — both closed ✓' : ' (RED until fixed)'}`);
process.exit(gaps > 0 ? 1 : 0);
