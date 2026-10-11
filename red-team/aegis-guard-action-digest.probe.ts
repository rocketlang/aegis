// aegis red-team — @xshieldai/aegis-guard: is an approval for one act accepted for a DIFFERENT act?
//
// Since 0.6.0 an approval must name the concrete act (action_digest). Through 0.6.0 the digest gave every
// value JSON cannot carry a guessed spelling, and the guesses collided: a Date, a URL, a Set, a Map, a RegExp
// and any class instance were all "{}"; NaN, Infinity and undefined were all "null". So an approval minted for
// one such act verified for another (found 11 October 2026 against the published 0.6.0). From 0.6.1 an action
// is plain data or it is refused with the package's own error.
//
// A "GAP" line means the second act was ACCEPTED on the first act's approval, or a value the digest cannot
// carry was not refused with IrrNoApprovalError. Run by aegis-guard-action-digest.battery.sh against an
// installed copy, with a throwaway key directory.
import * as g from '@xshieldai/aegis-guard';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

process.env.AEGIS_DIR = mkdtempSync(join(tmpdir(), 'guard-probe-'));
process.env.AEGIS_MINT_AUTHORITY = '1';
delete process.env.AEGIS_ALLOW_LABEL_ONLY_APPROVAL;
g.ensureSigningKeypair();

let gaps = 0; let broke = false;
const line = (tag: 'GAP ' | 'safe' | 'BROKE', name: string, note: string) => {
  if (tag === 'GAP ') gaps++; if (tag === 'BROKE') broke = true;
  console.log(`  [${tag}] ${name} — ${note}`);
};
const base = () => ({ service_id: 'svc', capability: 'pay', operation: 'send', nonce: crypto.randomUUID(), issued_at: Date.now(), expires_at: Date.now() + 60_000 });
const kind = (e: unknown) => (e as { constructor?: { name?: string } })?.constructor?.name ?? 'error';

// The controls: without them "refused" below could mean "nothing is ever accepted".
try {
  const t = g.mintActionApprovalToken(base(), { to: 'alice', amount: 100, tags: ['a', 'b'], note: null });
  g.verifyActionApprovalToken(t, 'svc', 'pay', 'send', { amount: 100, note: null, tags: ['a', 'b'], to: 'alice' });
  line('safe', 'control: the same plain act, keys in another order, is accepted', 'accepted');
  try { g.verifyActionApprovalToken(t, 'svc', 'pay', 'send', { to: 'mallory', amount: 100, tags: ['a', 'b'], note: null }); line('GAP ', 'control: another recipient as text', 'ACCEPTED'); }
  catch (e) { line(kind(e) === 'IrrNoApprovalError' ? 'safe' : 'BROKE', 'control: another recipient as text is refused', kind(e)); }
} catch (e) { line('BROKE', 'control: a plain act could not be minted and verified', String((e as Error).message).slice(0, 120)); }

// One approval, two different acts.
function cross(name: string, a: unknown, b: unknown) {
  let token: string;
  try { token = g.mintActionApprovalToken(base(), a); }
  catch (e) { line(kind(e) === 'IrrNoApprovalError' ? 'safe' : 'GAP ', name, `not minted: ${kind(e)}`); return; }
  try { g.verifyActionApprovalToken(token, 'svc', 'pay', 'send', b); line('GAP ', name, 'the second act was ACCEPTED on the first act\'s approval'); }
  catch (e) { line(kind(e) === 'IrrNoApprovalError' ? 'safe' : 'GAP ', name, `refused at verify: ${kind(e)}`); }
}
cross('Date: 1 Jan 2026 / 1 Jan 2030', { run_at: new Date('2026-01-01') }, { run_at: new Date('2030-01-01') });
cross('URL: a.example / evil.example', { target: new URL('https://a.example/') }, { target: new URL('https://evil.example/') });
cross('Set: {alice} / {mallory}', { to: new Set(['alice']) }, { to: new Set(['mallory']) });
cross('Map: table=logs / table=users', { args: new Map([['table', 'logs']]) }, { args: new Map([['table', 'users']]) });
cross('RegExp: /^tmp_/ / /.*/', { match: /^tmp_/ }, { match: /.*/ });
cross('amount NaN / amount null', { amount: NaN }, { amount: null });
cross('amount Infinity / amount null', { amount: Infinity }, { amount: null });
cross('limit undefined / limit null', { limit: undefined }, { limit: null });
cross('a hole in a list / null in a list', { ids: [1, , 3] }, { ids: [1, null, 3] });
cross('class instance holding 100 / holding 1000000', new (class Money { #v = 100; })(), new (class Money { #v = 1_000_000; })());
cross('a Date as the whole act / an empty object', new Date(0), {});
cross('a function field / null', { then: () => 1 }, { then: null });
cross('a symbol-keyed field / none', { a: 1, [Symbol('to')]: 'alice' }, { a: 1 });

// What the digest cannot carry is refused with the package's own error, never a TypeError or a crash.
for (const [name, v] of [['bigint', { amount: 10n }], ['an act that contains itself', (() => { const o: Record<string, unknown> = {}; o.self = o; return o; })()]] as const) {
  try { g.actionDigest(v); line('GAP ', name, 'digested'); }
  catch (e) { line(kind(e) === 'IrrNoApprovalError' ? 'safe' : 'GAP ', name, `throws ${kind(e)}`); }
}

console.log(`\n  aegis-guard action digest: ${broke ? 'BROKE' : `${gaps} gap(s)`}`);
process.exit(broke ? 3 : gaps ? 1 : 0);
