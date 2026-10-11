// aegis red-team probe — @xshieldai/aegis-suite as installed: which aegis-guard does the user get, how many
// copies are there, and does wireAllToBus() hear all of them. Run by aegis-suite-one-guard.battery.sh from an
// install folder; never against the source tree.
import { existsSync, readFileSync, readdirSync } from 'fs';
import { join } from 'path';
import { spawnSync } from 'child_process';

const ROOT = process.cwd();
let cases = 0, gaps = 0;
const say = (ok: boolean, what: string, detail = '') => { cases++; if (!ok) gaps++; console.log(`  [${ok ? 'safe' : 'GAP'}] ${what}${detail ? ' — ' + detail : ''}`); };
const num = (v: string) => v.split('.').map((n) => parseInt(n, 10));
const atLeast = (v: string, floor: string) => { const a = num(v), b = num(floor); for (let i = 0; i < 3; i++) { if ((a[i] ?? 0) !== (b[i] ?? 0)) return (a[i] ?? 0) > (b[i] ?? 0); } return true; };

// Every installed copy of a package, at any depth.
function copies(pkg: string, dir = join(ROOT, 'node_modules'), found: string[] = []): string[] {
  if (!existsSync(dir)) return found;
  const here = join(dir, pkg);
  if (existsSync(join(here, 'package.json'))) found.push(here);
  for (const e of readdirSync(dir)) {
    if (e === '.bin') continue;
    const subs = e.startsWith('@') ? readdirSync(join(dir, e)).map((s) => join(dir, e, s)) : [join(dir, e)];
    for (const s of subs) copies(pkg, join(s, 'node_modules'), found);
  }
  return found;
}
const versionAt = (dir: string) => JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')).version as string;

const guards = copies('@xshieldai/aegis-guard');
const top = join(ROOT, 'node_modules/@xshieldai/aegis-guard');
const topVersion = existsSync(top) ? versionAt(top) : 'none';
say(atLeast(topVersion, '0.6.1'), 'the aegis-guard your own code imports is 0.6.1 or later', topVersion);
say(guards.length === 1, 'one copy of aegis-guard is installed', guards.map((g) => versionAt(g)).join(' and '));

const FLOORS: Record<string, string> = { 'chitta-detect': '0.3.1', lakshmanrekha: '0.4.1', 'hanumang-mandate': '0.3.1', aegis: '2.17.2' };
for (const [p, floor] of Object.entries(FLOORS)) {
  const all = copies(`@xshieldai/${p}`).map(versionAt);
  say(all.length === 1 && atLeast(all[0], floor), `${p}: one copy, ${floor} or later`, all.join(' and ') || 'none');
}

// Does the bus hear a refusal from every installed copy of aegis-guard?
const { wireAllToBus } = await import('@xshieldai/aegis-suite');
const seen: string[] = [];
wireAllToBus({ persist: false, bus: { emit: (r: { primitive: string; event_type: string }) => { seen.push(`${r.primitive}:${r.event_type}`); } } });
for (const g of guards) {
  const before = seen.length;
  const mod = await import(join(g, JSON.parse(readFileSync(join(g, 'package.json'), 'utf8')).main ?? 'src/index.ts'));
  let refused = false;
  try { mod.verifyApprovalToken('not-a-signed-token', 'probe', 'settle', 'record_settle'); } catch { refused = true; }
  const where = g === top ? 'the copy your code imports' : 'the copy inside ' + g.slice(ROOT.length + 1).split('/node_modules/@xshieldai/aegis-guard')[0].replace('node_modules/', '');
  say(refused && seen.length > before, `a refusal by aegis-guard ${versionAt(g)} (${where}) reaches the bus`, refused ? `${seen.length - before} receipt(s)` : 'it did not refuse');
}

// The command-line front door lists all six.
const st = spawnSync(process.execPath, [join(ROOT, 'node_modules/@xshieldai/aegis-suite/bin/aegis-suite.js'), 'status'], { encoding: 'utf8', env: { ...process.env } });
const listed = (st.stdout.match(/✓/g) ?? []).length;
say(st.status === 0 && listed === 6, '`aegis-suite status` runs and finds all six packages', `exit ${st.status}, ${listed} found`);

console.log(`\nRESULT cases=${cases} gaps=${gaps}`);
process.exit(gaps ? 1 : 0);
