/**
 * "AEGIS — the control plane, live" — governance film over the real Command Center.
 * Auth via founder-minted session cookie (/tmp/aegis-sid.txt) — never auto-login.
 * SAFETY: the script clicks TABS ONLY. It must never click PAUSE / RESUME / KILL ALL.
 * Rig discipline from mari8x desk-films rig.mjs (TTS cache, CFR, captions, sanity gates).
 */
import { chromium } from 'playwright';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync, rmSync, readdirSync, statSync, existsSync, readFileSync, writeFileSync } from 'node:fs';

const VOICE = process.env.VOICE || 'en-GB-SoniaNeural';
const STAMP = process.env.STAMP || new Date().toISOString().slice(0, 10);
const TAKE = process.env.TAKE ? `-take${process.env.TAKE}` : '';
const OUTFILE = `/root/mari8x-videos/aegis-control-plane-live-${STAMP}${TAKE}.mp4`;
if (existsSync(OUTFILE)) { console.error(`ABORT (DFM-001): ${OUTFILE} exists. TAKE=2 for a new take.`); process.exit(2); }

const COOKIE_RAW = readFileSync('/tmp/aegis-sid.txt', 'utf8').trim();
const BASE = 'http://localhost:4850';
const W = 1920, H = 1080;
const FONT = '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf';
const WORK = '/tmp/aegis-film-work';
rmSync(WORK, { recursive: true, force: true }); mkdirSync(WORK, { recursive: true });

// beat.tab = dashboard tab to click (null = stay); beat.scrollTo = px scroll
const BEATS = [
  { n: 1, tab: 'OVERVIEW',
    narration: 'This is AEGIS — the control plane over every A I agent in the ANKR fleet. It is live, not a mock-up: the message window, the weekly budget, the token velocity — all moving as you watch. And a kill-switch in the corner.',
    caption: 'AEGIS Command Center — live, right now' },
  { n: 2, tab: null, scrollTo: 80,
    narration: 'Seven agent processes are running this second. And one of the sessions on this screen is the very agent that is making this film. AEGIS watches the watcher.',
    caption: 'The agent making this film is on this screen' },
  { n: 3, tab: 'AGENTS',
    narration: 'Every session carries its own meter — messages, spawns, and money. The expensive ones are visible at a glance, and when one runs hot it gets paused. Not debated — paused.',
    caption: 'Per-session cost · spawns · pause state' },
  { n: 4, tab: 'LIMITS',
    narration: 'Budgets here are hard gates, not suggestions: message windows, token ceilings, spawn depth, daily and weekly money limits, and a heartbeat that pauses anything that goes silent. This page exists because one runaway agent once made eight hundred and forty-seven A P I calls in six minutes.',
    caption: 'Hard gates: budgets · spawn caps · heartbeat' },
  { n: 5, tab: 'POSTURE',
    narration: 'HANUMANG scores every axis of trust — identity, authorisation, scope, budget, depth, purpose, revocability. Below it, the KAVACH decision log, and an active sock-puppet defense with a published D O I.',
    caption: '7-axis trust posture · KAVACH decisions' },
  { n: 6, tab: 'DIGITAL TWIN',
    narration: 'Underneath, every request flows through one pipeline: intercept, policy, firewall, kernel enforcement — and a S H A two-fifty-six sealed ledger. The enforcement is structural. The agent cannot opt out.',
    caption: 'Intercept → policy → kernel ENFORCE → sealed ledger' },
  { n: 7, tab: 'OVERVIEW',
    narration: 'And if everything goes wrong at once — one switch, held by a human. As the footer puts it: AEGIS is the kill-switch between your A I agents and your credit card.',
    caption: 'The kill-switch between your agents and your credit card' },
];

const sh = (c, a) => execFileSync(c, a, { stdio: 'pipe' });
const TTSCACHE = '/tmp/aegis-tts-cache'; mkdirSync(TTSCACHE, { recursive: true });
const tts = (t, o) => {
  const key = `${TTSCACHE}/${Buffer.from(t).toString('base64url').slice(0, 40)}.mp3`;
  if (existsSync(key) && statSync(key).size > 1000) { sh('cp', [key, o]); return; }
  for (let i = 0; i < 3; i++) {
    const r = spawnSync('edge-tts', ['--voice', VOICE, '--text', t, '--write-media', o], { stdio: 'pipe' });
    if (r.status === 0 && existsSync(o) && statSync(o).size > 1000) { sh('cp', [o, key]); return; }
    console.log(`  tts retry ${i + 1}/3`); execFileSync('sleep', [String((i + 1) * 8)]);
  }
  throw new Error('edge-tts failed');
};
const dur = (f) => parseFloat(sh('ffprobe', ['-v', 'error', '-show_entries', 'format=duration', '-of', 'default=nw=1:nk=1', f]).toString().trim()) || 0;

console.log(`── AEGIS control plane film → ${OUTFILE}`);
const mp3s = [];
for (const b of BEATS) { const f = `${WORK}/b${b.n}.mp3`; tts(b.narration, f); mp3s.push({ n: b.n, f, d: dur(f) }); }
const total = mp3s.reduce((s, m) => s + m.d, 0);
console.log(`  narration: ${total.toFixed(1)}s (cap 130s)`);
if (total > 130) { console.error('ABORT: narration exceeds cap'); process.exit(3); }
writeFileSync(`${WORK}/alist.txt`, mp3s.map((m) => `file '${m.f}'`).join('\n'));
sh('ffmpeg', ['-y', '-f', 'concat', '-safe', '0', '-i', `${WORK}/alist.txt`, '-c:a', 'libmp3lame', `${WORK}/narration.mp3`]);

const browser = await chromium.launch({ headless: true });
const ctx = await browser.newContext({ viewport: { width: W, height: H }, recordVideo: { dir: WORK, size: { width: W, height: H } } });
const eq = COOKIE_RAW.indexOf('=');
await ctx.addCookies([{ name: COOKIE_RAW.slice(0, eq), value: COOKIE_RAW.slice(eq + 1), domain: 'localhost', path: '/' }]);
const pg = await ctx.newPage();
await pg.goto(`${BASE}/`, { waitUntil: 'domcontentloaded', timeout: 20000 });
await pg.waitForTimeout(4000);

const t0 = Date.now(); let cum = 0;
for (const [i, b] of BEATS.entries()) {
  cum += mp3s[i].d * 1000;
  try {
    if (b.tab) { await pg.click(`text="${b.tab}"`, { timeout: 5000 }); await pg.waitForTimeout(1200); }
    if (b.scrollTo != null) { await pg.evaluate((y) => window.scrollTo({ top: y, behavior: 'smooth' }), b.scrollTo); }
  } catch (e) { console.log(`  beat ${b.n}: ${String(e.message).slice(0, 80)}`); }
  const el = Date.now() - t0; if (el < cum) await pg.waitForTimeout(cum - el);
  console.log(`  beat ${b.n} ok (${mp3s[i].d.toFixed(1)}s vo)`);
}
await pg.waitForTimeout(1500);
const video = pg.video();
await pg.close(); await ctx.close();
const webmPath = video ? await video.path().catch(() => null) : null;
await browser.close();
if (webmPath) { let last = -1; for (let i = 0; i < 20; i++) { const s = statSync(webmPath).size; if (s === last && s > 0) break; last = s; await new Promise((r) => setTimeout(r, 2000)); } }

let t = 0; const draws = [];
for (const [i, b] of BEATS.entries()) {
  const start = t; t += mp3s[i].d;
  const cf = `${WORK}/cap${b.n}.txt`; writeFileSync(cf, b.caption);
  draws.push(`drawtext=fontfile=${FONT}:textfile=${cf}:fontsize=34:fontcolor=white:box=1:boxcolor=black@0.55:boxborderw=14:x=(w-text_w)/2:y=h-110:enable='between(t,${start.toFixed(2)},${t.toFixed(2)})'`);
}
const webm = webmPath || readdirSync(WORK).filter((x) => x.endsWith('.webm')).map((x) => `${WORK}/${x}`).sort((a, b) => statSync(b).mtimeMs - statSync(a).mtimeMs)[0];
sh('ffmpeg', ['-y', '-fflags', '+genpts', '-i', webm, '-r', '25', '-pix_fmt', 'yuv420p', '-c:v', 'libx264', '-preset', 'veryfast', '-crf', '20', `${WORK}/video-cfr.mp4`]);
const rawDur = dur(`${WORK}/video-cfr.mp4`);
if (!(rawDur > total - 3)) { console.error(`CAPTURE FAIL: raw ${rawDur.toFixed(1)}s < narration ${total.toFixed(1)}s`); process.exit(1); }
sh('ffmpeg', ['-n', '-i', `${WORK}/video-cfr.mp4`, '-i', `${WORK}/narration.mp3`, '-map', '0:v:0', '-map', '1:a:0',
  '-vf', draws.join(','), '-c:v', 'libx264', '-preset', 'medium', '-crf', '23', '-pix_fmt', 'yuv420p',
  '-c:a', 'aac', '-movflags', '+faststart', '-shortest', OUTFILE]);
const vDur = dur(OUTFILE);
if (!(vDur > total - 3)) { console.error(`SANITY FAIL: ${vDur}s < ${total.toFixed(1)}s`); process.exit(1); }
writeFileSync(OUTFILE.replace(/\.mp4$/, '.narration.txt'), BEATS.map((b) => `[${b.n}] ${b.narration}`).join('\n\n'));
console.log(`FILM → ${OUTFILE} (video ${vDur.toFixed(1)}s / narration ${total.toFixed(1)}s)`);
