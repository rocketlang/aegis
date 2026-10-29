// SPDX-License-Identifier: AGPL-3.0-only
// The monitor's watcher must count what a session wrote before the watcher noticed its file (2026-10-29).
// Measured on this box over 12 sessions: 15 of 3,595 usage records never reached usage_log, and 5 sessions
// were missing their first records, because a file found on a later rescan was read from its end.
// History written before the monitor started is still not counted (that would double-count a resumed session).
// Run under a scratch HOME: the parser reads ~/.aegis config.
import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtempSync, mkdirSync, writeFileSync, appendFileSync, utimesSync, rmSync, existsSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { SessionWatcher } from "../src/monitor/watcher";

const POLL = 15;                       // the watcher rescans its folders every 10 polls
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));
const line = (sid: string, ts: string, out = 10) => JSON.stringify({
  type: "assistant", sessionId: sid, timestamp: ts,
  message: { role: "assistant", model: "claude-haiku-5-5", usage: { input_tokens: 1, output_tokens: out } },
}) + "\n";

let root: string, proj: string, w: SessionWatcher, seen: Array<{ sid: string; ts: string }>;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "aegis-watch-"));
  proj = join(root, ".claude", "projects", "-root-x");
  mkdirSync(proj, { recursive: true });
  seen = [];
  w = new SessionWatcher((r) => seen.push({ sid: r.session_id, ts: r.timestamp }), () => {}, POLL);
});
afterEach(() => { w.stop(); rmSync(root, { recursive: true, force: true }); });

describe("watcher catch-up", () => {
  test("a file there at start: its history is not counted, what follows is", async () => {
    const f = join(proj, "a.jsonl");
    writeFileSync(f, line("A", "2026-10-01T00:00:00Z"));
    w.start([join(root, ".claude", "projects")]);
    appendFileSync(f, line("A", new Date().toISOString()));
    await wait(POLL * 4);
    expect(seen.map((s) => s.sid)).toEqual(["A"]);
    expect(seen[0].ts).not.toBe("2026-10-01T00:00:00Z");
  });

  test("a file that appears after start: what it wrote before the rescan found it is counted", async () => {
    w.start([join(root, ".claude", "projects")]);
    await wait(POLL * 2);
    const f = join(proj, "b.jsonl");
    writeFileSync(f, line("B", new Date().toISOString()) + line("B", new Date().toISOString()));
    await wait(POLL * 14);             // one rescan, then a poll
    expect(seen.filter((s) => s.sid === "B").length).toBe(2);
  });

  test("a file that appears after start with older history: only lines from after the start are counted", async () => {
    w.start([join(root, ".claude", "projects")]);
    await wait(POLL * 2);
    const f = join(proj, "c.jsonl");
    writeFileSync(f, line("C", "2026-10-01T00:00:00Z") + line("C", new Date().toISOString()));
    await wait(POLL * 14);
    expect(seen.filter((s) => s.sid === "C").map((s) => s.ts)).not.toContain("2026-10-01T00:00:00Z");
    expect(seen.filter((s) => s.sid === "C").length).toBe(1);
  });

  test("a file dropped as idle and then resumed: nothing written in between is lost, nothing counted twice", async () => {
    const f = join(proj, "d.jsonl");
    writeFileSync(f, "");
    w.start([join(root, ".claude", "projects")]);
    appendFileSync(f, line("D", new Date().toISOString()));
    await wait(POLL * 3);
    const old = (Date.now() - 2 * 3600_000) / 1000;
    utimesSync(f, old, old);           // idle for over an hour: the watcher lets go of it
    await wait(POLL * 3);
    appendFileSync(f, line("D", new Date().toISOString(), 20) + line("D", new Date().toISOString(), 30));
    await wait(POLL * 14);
    expect(seen.filter((s) => s.sid === "D").length).toBe(3);
  });

  test("T046: a session resumed in a project folder idle for over a day is found", async () => {
    const old = join(root, ".claude", "projects", "-root-old");
    mkdirSync(old, { recursive: true });
    const f = join(old, "e.jsonl");
    writeFileSync(f, line("E", "2026-10-01T00:00:00Z"));
    const t = (Date.now() - 3 * 86400_000) / 1000;
    utimesSync(f, t, t); utimesSync(old, t, t);          // folder and file both idle for 3 days
    w.start([join(root, ".claude", "projects")]);
    await wait(POLL * 2);
    appendFileSync(f, line("E", new Date().toISOString()));   // appending leaves the folder's mtime alone
    await wait(POLL * 14);
    expect(seen.filter((s) => s.sid === "E").length).toBe(1);   // the new line; not the old history
  });
});

describe("T045: read positions survive a restart", () => {
  test("lines written while the monitor was down are counted once; nothing is counted twice", async () => {
    const state = join(root, "offsets.json");
    const f = join(proj, "g.jsonl");
    writeFileSync(f, line("G", "2026-10-01T00:00:00Z"));
    const w1 = new SessionWatcher((r) => seen.push({ sid: r.session_id, ts: r.timestamp }), () => {}, POLL, state);
    w1.start([join(root, ".claude", "projects")]);
    appendFileSync(f, line("G", new Date().toISOString()));
    await wait(POLL * 4);
    w1.stop();
    expect(existsSync(state)).toBe(true);
    appendFileSync(f, line("G", new Date().toISOString(), 20) + line("G", new Date().toISOString(), 30));   // while down
    const w2 = new SessionWatcher((r) => seen.push({ sid: r.session_id, ts: r.timestamp }), () => {}, POLL, state);
    w2.start([join(root, ".claude", "projects")]);
    await wait(POLL * 4);
    w2.stop();
    expect(seen.filter((s) => s.sid === "G").length).toBe(3);   // 1 before the restart + 2 while down; the old history never
  });

  test("a saved position past the file's end (file replaced) starts at the end", async () => {
    const state = join(root, "offsets2.json");
    const f = join(proj, "h.jsonl");
    writeFileSync(f, line("H", "2026-10-01T00:00:00Z"));
    writeFileSync(state, JSON.stringify({ [f]: 999999 }));
    const w3 = new SessionWatcher((r) => seen.push({ sid: r.session_id, ts: r.timestamp }), () => {}, POLL, state);
    w3.start([join(root, ".claude", "projects")]);
    appendFileSync(f, line("H", new Date().toISOString()));
    await wait(POLL * 4);
    w3.stop();
    expect(seen.filter((s) => s.sid === "H").length).toBe(1);
  });

  test("an unreadable state file is ignored (start at the end), never a crash", async () => {
    const state = join(root, "offsets3.json");
    writeFileSync(state, "{not json");
    const f = join(proj, "k.jsonl");
    writeFileSync(f, line("K", "2026-10-01T00:00:00Z"));
    const w4 = new SessionWatcher((r) => seen.push({ sid: r.session_id, ts: r.timestamp }), () => {}, POLL, state);
    w4.start([join(root, ".claude", "projects")]);
    appendFileSync(f, line("K", new Date().toISOString()));
    await wait(POLL * 4);
    w4.stop();
    expect(seen.filter((s) => s.sid === "K").length).toBe(1);
  });
});
