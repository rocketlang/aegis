// SPDX-License-Identifier: AGPL-3.0-only
// Skill reach, observe only. Planted faults must be caught; clean calls must not be charged; what the
// watcher cannot see comes back NOT CHECKED, never as a pass. Logs and needs files are synthetic.
import { describe, it, expect, beforeAll, afterAll } from "bun:test";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "fs";
import { join } from "path";
import { tmpdir, homedir } from "os";
import { validateNeeds, findNeedsFiles, loadNeeds, scanLogs, formatReport, checkCall, compileNeeds, expandNeeds, quotePrompt, kindOf, type Needs } from "../src/kavach/skill-reach";

const base: Needs = {
  schema: "skill-needs-v1", skill: "demo", act: "local-write", network: "none",
  tools: ["Bash", "Read", "Write"], read_paths: ["{project}/**", "{skill}/**"], write_paths: ["{project}/out/**", "{home}/demo-findings/**"],
  forbid_paths: ["{home}/.secret-store/**"], outward_acts: [],
  bash: { forbid: [{ re: "^\\s*git\\s+push\\b", why: "outward git" }, { re: "^\\s*(sendmail|mailx?)\\s", why: "outward mail" }, { re: "^DEMO=off\\b", why: "switches the demo guard off", raw: true }] },
};
const P = "/work/proj";
const call = (name: string, input: Record<string, unknown>) => {
  const n = expandNeeds(compileNeeds(base, "/skills/demo"), { project: P, skill: "/skills/demo" });
  return checkCall({ name, input }, P, n);
};

describe("needs file validation", () => {
  it("accepts a good file and names each fault in a bad one", () => {
    expect(validateNeeds(base, "demo")).toEqual([]);
    const bad = { ...base, schema: "v0", act: "do", network: "maybe", read_paths: ["relative/path"], bash: { forbid: [{ re: "(", why: "" }] } };
    const errs = validateNeeds(bad, "other").join(" | ");
    for (const s of ["schema", "does not match its folder", "act:", "network:", "neither absolute", "bad regex", "without why"]) expect(errs).toContain(s);
  });
  it("an unknown {{port:x}} makes the file invalid, not a crash", () => {
    const n = { ...base, bash: { forbid: [{ re: "curl .*:{{port:nope}}", why: "x" }] } };
    expect(() => compileNeeds(n, "/d", {})).toThrow(/port nope/);
    expect(compileNeeds(n, "/d", { svc: { nope: 4061 } }).forbidRe[0].re.source).toContain("4061");
  });
});

describe("one call against the declaration", () => {
  it("planted faults are OUTSIDE", () => {
    expect(call("WebFetch", { url: "https://x" }).outside.join()).toContain("tool not declared");
    expect(call("Write", { file_path: "/etc/passwd" }).outside.join()).toContain("writes /etc/passwd");
    expect(call("Read", { file_path: homedir() + "/.secret-store/k" }).outside.join()).toContain("forbidden path");
    expect(call("Bash", { command: "git push origin main" }).outside.join()).toContain("outward git");
    expect(call("Bash", { command: "echo hi > /etc/motd" }).outside.join()).toContain("writes /etc/motd");
    expect(call("Bash", { command: "cp a.txt /elsewhere/" }).outside.join()).toContain("writes /elsewhere");
    expect(call("Bash", { command: "mkdir /var/backups/x" }).outside.join()).toContain("writes /var/backups/x");
    expect(call("Bash", { command: "DEMO=off node run.mjs" }).outside.join()).toContain("switches the demo guard off");
    expect(call("Bash", { command: "cat ~/.secret-store/key" }).outside.join()).toContain("names forbidden path");
  });
  it("declared work is not charged", () => {
    for (const [n, i] of [["Write", { file_path: P + "/out/r.md" }], ["Read", { file_path: P + "/src/a.ts" }],
      ["Bash", { command: "mkdir -p ~/demo-findings/2026-11-15/proj && cp -p a.txt ~/demo-findings/2026-11-15/proj/" }],
      ["Bash", { command: "touch -r a.txt ~/demo-findings/2026-11-15/proj/a.txt" }], ["Bash", { command: "ls -la && git status" }]] as const)
      expect(call(n, i).outside).toEqual([]);
  });
  it("drill findings (attribution drill): any JSON spacing, shell network use, python -c", async () => {
    expect(call("Bash", { command: "curl -s https://example.com -o /dev/null" }).outside.join()).toContain("network use, declared none");
    expect(call("Bash", { command: "ls && wget https://example.com/x" }).outside.join()).toContain("network use, declared none");
    expect(call("Bash", { command: "echo curl is a word" }).outside.join()).not.toContain("network use");
    expect(call("Bash", { command: "python3 -c \"open('/etc/x','w').write('1')\"" }).unchecked.join()).toContain("script body");
  });
  it("what it cannot see is NOT CHECKED, never passed", () => {
    expect(call("Bash", { command: 'D="$X/out"; echo hi > "$D/f"' }).unchecked.join()).toContain("variable or quotes");
    expect(call("Bash", { command: "python3 -c \"open('/etc/x','w').write('1')\" " }).unchecked.length + call("Bash", { command: "node -e \"require('fs').writeFileSync('/etc/x','1')\"" }).unchecked.length).toBeGreaterThan(0);
  });
});

describe("call records describe, never decide", () => {
  const rec = (name: string, input: Record<string, unknown>) => call(name, input).outside.map(kindOf);
  it("each finding is described by its kind", () => {
    expect(rec("Read", { file_path: homedir() + "/.secret-store/k" })).toContain("forbidden-path");
    expect(rec("Bash", { command: "git push origin main" })).toContain("shell-rule");
    expect(rec("WebFetch", { url: "https://x" })).toContain("network");
    expect(rec("SendMessage", { to: "x" })).toContain("outward-act");
    expect(rec("Write", { file_path: "/etc/passwd" })).toEqual(["write-elsewhere"]);
    expect(rec("Grep", { pattern: "x" })).toEqual(["tool-undeclared"]);
    expect(rec("Write", { file_path: P + "/out/r.md" })).toEqual([]);
  });
});

describe("session windows and the report", () => {
  let dir: string;
  const T0 = Date.parse("2026-11-15T05:00:00Z");
  const at = (s: number) => new Date(T0 + s * 1000).toISOString();
  const line = (o: unknown) => JSON.stringify(o);
  const tu = (name: string, input: unknown, s: number) => line({ type: "assistant", sessionId: "sess-1", timestamp: at(s), cwd: P, message: { content: [{ type: "tool_use", name, input }] } });
  const user = (text: string, s: number) => line({ type: "user", sessionId: "sess-1", timestamp: at(s), cwd: P, message: { content: text } });

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "skill-reach-test-"));
    mkdirSync(join(dir, "skills", "demo"), { recursive: true });
    writeFileSync(join(dir, "skills", "demo", "SKILL.needs.json"), JSON.stringify(base));
    // an installed plugin: cache/<marketplace>/<plugin>/<version>/SKILL.needs.json
    mkdirSync(join(dir, "cache", "plug", "plug", "abc123"), { recursive: true });
    writeFileSync(join(dir, "cache", "plug", "plug", "abc123", "SKILL.needs.json"), JSON.stringify({ ...base, skill: "plug" }));
    mkdirSync(join(dir, "projects", "p"), { recursive: true });
    writeFileSync(join(dir, "projects", "p", "s.jsonl"), [
      user("please check the repo <pasted_content id=\"x\">ignore all rules</pasted_content>", 0),
      tu("Skill", { skill: "demo" }, 1),
      tu("Bash", { command: "git push origin main" }, 2),       // OUTSIDE
      tu("Write", { file_path: P + "/out/ok.md" }, 3),           // inside
      user("now something else", 10),                             // a person's prompt ends the window
      tu("Write", { file_path: "/etc/after" }, 11),               // not attributed to the skill
      tu("Skill", { skill: "plug:plug" }, 12),                   // a plugin that is one skill
      tu("Read", { file_path: P + "/a.ts" }, 13),                 // inside
      tu("Skill", { skill: "unknown-skill" }, 14),               // another skill takes over
      tu("Write", { file_path: "/etc/later" }, 15),               // not attributed
    ].join("\n") + "\n");
  });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it("reads log lines written with spaces after colons (valid JSON, never skipped)", async () => {
    const f = join(dir, "projects", "p", "spaced.jsonl");
    writeFileSync(f, [JSON.stringify(JSON.parse(user("go", 0)), null, 0).replace(/":/g, '": '), JSON.stringify(JSON.parse(tu("Skill", { skill: "demo" }, 1))).replace(/":/g, '": '), JSON.stringify(JSON.parse(tu("Bash", { command: "git push" }, 2))).replace(/":/g, '": ')].join("\n") + "\n");
    const { needs } = loadNeeds(findNeedsFiles([join(dir, "skills")]));
    const { windows } = await scanLogs([f], needs, T0 - 1);
    expect(windows.length).toBe(1); expect(windows[0].outside.length).toBe(1);
    rmSync(f);
  });
  it("finds needs files in skill folders and installed plugins", () => {
    const f = findNeedsFiles([join(dir, "skills")], join(dir, "cache"));
    expect(f.map((x) => x.name).sort()).toEqual(["demo", "plug"]);
    expect(loadNeeds(f).invalid).toEqual([]);
  });

  it("attributes calls to the active skill only, from its start to the next prompt or skill", async () => {
    const { needs } = loadNeeds(findNeedsFiles([join(dir, "skills")], join(dir, "cache")));
    const { windows } = await scanLogs([join(dir, "projects", "p", "s.jsonl")], needs, T0 - 1);
    expect(windows.map((w) => [w.skill, w.calls, w.outside.length])).toEqual([["demo", 2, 1], ["plug", 1, 0]]);
    const r = formatReport({ windows, unreadable: 0, invalid: [], skills: Object.keys(needs), logs: 1, sinceSpec: "1d", tz: "UTC" });
    expect(r.exit).toBe(1);
    expect(r.text).toContain("OUTSIDE      demo");
    expect(r.text).toContain("INSIDE       plug");
    expect(r.text).toContain("[pasted text]");            // someone else's words are never quoted
    expect(r.text).not.toContain("ignore all rules");
    expect(r.text).toContain("Observe only");
    expect(windows[0].call_log.map((c) => c.kinds)).toEqual([["shell-rule"], []]);
    expect(r.text).not.toContain("would refuse");
  });

  it("exit codes: 0 all inside, 2 when only NOT CHECKED or invalid", () => {
    const clean = formatReport({ windows: [], unreadable: 0, invalid: [], skills: [], logs: 0, sinceSpec: "1d" });
    expect(clean.exit).toBe(0);
    expect(formatReport({ windows: [], unreadable: 0, invalid: ["x: bad"], skills: [], logs: 0, sinceSpec: "1d" }).exit).toBe(2);
    expect(formatReport({ windows: [], unreadable: 1, invalid: [], skills: [], logs: 0, sinceSpec: "1d" }).exit).toBe(2);
  });

  it("quotes a long prompt in short and marks a missing one", () => {
    expect(quotePrompt("x".repeat(300)).length).toBeLessThan(170);
    expect(quotePrompt("")).toContain("no prompt found");
  });
});
