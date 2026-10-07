// SPDX-License-Identifier: AGPL-3.0-only
// check-destructive, driven the way the agent harness drives it: stdin is a SOCKET.
//
// A pipe-fed test cannot see a hook that reads "/dev/stdin" go blind, so every case here
// goes through tests/helpers/run-hook-on-socket.py. Each case runs in its own throwaway
// HOME. Run the file with the network cut:   unshare -n bun test tests/destructive-gate-armed.test.ts
//
// Forced both ways: a match refuses and a clear command passes; the override passes and is
// recorded; Levels 0/1 stay out unless switched on; CRITICAL blocks at once unless the
// approval gate is switched on.
import { describe, it, expect } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

const ROOT = process.env.AEGIS_TEST_ROOT || join(import.meta.dir, "..");
const HELPER = join(import.meta.dir, "helpers/run-hook-on-socket.py");
const TOKEN = "TEST-OVERRIDE-TOKEN";
const RULES = {
  allowed_override_token: TOKEN,
  bash_block_patterns: [
    { pattern: "DROP\\s+TABLE", flags: "i", reason: "test critical", severity: "CRITICAL" },
    { pattern: "DELETE\\s+FROM\\s+", flags: "i", reason: "test high", severity: "HIGH" },
  ],
};

function home(opts: { rules?: boolean; kavach?: Record<string, unknown> } = {}): string {
  const h = mkdtempSync(join(tmpdir(), "aegis-destructive-"));
  mkdirSync(join(h, ".aegis"), { recursive: true });
  if (opts.rules !== false) writeFileSync(join(h, ".aegis/destructive-rules.json"), JSON.stringify(RULES));
  if (opts.kavach) writeFileSync(join(h, ".aegis/config.json"), JSON.stringify({ kavach: opts.kavach }));
  return h;
}

function hook(h: string, payload: unknown): { exit: number; stderr: string; ledger: any[]; ms: number } {
  const ledgerFile = join(h, "refusals.jsonl");
  const t0 = Date.now();
  const r = Bun.spawnSync(["python3", HELPER, ROOT, "check-destructive"], {
    stdin: Buffer.from(typeof payload === "string" ? payload : JSON.stringify(payload)),
    env: { ...process.env, HOME: h, AEGIS_HOME: "", AEGIS_REFUSAL_LEDGER: ledgerFile, CLAUDE_CODE_SESSION_ID: "destructive-test" },
  });
  if (r.exitCode !== 0) throw new Error(`socket helper broke (exit ${r.exitCode}): ${r.stderr.toString()}`);
  const out = JSON.parse(r.stdout.toString());
  const ledger = existsSync(ledgerFile)
    ? readFileSync(ledgerFile, "utf-8").split("\n").filter(Boolean).map((l) => JSON.parse(l))
    : [];
  return { exit: out.exit, stderr: out.stderr, ledger, ms: Date.now() - t0 };
}

const bash = (command: string) => ({ tool_name: "Bash", session_id: "destructive-test", tool_input: { command } });

describe("check-destructive on a socket", () => {
  it("refuses a HIGH match and records it under its rule", () => {
    const h = home();
    const r = hook(h, bash(`psql -d scratch -c "DELETE FROM t"`));
    expect(r.exit).toBe(2);
    expect(r.ledger.length).toBe(1);
    expect(r.ledger[0].gate).toBe("aegis-destructive");
    expect(r.ledger[0].kind).toBe("refused");
    expect(r.ledger[0].rule).toBe("KAV-052");
  });

  it("refuses a CRITICAL match at once, without opening the approval gate", () => {
    const h = home();
    const r = hook(h, bash(`psql -d scratch -c "DROP TABLE t"`));
    expect(r.exit).toBe(2);
    expect(r.stderr).toContain("CRITICAL");
    expect(r.stderr).not.toContain("approval gate");
    expect(r.ms).toBeLessThan(20000);
    expect(r.ledger.length).toBe(1);
  });

  it("opens the approval gate for CRITICAL only when that is switched on", () => {
    const h = home({ kavach: { destructive_critical: "approve", notify_via_webhook: false, timeout_level1_s: 1, timeout_level2_s: 1, timeout_level3_s: 1, timeout_level4_s: 1 } });
    const r = hook(h, bash(`psql -d scratch -c "DROP TABLE t"`));
    expect(r.exit).toBe(2); // nobody answers: silence is a block
    expect(r.stderr).toContain("approval gate");
  });

  it("passes a clear command and writes nothing", () => {
    const h = home();
    const r = hook(h, bash("ls -la /tmp"));
    expect(r.exit).toBe(0);
    expect(r.ledger.length).toBe(0);
  });

  it("passes a keyword that is only displayed", () => {
    const h = home();
    const r = hook(h, bash("echo 'DROP TABLE is a phrase'"));
    expect(r.exit).toBe(0);
    expect(r.ledger.length).toBe(0);
  });

  // Until 2.5.0 a token typed into the command overrode the gate (KAV-098 ended that).
  it("a token typed into the command no longer overrides", () => {
    const h = home();
    const r = hook(h, bash(`psql -d scratch -c "DELETE FROM t" # ${TOKEN}`));
    expect(r.exit).toBe(2);
    expect(r.stderr).not.toContain(TOKEN);
    expect(r.stderr).toContain("approve-destructive");
  });

  // Since 2026-10-07 separation is the default (KAV-098): with NO approver configured, the gate
  // honours no same-account override at all, so an agent cannot approve its own command. The
  // single-box local-file override is the EXPLICIT opt-out (AEGIS_ALLOW_INSECURE_LOCAL_APPROVAL).
  it("by default (no approver) a refused command cannot be approved — self-approval is off", () => {
    const h = home();
    const cmd = `psql -d scratch -c "DELETE FROM t"`;
    const refused = hook(h, bash(cmd));
    expect(refused.exit).toBe(2);
    const code = /approve-destructive ([0-9a-f]{8})/.exec(refused.stderr)?.[1] ?? "";
    expect(code).toHaveLength(8);

    // approve-destructive refuses in the default (none) mode and points the person at `aegis init`.
    const env = { ...process.env, HOME: h, AEGIS_HOME: "", AEGIS_REFUSAL_LEDGER: join(h, "refusals.jsonl") };
    const approve = (c: string) => Bun.spawnSync(["bun", "run", join(ROOT, "src/cli/index.ts"), "approve-destructive", c], { env });
    expect(approve(code).exitCode).toBe(1);
    // and even a forged local approval file does not open the gate, because the gate ignores it
    writeFileSync(join(h, ".aegis/destructive-approvals.json"),
      JSON.stringify([{ code, hash: "", approved_at: Date.now(), expires_at: Date.now() + 600000 }]));
    expect(hook(h, bash(cmd)).exit).toBe(2);
  });

  it("insecure-local opt-out: a person's one-time approval lets that exact command through once, on the record", () => {
    const prev = process.env.AEGIS_ALLOW_INSECURE_LOCAL_APPROVAL;
    process.env.AEGIS_ALLOW_INSECURE_LOCAL_APPROVAL = "1"; // explicitly accept the single-box file override
    try {
      const h = home();
      const cmd = `psql -d scratch -c "DELETE FROM t"`;
      const refused = hook(h, bash(cmd));
      expect(refused.exit).toBe(2);
      const code = /approve-destructive ([0-9a-f]{8})/.exec(refused.stderr)?.[1] ?? "";
      expect(code).toHaveLength(8);

      const env = { ...process.env, HOME: h, AEGIS_HOME: "", AEGIS_REFUSAL_LEDGER: join(h, "refusals.jsonl") };
      const approve = (c: string) => Bun.spawnSync(["bun", "run", join(ROOT, "src/cli/index.ts"), "approve-destructive", c], { env });
      expect(approve("00000000").exitCode).toBe(1); // a code nobody was given
      expect(approve(code).exitCode).toBe(0);

      expect(hook(h, bash(cmd + " ")).exit).toBe(2); // not the same command
      const allowed = hook(h, bash(cmd));
      expect(allowed.exit).toBe(0);
      expect(allowed.ledger.some((row) => row.kind === "override" && row.rule === "KAV-098")).toBe(true);
      expect(hook(h, bash(cmd)).exit).toBe(2); // used up: a second run is a new refusal
    } finally {
      if (prev === undefined) delete process.env.AEGIS_ALLOW_INSECURE_LOCAL_APPROVAL;
      else process.env.AEGIS_ALLOW_INSECURE_LOCAL_APPROVAL = prev;
    }
  });

  it("input that is not JSON is refused, like any call the gate cannot judge", () => {
    const h = home();
    expect(hook(h, '{"tool_name":"Bash","tool_input":{"command":"ls"').exit).toBe(2);
    expect(hook(h, "[1,2]").exit).toBe(2);
  });

  it("refuses when its rules cannot be read, and still passes an empty command", () => {
    const h = home({ rules: false });
    expect(hook(h, bash("ls")).exit).toBe(2);
    expect(hook(h, bash("")).exit).toBe(0);
  });

  it("leaves Levels 0 and 1 out by default: no valve state is touched", () => {
    const h = home();
    expect(hook(h, bash("ls")).exit).toBe(0);
    expect(hook(h, { tool_name: "Write", session_id: "destructive-test", tool_input: { file_path: "/tmp/x", content: "x" } }).exit).toBe(0);
    expect(existsSync(join(h, ".aegis/agents"))).toBe(false);
  });

  it("runs Levels 0 and 1 only when they are switched on", () => {
    const h = home({ kavach: { perm_mask_levels: "live", notify_via_webhook: false } });
    hook(h, bash("ls"));
    expect(existsSync(join(h, ".aegis/agents"))).toBe(true);
  });

  it("falls back to the defaults when the config cannot be parsed", () => {
    const h = home();
    writeFileSync(join(h, ".aegis/config.json"), "{ this is not json");
    const r = hook(h, bash(`psql -d scratch -c "DROP TABLE t"`));
    expect(r.exit).toBe(2);
    expect(r.stderr).not.toContain("approval gate");
    expect(existsSync(join(h, ".aegis/agents"))).toBe(false);
  });
});
