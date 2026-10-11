// SPDX-License-Identifier: AGPL-3.0-only
// kavachos run: a bare "--" ends kavachos's options; the agent's words are the agent's (agent-kernel 2.5.0).
// The end-to-end proof against an installed package is red-team/kavachos-run-args.battery.sh.
import { describe, expect, test } from "bun:test";
import { splitRunArgs, versionAtLeast } from "../src/kernel/run-args";

describe("kavachos run arguments", () => {
  test("after -- every word is the agent's, options included", () => {
    const r = splitRunArgs(["--trust-mask=0xFF", "--", "bun", "agent.ts", "--port", "4900", "--dry-run", "--allow-unconstrained-egress"]);
    expect(r.error).toBeUndefined();
    expect(r.separated).toBe(true);
    expect(r.optionArgs).toEqual(["--trust-mask=0xFF"]);
    expect(r.agentArgs).toEqual(["bun", "agent.ts", "--port", "4900", "--dry-run", "--allow-unconstrained-egress"]);
  });

  test("only the first -- separates; a later one belongs to the agent", () => {
    const r = splitRunArgs(["--", "sh", "-c", "x", "--", "--needs=1"]);
    expect(r.optionArgs).toEqual([]);
    expect(r.agentArgs).toEqual(["sh", "-c", "x", "--", "--needs=1"]);
  });

  test("a binary whose name starts with a dash is still the binary after --", () => {
    expect(splitRunArgs(["--", "--dry-run"]).agentArgs).toEqual(["--dry-run"]);
  });

  test("a word that is not an option before -- refuses the line", () => {
    expect(splitRunArgs(["bun", "--", "agent.ts"]).error).toContain("before \"--\"");
    expect(splitRunArgs(["--verbose", "-v", "--", "bun"]).error).toBeUndefined();
  });

  test("-- with nothing after it refuses the line", () => {
    expect(splitRunArgs(["--trust-mask=1", "--"]).error).toContain("nothing after");
  });

  test("without -- the old reading holds, and options after the binary are named", () => {
    const r = splitRunArgs(["bun", "agent.ts", "--trust-mask=0xFF", "--port", "4900"]);
    expect(r.separated).toBe(false);
    expect(r.agentArgs).toEqual(["bun", "agent.ts", "4900"]);
    expect(r.optionArgs).toContain("--trust-mask=0xFF");
    expect(r.optionsAfterBinary).toEqual(["--trust-mask=0xFF", "--port"]);
    expect(splitRunArgs(["--trust-mask=0xFF", "bun", "agent.ts"]).optionsAfterBinary).toEqual([]);
  });

  test("version comparison", () => {
    expect(versionAtLeast("2.5.0", "2.5.0")).toBe(true);
    expect(versionAtLeast("2.10.0", "2.5.0")).toBe(true);
    expect(versionAtLeast("3.0.0", "2.5.0")).toBe(true);
    expect(versionAtLeast("2.4.9", "2.5.0")).toBe(false);
    expect(versionAtLeast("garbage", "2.5.0")).toBe(false);
  });
});
