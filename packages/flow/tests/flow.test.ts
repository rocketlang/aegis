// SPDX-License-Identifier: AGPL-3.0-only
import { describe, expect, test } from "bun:test";
import { FlowRefusal, fromClaudeHook, isWithin, narrow, narrowFromParent, stamp } from "../src/index.js";

describe("narrow (GTP-020)", () => {
  test("child = parent & requested", () => {
    expect(narrow(0b0011, 0b1111)).toBe(0b0011);
    expect(narrow(0b1010, 0b0110)).toBe(0b0010);
  });
  test("a full 32-bit mask stays unsigned", () => {
    expect(narrow(0xffffffff, 0xffffffff)).toBe(0xffffffff);
  });
  for (const bad of [-1, 1.5, 2 ** 32, NaN, "3" as unknown as number]) {
    test(`refuses a mask that is not a 32-bit unsigned integer: ${String(bad)}`, () => {
      expect(() => narrow(bad, 1)).toThrow(FlowRefusal);
      expect(() => narrow(1, bad)).toThrow(FlowRefusal);
    });
  }
});

describe("narrowFromParent (GTP-021)", () => {
  test("a found parent narrows", () => {
    expect(narrowFromParent("p1", { effective_mask: 0b0011 }, 0xffff)).toBe(0b0011);
  });
  test("a missing parent is refused, never read as a root", () => {
    for (const missing of [null, undefined]) {
      try {
        narrowFromParent("ses_does_not_exist", missing, 0xffff);
        throw new Error("did not refuse");
      } catch (e) {
        expect(e).toBeInstanceOf(FlowRefusal);
        expect((e as FlowRefusal).rule).toBe("GTP-021");
      }
    }
  });
});

describe("isWithin", () => {
  test("subset holds, a bit outside does not", () => {
    expect(isWithin(0b0010, 0b0011)).toBe(true);
    expect(isWithin(0b0100, 0b0011)).toBe(false);
  });
});

describe("stamp (GTP-024)", () => {
  test("adds set fields and leaves the event otherwise unchanged", () => {
    const e = { receipt_id: "r1", primitive: "aegis" };
    const out = stamp(e, { flow_id: "cc:s", turn_id: "tool:t", parent_turn_id: undefined });
    expect(out).toEqual({ receipt_id: "r1", primitive: "aegis", flow_id: "cc:s", turn_id: "tool:t" });
    expect(e).toEqual({ receipt_id: "r1", primitive: "aegis" });
  });
  test("never overwrites a field the event already carries", () => {
    expect(stamp({ flow_id: "original" }, { flow_id: "other" }).flow_id).toBe("original");
  });
  test("ignores empty strings", () => {
    expect(stamp({}, { flow_id: "" })).toEqual({});
  });
});

describe("fromClaudeHook (GTP-018)", () => {
  test("main-agent tool call: parent is the prompt", () => {
    expect(fromClaudeHook({ session_id: "S", prompt_id: "P", tool_use_id: "T", hook_event_name: "PreToolUse" }))
      .toEqual({ flow_id: "cc:S", turn_id: "tool:T", parent_turn_id: "prompt:P" });
  });
  test("subagent tool call: parent is the subagent", () => {
    expect(fromClaudeHook({ session_id: "S", prompt_id: "P", tool_use_id: "T", agent_id: "A" }))
      .toEqual({ flow_id: "cc:S", turn_id: "tool:T", parent_turn_id: "agent:A" });
  });
  test("prompt hook: the prompt is the turn, with no parent", () => {
    expect(fromClaudeHook({ session_id: "S", prompt_id: "P", hook_event_name: "UserPromptSubmit" }))
      .toEqual({ flow_id: "cc:S", turn_id: "prompt:P" });
  });
  test("no session id: no flow, never a made-up id", () => {
    expect(fromClaudeHook({ tool_use_id: "T" })).toEqual({});
    expect(fromClaudeHook(null)).toEqual({});
    expect(fromClaudeHook({ session_id: 42 as unknown as string })).toEqual({});
  });
});

describe("mandateStatus (GTP-017, GTP-022)", () => {
  const { mandateStatus } = require("../src/index.js") as typeof import("../src/index.js");
  const m = { mudrika_id: "mdr_1", trust_mask: 0b0111, issued_at: "2026-10-15T00:00:00.000Z", ttl_seconds: 86400 };
  const at = (iso: string) => ({ now: new Date(iso) });
  test("valid inside its lifetime, expired at its end", () => {
    expect(mandateStatus(m, at("2026-10-15T23:59:59.000Z"))).toBe("valid");
    expect(mandateStatus(m, at("2026-10-16T00:00:00.000Z"))).toBe("expired");
  });
  test("revoked wins over valid", () => {
    expect(mandateStatus(m, { ...at("2026-10-15T01:00:00.000Z"), revoked: new Set(["mdr_1"]) })).toBe("revoked");
  });
  test("missing and malformed are never valid", () => {
    expect(mandateStatus(null)).toBe("missing");
    expect(mandateStatus({ ...m, trust_mask: -1 })).toBe("malformed");
    expect(mandateStatus({ ...m, issued_at: "yesterday" })).toBe("malformed");
    expect(mandateStatus({ ...m, ttl_seconds: 0 })).toBe("malformed");
    expect(mandateStatus({ ...m, mudrika_id: "" })).toBe("malformed");
  });
});

describe("effectiveCeiling (GTP-019)", () => {
  const { effectiveCeiling, FlowRefusal } = require("../src/index.js") as typeof import("../src/index.js");
  test("the AND of every layer present", () => {
    expect(effectiveCeiling({ mandate: 0b1111 })).toBe(0b1111);
    expect(effectiveCeiling({ mandate: 0b1111, envelope: 0b0111, parent: 0b0011 })).toBe(0b0011);
    expect(effectiveCeiling({ mandate: 0b0101, envelope: 0b1111, session: 0b0110 })).toBe(0b0100);
  });
  test("no mandate is refused, never treated as everything", () => {
    for (const mandate of [undefined, null]) {
      try { effectiveCeiling({ mandate, envelope: 0xff }); throw new Error("did not refuse"); }
      catch (e) { expect(e).toBeInstanceOf(FlowRefusal); expect((e as InstanceType<typeof FlowRefusal>).rule).toBe("GTP-017"); }
    }
  });
});
