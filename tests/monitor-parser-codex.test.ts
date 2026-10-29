// SPDX-License-Identifier: AGPL-3.0-only
// AEG-T037: the Codex parser, checked against the shape of the 40 real Codex rollouts on this box (2026-10-29).
// Lines here are synthetic, built to that shape; no real session content. Run under a scratch HOME.
import { describe, test, expect } from "bun:test";
import { parseLine } from "../src/monitor/parser";

const FILE = "/root/.codex/sessions/2026/01/16/rollout-2026-01-16T10-02-32-019bc513-9185-7e03-a931-2a163d712097.jsonl";
const line = (o: unknown) => JSON.stringify(o);
const meta = line({ timestamp: "2026-01-16T04:32:32Z", type: "session_meta", payload: { id: "019bc513-9185-7e03-a931-2a163d712097", originator: "codex_cli_rs" } });
const turn = (model: string) => line({ timestamp: "2026-01-16T04:32:33Z", type: "turn_context", payload: { model, cwd: "/root" } });
const user = line({ timestamp: "2026-01-16T04:32:34Z", type: "event_msg", payload: { type: "user_message", message: "x", images: [], local_images: [], text_elements: [] } });
const tokens = (u: Record<string, number> | null, ts = "2026-01-16T04:32:40Z") => line({ timestamp: ts, type: "event_msg", payload: { type: "token_count", info: u && { total_token_usage: u, last_token_usage: u, model_context_window: null }, rate_limits: {} } });

describe("Codex parser", () => {
  test("one session id for the whole file, from its name", () => {
    expect(parseLine(meta, FILE).session_id).toBe("codex-019bc513");
    expect(parseLine(tokens({ input_tokens: 10, cached_input_tokens: 0, output_tokens: 1, reasoning_output_tokens: 0, total_tokens: 11 }), FILE).usage?.session_id).toBe("codex-019bc513");
  });

  test("a person typing is user activity for that session (the payload carries no session id)", () => {
    const p = parseLine(user, FILE);
    expect(p.is_user_message).toBe(true);
    expect(p.session_id).toBe("codex-019bc513");
  });

  test("the model is the one the turn named, not a fixed guess", () => {
    const f = FILE.replace("019bc513", "019bc514");
    parseLine(turn("deepseek/deepseek-chat"), f);
    expect(parseLine(tokens({ input_tokens: 2148, cached_input_tokens: 0, output_tokens: 7, reasoning_output_tokens: 0, total_tokens: 2155 }), f).usage?.model).toBe("deepseek/deepseek-chat");
    parseLine(turn("gpt-4o"), f);
    expect(parseLine(tokens({ input_tokens: 5, cached_input_tokens: 0, output_tokens: 5, reasoning_output_tokens: 0, total_tokens: 10 }), f).usage?.model).toBe("gpt-4o");
  });

  test("cached input is charged once, at the cached rate", () => {
    const f = FILE.replace("019bc513", "019bc515");
    parseLine(turn("gpt-4o"), f);
    const none = parseLine(tokens({ input_tokens: 1_000_000, cached_input_tokens: 0, output_tokens: 0, reasoning_output_tokens: 0, total_tokens: 1_000_000 }), f).usage!;
    const half = parseLine(tokens({ input_tokens: 1_000_000, cached_input_tokens: 500_000, output_tokens: 0, reasoning_output_tokens: 0, total_tokens: 1_000_000 }), f).usage!;
    // 1M input at 2.50: 2.50. Half of it cached at 1.25: 0.625 + 1.25 = 1.875, never more than with no cache.
    expect(none.estimated_cost_usd).toBeCloseTo(2.5, 6);
    expect(half.estimated_cost_usd).toBeCloseTo(1.875, 6);
    expect(half.input_tokens).toBe(500_000);
    expect(half.cache_read_tokens).toBe(500_000);
  });

  test("a token event with no usage counts nothing (30 of the 32 real ones)", () => {
    expect(parseLine(tokens(null), FILE).usage).toBe(null);
  });

  test("reasoning tokens are part of output, never counted twice (codex-rs blended_total)", () => {
    const f = FILE.replace("019bc513", "019bc516");
    parseLine(turn("gpt-4o"), f);
    const u = parseLine(tokens({ input_tokens: 0, cached_input_tokens: 0, output_tokens: 1_000_000, reasoning_output_tokens: 400_000, total_tokens: 1_000_000 }), f).usage!;
    expect(u.output_tokens).toBe(1_000_000);
    expect(u.estimated_cost_usd).toBeCloseTo(10, 6);   // 1M output at 10, not 14
  });
});

