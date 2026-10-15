// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// Flow close: the end of a flow, judged against what its mandate requires (governed-turn-protocol §19, P5).
//
// @rule:GTP-025 a flow does not close as done until its mandate's required_return_proof is matched by
// evidence: the receipts grade of the agent's last message (show-me-the-receipts, from the session record
// only; no command is run) and hanumang's return-with-proof axis (HNG-S-005).
//
// At the end of every turn a flow receipt is written: the mandate, what the flow did (its tool calls,
// refusals and subagents, from the private flow events), and the proof result. It is signed with this
// machine's Mudrika secret and kept owner-only under <aegis dir>/flow-receipts/. A receipt whose proof is
// missing says the flow is still open. Whether the agent is also sent back to prove it is the caller's
// decision (refusing is opt-in: mandateEnforced).

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { join } from "path";
import { scoreAxis } from "@xshieldai/hanumang-mandate";
import { grade, toHanumanG } from "show-me-the-receipts";
import { getAegisDir } from "../core/config";
import { signWithMachineSecret } from "../kernel/mudrika";
import { readFlowEvents, summariseFlows } from "../acc/flow-events";
import { appendToChain } from "./receipt-chain";
import { DEFAULT_RETURN_PROOF, isReturnProof, judgeMandate, loadMandateForSession } from "./mandate";
import type { Mandate, ReturnProof } from "./mandate";

export interface GradedClaim { verdict: string; text: string; why?: string; type?: string }
export interface ReceiptsReport { results: GradedClaim[]; bareDone?: string | null; hedged?: string[] }

export interface ProofResult {
  required: ReturnProof;
  met: boolean;
  /** What is missing, one line each, for the agent and the person. Empty when met. */
  missing: string[];
  counts: Record<string, number>;
}

const SAFE_ID = /^[A-Za-z0-9_-]{1,128}$/;

/** Judge one required proof against one receipts report. Pure. @rule:GTP-025 */
export function judgeReturnProof(required: ReturnProof, report: ReceiptsReport | null): ProofResult {
  const counts: Record<string, number> = {};
  for (const c of report?.results ?? []) counts[c.verdict] = (counts[c.verdict] ?? 0) + 1;
  if (required === "none-declared") return { required, met: true, missing: [], counts };
  if (!report) return { required, met: false, missing: ["the session record could not be graded, so nothing is proven"], counts };
  const missing: string[] = [];
  for (const c of report.results) {
    if (c.verdict === "FALSE" || c.verdict === "STALE") missing.push(`${c.verdict}: "${oneLine(c.text)}"${c.why ? ` (${c.why})` : ""}`);
    else if (required === "receipts-strict" && c.verdict === "NO RECEIPT") missing.push(`NO RECEIPT: "${oneLine(c.text)}"`);
  }
  // A bare "done" that names nothing checkable claims completion with no proof at all.
  if (report.bareDone) missing.push(`says it is done, but names nothing that can be checked: "${oneLine(report.bareDone)}"`);
  if (required === "receipts-strict") for (const h of report.hedged ?? []) missing.push(`a hedged completion claim, nothing checked: "${oneLine(h)}"`);
  return { required, met: missing.length === 0, missing, counts };
}

export interface FlowCloseInput {
  session_id?: unknown;
  transcript_path?: unknown;
  last_assistant_message?: unknown;
  stop_hook_active?: unknown;
}

export interface FlowReceipt {
  receipt_version: "v1";
  flow_id: string;
  closed_at: string;
  status: "closed" | "open";
  mandate: { mandate_id: string; status: string; required_return_proof: string } | null;
  flow: { turns: number; blocked: number; subagents: number } | null;
  proof: ProofResult | null;
  /** hanumang return_with_proof (HNG-S-005), with this receipt as the filed, signed return receipt. */
  hng_return_with_proof: { score: number; outcome: string; notes: string[] } | null;
  /** Its place in the receipt chain: sequence number and the SHA-256 of the previous receipt (gap 3). */
  chain?: { seq: number; prev: string } | null;
  signature?: string;
}

export interface FlowCloseResult { receipt: FlowReceipt | null; path: string | null; reason?: string }

function oneLine(s: string): string {
  const t = String(s).replace(/\s+/g, " ").trim();
  return t.length > 140 ? t.slice(0, 137) + "…" : t;
}

/** JSON with every object's keys sorted, at every depth: what the signature covers. */
function stable(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(stable).join(",")}]`;
  if (v && typeof v === "object") return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${stable((v as Record<string, unknown>)[k])}`).join(",")}}`;
  return JSON.stringify(v ?? null);
}

/** The text a flow receipt's signature covers: everything but the signature. */
export function receiptCanonical(r: FlowReceipt): string {
  const { signature: _s, ...rest } = r;
  return stable(rest);
}

/**
 * Close (or keep open) one Claude Code flow at the end of a turn and write its receipt. Never throws:
 * a fault here must not trap the agent. `gradeFn` is injectable for tests.
 */
export function closeFlow(input: FlowCloseInput, gradeFn: (path: string, opts: object) => ReceiptsReport = grade as never): FlowCloseResult {
  try {
    const session = typeof input.session_id === "string" ? input.session_id : "";
    if (!SAFE_ID.test(session)) return { receipt: null, path: null, reason: "no usable session id; nothing to close" };
    const flowId = `cc:${session}`;
    const mandate: Mandate | null = loadMandateForSession(session);
    const mStatus = judgeMandate(mandate);
    const required: ReturnProof = mandate && isReturnProof(mandate.required_return_proof) ? mandate.required_return_proof : mandate ? DEFAULT_RETURN_PROOF : "none-declared";

    let report: ReceiptsReport | null = null;
    if (typeof input.transcript_path === "string" && existsSync(input.transcript_path)) {
      try {
        report = gradeFn(input.transcript_path, {
          rerun: false, // never run a command from this hook; the session record is the evidence
          finalText: typeof input.last_assistant_message === "string" ? input.last_assistant_message : undefined,
        });
      } catch { report = null; }
    }
    // A flow with no mandate has no root of authority to answer to (GTP-017): it stays open.
    const proof = mandate ? judgeReturnProof(required, report) : null;

    const summary = summariseFlows(readFlowEvents({ flowId })).find((f) => f.flow_id === flowId) ?? null;
    const hng = report && mandate ? (() => {
      const bridge = toHanumanG(report as never, { taskId: session }) as { inputs: Array<Record<string, unknown>> };
      const fromReceipts = bridge.inputs.find((i) => i.axis === "return_with_proof") ?? {};
      const s = scoreAxis({ ...fromReceipts, axis: "return_with_proof", receipt_filed: true, receipt_signed: true, actions_listed: summary !== null, task_id: session } as never) as { score: number; outcome: string; notes: string[] };
      return { score: s.score, outcome: s.outcome, notes: s.notes };
    })() : null;

    const receipt: FlowReceipt = {
      receipt_version: "v1",
      flow_id: flowId,
      closed_at: new Date().toISOString(),
      status: proof?.met ? "closed" : "open",
      mandate: mandate ? { mandate_id: mandate.mudrika_id, status: mStatus, required_return_proof: required } : null,
      flow: summary ? { turns: summary.turns, blocked: summary.blocked, subagents: summary.subagents } : null,
      proof,
      hng_return_with_proof: hng,
    };
    const name = `${session}.${Date.now().toString(36)}.json`;
    // Chained: each receipt names the previous one and is signed with that link in it (receipt-chain.ts).
    const chained = appendToChain(name, receipt as unknown as Record<string, unknown>);
    if (chained) {
      return { receipt: JSON.parse(readFileSync(chained.path, "utf8")) as FlowReceipt, path: chained.path };
    }
    // The chain was busy past its wait: write the receipt unchained and say so, never trap the agent.
    receipt.chain = null;
    receipt.signature = signWithMachineSecret(receiptCanonical(receipt));
    const dir = join(getAegisDir(), "flow-receipts");
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });
    const path = join(dir, name);
    writeFileSync(path, JSON.stringify(receipt, null, 2), { mode: 0o600 });
    return { receipt, path, reason: "receipt written UNCHAINED: the chain lock was busy" };
  } catch (e) {
    return { receipt: null, path: null, reason: `flow-close fault: ${String((e as Error)?.message ?? e).slice(0, 120)}` };
  }
}
