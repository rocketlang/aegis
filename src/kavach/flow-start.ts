// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// Flow start: the root of a flow, set at a session's start or resume (governed-turn-protocol §19, P3/P4 gap 1).
//
// @rule:GTP-017 a flow's root is its mandate: kept when valid, issued when missing, renewed when expired
// (founder ruling 2026-10-15: 24 hours, renewed at session start). Never replaced when revoked (GTP-022).
// @rule:GTP-019 the session's ROOT ENVELOPE is requested naming that mandate, so the envelope's ceiling is
// computed from the mandate. One envelope per Claude Code session, kept at <aegis dir>/flows/<session>.json.
//
// Why this exists (found 15 October 2026): the older session hook recorded the box's envelope in ONE file,
// <aegis dir>/ase_session_id, and asked for an envelope only while that file was missing. It was written
// once in May, so every later session shared that one envelope and no session had a root of its own. That
// hook is left as it is (its budget check still reads the shared file); this one gives each session its own.

import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { join } from "path";
import { execFileSync } from "child_process";
import { getAegisDir } from "../core/config";
import { deriveTrustFromGitRemote } from "../core/ase";
import { ensureMandateForSession, flowEnvLine, isReturnProof } from "./mandate";
import type { MandateStatus, ReturnProof } from "./mandate";

const SAFE_ID = /^[A-Za-z0-9_-]{1,128}$/;

export interface FlowStartInput { session_id?: unknown; cwd?: unknown; source?: unknown }

export interface FlowRoot {
  session_id: string;
  /** Set when this session was started under another flow (AEGIS_FLOW). */
  parent_session?: string;
  mandate_id: string | null;
  mandate_status: MandateStatus;
  envelope_session_id: string | null;
  updated_at: string;
}

export interface FlowStartResult {
  root: FlowRoot | null;
  /** What happened, one line, for the hook's stderr and the tests. */
  note: string;
}

export interface FlowStartDeps {
  aegisUrl: string;
  fetchFn?: typeof fetch;
  returnProof?: unknown;
  /** The repository's remote, for the trust mask. Default: `git remote get-url origin` in cwd. */
  remoteOf?: (cwd: string) => string | null;
  /** AEGIS_FLOW as this session's process received it (a parent flow carried into a subprocess). */
  flowEnv?: unknown;
  /** CLAUDE_ENV_FILE: where to hand this flow to the session's later shell commands. */
  envFile?: string;
}

export const flowRootPath = (session: string): string => join(getAegisDir(), "flows", `${session}.json`);

export function readFlowRoot(session: string): FlowRoot | null {
  if (!SAFE_ID.test(session)) return null;
  try { return JSON.parse(readFileSync(flowRootPath(session), "utf8")) as FlowRoot; } catch { return null; }
}

function gitRemote(cwd: string): string | null {
  try {
    return execFileSync("git", ["-C", cwd, "remote", "get-url", "origin"], { encoding: "utf8", timeout: 1500, stdio: ["ignore", "pipe", "ignore"] }).trim() || null;
  } catch { return null; }
}

/** Never throws: a fault here must not stop a session from starting. */
export async function startFlow(input: FlowStartInput, deps: FlowStartDeps): Promise<FlowStartResult> {
  try {
    const session = typeof input.session_id === "string" ? input.session_id : "";
    if (!SAFE_ID.test(session)) return { root: null, note: "no usable session id; no flow root" };
    const cwd = typeof input.cwd === "string" && input.cwd ? input.cwd : process.cwd();
    const { service_key, trust_mask } = deriveTrustFromGitRemote((deps.remoteOf ?? gitRemote)(cwd));
    const returnProof: ReturnProof | undefined = isReturnProof(deps.returnProof) ? deps.returnProof : undefined;

    const m = ensureMandateForSession(session, { trustMask: trust_mask, scopeKey: service_key, returnProof, flowEnv: deps.flowEnv });
    const previous = readFlowRoot(session);
    const parentSession = m.mandate?.parent_session;
    const root: FlowRoot = {
      session_id: session,
      ...(parentSession ? { parent_session: parentSession } : {}),
      mandate_id: m.mandate?.mudrika_id ?? null,
      mandate_status: m.status,
      envelope_session_id: previous?.envelope_session_id ?? null,
      updated_at: new Date().toISOString(),
    };

    let note = m.issued ? (m.renewed ? `mandate ${root.mandate_id} renewed (was ${m.renewed}, expired)` : `mandate ${root.mandate_id} issued`)
      : m.mandate ? `mandate ${root.mandate_id} ${m.status}` : m.refused ? `no mandate: ${m.refused}` : "no mandate (no principal in the approvers file)";
    if (parentSession) note += ` (child of ${parentSession})`;

    // A new root envelope only when there is a valid mandate and none was issued for THIS mandate yet.
    const parentEnvelope = parentSession ? readFlowRoot(parentSession)?.envelope_session_id ?? null : null;
    const needEnvelope = m.status === "valid" && root.mandate_id && !(previous?.envelope_session_id && previous.mandate_id === root.mandate_id);
    if (needEnvelope && parentSession && !parentEnvelope) {
      root.envelope_session_id = null; // a child is never made a root (GTP-021)
      note += "; no envelope requested: the parent flow has no root envelope";
    } else if (needEnvelope) {
      try {
        const res = await (deps.fetchFn ?? fetch)(`${deps.aegisUrl}/api/v1/aegis/session`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          // A child flow's envelope is a child of its parent's root envelope (narrowed by ASE, KAV-065);
          // a root flow's names its mandate (GTP-017/019).
          body: JSON.stringify({ agent_type: "hook-native", service_key, trust_mask, tenant_id: "default", declared_caps: [], budget_usd: 0,
            ...(parentEnvelope ? { parent_session_id: parentEnvelope } : { mandate_id: root.mandate_id }) }),
          signal: AbortSignal.timeout(3000),
        });
        const body = (await res.json().catch(() => ({}))) as { session_id?: string; error?: string };
        if (res.ok && typeof body.session_id === "string") {
          root.envelope_session_id = body.session_id;
          note += `; root envelope ${body.session_id}`;
        } else {
          root.envelope_session_id = null;
          note += `; root envelope refused (${res.status}${body.error ? `: ${String(body.error).slice(0, 120)}` : ""})`;
        }
      } catch (e) {
        root.envelope_session_id = null;
        note += `; root envelope not issued (aegis unreachable: ${String((e as Error)?.message ?? e).slice(0, 80)})`;
      }
    } else if (m.status !== "valid") {
      root.envelope_session_id = null; // a flow whose mandate is not valid has no live root envelope
    }

    const dir = join(getAegisDir(), "flows");
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });
    writeFileSync(flowRootPath(session), JSON.stringify(root, null, 2), { mode: 0o600 });

    // Carriage (GTP §19.4): later shell commands of this session carry the flow, so an agent started there
    // is this flow's child. Appended, never overwritten: the file belongs to every SessionStart hook.
    if (m.status === "valid" && root.mandate_id && deps.envFile) {
      const line = flowEnvLine(session, root.mandate_id);
      if (line) { try { appendFileSync(deps.envFile, line); note += "; flow carried to shell commands"; } catch { note += "; could not write CLAUDE_ENV_FILE"; } }
    }
    return { root, note };
  } catch (e) {
    return { root: null, note: `flow-start fault: ${String((e as Error)?.message ?? e).slice(0, 120)}` };
  }
}
