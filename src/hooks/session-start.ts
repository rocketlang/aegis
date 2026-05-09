// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// session-start — UserPromptSubmit hook
// Fires on every user prompt. First fire per session = session registration.
// Captures the DESK: hostname, cwd, git remote, model, Claude Code version.
//
// @rule:KOS-076 every Claude Code session auto-registers at first prompt;
//               desk context (hostname/cwd/git/model) is the audit anchor
//
// Records to:
//   ~/.aegis/aegis.db  sessions table  (structured, queryable)
//   ~/.aegis/sessions/{session_id}.desk.json  (self-contained, offline-verifiable)

import { readFileSync, writeFileSync, existsSync, mkdirSync, readdirSync, renameSync } from "fs";
import { join } from "path";
import { hostname } from "os";
import { execSync } from "child_process";
import { getAegisDir } from "../core/config";
import { getDb, acknowledgeAllBgAgents } from "../core/db";
import { issueMudrika, loadOrRotateMudrika } from "../kernel/mudrika";
import { createTurn } from "../telemetry/turn-store";
import { deriveTrustFromGitRemote, loadEnvelopeBySessionId, createDefaultEnvelope, storeEnvelope } from "../core/ase";
import { verifyLineage, formatGnt002Log } from "../kavach/genetic-trust";
import { DASHBOARD_PORT } from "../core/config";

interface HookPayload {
  session_id?: string;
  cwd?: string;
  transcript_path?: string;
  hook_event_name?: string;
  prompt?: string;
}

interface DeskContext {
  session_id: string;
  registered_at: string;
  hostname: string;
  cwd: string;
  git_remote: string | null;
  git_branch: string | null;
  git_repo: string | null;
  model: string | null;
  claude_code_version: string | null;
  transcript_path: string | null;
  rule_ref: "KOS-076";
}

function tryExec(cmd: string): string | null {
  try {
    return execSync(cmd, { encoding: "utf-8", timeout: 2000, stdio: ["pipe","pipe","pipe"] }).trim() || null;
  } catch {
    return null;
  }
}

// ─── Oracle Phase 1 — Baseline Snapshot (SOR-T-101 to SOR-T-104) ─────────────
// @rule:SOR-001 @rule:SOR-003 @rule:SOR-004

const SERVICES_JSON   = "/root/.ankr/config/services.json";
const PROPOSALS_DIR   = "/root/proposals";
const TODOS_DIR       = "/root/ankr-todos";
const DOC_TYPES       = ["brainstorm", "project", "logics", "todo", "deep-knowledge"] as const;

function detectService(cwd: string): { service_key: string | null; detection_method: string } {
  // SOR-YK-001 Phase 1: CWD-based detection only
  try {
    const registry = JSON.parse(readFileSync(SERVICES_JSON, "utf-8")).services ?? {};
    const cwdKey = cwd.split("/").pop() ?? "";
    if (cwdKey && registry[cwdKey]) return { service_key: cwdKey, detection_method: "cwd" };
    // Try stripping -backend / -api suffix
    const stripped = cwdKey.replace(/-(backend|api)$/, "");
    if (stripped !== cwdKey && registry[stripped]) return { service_key: stripped, detection_method: "cwd-stripped" };
  } catch { /* fail open */ }
  return { service_key: null, detection_method: "none" };
}

function runOraclePhase1(sessionId: string, cwd: string): void {
  const baselinePath = join(sessionsDir(), `${sessionId}.baseline.json`);
  if (existsSync(baselinePath)) return; // SOR-INF-007: skip on /resume

  const now = new Date().toISOString();
  const { service_key, detection_method } = detectService(cwd);

  let codex: Record<string, unknown> = {};
  let detected = false;
  let codexPath: string | null = null;

  if (service_key) {
    try {
      const registry = JSON.parse(readFileSync(SERVICES_JSON, "utf-8")).services ?? {};
      const svcEntry = registry[service_key];
      const candidate = svcEntry?.path ? join(svcEntry.path, "codex.json") : join("/root", service_key, "codex.json");
      if (existsSync(candidate)) { codex = JSON.parse(readFileSync(candidate, "utf-8")); codexPath = candidate; detected = true; }
    } catch { /* partial baseline still valid */ }
  }

  // SOR-T-103: doc presence check for k_mask bits 0-4
  const docsPresent: string[] = [];
  const docsMissing: string[] = [];
  if (service_key) {
    for (const dt of DOC_TYPES) {
      try {
        const dir = dt === "todo" ? TODOS_DIR : PROPOSALS_DIR;
        const found = readdirSync(dir).some(f => f.startsWith(`${service_key}--${dt}--`));
        (found ? docsPresent : docsMissing).push(dt);
      } catch { docsMissing.push(dt); }
    }
  }

  const baseline = {
    session_id: sessionId, service_key, detection_method, detected_at: now, detected,
    ...(codexPath ? { codex_path: codexPath } : {}),
    k_mask:      codex.k_mask      ?? null,
    trust_mask:  codex.trust_mask  ?? null,
    req_mask:    codex.req_mask    ?? null,
    docs_present: docsPresent,
    docs_missing: docsMissing,
  };

  // SOR-YK-008: atomic write
  const tmp = baselinePath + ".tmp";
  writeFileSync(tmp, JSON.stringify(baseline, null, 2), { mode: 0o600 });
  renameSync(tmp, baselinePath);

  process.stderr.write(
    `[KAVACH:oracle] baseline | service=${service_key ?? "none"} | k_mask=${codex.k_mask ?? "?"} | missing=${docsMissing.join(",") || "none"}\n`
  );
}

function sessionsDir(): string {
  const dir = join(getAegisDir(), "sessions");
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  return dir;
}

function deskPath(sessionId: string): string {
  return join(sessionsDir(), `${sessionId}.desk.json`);
}

// @rule:KOS-076
async function run(): Promise<void> {
  const stdin = (() => {
    try { return readFileSync("/dev/stdin", "utf-8"); } catch { return "{}"; }
  })();

  let payload: HookPayload = {};
  try { payload = JSON.parse(stdin); } catch {}

  // Claude Code v2.1+ does not inject session_id — derive a stable ID for the session lifetime.
  // Priority: payload > env > state file (reuse if desk exists) > fresh timestamp
  const currentSessionFile = join(getAegisDir(), "current_session");
  const storedId = existsSync(currentSessionFile)
    ? readFileSync(currentSessionFile, "utf-8").trim()
    : null;
  const sessionId =
    payload.session_id ??
    process.env.CLAUDE_SESSION_ID ??
    (storedId && existsSync(deskPath(storedId)) ? storedId : null) ??
    `ses_${Date.now()}`;
  const cwd = payload.cwd ?? process.cwd();

  // @rule:KOS-T095 — "force quit" escape: user types it when Stop hook blocks on bg agents
  const prompt = payload.prompt ?? "";
  if (/\bforce\s*quit\b/i.test(prompt)) {
    try {
      acknowledgeAllBgAgents(sessionId);
      process.stderr.write(`[KAVACH:bg] force quit — background agent guard cleared. Ctrl+C now to exit.\n`);
    } catch {}
  }

  // @rule:KOS-091 — create a new turn row for every prompt (regardless of desk-already-registered)
  try { createTurn(sessionId, payload.prompt?.slice(0, 200) ?? null); } catch {}

  // @rule:ASE-012 budget check on every prompt fire (after first UPS).
  // Runs before the desk-already-registered early return so budget is checked every turn.
  // @rule:ASE-011 fail open if Aegis unreachable — never fail closed for inference
  const aseSessionFile = join(getAegisDir(), "ase_session_id");
  const aseSessionId = existsSync(aseSessionFile)
    ? readFileSync(aseSessionFile, "utf-8").trim()
    : null;
  if (aseSessionId) {
    try {
      const AEGIS_URL = process.env.AEGIS_URL ?? `http://localhost:${DASHBOARD_PORT}`;
      const envRes = await fetch(`${AEGIS_URL}/api/v1/aegis/session/${encodeURIComponent(aseSessionId)}`);
      if (envRes.ok) {
        const envData = await envRes.json() as { budget_usd?: number; budget_remaining?: number | null };
        if (
          typeof envData.budget_usd === "number" &&
          envData.budget_usd > 0 &&
          typeof envData.budget_remaining === "number" &&
          envData.budget_remaining <= 0
        ) {
          // @rule:ASE-012 block prompt — budget exhausted
          const used = (envData as any).budget_used_usd ?? envData.budget_usd;
          process.stdout.write(JSON.stringify({
            decision: "block",
            reason: `AEGIS: session budget $${envData.budget_usd.toFixed(2)} exhausted (used: $${Number(used).toFixed(2)})`,
          }));
          // Emit budget blocked event best-effort
          try {
            await fetch(`${AEGIS_URL}/api/v1/forja/sense/emit`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ event: "aegis.session.budget.gate_blocked", payload: { session_id: aseSessionId, rule_ref: "ASE-012" } }),
            });
          } catch {}
          process.exit(0);
        }
      }
    } catch {
      // Fail open — Aegis unreachable is not a reason to block inference
      process.stderr.write("[KAVACH:ase] Aegis unreachable for budget check — failing open\n");
    }
  }

  // Only register desk once per session — subsequent prompts are already captured
  if (existsSync(deskPath(sessionId))) return;

  const now = new Date().toISOString();

  // Capture desk context
  const gitRemote = tryExec("git remote get-url origin");
  const gitBranch = tryExec("git rev-parse --abbrev-ref HEAD");
  const gitRepo = tryExec("git rev-parse --show-toplevel");
  const model =
    process.env.ANTHROPIC_MODEL ??
    process.env.CLAUDE_MODEL ??
    process.env.CLAUDE_CODE_MODEL ??
    null;
  const claudeVersion = tryExec("claude --version 2>/dev/null");

  const desk: DeskContext = {
    session_id: sessionId,
    registered_at: now,
    hostname: hostname(),
    cwd,
    git_remote: gitRemote,
    git_branch: gitBranch,
    git_repo: gitRepo,
    model,
    claude_code_version: claudeVersion,
    transcript_path: payload.transcript_path ?? null,
    rule_ref: "KOS-076",
  };

  // Write desk file — self-contained, offline-verifiable per session
  writeFileSync(deskPath(sessionId), JSON.stringify(desk, null, 2), { mode: 0o600 });

  // Persist session ID so PostToolUse + Stop hooks can correlate without payload
  writeFileSync(join(getAegisDir(), "current_session"), sessionId, { mode: 0o600 });

  // @rule:BMC-003 initialise session_mask = 1 (bit 0: core-invariants always on)
  // Written fresh on every new desk registration. Preserved on /resume (desk already exists).
  writeFileSync(join(getAegisDir(), "current_session_mask"), "1", { mode: 0o600 });

  // @rule:SOR-001 @rule:SOR-004 oracle Phase 1: capture pre-session baseline
  // Fail open — any error here must never block session start
  try { runOraclePhase1(sessionId, cwd); } catch { /* SOR-004 */ }

  // Register in sessions table
  try {
    const db = getDb();
    const existing = db.query("SELECT session_id FROM sessions WHERE session_id = ?").get(sessionId);
    if (existing) {
      db.run(
        `UPDATE sessions SET hostname=?, model=?, git_remote=?, project_path=? WHERE session_id=?`,
        [desk.hostname, desk.model ?? null, desk.git_remote ?? null, cwd, sessionId]
      );
    } else {
      db.run(
        `INSERT INTO sessions (session_id, project_path, first_seen, last_activity, status, hostname, model, git_remote)
         VALUES (?,?,?,?,'active',?,?,?)`,
        [sessionId, cwd, now, now, desk.hostname, desk.model ?? null, desk.git_remote ?? null]
      );
    }
  } catch { /* desk file is the fallback */ }

  // @rule:ASE-001 @rule:ASE-013 — issue sealed ASE for this hook-native session
  // First UPS fire only (ase_session_id file not yet written).
  // Fail open if Aegis unreachable — desk registration must not block a new session.
  if (!existsSync(aseSessionFile)) {
    try {
      const { service_key, trust_mask } = deriveTrustFromGitRemote(gitRemote);
      const AEGIS_URL = process.env.AEGIS_URL ?? `http://localhost:${DASHBOARD_PORT}`;
      // @rule:GNT-002 — read parent session ID from env (set by Claude Code for child agents)
      const parentSessionId = process.env.CLAUDE_PARENT_SESSION_ID ?? null;

      const aseBody = {
        agent_type: "hook-native",
        service_key,
        trust_mask,
        tenant_id: "default",
        declared_caps: [],  // conservative default; agents may call with explicit caps
        budget_usd: 0,      // unlimited by default; set via env AEGIS_SESSION_BUDGET_USD
        parent_session_id: parentSessionId,
      };
      const budgetFromEnv = parseFloat(process.env.AEGIS_SESSION_BUDGET_USD ?? "0");
      if (budgetFromEnv > 0) aseBody.budget_usd = budgetFromEnv;

      const aseRes = await fetch(`${AEGIS_URL}/api/v1/aegis/session`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(aseBody),
      });
      if (aseRes.ok) {
        const aseData = await aseRes.json() as { session_id?: string; sealed_hash?: string };
        if (aseData.session_id) {
          writeFileSync(aseSessionFile, aseData.session_id, { mode: 0o600 });
          process.stderr.write(
            `[KAVACH:ase] sealed session ${aseData.session_id} | hash=${aseData.sealed_hash?.slice(0, 12)}... | service=${service_key}\n`
          );
        }
      } else {
        // Fall back to local envelope creation (Aegis not running yet)
        const localEnvelope = createDefaultEnvelope(sessionId, gitRemote);
        storeEnvelope(localEnvelope);
        writeFileSync(aseSessionFile, localEnvelope.session_id, { mode: 0o600 });
        process.stderr.write(`[KAVACH:ase] local sealed session ${localEnvelope.session_id} (Aegis offline)\n`);
      }
    } catch (err) {
      process.stderr.write(`[KAVACH:ase] envelope issuance failed — ${String(err)} — failing open\n`);
    }
  }

  // @rule:GNT-002 — verify child trust_mask is a valid subset of parent trust_mask
  // Fires only when CLAUDE_PARENT_SESSION_ID is set (child agent session).
  // Fail open — lineage violation is an alert, not a session block.
  try {
    const parentSessionId = process.env.CLAUDE_PARENT_SESSION_ID ?? null;
    if (parentSessionId) {
      const childEnvelope = loadEnvelopeBySessionId(sessionId);
      const parentEnvelope = loadEnvelopeBySessionId(parentSessionId);
      const childMask = childEnvelope?.trust_mask ?? 1;
      const parentMask = parentEnvelope?.trust_mask ?? null;
      const lineage = verifyLineage(childMask, parentMask);
      process.stderr.write(formatGnt002Log(lineage) + "\n");
      if (!lineage.valid && lineage.reason === "MASK_OVERFLOW") {
        // Overflow: child has bits parent doesn't. This is a self-elevation attempt.
        // Alert — do not block (fail open); AEGIS enforcement layer handles escalation.
        process.stderr.write(
          `[KAVACH:GNT-002] ALERT — child session ${sessionId} has elevated trust beyond ` +
          `parent ${parentSessionId} — potential self-elevation — GNT-002\n`
        );
      }
    }
  } catch { /* GNT-002 is advisory — never block session start */ }

  // Issue mudrika for this session if not present
  try {
    const existing = loadOrRotateMudrika(sessionId);
    if (!existing) {
      const domain = process.env.KAVACHOS_DOMAIN ?? "general";
      const cred = issueMudrika(sessionId, sessionId, domain);
      try {
        getDb().run("UPDATE sessions SET mudrika_uri=? WHERE session_id=?", [cred.uri, sessionId]);
      } catch {}
    }
  } catch { /* mudrika optional at session start */ }

  process.stderr.write(
    `[KAVACH:session] registered ${sessionId} | host=${desk.hostname} | model=${desk.model ?? "unknown"} | cwd=${cwd}\n`
  );
}

run().then(() => process.exit(0)).catch(err => {
  process.stderr.write(`[KAVACH:session-start] fatal: ${err}\n`);
  process.exit(0); // always exit 0 — hook failure must not block Claude Code
});
