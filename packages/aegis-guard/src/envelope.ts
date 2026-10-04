// @xshieldai/aegis-guard — Agent Session Envelope helpers (ASE-T020)
//
// issueEnvelope  — POST /api/v1/aegis/session   — proxy-native agent frameworks use this at startup
// verifyEnvelope — GET  /api/v1/aegis/sessions/:id/audit — check seal integrity + drift
//
// @rule:ASE-001 every proxy-native agent session must call issueEnvelope before its first LLM call
// @rule:ASE-002 sealed_hash is computed by Aegis at issuance and returned in the response
// @rule:INF-ASE-002 if sealed_hash_verified=false the session must be quarantined immediately
// @rule:ASE-016 the helpers read the answer strictly: a seal is verified only when the
//               answer says exactly `true`, for the session that was asked about; an
//               answer with no session id or no seal is not an envelope
//
// These helpers trust the Aegis endpoint they are pointed at (aegis_url, or AEGIS_URL, or
// http://localhost:4850) and the connection to it. They do not recompute the seal.

export interface IssueEnvelopeParams {
  /** agent_type must be 'proxy-native' for frameworks calling this directly */
  agent_type?: "proxy-native" | "hook-native";
  service_key?: string;
  tenant_id?: string;
  trust_mask?: number;
  perm_mask?: number;
  class_mask?: number;
  /** Capabilities declared at birth — must be a subset of trust_mask. Empty = conservative default. */
  declared_caps?: string[];
  budget_usd?: number;
  parent_session_id?: string;
  /** Override the Aegis dashboard URL (default: AEGIS_URL env or http://localhost:4850) */
  aegis_url?: string;
}

export interface EnvelopeIssueResult {
  session_id: string;
  agent_id: string;
  sealed_hash: string;
  issued_at: string;
  expires_at: string;
  budget_usd: number;
  declared_caps: string[];
  perm_mask: number;
  class_mask: number;
}

export interface EnvelopeVerifyResult {
  session_id: string;
  /** true = sealed_hash matches stored fields. false = tampered — quarantine immediately. @rule:INF-ASE-002 */
  verified: boolean;
  drift_detected: boolean;
  drift_set: string[];
  declared_caps: string[];
  actual_caps_used: string[];
  budget_usd: number;
  budget_used_usd: number;
}

function aegisBase(override?: string): string {
  const base = override ?? process.env.AEGIS_URL ?? "http://localhost:4850";
  // Only http and https. Some runtimes will fetch a file: address and hand its contents
  // back as if Aegis had answered.
  let scheme = "";
  try { scheme = new URL(base).protocol; } catch { throw new Error("aegis-guard: the Aegis address is not a URL"); }
  if (scheme !== "http:" && scheme !== "https:") throw new Error(`aegis-guard: unsupported Aegis address scheme ${scheme}`);
  return base.replace(/\/+$/, "");
}

// @rule:ASE-001 issue a sealed envelope before the first action
export async function issueEnvelope(params: IssueEnvelopeParams): Promise<EnvelopeIssueResult> {
  const url = `${aegisBase(params.aegis_url)}/api/v1/aegis/session`;
  const body: Record<string, unknown> = {
    agent_type: params.agent_type ?? "proxy-native",
  };
  if (params.service_key)       body.service_key       = params.service_key;
  if (params.tenant_id)         body.tenant_id         = params.tenant_id;
  if (params.trust_mask != null) body.trust_mask       = params.trust_mask;
  if (params.perm_mask != null)  body.perm_mask        = params.perm_mask;
  if (params.class_mask != null) body.class_mask       = params.class_mask;
  if (params.declared_caps)     body.declared_caps     = params.declared_caps;
  if (params.budget_usd != null) body.budget_usd       = params.budget_usd;
  if (params.parent_session_id)  body.parent_session_id = params.parent_session_id;

  const resp = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  if (!resp.ok) {
    const text = await resp.text().catch(() => resp.statusText);
    throw new Error(`issueEnvelope failed (${resp.status}): ${text}`);
  }

  const data = await resp.json() as Record<string, unknown>;
  // @rule:ASE-016 — a 200 that carries an error, or no session id, or no seal, is not an
  // envelope. Before v0.4.0 it came back as a result with empty strings in it.
  if (data === null || typeof data !== "object" || data.ok === false) {
    throw new Error(`issueEnvelope failed: ${String((data as Record<string, unknown> | null)?.error ?? "the answer is not an envelope").slice(0, 200)}`);
  }
  if (typeof data.session_id !== "string" || data.session_id === "" ||
      typeof data.sealed_hash !== "string" || data.sealed_hash === "") {
    throw new Error("issueEnvelope failed: the answer has no session_id or no sealed_hash");
  }
  return {
    session_id:    data.session_id,
    agent_id:      String(data.agent_id ?? data.session_id),
    sealed_hash:   data.sealed_hash,
    issued_at:     String(data.issued_at ?? ""),
    expires_at:    String(data.expires_at ?? ""),
    budget_usd:    Number(data.budget_usd ?? 0),
    declared_caps: Array.isArray(data.declared_caps) ? data.declared_caps as string[] : [],
    perm_mask:     Number(data.perm_mask ?? data.trust_mask ?? 0),
    class_mask:    Number(data.class_mask ?? 0xFFFF),
  };
}

// @rule:INF-ASE-002 caller must quarantine if verified=false
export async function verifyEnvelope(
  sessionId: string,
  options?: { aegis_url?: string },
): Promise<EnvelopeVerifyResult> {
  const url = `${aegisBase(options?.aegis_url)}/api/v1/aegis/sessions/${encodeURIComponent(sessionId)}/audit`;

  const resp = await fetch(url);
  if (!resp.ok) {
    const text = await resp.text().catch(() => resp.statusText);
    throw new Error(`verifyEnvelope failed (${resp.status}): ${text}`);
  }

  const data = await resp.json() as Record<string, unknown>;
  if (data === null || typeof data !== "object" || data.ok === false) {
    throw new Error(`verifyEnvelope failed: ${String((data as Record<string, unknown> | null)?.error ?? "the answer is not an audit").slice(0, 200)}`);
  }
  // @rule:ASE-016 — the audit must be for the session that was asked about.
  if (data.session_id !== sessionId) {
    throw new Error("verifyEnvelope failed: the audit that came back is for another session, or names none");
  }
  const drift_set: string[] = Array.isArray(data.drift_set) ? data.drift_set as string[] : [];
  return {
    session_id:        sessionId,
    // Only the boolean true. Boolean("false") is true, and so is Boolean("tampered").
    verified:          data.sealed_hash_verified === true,
    // Drift unless the answer says exactly false AND the list is an empty list (or absent).
    drift_detected:    drift_set.length > 0 ||
                       (data.drift_set !== undefined && !Array.isArray(data.drift_set)) ||
                       (data.drift_detected !== undefined && data.drift_detected !== false),
    drift_set,
    declared_caps:     Array.isArray(data.declared_caps)     ? data.declared_caps as string[]    : [],
    actual_caps_used:  Array.isArray(data.actual_caps_used)  ? data.actual_caps_used as string[] : [],
    // The audit route names these budget_allocated and budget_used.
    budget_usd:        Number(data.budget_usd       ?? data.budget_allocated ?? 0),
    budget_used_usd:   Number(data.budget_used_usd  ?? data.budget_used      ?? 0),
  };
}
