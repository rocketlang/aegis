// @ankr/aegis-guard — Agent Session Envelope helpers (ASE-T020)
//
// issueEnvelope  — POST /api/v1/aegis/session   — proxy-native agent frameworks use this at startup
// verifyEnvelope — GET  /api/v1/aegis/sessions/:id/audit — check seal integrity + drift
//
// @rule:ASE-001 every proxy-native agent session must call issueEnvelope before its first LLM call
// @rule:ASE-002 sealed_hash is computed by Aegis at issuance and returned in the response
// @rule:INF-ASE-002 if sealed_hash_verified=false the session must be quarantined immediately

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
  return override ?? process.env.AEGIS_URL ?? "http://localhost:4850";
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
  return {
    session_id:    String(data.session_id ?? ""),
    agent_id:      String(data.agent_id ?? data.session_id ?? ""),
    sealed_hash:   String(data.sealed_hash ?? ""),
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
  const drift_set: string[] = Array.isArray(data.drift_set) ? data.drift_set as string[] : [];
  return {
    session_id:        sessionId,
    verified:          Boolean(data.sealed_hash_verified ?? false),
    drift_detected:    Boolean(data.drift_detected ?? drift_set.length > 0),
    drift_set,
    declared_caps:     Array.isArray(data.declared_caps)     ? data.declared_caps as string[]    : [],
    actual_caps_used:  Array.isArray(data.actual_caps_used)  ? data.actual_caps_used as string[] : [],
    budget_usd:        Number(data.budget_usd       ?? 0),
    budget_used_usd:   Number(data.budget_used_usd  ?? 0),
  };
}
