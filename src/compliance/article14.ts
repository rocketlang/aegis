// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// EU AI Act Article 14 — Human Oversight evidence collector
// Article 14 requires: humans can understand, oversee, intervene, correct, suspend AI.
// KAVACH DAN gate is the implementation. Every gate event is one Article 14 evidence record.
//
// @rule:KOS-070 Article 14 evidence: every DAN gate event logged as structured JSON

import { getDb } from "../core/db";
import type { KavachApproval } from "../core/types";

export interface Article14Event {
  event_id: string;
  occurred_at: string;
  agent_id: string | null;
  session_id: string;
  action_requested: string;
  tool_name: string;
  dan_level: number;
  dan_level_label: string;
  consequence: string;
  human_decision: "ALLOWED" | "STOPPED" | "TIMED_OUT" | "EXPLAINED" | "PENDING";
  decided_by: string | null;
  decided_at: string | null;
  decision_latency_ms: number | null;
  oversight_demonstrated: boolean;
  rule_ref: "KOS-070";
  article: "EU AI Act Article 14 — Human Oversight";
}

export interface Article14Evidence {
  article: "14";
  title: "Human Oversight";
  effective_date: "2026-08-02";
  period_from: string;
  period_to: string;
  total_gate_events: number;
  events_with_human_decision: number;
  events_stopped: number;
  events_allowed: number;
  events_timed_out: number;
  oversight_rate_pct: number;
  compliant: boolean;
  compliance_note: string;
  events: Article14Event[];
}

const DAN_LABELS: Record<number, string> = {
  1: "L1 — Recoverable (data loss possible)",
  2: "L2 — Hard to reverse (external action)",
  3: "L3 — Irreversible (destructive schema/infra)",
  4: "L4 — Catastrophic (irreversible + high blast radius)",
};

function mapDecision(status: KavachApproval["status"]): Article14Event["human_decision"] {
  switch (status) {
    case "allowed": return "ALLOWED";
    case "stopped": return "STOPPED";
    case "timed_out": return "TIMED_OUT";
    case "explained": return "EXPLAINED";
    default: return "PENDING";
  }
}

// @rule:KOS-070
export function collectArticle14Evidence(
  from: Date,
  to: Date
): Article14Evidence {
  const db = getDb();

  const rows = db.query(
    `SELECT id, created_at, command, tool_name, level, consequence, session_id,
            status, decided_at, decided_by
     FROM kavach_approvals
     WHERE created_at >= ? AND created_at <= ?
     ORDER BY created_at ASC`
  ).all(from.toISOString(), to.toISOString()) as KavachApproval[];

  const events: Article14Event[] = rows.map((row) => {
    const decision = mapDecision(row.status);
    const latencyMs =
      row.created_at && row.decided_at
        ? new Date(row.decided_at).getTime() - new Date(row.created_at).getTime()
        : null;

    return {
      event_id: row.id,
      occurred_at: row.created_at,
      agent_id: null,                       // not stored at approval level — session is the trace
      session_id: row.session_id,
      action_requested: row.command,
      tool_name: row.tool_name,
      dan_level: row.level,
      dan_level_label: DAN_LABELS[row.level] ?? `L${row.level}`,
      consequence: row.consequence,
      human_decision: decision,
      decided_by: row.decided_by ?? null,
      decided_at: row.decided_at ?? null,
      decision_latency_ms: latencyMs,
      // Oversight demonstrated = a human actively decided (not timed out or pending)
      oversight_demonstrated: decision === "ALLOWED" || decision === "STOPPED" || decision === "EXPLAINED",
      rule_ref: "KOS-070",
      article: "EU AI Act Article 14 — Human Oversight",
    };
  });

  const withDecision = events.filter((e) => e.oversight_demonstrated).length;
  const stopped = events.filter((e) => e.human_decision === "STOPPED").length;
  const allowed = events.filter((e) => e.human_decision === "ALLOWED").length;
  const timedOut = events.filter((e) => e.human_decision === "TIMED_OUT").length;
  const oversightRate = events.length > 0 ? Math.round((withDecision / events.length) * 100) : 100;

  // Compliant if: oversight rate ≥ 80% OR total events = 0 (no gate events = no violations)
  const compliant = events.length === 0 || oversightRate >= 80;

  return {
    article: "14",
    title: "Human Oversight",
    effective_date: "2026-08-02",
    period_from: from.toISOString(),
    period_to: to.toISOString(),
    total_gate_events: events.length,
    events_with_human_decision: withDecision,
    events_stopped: stopped,
    events_allowed: allowed,
    events_timed_out: timedOut,
    oversight_rate_pct: oversightRate,
    compliant,
    compliance_note: events.length === 0
      ? "No DAN gate events in period — no dangerous actions attempted."
      : compliant
        ? `Human oversight demonstrated on ${oversightRate}% of gate events. DAN gate operational.`
        : `Oversight rate ${oversightRate}% below 80% threshold. Review timed-out events.`,
    events,
  };
}
