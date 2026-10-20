// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// aegis Bulkhead — governed communication between agents (key aegis-bulkhead, rules BLK-*).
// Logics: /root/proposals/aegis-bulkhead--logics--formal--2026-10-21.md

// @rule:BLK-003 the kinds are FINDING, REQUEST and ACK; there is no COMMAND kind
export const KINDS = ["FINDING", "REQUEST", "ACK"] as const;
export type Kind = (typeof KINDS)[number];

// A one-way door between two compartments, declared by a person in doors.json.
export interface Door {
  id: string;
  from: string;              // compartment id (aegis swarm_id)
  to: string;                // compartment id
  kinds: Kind[];
  fields?: string[];         // allowed body keys; absent = any key
  rate_per_min?: number;     // default 30
  max_depth?: number;        // default 4
  pingpong_max?: number;     // default 6: messages between one pair on one subject per window
  parties?: string[];        // P3, cross-party doors
}

// Who an agent is, as proven by its delegation token (BLK-YK-002).
export interface Identity {
  agent_id: string;
  mask: number;              // effective mask from the token chain
  compartment: string;       // swarm_id
  ceiling: number;           // swarm_mask
}

export interface SendInput {
  to: string;                // receiving agent_id
  kind: Kind | string;
  subject: string;
  body?: Record<string, unknown>;
  evidence_ref?: string;
  in_reply_to?: string;
  received_hash?: string;    // ACK only: hash of the message the receiver got
}

export interface Envelope {
  id: string;
  door: string | null;       // null inside one compartment
  from: string;
  to: string;
  kind: Kind;
  subject: string;
  body: Record<string, unknown>;
  evidence_ref?: string;
  in_reply_to?: string;
  received_hash?: string;
  depth: number;             // computed by the bulkhead, never taken from the sender
  sent_at: string;
  // carried for the taint, not part of what the receiver may change
  sender_mask: number;
  sender_ceiling: number;
}

export interface Delivered extends Envelope {
  hash: string;
  untrusted: true;           // INF-BLK-001: data with provenance, never an instruction
}

export interface Taint {
  agent_id: string;
  message_id: string;
  cap: number;               // sender_mask & sender_ceiling & receiver ceiling
  expires_at: number;        // epoch ms
}

export type SendResult =
  | { ok: true; id: string; hash: string; door: string | null }
  | { ok: false; rule: string; reason: string };

export const DEFAULTS = {
  rate_per_min: 30,
  max_depth: 4,
  pingpong_max: 6,
  pingpong_window_ms: 10 * 60_000,
  taint_ms: 10 * 60_000,     // BLK-YK-003
  body_max_bytes: 2048,
};
