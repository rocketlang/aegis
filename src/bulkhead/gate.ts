// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// The bulkhead's face in the live destructive gate (check-destructive). Reads the bulkhead state; never writes.
// @rule:BLK-004 an action taken while tainted runs under receiver & every live taint's cap
// @rule:BLK-013 a tool whose required bits are not all inside the cap is refused; a state that exists
//               but cannot be read refuses; no bulkhead folder means no taint and no change

import { existsSync, readFileSync } from "fs";
import { join } from "path";

export type GateVerdict =
  | { allowed: true; tainted: false }
  | { allowed: true; tainted: true; cap: number; tainted_by: string[] }
  | { allowed: false; reason: string; cap?: number; tainted_by?: string[] };

export function bulkheadVerdict(dir: string, agentId: string, ownMask: number | (() => number), requiredBits: number, now = Date.now()): GateVerdict {
  const sp = join(dir, "state.json");
  if (!existsSync(sp)) return { allowed: true, tainted: false };
  let taints: { agent_id: string; message_id: string; cap: number; expires_at: number }[];
  try {
    const st = JSON.parse(readFileSync(sp, "utf-8"));
    taints = Array.isArray(st.taints) ? st.taints : [];
  } catch (e) {
    return { allowed: false, reason: `bulkhead state ${sp} cannot be read (${(e as Error).message}); a gate that cannot read its state refuses` };
  }
  const live = taints.filter((t) => t && t.agent_id === agentId && Number(t.expires_at) > now);
  if (live.length === 0) return { allowed: true, tainted: false };
  const own = typeof ownMask === "function" ? ownMask() : ownMask;
  const cap = live.reduce((m, t) => m & Number(t.cap), own);
  const tainted_by = live.map((t) => t.message_id);
  if ((requiredBits & ~cap) !== 0) {
    return {
      allowed: false, cap, tainted_by,
      reason: `acting on a peer's message (${tainted_by.join(", ")}): this tool needs bits 0x${requiredBits.toString(16)}, the cap is 0x${cap.toString(16)}`,
    };
  }
  return { allowed: true, tainted: true, cap, tainted_by };
}
