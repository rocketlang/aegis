// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// The default identity check: the agent's aegis delegation token (SDT) and its swarm.
// @rule:BLK-YK-002 verify a peer by its token, never by its name
// @rule:INF-BLK-002 a compartment is an aegis swarm; its swarm_mask is the ceiling (KAV-090)

import type { IdentityResolver } from "./bulkhead";
import type { ScopedDelegationToken } from "../auth/types";

export async function sdtIdentity(): Promise<IdentityResolver> {
  const { validateChain, isExpired, getSdtById } = await import("../auth/sdt");
  const { getAgentSwarm } = await import("../sandbox/swarm");
  const { canonical } = await import("./bell-book");
  return {
    resolve(token: unknown) {
      const t = token as ScopedDelegationToken;
      if (!t || typeof t !== "object" || !t.identity?.agent_id || !t.delegation) return { error: "no delegation token" };
      // validateChain checks the parent covers the child, not that the token is the one aegis issued:
      // an agent could raise its own mask up to its parent's. So the presented token must be the stored one.
      const stored = getSdtById(t.token_id);
      if (!stored) return { error: "token was not issued by this aegis" };
      if (canonical(stored) !== canonical(t)) return { error: "token differs from the one issued" };
      if (isExpired(t)) return { error: "token expired" };
      const v = validateChain(t);
      if (!v.valid) return { error: `token chain: ${v.reason}` };
      const swarm = getAgentSwarm(t.identity.agent_id);
      if (!swarm) return { error: `${t.identity.agent_id} is in no compartment (swarm)` };
      if (swarm.expires_at && Date.now() > swarm.expires_at) return { error: `compartment ${swarm.swarm_id} has expired` };
      return { agent_id: t.identity.agent_id, mask: v.effective_mask, compartment: swarm.swarm_id, ceiling: swarm.swarm_mask };
    },
    compartmentOf(agentId: string) {
      const s = getAgentSwarm(agentId);
      return s ? { compartment: s.swarm_id, ceiling: s.swarm_mask } : null;
    },
  };
}
