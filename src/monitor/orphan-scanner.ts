// AEGIS — NHI Orphan Scanner
// @rule:NHI-009 — daily cron: finds agents with no owner, expired TTL, or 90+ days idle
// @rule:INF-NHI-001 — no owner + active → SENSE alert → 48h grace → auto-retire
// @rule:INF-NHI-002 — credential_expires_at < now + active → auto-set inactive → alert

const REGISTRY_URL = process.env.REGISTRY_URL ?? "http://localhost:4586";
const REGISTRY_ADMIN_KEY = process.env.REGISTRY_ADMIN_KEY ?? "ankr-registry-dev-key";

interface OrphanResult {
  agent_id: string;
  name: string;
  owner: string;
  status: string;
  registered_at: string;
  credential_expires_at: string;
  trust_mask: number;
}

async function fetchOrphans(): Promise<OrphanResult[]> {
  const res = await fetch(`${REGISTRY_URL}/api/v2/agents/orphans`, {
    headers: { "X-Admin-Key": REGISTRY_ADMIN_KEY },
  });
  if (!res.ok) throw new Error(`Registry responded ${res.status}`);
  const data = await res.json() as { ok: boolean; orphans: OrphanResult[] };
  return data.orphans ?? [];
}

async function sleepAgent(agent_id: string, reason: string): Promise<void> {
  await fetch(`${REGISTRY_URL}/api/v2/agents/${agent_id}/sleep`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Admin-Key": REGISTRY_ADMIN_KEY },
    body: JSON.stringify({ actor: "aegis-orphan-scanner", reason }),
  });
}

export async function runOrphanScan(): Promise<void> {
  console.log(`[AEGIS:NHI] Orphan scan started — ${new Date().toISOString()}`);

  let orphans: OrphanResult[] = [];
  try {
    orphans = await fetchOrphans();
  } catch (err: any) {
    console.warn(`[AEGIS:NHI] Registry unreachable — scan skipped: ${err.message}`);
    return;
  }

  if (orphans.length === 0) {
    console.log(`[AEGIS:NHI] No orphans found.`);
    return;
  }

  console.error(`\n\x1b[31m[AEGIS:NHI] ${orphans.length} ORPHANED AGENT(S) DETECTED\x1b[0m`);

  for (const orphan of orphans) {
    const expired = orphan.credential_expires_at && new Date(orphan.credential_expires_at) < new Date();
    const noOwner = !orphan.owner || orphan.owner === '';
    const reason = noOwner ? 'no owner (NHI-001)' : expired ? 'credential TTL expired (NHI-002)' : 'idle >90 days (NHI-009)';

    console.error(`  ⚠  ${orphan.agent_id} — ${reason}`);
    console.error(`     owner: ${orphan.owner || '(none)'} · status: ${orphan.status} · registered: ${orphan.registered_at}`);

    // Auto-sleep on TTL expiry or no owner (48h grace in production — immediate in scanner)
    // @rule:INF-NHI-001 / INF-NHI-002
    if (expired || noOwner) {
      try {
        await sleepAgent(orphan.agent_id, `auto-sleep by orphan scanner: ${reason}`);
        console.error(`     → slept (48h grace before auto-retire)`);
      } catch (e: any) {
        console.error(`     → sleep failed: ${e.message}`);
      }
    }
  }

  console.error(`\n\x1b[33m[AEGIS:NHI] Action required: assign owners or retire these agents.\x1b[0m\n`);
}

// Run as standalone: bun run /root/aegis/src/monitor/orphan-scanner.ts
if (import.meta.main) {
  runOrphanScan().catch(console.error);
}

// Export for cron integration
export { REGISTRY_URL };
