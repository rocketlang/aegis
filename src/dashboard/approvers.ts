/**
 * Who may DECIDE a KAVACH approval.
 *
 * Reads the SAME founder-editable state file ankrclaw uses
 * (/root/.ankr/state/ankrclaw/approvers.json) so there is one approver list for the
 * whole approval plane rather than a second one to drift out of sync. Read fresh on
 * every call — adding an approver takes effect immediately, no restart.
 *
 * WHY THIS EXISTS: POST /api/approvals/webhook sits in the dashboard's PUBLIC
 * pass-through list (server.ts) because AnkrClaw calls it with no browser session. It
 * read `from` straight off the request body and passed it to decideKavachApproval as
 * `decidedBy` with no verification at all — so anyone who could reach the port could
 * enumerate pending approvals via the public GET and flip any of them to allowed.
 * Dual control did not save it: the check is only first_approver !== decidedBy, and
 * both strings came from the same unauthenticated body.
 * Ref: proposals/ankr-agentic-surface-sweep--findings--formal--2026-07-20.md item 4.
 *
 * CHANNEL SHAPES: Telegram sends a numeric chat id, WhatsApp an E.164 number. Entries
 * may be bare ("8038863841"), channel-qualified ("telegram:8038863841"), or grouped
 * under {"owners": {"telegram": [...], "whatsapp": [...]}}. This service does not know
 * which channel a webhook originated from, so it matches across ALL channels — the
 * check that matters here is "is this a real, listed approver", not "which app did it
 * come from". Phone-shaped ids also compare digits-only.
 *
 * FAIL-CLOSED: an absent or unreadable file yields an empty set, and an empty set
 * authorises nobody.
 */
import { readFileSync } from "node:fs";

const APPROVERS_FILE =
  process.env.AOS_APPROVERS_FILE ?? "/root/.ankr/state/ankrclaw/approvers.json";

function variants(raw: string): string[] {
  const s = String(raw).trim();
  if (!s) return [];
  const out = new Set<string>();
  // strip an optional channel prefix, then keep both the literal and digits-only forms
  const bare = s.replace(/^(telegram|whatsapp)\s*:\s*/i, "").trim();
  for (const v of [s, bare]) {
    if (!v) continue;
    out.add(v);
    const digits = v.replace(/\D/g, "");
    if (digits) out.add(digits);
  }
  return [...out];
}

/** Every accepted identifier, flattened across channels and normalisations. */
function loadApproverIds(): Set<string> {
  const out = new Set<string>();
  const add = (v: unknown) => {
    if (v == null) return;
    for (const x of variants(String(v))) out.add(x);
  };
  for (const c of (process.env.AOS_APPROVER_CHATS ?? "").split(",")) add(c);
  try {
    const j = JSON.parse(readFileSync(APPROVERS_FILE, "utf8"));
    const owners = Array.isArray(j) ? j : j?.owners;
    if (Array.isArray(owners)) {
      for (const c of owners) add(c);
    } else if (owners && typeof owners === "object") {
      for (const list of Object.values(owners)) {
        if (Array.isArray(list)) for (const c of list) add(c);
      }
    }
  } catch {
    /* file optional — absence means nobody approves */
  }
  return out;
}

/** True only if `from` resolves to an explicitly listed approver. Unknown => false. */
export function isApprover(from: string | null | undefined): boolean {
  if (from == null) return false;
  const ids = loadApproverIds();
  if (ids.size === 0) return false;
  return variants(String(from)).some((v) => ids.has(v));
}

export const APPROVERS_FILE_PATH = APPROVERS_FILE;
