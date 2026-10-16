// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// KAVACH — the send guard's effector: ankr-mailer's POST /send (founder: "connect send to the mailer",
// 2026-10-16). The mailer holds the mail accounts (ANU-016); the guard hands it only the message.
//
// The mailer's /send ignores cc and bcc (and adds its own blind copy to the founder). A message whose
// cc or bcc is not empty is therefore refused here, never sent without them: what goes out must be
// what was judged and approved. The mailer's own word list still applies at send (it answers 403).
//
// Where the mailer is: ports.json `backend.ankrMailer` (R-008). No port there = no send; never a
// guessed one. AEGIS_MAILER_URL overrides it for tests; pointing it elsewhere can only divert a
// message away from the mailer, never past the guard.

import { readFileSync } from "fs";
import { PORTS_JSON } from "./plant-state";
import type { Effector } from "./outward";
import type { SendHandoff } from "./outward-send";

export function mailerUrl(portsPath = PORTS_JSON): string {
  if (process.env.AEGIS_MAILER_URL) return process.env.AEGIS_MAILER_URL.replace(/\/$/, "");
  const ports = JSON.parse(readFileSync(portsPath, "utf8"));
  const port = ports?.backend?.ankrMailer;
  if (!Number.isInteger(port)) throw new Error("ports.json has no backend.ankrMailer: no mailer to send through (R-008)");
  return `http://127.0.0.1:${port}`;
}

export function mailerEffector(url: string, fetchImpl: typeof fetch = fetch): Effector<SendHandoff> {
  return {
    name: "ankr-mailer",
    async deliver(h) {
      if (h.cc.length || h.bcc.length) throw new Error("ANU-016: ankr-mailer /send cannot carry cc or bcc; refused rather than sent without them");
      const r = await fetchImpl(`${url}/send`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ to: h.to.length === 1 ? h.to[0] : h.to, subject: h.subject, text: h.body, account: h.from, noSignature: true }),
        signal: AbortSignal.timeout(30_000),
      });
      let body: any = null;
      try { body = await r.json(); } catch { /* not JSON */ }
      if (r.status !== 200 || !body?.ok || typeof body.messageId !== "string") {
        throw new Error(`ankr-mailer answered ${r.status}: ${String(body?.error ?? "no ok").slice(0, 200)}`);
      }
      return { ref: body.messageId };
    },
  };
}
