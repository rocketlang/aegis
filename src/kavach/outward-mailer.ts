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
//
// Attachments: the mailer reads a file by its path. Each file is first copied into a private
// directory and the copy's SHA-256 checked against the proposal's; the mailer is given the copy, so
// a change to the original after that check cannot reach the mail. The copies are removed after.
// Ceiling: the mailer runs on this box and could read another path if told to; the guard only ever
// names the checked copy.

import { copyFileSync, mkdtempSync, readFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import { basename, join } from "path";
import { PORTS_JSON } from "./plant-state";
import type { Effector } from "./outward";
import { sha256File, type SendHandoff } from "./outward-send";

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
      const files = h.attachments ?? [];
      const dir = files.length ? mkdtempSync(join(tmpdir(), "aegis-attach-")) : null; // mkdtemp makes it 0700
      try {
        const attachments = files.map((a, i) => {
          const copy = join(dir!, `${i}-${basename(a.path)}`);
          copyFileSync(a.path, copy);
          if (sha256File(copy) !== a.sha256) throw new Error(`ANU-013: ${a.path} changed after it was judged; nothing sent`);
          return { filename: basename(a.path), path: copy };
        });
        const r = await fetchImpl(`${url}/send`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            to: h.to.length === 1 ? h.to[0] : h.to, subject: h.subject, text: h.body, account: h.from, noSignature: true,
            ...(attachments.length ? { attachments } : {}),
          }),
          signal: AbortSignal.timeout(30_000),
        });
        let body: any = null;
        try { body = await r.json(); } catch { /* not JSON */ }
        if (r.status !== 200 || !body?.ok || typeof body.messageId !== "string") {
          throw new Error(`ankr-mailer answered ${r.status}: ${String(body?.error ?? "no ok").slice(0, 200)}`);
        }
        return { ref: body.messageId };
      } finally {
        if (dir) rmSync(dir, { recursive: true, force: true });
      }
    },
  };
}
