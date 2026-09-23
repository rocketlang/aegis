// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// KAVACH — Host trust: on what basis is the host believed honest?
//
// @rule:PRA-007 The ceiling of a self-measurement is a FIELD, not a sentence. A consumer
//               can filter a field; nobody can filter prose.
// @rule:PRA-008 The rung is never rounded up. A host asserting its own trustworthiness is
//               precisely the host that cannot be believed on that assertion, so a claim
//               only ever selects which evidence to go and check.
//
// WHY THIS EXISTS
//
// measure-launch.ts computes what governs an agent and prints an honest ceiling: the host
// computed the value about itself, so it does not survive a host that lies. That sentence
// was true and completely unreadable — it lived in three prose blocks where no program
// could reach it. Anything downstream that wanted to ask "how much is this measurement
// worth?" had to parse English, so nothing asked.
//
// This turns the ceiling into a value. Today the honest answer on almost every host is
// `assumed`, which is a scoped null and not a failure. The point is that when a host DOES
// boot under a measured chain, the rung reads up on its own, rather than depending on a
// human to remember to mention it.
//
// WHAT THIS IS NOT
//
// It is not a boot stack and must never grow into one. Measured boot needs hardware — a
// TPM, or an SPL that measures — and AEGIS runs on bare metal, in VMs and in containers,
// so there is no zero-dependency floor for it. This module only ever OBSERVES a chain that
// something else established, and says plainly when there is none.

import { existsSync, readFileSync, readdirSync } from "fs";
import { AEGIS_DIR_PATH } from "./plant-state";

/** The rungs, lowest first. Order is meaningful: index is the rung. */
export const HOST_TRUST_ORDER = ["assumed", "measured-boot", "tpm-quote"] as const;
export type HostTrust = (typeof HOST_TRUST_ORDER)[number];

export function rung(t: HostTrust): number {
  return HOST_TRUST_ORDER.indexOf(t);
}

/** One thing that was actually looked at. Evidence, never assertion. */
export interface Probe {
  what: string;
  found: boolean;
  detail: string;
}

export interface HostTrustReading {
  level: HostTrust;
  /** Why this rung and not a higher one. Populated even at the top. */
  why: string;
  probes: Probe[];
  /** A claim the host made about itself, recorded whether or not it stood. */
  claimed?: HostTrust;
  /** Why a claim did not stand. Its presence means the host overstated itself. */
  claim_refused?: string;
}

/** What the declaration file may assert. The file is an INDEX to evidence, not evidence. */
export interface HostTrustClaim {
  claim?: string;
  /** Expected PCR values, as `{ "0": "<hex>", ... }`, or a path to a file holding them. */
  pcr_reference?: Record<string, string> | string;
  bank?: string;
}

export interface TrustInputs {
  /** What the host says about itself, if anything. Absence is normal, not an error. */
  claim?: HostTrust;
  /** Expected PCR values from a published reference. */
  reference?: Record<string, string>;
  /** PCR values read live off this host. */
  live?: Record<string, string>;
  /** Set only by a verifier that actually checked a quote. Nothing sets it yet. */
  quoteVerified?: boolean;
  /** Probes already run by the caller, carried into the verdict. */
  probes?: Probe[];
}

const norm = (s: string) => s.trim().toLowerCase().replace(/^0x/, "");

/**
 * Every verdict leaves through here, and that is the point.
 *
 * @rule:PRA-008 — the rung reached is compared against the rung claimed at ONE place. An
 * earlier draft of this file set `claim_refused` at each return site and missed the case
 * that matters most: a host claiming `tpm-quote` whose evidence only reaches
 * `measured-boot` returned a clean measured-boot reading and said nothing about the
 * overclaim. Checking it per-branch is how that hole opened; checking it on the way out
 * is why it cannot reopen.
 */
function finalise(r: HostTrustReading): HostTrustReading {
  if (r.claimed && rung(r.claimed) > rung(r.level) && !r.claim_refused) {
    r.claim_refused = `claimed ${r.claimed}, but the evidence reaches only ${r.level}: ${r.why}`;
  }
  return r;
}

/**
 * Decide the rung from evidence alone.
 *
 * Pure on purpose. The IO wrapper below gathers files and sysfs, and this decides — which
 * means the test can force EVERY outcome with fixtures instead of a path override. A guard
 * that can only ever be observed failing is a guard nobody has seen work.
 *
 * @rule:PRA-008 the claim never raises the rung by itself; only evidence does.
 */
export function decideHostTrust(input: TrustInputs): HostTrustReading {
  const probes: Probe[] = [...(input.probes ?? [])];
  const claimed = input.claim;

  // ── rung 2: a verified quote ────────────────────────────────────────────────
  // Nothing in this codebase can produce one. Saying so is the honest position, and it
  // keeps the rung real for the day something does, rather than leaving a gap that a
  // future reader mistakes for an oversight.
  if (input.quoteVerified === true) {
    probes.push({ what: "tpm quote", found: true, detail: "verified by the caller" });
    return finalise({ level: "tpm-quote", why: "a quote was verified off-host", probes, claimed });
  }

  // ── rung 1: a boot reference that agrees with live PCRs ─────────────────────
  const ref = input.reference;
  const live = input.live;
  const refCount = ref ? Object.keys(ref).length : 0;
  const liveCount = live ? Object.keys(live).length : 0;

  if (refCount > 0 && liveCount > 0) {
    const mismatched: string[] = [];
    const missing: string[] = [];
    for (const [idx, expected] of Object.entries(ref!)) {
      const got = live![idx];
      if (got === undefined) missing.push(idx);
      else if (norm(got) !== norm(expected)) mismatched.push(idx);
    }

    if (missing.length === 0 && mismatched.length === 0) {
      probes.push({
        what: "boot reference vs live PCRs",
        found: true,
        detail: `${refCount} PCR value(s) agree`,
      });
      return finalise({
        level: "measured-boot",
        why: `${refCount} PCR value(s) match the published boot reference`,
        probes,
        claimed,
      });
    }

    // Evidence exists and DISAGREES. This is the loudest case in the module: it is not a
    // missing instrument, it is a host whose boot does not match what was published for it.
    const detail =
      mismatched.length > 0
        ? `PCR ${mismatched.join(", ")} differ from the reference`
        : `PCR ${missing.join(", ")} absent from this host`;
    probes.push({ what: "boot reference vs live PCRs", found: false, detail });
    return finalise({
      level: "assumed",
      why: `a boot reference was published for this host and does NOT agree: ${detail}`,
      probes,
      claimed,
      // Both branches carry the DETAIL. A consumer that reads only this field must learn
      // what is wrong, not merely that something is — the specifics living solely in `why`
      // is how a loud field turns into a quiet one.
      claim_refused: claimed
        ? `claimed ${claimed}, but ${detail}`
        : `no claim was made, yet the published reference disagrees (${detail}) — investigate before trusting any measurement from this host`,
    });
  }

  // ── rung 0: assumed ─────────────────────────────────────────────────────────
  // The floor, and the honest answer nearly everywhere. Not a failure: a scoped null.
  let why: string;
  if (refCount === 0 && liveCount === 0) {
    why = "no boot reference and no readable PCRs — the host is taken on trust";
  } else if (refCount === 0) {
    why = "PCRs are readable but no boot reference was published to compare them against";
  } else {
    why = "a boot reference exists but this host exposes no PCRs to compare it against";
  }

  return finalise({ level: "assumed", why, probes, claimed });
}

// ── The IO half ───────────────────────────────────────────────────────────────

const DECLARATION = `${AEGIS_DIR_PATH}/host-trust.json`;

/**
 * DELIBERATELY NOT ENV-OVERRIDABLE, unlike every other root in this codebase.
 *
 * ANKR_CONFIG_DIR, ANKR_STATE_DIR and AEGIS_HOME are overridable because relocating them
 * is a portability need, and ANU-007 makes the override announce itself so a verdict can
 * never rest on a moved instrument silently.
 *
 * This one is different in kind. Whoever chooses where the PCRs are read from chooses what
 * the host measures, and could point it at a directory of hand-written files to manufacture
 * `measured-boot` out of nothing — the exact forgery this module exists to prevent. An
 * announced override would not help: the rung would already be wrong by the time anything
 * read the announcement.
 *
 * The consequence is accepted on purpose: `measured-boot` is unreachable on a host without
 * a TPM, including this one, and cannot be demonstrated live here. It is forced by fixture
 * in host-trust.test.ts against the pure decision function instead, which is where a
 * positive outcome can be proven without opening a hole to prove it.
 */
const PCR_SYSFS = "/sys/class/tpm/tpm0/pcr-sha256";

/** Live PCR values from sysfs, where the kernel exposes them (5.12+ with a TPM). */
export function readLivePcrs(dir: string = PCR_SYSFS): { pcrs: Record<string, string>; probe: Probe } {
  if (!existsSync(dir)) {
    return { pcrs: {}, probe: { what: "live PCRs", found: false, detail: `${dir} does not exist — no TPM exposed` } };
  }
  const pcrs: Record<string, string> = {};
  try {
    for (const name of readdirSync(dir)) {
      if (!/^\d+$/.test(name)) continue;
      try {
        pcrs[name] = readFileSync(`${dir}/${name}`, "utf-8").trim();
      } catch {
        // one unreadable PCR is not a reason to discard the rest; the comparison will
        // report it as absent, which is the outcome we want it to reach on its own
      }
    }
  } catch (e: any) {
    return { pcrs: {}, probe: { what: "live PCRs", found: false, detail: `unreadable: ${e?.message}` } };
  }
  const n = Object.keys(pcrs).length;
  return { pcrs, probe: { what: "live PCRs", found: n > 0, detail: n > 0 ? `${n} read from ${dir}` : `${dir} exposed no PCR values` } };
}

/** The host's own declaration. Missing is the normal case and is never an error. */
export function readClaim(path: string = DECLARATION): { claim?: HostTrust; reference?: Record<string, string>; probe: Probe } {
  if (!existsSync(path)) {
    return { probe: { what: "host-trust declaration", found: false, detail: `${path} absent — nothing claimed` } };
  }
  let raw: HostTrustClaim;
  try {
    raw = JSON.parse(readFileSync(path, "utf-8"));
  } catch (e: any) {
    // An unreadable declaration does NOT fall back to silence. It is a file someone put
    // there on purpose, and failing to parse it is a fact about this host.
    return { probe: { what: "host-trust declaration", found: false, detail: `${path} is present but unparseable: ${e?.message}` } };
  }

  const claim = (HOST_TRUST_ORDER as readonly string[]).includes(String(raw.claim))
    ? (raw.claim as HostTrust)
    : undefined;

  let reference: Record<string, string> | undefined;
  let refDetail = "no pcr_reference";
  if (typeof raw.pcr_reference === "string") {
    try {
      const loaded = JSON.parse(readFileSync(raw.pcr_reference, "utf-8"));
      reference = (loaded.pcr ?? loaded) as Record<string, string>;
      refDetail = `reference loaded from ${raw.pcr_reference}`;
    } catch (e: any) {
      refDetail = `pcr_reference ${raw.pcr_reference} unreadable: ${e?.message}`;
    }
  } else if (raw.pcr_reference && typeof raw.pcr_reference === "object") {
    reference = raw.pcr_reference;
    refDetail = "reference inline in the declaration";
  }

  // Only string-valued PCR entries survive; a nested object (a per-slot reference, say)
  // is not something this comparison can speak to, and guessing would be the whole sin.
  if (reference) {
    reference = Object.fromEntries(Object.entries(reference).filter(([, v]) => typeof v === "string"));
    if (Object.keys(reference).length === 0) reference = undefined;
  }

  return {
    claim,
    reference,
    probe: {
      what: "host-trust declaration",
      found: true,
      detail: `${path}: claim=${claim ?? "none"}, ${refDetail}`,
    },
  };
}

/** The reading for THIS host, right now. */
export function readHostTrust(): HostTrustReading {
  const c = readClaim();
  const l = readLivePcrs();
  return decideHostTrust({
    claim: c.claim,
    reference: c.reference,
    live: l.pcrs,
    probes: [c.probe, l.probe],
  });
}

export function renderHostTrust(r: HostTrustReading): string {
  const L: string[] = [];
  L.push(`  host_trust      ${r.level}`);
  L.push(`    ${r.why}`);
  for (const p of r.probes) L.push(`    [${p.found ? "ok " : "-- "}] ${p.what}: ${p.detail}`);
  if (r.claim_refused) L.push(`    REFUSED — ${r.claim_refused}`);
  return L.join("\n");
}
