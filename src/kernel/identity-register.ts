// SPDX-License-Identifier: AGPL-3.0-only
//
// identity-register — the register, not the credential.
//
// A device identity with no hardware anchor CAN be cloned: copy the key and the second
// machine is indistinguishable from the first. That cannot be prevented in software.
// It can be made VISIBLE. This is that register.
//
// The maritime reading, which is where the idea came from: you cannot stop someone
// forging a Certificate of Competency. You can make the same certificate number
// appearing on two ships at once something the registry notices. Enforcement moves from
// the credential to the register.
//
// ─────────────────────────────────────────────────────────────────────────────────────
// WHAT THIS DELIBERATELY DOES NOT DO — read before extending it
//
// It does NOT decide which of two claimants is genuine, and it never will. Both present
// identical credentials; that is what cloning means. Any automatic choice is a coin toss
// with a pumping station on one side of it. Sandboxing, quarantining or cutting off the
// WRONG one disables a real device in the field, which is a worse outcome than the
// duplication it was reacting to.
//
// So a contested identity is marked CONTESTED and BOTH keep running. What is withheld is
// ESCALATION — no new authority is granted under a contested identity — and the decision
// of which is genuine is referred to a human with the evidence attached. Deny escalation,
// never deny operation. (Same discipline as: never disable a broken service to silence
// churn; authorisation is founder-decided, never auto-cleared.)
//
// The one case with NO ambiguity is a decoy. A decoy identity is enrolled and issued to
// nobody. Any sighting of it is an attacker, with no real device to misjudge, so a decoy
// raises ALARM immediately and safely. That is the honeypot idea in the only form that
// cannot hurt a genuine device.
// ─────────────────────────────────────────────────────────────────────────────────────

import { createHash } from "node:crypto";

export type Verdict = "OK" | "CONTESTED" | "ALARM" | "UNKNOWN";

/** One sighting of an identity, as reported by a device. Append-only; never edited. */
export interface Sighting {
  identity: string;
  /** Distinguishes one running instance from another: a per-boot random value. Two
   *  different instances of one identity is precisely the duplication we are looking
   *  for. A device that cannot produce one is refused rather than assumed unique. */
  instance: string;
  /** Monotonic within an instance. A repeat or a regression means a replayed receipt. */
  counter: number;
  /** Compiled policy digests, carried so a reader can see WHAT was running, not just
   *  that something was. Opaque here on purpose — this file does not parse policy. */
  progTag?: string;
  mapDigest?: string;
  /** Seconds since epoch, as reported. NOT trusted for ordering: the register orders by
   *  arrival, because a clone controls its own clock. Kept for the human reading it. */
  reportedAt?: number;
}

export interface Enrolment {
  identity: string;
  /** Who vouches for the binding of this identity to a device (XRA-R-007). Recorded so
   *  a reader can weigh it: "silicon" and "registrar-statement" are not the same claim. */
  voucher: string;
  /** A decoy is issued to no device. Any sighting of it is unambiguously an attacker. */
  decoy?: boolean;
}

export interface Finding {
  identity: string;
  verdict: Verdict;
  reason: string;
  /** The sightings a human needs in order to rule. Evidence, not a summary. */
  evidence: Sighting[];
}

/**
 * Append-only. Entries are never mutated or removed: a register that can be edited is
 * not a register. Verdicts are computed from the log each time rather than stored, so a
 * stale verdict cannot outlive the evidence that produced it.
 */
export class IdentityRegister {
  private enrolments = new Map<string, Enrolment>();
  private log: Sighting[] = [];

  enrol(e: Enrolment): void {
    if (this.enrolments.has(e.identity)) {
      throw new Error(`identity already enrolled: ${e.identity} (append-only; re-enrolment would erase history)`);
    }
    if (!e.voucher || !e.voucher.trim()) {
      // XRA-R-007. An identity with no named voucher is an assertion about nothing.
      throw new Error(`refusing enrolment of ${e.identity}: no voucher named`);
    }
    this.enrolments.set(e.identity, { ...e });
  }

  /** Records a sighting verbatim. Rejects only what it cannot reason about. */
  record(s: Sighting): void {
    if (!s.identity || !s.instance) {
      throw new Error("refusing a sighting with no identity or no instance value");
    }
    if (!Number.isInteger(s.counter) || s.counter < 0) {
      throw new Error(`refusing a sighting with a non-monotonic counter: ${s.counter}`);
    }
    this.log.push({ ...s });
  }

  entries(): readonly Sighting[] { return this.log; }

  /**
   * The whole point. Computed from the log, never cached.
   *
   *   ALARM      a decoy was sighted, or a sighting arrived for an identity never enrolled
   *   CONTESTED  two instances of one identity, or a counter that repeated or went back
   *   OK         one instance, counters strictly increasing
   *   UNKNOWN    enrolled, never seen
   */
  verdict(identity: string): Finding {
    const seen = this.log.filter(s => s.identity === identity);
    const enr = this.enrolments.get(identity);

    if (!enr) {
      return {
        identity, verdict: "ALARM", evidence: seen,
        reason: seen.length
          ? "sightings for an identity that was never enrolled — nothing vouches for this"
          : "identity is not enrolled",
      };
    }
    if (enr.decoy) {
      return seen.length
        ? { identity, verdict: "ALARM", evidence: seen,
            reason: `decoy identity sighted ${seen.length} time(s) — issued to no device, so this is an attacker and there is no genuine party to misjudge` }
        : { identity, verdict: "OK", evidence: [], reason: "decoy, never sighted" };
    }
    if (seen.length === 0) {
      return { identity, verdict: "UNKNOWN", evidence: [], reason: "enrolled, never seen" };
    }

    const instances = [...new Set(seen.map(s => s.instance))];
    if (instances.length > 1) {
      return {
        identity, verdict: "CONTESTED", evidence: seen,
        reason: `${instances.length} instances reporting as one identity (${instances.join(", ")}) — ` +
                `duplication is visible. Which is genuine is NOT decided here: both keep running, ` +
                `no new authority is granted under this identity, and a human rules with this evidence.`,
      };
    }

    // One instance. Counters must strictly increase in arrival order; a repeat or a
    // regression is a replayed receipt, which is duplication wearing one instance value.
    const counters = seen.map(s => s.counter);
    for (let i = 1; i < counters.length; i++) {
      if (counters[i] <= counters[i - 1]) {
        return {
          identity, verdict: "CONTESTED", evidence: seen,
          reason: `counter did not advance (${counters[i - 1]} → ${counters[i]}) — a replayed or ` +
                  `duplicated receipt under one instance value. Same handling: visible, not adjudicated.`,
        };
      }
    }
    return { identity, verdict: "OK", evidence: seen, reason: `one instance, ${seen.length} sighting(s), counters advancing` };
  }

  /** Every enrolled identity plus any unenrolled ones that turned up. */
  sweep(): Finding[] {
    const ids = new Set<string>([...this.enrolments.keys(), ...this.log.map(s => s.identity)]);
    return [...ids].map(id => this.verdict(id))
      .sort((a, b) => ["ALARM", "CONTESTED", "UNKNOWN", "OK"].indexOf(a.verdict)
                    - ["ALARM", "CONTESTED", "UNKNOWN", "OK"].indexOf(b.verdict));
  }

  /**
   * Escalation gate. The ONLY enforcement this register performs.
   *
   * A contested or alarmed identity is refused NEW authority. It is never used to stop
   * an already-running device, because we cannot tell which device we would be stopping.
   */
  mayGrantNewAuthority(identity: string): { allow: boolean; reason: string } {
    const f = this.verdict(identity);
    if (f.verdict === "OK") return { allow: true, reason: f.reason };
    return {
      allow: false,
      reason: `no new authority under a ${f.verdict} identity — ${f.reason}. ` +
              `Existing operation is untouched by design.`,
    };
  }

  /** Digest over the log in order, so a reader can confirm nothing was removed later. */
  digest(): string {
    const h = createHash("sha256");
    for (const s of this.log) {
      h.update(`${s.identity}\u0000${s.instance}\u0000${s.counter}\u0000${s.progTag ?? ""}\u0000${s.mapDigest ?? ""}\n`);
    }
    return h.digest("hex");
  }
}
