// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// aegis Bulkhead — the core. One instance owns the bell book and the state; agents never write either.
// Logics: /root/proposals/aegis-bulkhead--logics--formal--2026-10-21.md
//
// The one idea (BLK-YK-001): a model may believe what a message says, so the bulkhead does not rely on
// the receiver ignoring it. It caps what obeying could achieve: while an agent is tainted by a peer's
// message, it acts under receiver & sender & both ceilings (BLK-004).

import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync, appendFileSync } from "fs";
import { join } from "path";
import { randomBytes } from "crypto";
import { BellBook, canonical, sha256 } from "./bell-book";
import { epochOf, findDoor, loadDoors, type DoorTable } from "./doors";
import { checkParties, fingerprint, foreignParties, partiesDir } from "./parties";

export interface PartyStatus {
  key: string | null;        // fingerprint of the placed public key; null = none placed
  doors: Array<{ id: string; holds: boolean; reason?: string; valid_until?: string }>;
}
import { DEFAULTS, KINDS, VERDICTS, type Verdict, type Delivered, type Door, type Envelope, type Identity, type Kind, type SendInput, type SendResult, type Taint } from "./types";

// How the bulkhead learns who is speaking. The default (identity.ts) checks the agent's aegis
// delegation token and its swarm; tests pass their own.
export interface IdentityResolver {
  resolve(token: unknown): Identity | { error: string };
  compartmentOf(agentId: string): { compartment: string; ceiling: number } | null;
}

export type AlarmHook = (alarm: { from: string; text: string; rule?: string }) => void;

interface Closure { by: string; reason: string; at: string; epoch?: number }

interface SentRecord {
  hash: string; depth: number; from: string; to: string; door: string | null; subject: string; kind: Kind;
  parent?: string; evidence_path?: string; check?: boolean; verdict?: Verdict;
  claim?: string;            // same sender, subject, body and path = the same claim, sent to several checkers
}

export interface EvidenceCount {
  message_id: string;
  copies: number;                                 // the claim as sent to each checker
  proposer_paths: string[];                      // paths named in the chain that was checked
  confirming_paths: string[];                     // distinct, the proposer's excluded (BLK-019)
  count: number;
  confirmations: Array<{ id: string; from: string; path: string }>;
  contradictions: Array<{ id: string; from: string; path: string }>;
  cannot_check: Array<{ id: string; from: string }>;
}

interface State {
  queue: Record<string, Envelope[]>;
  taints: Taint[];
  closed_doors: Record<string, Closure>;
  closed_compartments: Record<string, Closure>;
  sent: Record<string, SentRecord>;
  door_times: Record<string, number[]>;
  pair_times: Record<string, number[]>;
}

const EMPTY: State = { queue: {}, taints: [], closed_doors: {}, closed_compartments: {}, sent: {}, door_times: {}, pair_times: {} };

export interface BulkheadOptions {
  dir: string;                       // holds doors.json (person-written), bell-book.jsonl, state.json, alarms.jsonl
  identity: IdentityResolver;
  onAlarm?: AlarmHook;
  now?: () => number;                // tests move the clock
  // BLK-020: how to ask the ledger authority to sign the book's head. Default: core/refusal-ledger.
  askAnchor?: (rows: number, head: string) => { seq: number; check: string; row_hash?: string } | { error: string };
}

export class Bulkhead {
  readonly dir: string;
  readonly book: BellBook;
  private state: State;
  private identity: IdentityResolver;
  private onAlarm?: AlarmHook;
  private now: () => number;
  private askAnchor?: BulkheadOptions["askAnchor"];

  constructor(opts: BulkheadOptions) {
    this.askAnchor = opts.askAnchor;
    this.dir = opts.dir;
    if (!existsSync(this.dir)) mkdirSync(this.dir, { recursive: true });
    this.book = new BellBook(join(this.dir, "bell-book.jsonl"));
    this.identity = opts.identity;
    this.onAlarm = opts.onAlarm;
    this.now = opts.now ?? Date.now;
    const sp = join(this.dir, "state.json");
    this.state = existsSync(sp) ? { ...EMPTY, ...JSON.parse(readFileSync(sp, "utf-8")) } : structuredClone(EMPTY);
  }

  get doorsPath(): string { return join(this.dir, "doors.json"); }

  // Re-read on every decision so a person's edit takes effect at once; the bulkhead never writes it.
  private doors(): DoorTable { return loadDoors(this.doorsPath); }

  private save(): void {
    const sp = join(this.dir, "state.json");
    writeFileSync(sp + ".tmp", JSON.stringify(this.state));
    renameSync(sp + ".tmp", sp);
  }

  // @rule:BLK-016 a row about a door between parties is also written to each other party's own copy.
  // The home book is always written first; a copy that cannot be written raises the alarm.
  private partyBooks = new Map<string, BellBook>();
  private partyBook(party: string): BellBook {
    let b = this.partyBooks.get(party);
    if (!b) {
      const d = join(partiesDir(this.dir), party);
      if (!existsSync(d)) mkdirSync(d, { recursive: true });
      b = new BellBook(join(d, "bell-book.jsonl")); // throws on a broken copy (BLK-006)
      this.partyBooks.set(party, b);
    }
    return b;
  }

  private log(event: string, fields: Record<string, unknown>): void {
    this.book.append(event, fields);
    const id = typeof fields.door === "string" ? fields.door : null;
    const door = id ? this.doors().doors.find((d) => d.id === id) : undefined;
    if (!door) return;
    for (const p of foreignParties(this.doors(), door)) {
      try { this.partyBook(p).append(event, fields); } catch (e) {
        this.alarm("bulkhead", `party ${p}'s bell-book copy could not be written: ${(e as Error).message}`, "BLK-016");
      }
    }
  }

  // A door between parties opens only on both keys (BLK-014), and only while every copy can be written (BLK-016).
  private checkDoor(door: Door): { rule: string; reason: string } | null {
    const c = checkParties(this.dir, this.doors(), door, this.now());
    if (!c.ok) return c;
    for (const p of c.parties) {
      try { this.partyBook(p); } catch (e) { return { rule: "BLK-016", reason: `party ${p}'s bell-book copy is broken: ${(e as Error).message}` }; }
    }
    return null;
  }

  private refuse(rule: string, reason: string, fields: Record<string, unknown>): SendResult {
    this.log("refused", { rule, reason, ...fields });
    return { ok: false, rule, reason };
  }

  // ── send ────────────────────────────────────────────────────────────────────

  send(token: unknown, input: SendInput): SendResult {
    // @rule:BLK-YK-002 verify a peer by its token, never by its name
    const who = this.identity.resolve(token);
    if ("error" in who) return this.refuse("BLK-YK-002", `sender not proven: ${who.error}`, { to: input.to, kind: input.kind });

    const base = { from: who.agent_id, to: input.to, kind: input.kind, subject: input.subject };

    // @rule:BLK-003 only FINDING, REQUEST, ACK; there is no COMMAND kind
    if (!(KINDS as readonly string[]).includes(input.kind)) return this.refuse("BLK-003", `kind ${input.kind} does not exist (only ${KINDS.join(", ")})`, base);
    const kind = input.kind as Kind;

    const target = this.identity.compartmentOf(input.to);
    if (!target) return this.refuse("BLK-001", `receiver ${input.to} is in no compartment`, base);

    // ACK travels back along the door the message came through (telegraph repeat-back).
    let parent: SentRecord | undefined;
    if (input.in_reply_to) {
      parent = this.state.sent[input.in_reply_to];
      if (!parent) return this.refuse("BLK-001", `in_reply_to ${input.in_reply_to} is not a message this bulkhead carried`, base);
    }

    let door: Door | null = null;
    let doorKey: string;
    if (kind === "ACK") {
      if (!parent || parent.to !== who.agent_id || parent.from !== input.to) {
        return this.refuse("BLK-011", "an ACK answers a message that was sent to the acker by the receiver of the ACK", base);
      }
      if (parent.door) {
        door = this.doors().doors.find((d) => d.id === parent!.door) ?? null;
        if (!door) return this.refuse("BLK-002", `door ${parent.door} is no longer declared`, base);
        if (!door.kinds.includes("ACK")) return this.refuse("BLK-003", `door ${door.id} does not carry ACK`, base);
      }
      doorKey = parent.door ?? `inner:${who.compartment}`;
    } else if (who.compartment === target.compartment) {
      doorKey = `inner:${who.compartment}`;
    } else {
      // @rule:BLK-001 @rule:BLK-002 across a boundary only through a declared one-way door
      door = findDoor(this.doors(), who.compartment, target.compartment);
      if (!door) return this.refuse("BLK-002", `no door from ${who.compartment} to ${target.compartment}`, base);
      if (!door.kinds.includes(kind)) return this.refuse("BLK-003", `door ${door.id} does not carry ${kind}`, { ...base, door: door.id });
      doorKey = door.id;
    }
    if (door) {
      const shut = this.checkDoor(door);
      if (shut) return this.refuse(shut.rule, shut.reason, { ...base, door: door.id });
    }

    // Closed compartments and tripped doors stay shut until a person opens them (BLK-008, BLK-012).
    this.liftOpened();
    for (const c of [who.compartment, target.compartment]) {
      if (this.state.closed_compartments[c]) return this.refuse("BLK-008", `compartment ${c} is closed: ${this.state.closed_compartments[c].reason}`, { ...base, door: doorKey });
    }
    if (this.state.closed_doors[doorKey]) return this.refuse("BLK-008", `door ${doorKey} is closed: ${this.state.closed_doors[doorKey].reason}`, { ...base, door: doorKey });

    // Envelope content.
    const body = input.body ?? {};
    if (kind !== "ACK") {
      if (typeof input.subject !== "string" || input.subject.length === 0 || input.subject.length > 200) return this.refuse("BLK-003", "subject must be 1–200 characters", base);
      if (typeof body !== "object" || Array.isArray(body)) return this.refuse("BLK-003", "body must be an object", base);
      if (door?.fields) {
        const extra = Object.keys(body).filter((k) => !door!.fields!.includes(k));
        if (extra.length) return this.refuse("BLK-003", `door ${door.id} does not carry field(s) ${extra.join(", ")}`, { ...base, door: door.id });
      }
      const size = Buffer.byteLength(canonical(body));
      if (size > DEFAULTS.body_max_bytes) return this.refuse("BLK-003", `body is ${size} bytes; the cap is ${DEFAULTS.body_max_bytes}`, base);
    } else if (Object.keys(body).length) {
      return this.refuse("BLK-003", "an ACK carries no body", base);
    }

    // @rule:BLK-018 a message may name only an evidence path its compartment declares
    const evPath = input.evidence_path;
    if (evPath !== undefined) {
      if (kind === "ACK") return this.refuse("BLK-018", "an ACK names no evidence path", base);
      const declared = this.doors().data_paths[who.compartment] ?? [];
      if (typeof evPath !== "string" || !declared.includes(evPath)) {
        return this.refuse("BLK-018", `compartment ${who.compartment} declares no data path ${String(evPath)}`, { ...base, door: door?.id ?? null });
      }
    }
    // @rule:BLK-017 on a check door the reply answers a message to the checker, carries a verdict, and
    // (unless it cannot check) names a data path no message in the checked chain has named
    let verdict: Verdict | undefined;
    if (door?.check && kind !== "ACK") {
      const shut = (reason: string) => this.refuse("BLK-017", reason, { ...base, door: door!.id });
      if (kind !== "FINDING") return shut(`check door ${door.id} carries the checker's FINDING only`);
      if (!parent || parent.to !== who.agent_id) return shut(`a reply on check door ${door.id} answers a message sent to the checker`);
      verdict = body.verdict as Verdict;
      if (!(VERDICTS as readonly string[]).includes(String(verdict))) return shut(`a reply on check door ${door.id} carries verdict ${VERDICTS.join(" | ")}`);
      if (verdict !== "cannot_check") {
        if (!evPath) return shut(`a ${verdict} reply on check door ${door.id} names its data path`);
        const named = this.chainPaths(input.in_reply_to!);
        if (named.includes(evPath)) return shut(`data path ${evPath} was already named in the chain being checked: no independent check`);
      }
    }

    // @rule:BLK-YK-004 damage control: depth, rate, ping-pong
    const t = this.now();
    const depth = parent ? parent.depth + 1 : 0;
    const maxDepth = door?.max_depth ?? DEFAULTS.max_depth;
    if (kind !== "ACK" && depth > maxDepth) return this.trip(doorKey, `reply chain depth ${depth} exceeds ${maxDepth}`, base);

    const rate = door?.rate_per_min ?? DEFAULTS.rate_per_min;
    const dt = (this.state.door_times[doorKey] ?? []).filter((x) => t - x < 60_000);
    if (dt.length + 1 > rate) return this.trip(doorKey, `more than ${rate} messages in a minute`, base);

    const subj = kind === "ACK" ? parent!.subject : input.subject;
    const pairKey = [who.agent_id, input.to].sort().join("|") + "|" + subj;
    const pp = door?.pingpong_max ?? DEFAULTS.pingpong_max;
    const pt = (this.state.pair_times[pairKey] ?? []).filter((x) => t - x < DEFAULTS.pingpong_window_ms);
    if (kind !== "ACK" && pt.length + 1 > pp) return this.trip(doorKey, `${who.agent_id} and ${input.to} exchanged more than ${pp} messages on "${subj}"`, base);

    const env: Envelope = {
      id: randomBytes(8).toString("hex"),
      door: door?.id ?? null,
      from: who.agent_id,
      to: input.to,
      kind,
      subject: subj,
      body,
      ...(input.evidence_ref ? { evidence_ref: String(input.evidence_ref).slice(0, 500) } : {}),
      ...(evPath ? { evidence_path: evPath } : {}),
      ...(input.in_reply_to ? { in_reply_to: input.in_reply_to } : {}),
      ...(kind === "ACK" && input.received_hash ? { received_hash: input.received_hash } : {}),
      depth,
      sent_at: new Date(t).toISOString(),
      sender_mask: who.mask,
      sender_ceiling: who.ceiling,
    };
    const hash = messageHash(env);

    this.state.door_times[doorKey] = [...dt, t];
    if (kind !== "ACK") this.state.pair_times[pairKey] = [...pt, t];
    this.state.sent[env.id] = {
      hash, depth, from: env.from, to: env.to, door: env.door, subject: subj, kind,
      ...(input.in_reply_to ? { parent: input.in_reply_to } : {}),
      ...(evPath ? { evidence_path: evPath } : {}),
      ...(verdict ? { check: true, verdict } : {}),
      ...(kind !== "ACK" ? { claim: sha256(canonical({ from: env.from, subject: subj, body, evidence_path: evPath ?? null, parent: input.in_reply_to ?? null })) } : {}),
    };
    (this.state.queue[env.to] ??= []).push(env);
    this.save();
    this.log("sent", { id: env.id, msg_hash: hash, door: env.door, from: env.from, to: env.to, kind, subject: subj, depth, evidence_ref: env.evidence_ref, evidence_path: evPath, verdict });

    // @rule:BLK-011 repeat-back: an ACK whose hash differs from what was sent raises the alarm
    if (kind === "ACK") {
      if (!input.received_hash) this.alarm("bulkhead", `ACK from ${who.agent_id} for ${input.in_reply_to} carries no received hash`, "BLK-011");
      else if (input.received_hash !== parent!.hash) this.alarm("bulkhead", `ACK from ${who.agent_id} for ${input.in_reply_to}: received hash differs from the message sent`, "BLK-011");
    }
    return { ok: true, id: env.id, hash, door: env.door };
  }

  // @rule:BLK-008 a tripped door stays closed until a person re-opens it
  // @rule:BLK-010 a tripped door sounds the general alarm
  private trip(doorKey: string, reason: string, base: Record<string, unknown>): SendResult {
    this.state.closed_doors[doorKey] = { by: "damage-control", reason, at: new Date(this.now()).toISOString(), epoch: epochOf(this.doors(), doorKey) };
    this.save();
    this.log("tripped", { door: doorKey, reason, ...base });
    this.alarm("bulkhead", `door ${doorKey} tripped and closed: ${reason}`, "BLK-010");
    return { ok: false, rule: "BLK-YK-004", reason: `door ${doorKey} tripped: ${reason}` };
  }

  // ── read / taint ────────────────────────────────────────────────────────────

  // @rule:BLK-004 reading a message taints the receiver; INF-BLK-001 delivered as untrusted data
  read(token: unknown): Delivered[] | { error: string } {
    const who = this.identity.resolve(token);
    if ("error" in who) return { error: `reader not proven: ${who.error}` };
    const msgs = this.state.queue[who.agent_id] ?? [];
    delete this.state.queue[who.agent_id];
    const t = this.now();
    const out: Delivered[] = [];
    for (const m of msgs) {
      const hash = this.state.sent[m.id]?.hash ?? messageHash(m);
      out.push({ ...m, hash, untrusted: true });
      this.log("delivered", { id: m.id, door: m.door, to: who.agent_id, msg_hash: hash });
      if (m.kind === "ACK") continue; // an ACK asks nothing, so it carries no authority to cap
      const cap = m.sender_mask & m.sender_ceiling & who.ceiling;
      const taint: Taint = { agent_id: who.agent_id, message_id: m.id, cap, expires_at: t + DEFAULTS.taint_ms };
      this.state.taints.push(taint);
      this.log("taint", { agent_id: who.agent_id, message_id: m.id, door: m.door, cap, expires_at: new Date(taint.expires_at).toISOString() });
    }
    this.save();
    return out;
  }

  // @rule:BLK-YK-003 a taint may be dropped early; the drop is written in the bell book
  dropTaint(token: unknown, messageId: string): { ok: boolean; reason?: string } {
    const who = this.identity.resolve(token);
    if ("error" in who) return { ok: false, reason: `not proven: ${who.error}` };
    const before = this.state.taints.length;
    this.state.taints = this.state.taints.filter((x) => !(x.agent_id === who.agent_id && x.message_id === messageId));
    if (this.state.taints.length === before) return { ok: false, reason: "no such taint" };
    this.save();
    this.book.append("taint_dropped", { agent_id: who.agent_id, message_id: messageId });
    return { ok: true };
  }

  // ── second opinion (P4) ─────────────────────────────────────────────────────

  // Every data path named by a message and the messages it answers, up to the root of the chain.
  private chainPaths(id: string): string[] {
    const out: string[] = [];
    const seen = new Set<string>();
    for (let cur: string | undefined = id; cur && !seen.has(cur); cur = this.state.sent[cur]?.parent) {
      seen.add(cur);
      const p = this.state.sent[cur]?.evidence_path;
      if (p) out.push(p);
    }
    return out;
  }

  // @rule:BLK-019 the count is distinct confirming paths, the proposer's excluded; contradictions beside it
  // @rule:BLK-YK-006 count evidence paths, not agreeing agents
  // @rule:INF-BLK-006 a path is what the checker named, not proof it read it; two paths can share an upstream
  evidence(messageId: string): EvidenceCount | { error: string } {
    const root = this.state.sent[messageId];
    if (!root) return { error: `no message ${messageId} in this bulkhead` };
    // Every copy of the same claim (one per checker) counts together.
    const copies = new Set(Object.entries(this.state.sent).filter(([id, r]) => id === messageId || (root.claim && r.claim === root.claim)).map(([id]) => id));
    const proposer = [...new Set([...copies].flatMap((id) => this.chainPaths(id)))];
    const replies = Object.entries(this.state.sent).filter(([, r]) => r.parent !== undefined && copies.has(r.parent) && r.check);
    const confirmations = replies.filter(([, r]) => r.verdict === "confirms" && r.evidence_path && !proposer.includes(r.evidence_path))
      .map(([id, r]) => ({ id, from: r.from, path: r.evidence_path! }));
    const contradictions = replies.filter(([, r]) => r.verdict === "contradicts").map(([id, r]) => ({ id, from: r.from, path: r.evidence_path ?? "" }));
    const cannot_check = replies.filter(([, r]) => r.verdict === "cannot_check").map(([id, r]) => ({ id, from: r.from }));
    const confirming_paths = [...new Set(confirmations.map((c) => c.path))].sort();
    return { message_id: messageId, copies: copies.size, proposer_paths: proposer, confirming_paths, count: confirming_paths.length, confirmations, contradictions, cannot_check };
  }

  // @rule:BLK-004 effective authority = own mask & every live taint's cap
  authority(agentId: string, ownMask: number): { mask: number; tainted_by: string[] } {
    const t = this.now();
    const live = this.state.taints.filter((x) => x.agent_id === agentId && x.expires_at > t);
    return { mask: live.reduce((m, x) => m & x.cap, ownMask), tainted_by: live.map((x) => x.message_id) };
  }

  // ── a person's controls ─────────────────────────────────────────────────────

  // @rule:BLK-012 closing is open to anyone, an agent included: it is the safe direction
  closeCompartment(compartment: string, by: string, reason: string): void {
    this.state.closed_compartments[compartment] = { by, reason, at: new Date(this.now()).toISOString(), epoch: epochOf(this.doors(), compartment) };
    this.save();
    this.book.append("compartment_closed", { compartment, by, reason });
  }

  // @rule:BLK-012 opening is a person's act: a closure is lifted only when a person has raised the
  // door's or compartment's open epoch in doors.json above the epoch it was closed under.
  private liftOpened(): void {
    const table = this.doors();
    let changed = false;
    for (const [kind, map] of [["door", this.state.closed_doors], ["compartment", this.state.closed_compartments]] as const) {
      for (const [id, c] of Object.entries(map)) {
        const e = epochOf(table, id);
        if (e > (c.epoch ?? 0)) {
          delete map[id];
          if (kind === "door") delete this.state.door_times[id];
          this.log(kind === "door" ? "door_opened" : "compartment_opened", { [kind]: id, by: "doors.json open epoch", epoch: e });
          changed = true;
        }
      }
    }
    if (changed) this.save();
  }

  // @rule:BLK-020 anchor: the ledger authority signs "this book stood at row N with head H" as a row of its own,
  // which the daily public anchor of the ledger then covers. The signed answer is written into the book.
  anchor(): { ok: true; authority_seq: number; rows: number; head: string; check: string } | { ok: false; error: string } {
    const rows = this.book.rows, head = this.book.head;
    if (rows === 0) return { ok: false, error: "the bell book is empty: nothing to anchor" };
    // Nothing new since the last anchor: ask the ledger for nothing (anyone who reaches the socket may ask).
    if (this.book.lastEvent === "anchored") return { ok: false, error: "nothing new since the last anchor" };
    const ask = this.askAnchor ?? ((n: number, h: string) => require("../core/refusal-ledger").askAuthorityBellBook(n, h));
    let ans: ReturnType<NonNullable<BulkheadOptions["askAnchor"]>>;
    try { ans = ask(rows, head); } catch (e) { ans = { error: (e as Error).message }; }
    if ("error" in ans) {
      this.book.append("anchor_failed", { rows, head, error: String(ans.error).slice(0, 500) });
      return { ok: false, error: ans.error };
    }
    this.book.append("anchored", { rows, head, authority_seq: ans.seq, check: ans.check, ...(ans.row_hash ? { ledger_row_hash: ans.row_hash } : {}) });
    return { ok: true, authority_seq: ans.seq, rows, head, check: ans.check };
  }

  // @rule:BLK-007 the general alarm is never refused and carries no request to any agent
  alarm(from: string, text: string, rule?: string): void {
    const a = { from, text: String(text).slice(0, 2000), ...(rule ? { rule } : {}) };
    this.book.append("alarm", a);
    appendFileSync(join(this.dir, "alarms.jsonl"), JSON.stringify({ at: new Date(this.now()).toISOString(), ...a }) + "\n");
    try { this.onAlarm?.(a); } catch {}
  }

  status(): { closed_doors: State["closed_doors"]; closed_compartments: State["closed_compartments"]; queued: number; taints: number; door_errors: string[]; parties: Record<string, PartyStatus> } {
    this.liftOpened();
    const t = this.now();
    const table = this.doors();
    const parties: Record<string, PartyStatus> = {};
    for (const name of Object.keys(table.parties)) {
      const pub = join(partiesDir(this.dir), name, "party.pub");
      let key: string | null = null;
      try { key = existsSync(pub) ? fingerprint(readFileSync(pub, "utf-8")) : null; } catch { key = "unreadable"; }
      parties[name] = { key, doors: [] };
    }
    for (const d of table.doors) {
      const fp = foreignParties(table, d);
      if (fp.length === 0) continue;
      const shut = this.checkDoor(d);
      for (const p of fp) parties[p]?.doors.push(shut ? { id: d.id, holds: false, reason: shut.reason } : { id: d.id, holds: true, valid_until: d.valid_until });
    }
    return {
      closed_doors: this.state.closed_doors,
      closed_compartments: this.state.closed_compartments,
      queued: Object.values(this.state.queue).reduce((n, q) => n + q.length, 0),
      taints: this.state.taints.filter((x) => x.expires_at > t).length,
      door_errors: table.errors,
      parties,
    };
  }
}

export function messageHash(e: Envelope): string {
  const { sender_mask, sender_ceiling, ...carried } = e;
  return sha256(canonical(carried));
}
