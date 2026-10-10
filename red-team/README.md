# aegis red-team

Runnable red tests that reproduce the findings of the independent security review (Andrey Lazarev,
October 2026) as exploits against our own code. They are public on purpose: a security claim you cannot
run is a claim you should not trust.

**How to read a result.** Each battery prints one line per check:

- `GAP` — the exploit **succeeded**. The battery exits non-zero. It stays RED until the code is fixed.
- `safe` — the exploit was refused. When every check is `safe`, the battery exits `0`.

A battery is written to go **green only when the fix lands** — not when the fix is described, and not
when a commit is merged, but when the behaviour changes in the package you can install. A fix is always a
URL: the version on the registry (with its provenance) and the commit that made it.

Exit codes: `0` all closed · `1` gap(s) reproduced (RED until fixed) · `3` broke (could not run).

## Batteries

### `point1-self-approval` — the approval authority at the agent's own uid
**Finding (deepest, review point 1).** The thing that approves an action and the agent whose action is
approved run under the same uid, so the agent can approve itself. Reproduced against the destructive
gate: a thread at the agent's own uid writes the one-time-approval file `~/.aegis/destructive-approvals.json`,
and the gate honours it — no person, no signature. It drives the exact gate expression at
`src/cli/commands/check-destructive.ts:170`.

```
bun red-team/point1-self-approval.probe.ts
# or: ./red-team/point1-self-approval.battery.sh
```

Status: **green** for the destructive gate (default + hardened). Separation is now the default (founder
ruling, 2026-10-07):

- **default (no approver configured)** — the gate honours *no* same-account override at all, so an agent
  cannot approve its own command on any box. The forged approval is ignored.
- **hardened** — a separate-uid approver daemon owns the store; the gate asks it, not the agent-writable
  file. A person approves over a socket the agent's uid cannot open.
- **insecure-local** — the old forgeable single-box file override returns only if someone sets
  `AEGIS_ALLOW_INSECURE_LOCAL_APPROVAL` explicitly.

The same-process probe proves the gate no longer trusts the agent-writable file. The other half — that the
agent's uid genuinely *cannot* write the approver's store or open the approve socket — is OS-enforced and
proven by `point1-uid-boundary.disposable.sh`, **on a disposable host with a real second uid** (it creates
and deletes system users; never run it on a live box). The aegis-guard signing-key leg (self-mint) is a
separate increment, still RED. Tracked in the public
[Fixes landed](https://ankr.in/xshield-self-audit.html#fixes) list.

### `point1-uid-boundary` (disposable host) — the uid boundary itself
Creates a real `aegis-approver` account and a separate `agent` account, starts the daemon as the approver,
and proves the agent's uid cannot write the store or open the approve socket while it can still *ask*.

```
sudo AEGIS_DISPOSABLE_HOST=1 ./red-team/point1-uid-boundary.disposable.sh
```

### `aegis-guard-self-mint-and-label` — self-mint (point 1) and label-not-act (point 4)
Installs the **published** `@xshieldai/aegis-guard` into a throwaway HOME and runs two exploits:

- **P1 self-mint** — an agent at the signer's own uid reads `~/.aegis/approval-signing.key` and mints its
  own approval; `verify` accepts it. **Fixed in the repo, ships in 0.6.0** at the next weekly release:
  minting is now an authority action — a non-authority process is refused (`AEGIS_MINT_AUTHORITY=1` declares
  the authority; `AEGIS_ALLOW_INSECURE_LOCAL_MINT=1` is the explicit opt-out), and key generation is gated
  the same way. Default-safe: an agent that merely calls the SDK cannot mint or make a key. *Honest ceiling:*
  on one uid a determined agent can set the env itself — the real boundary is the key living under a
  different uid the agent cannot read; this gate stops the lazy path, the OS stops the determined one. Pinned
  by repo test `GH-101b`. This published battery stays **GAP against 0.5.0** and flips when 0.6.0 is live.
- **P4 label-not-act** — a token binds to a label (service/capability/operation), not the concrete
  arguments, so one `drop_table` approval authorises dropping *any* table. **Fixed in 0.6.0 — enforced
  default.** 0.5.0 *added* `mintActionApprovalToken` / `verifyActionApprovalToken` but left the label-only
  path as the default (partial). 0.6.0 makes action-binding the **default**: the base verifier refuses a
  token with no `action_digest`, so a label-only approval is rejected everywhere, unless a caller sets
  `AEGIS_ALLOW_LABEL_ONLY_APPROVAL=1` (explicit opt-out). Pinned by repo test `GH-109`. This published
  battery stays **GAP against 0.5.0** and flips to `safe` when 0.6.0 is live.

```
./red-team/aegis-guard-self-mint-and-label.battery.sh
```

### `varuna-no-auth` — open, cross-origin, unauthenticated ingest
Varuna's listener bound `0.0.0.0`, set `CORS: '*'`, and had no auth on ingest — a *writer* anyone on
the network could reach. **Fixed in `@xshieldai/varuna` 0.2.0 — safe by default:** loopback bind unless
`HOST` is set, CORS off unless `CORS_ORIGIN` is set, and every route but `/health` requires
`Authorization: Bearer <VARUNA_API_TOKEN>`. If it would be reachable off-box with no token the server
**refuses to start**, unless an operator sets `VARUNA_ALLOW_OPEN=1` knowingly. The probe drives the real
security decisions and the real auth hook directly (no listener — hermetic).

```
./red-team/varuna-no-auth.battery.sh
```

### `nallasetu-asymmetric` — shared HMAC → forgery + repudiation
Cross-org attestations were signed with HMAC-SHA256 over a **shared secret** in the registry — so either
party, or whoever held the registry, could forge the other's attestation, and neither could prove who
signed. An `A & B` capability intersection is only sound if a signature proves A really is A. **Fixed in
`@xshieldai/nallasetu` 0.2.0 — hard cutover to asymmetric:** each agent signs with its own Ed25519
private key; the registry holds **public keys only**; private seals live in a local keystore the
registry never returns. Plus a `mask_vocabulary` tag so an intersection only runs when bit *i* means the
same on both sides. The full five-primitive battery (25 checks) stays green; this public probe proves
the two crypto properties the review named (no forgery, no repudiation).

```
./red-team/nallasetu-asymmetric.battery.sh
```

### `egress-fail-closed` — the egress firewall failed open when the cgroup join failed
The kernel prepares an egress cgroup and attaches the BPF firewall, then the launcher joins the agent
into that cgroup before exec. Before the fix, if that join failed the launcher logged a warning and
**exec'd the agent anyway** — an unconstrained run that looked constrained. **Fixed in
`@xshieldai/agent-kernel` 2.2.0 — fail closed:** a failed join now **refuses to exec**, unless the
operator declared an unconstrained run (`--allow-unconstrained-egress`, propagated as
`KAVACHOS_ALLOW_UNCONSTRAINED_EGRESS`). The probe drives the real `_join_egress_cgroup()` with a bad
cgroup path — hermetic, no root/BPF. (The *full* BPF enforcement — that a non-allowlisted connection is
actually blocked — is proved separately on a disposable real-kernel runner.)

```
./red-team/egress-fail-closed.battery.sh
```

### `exec-race` — TOCTOU on the strict-exec allowlist (RED, open)
The supervisor allowlists `execve` by reading the path from the agent's memory and, on ALLOW, answers
`SECCOMP_USER_NOTIF_FLAG_CONTINUE` — which makes the **kernel re-read** the path pointer and run whatever
is there now. Between the supervisor's check and the kernel's re-read, another agent thread can swap the
pointer → a binary the supervisor never approved runs. The seccomp man page is explicit: `CONTINUE`
"cannot be used to implement security policy" for pointer arguments. (Deny is safe — it's `EPERM`, the
syscall never runs.) This probe proves the window deterministically against the real `_auto_decide_exec`,
modelling the swap as two successive reads; the live race-win is inherently flaky and belongs on a
disposable host.

```
./red-team/exec-race.battery.sh
```

Status: **closed in `@xshieldai/agent-kernel` 2.3.0 — Landlock.** There is no safe way to allow a
pointer-argument syscall via `CONTINUE`, so the exec allowlist is now enforced with **Landlock**: before
exec the launcher restricts `EXECUTE` to the allowlisted binaries (per-file rules) plus the runtime
library/loader dirs (so dynamic linking works), inherited across exec and irrevocable. The kernel checks
the *actual* file it opens, so a pointer swap buys nothing. `CONTINUE` stays as defence-in-depth. The
seccomp-layer probe above remains RED by design (that layer alone cannot bind a pointer arg); the
closure is proved by `exec-race-landlock` below.

### `exec-race-landlock` — the closure: Landlock binds the real file
A child applies the real `_apply_landlock_exec_confinement` (allowlisting one binary), then tries to
exec a NON-allowlisted binary — the kernel denies it (`EACCES`), while the allowlisted one still runs.
Landlock `restrict_self` is per-process, so each attempt is a `fork()`ed child and only that child is
confined — safe on any host, no root.

```
./red-team/exec-race-landlock.battery.sh
```

Status: **green** against this Landlock kernel (6.8). On a host without Landlock the launcher keeps the
seccomp exec gate and says so (`KAVACHOS_LANDLOCK_REQUIRE=1` makes a missing Landlock fail closed).

### `ledger-concealment` — the refusal log catches tampering, not just accidents
**Credit: Shyan-Ming Perng (JieGou)**, *"The Log Only Keeps the Yes"* — a row the refused identity can
write is evidence against accidents, not against concealment. **Shipped in `@xshieldai/aegis` 2.10.0:**
the refusal ledger can be sequenced + hash-chained + Ed25519-signed by an authority key held off the
agent's uid. `aegis ledger-verify` reports a **sequence gap** (a suppressed refusal), a **chain break**
or **bad signature** (an edited/forged row), or **UNVERIFIABLE** (an unsigned/legacy ledger — never
"OK"). The probe proves each is caught, against the real verifier; hermetic (crypto, no root/files).
Rung 2 of the concealment ladder — **tail truncation** needs the off-box witness that knows the true
`maxSeq` (rung 3), stated honestly.

```
./red-team/ledger-concealment.battery.sh
```

### `witness-offbox` — the independent collector catches what the box can't
**Credit: Shyan-Ming Perng (JieGou).** Rung 2 can't catch tail truncation or a silent agent — the on-box
record is the only record. The witness (`aegis witness`, **`@xshieldai/aegis` 2.11.0**) is an independent
collector in a trust domain the agent can't write as: it holds its own per-source high-water-mark and
alarms on a suppressed row (`gap`), a reorder/forgery (`chain`/`signature`), a source gone silent
(`stall` — *silence is the alarm*), and **tail truncation** (`reconcile` against its high-water-mark —
the gap rung 2 missed). The probe drives the real `Witness`; hermetic (crypto + a clock).

```
./red-team/witness-offbox.battery.sh
```

Status: **green.** Rung 3 of the concealment ladder. Honest ceiling: a compromised agent can stop
sending (caught as `stall`); full non-equivocation needs the witness itself attested/replicated.

### `ledger-authority-wired` — the two rungs above, actually connected
The two probes above drive the signing functions and the `Witness` class directly. Until
**`@xshieldai/aegis` 2.14.0** no gate called them: nothing signed a refusal, nothing sent one to a
witness, and the running witness kept nothing on disk. This battery runs the whole path with real
processes — a gate refuses, the separate-uid authority numbers and signs the row, a witness process
keeps its own copy — and forces the failures: authority unreachable (still refused, row marked
unsigned), witness restarted (still holds its rows), on-box ledger cut short (`truncation`, and
`ledger-verify --witness` exits 1), authority silent (`stall`), a row never delivered (`gap`).

```
./red-team/ledger-authority-wired.battery.sh
```

Status: **green.** What it does not show: the uid boundary (one user here — that is
`point1-uid-boundary.disposable.sh`), and a gate that refuses without asking the authority, which
leaves no row and no gap. That last one is open.


### `ledger-anchor` — the ledger's tail, in somebody else's log
A witness on the same host is a second copy, not a second trust domain. Since **`@xshieldai/aegis`
2.15.0** the authority signs a statement of where its ledger stands, `aegis ledger-anchor` submits it
to a public Sigsum log, and `aegis ledger-verify --anchor-log` reads the log back: an anchor in the log
that the file cannot produce is a cut or rewritten ledger (exit 1). The battery forces a file cut back
below an anchor, a rewritten ledger of the same length, a wrong log key, a log that swaps a leaf it
shows, no anchor at all, and a log that refuses for want of a token. Since **2.16.0** it also checks the
log's cosigning witnesses under a Sigsum trust policy and forces a missing quorum, a witness that signs
something else, and a policy that does not name the log. Rows after the last anchor are not covered
until the next one.

```
./red-team/ledger-anchor.battery.sh
```

### `attestation` — identify a malformed / impostor agent
Prove WHO an agent is (signed by its own Ed25519 identity key — the Nallasetu model) and WHAT it runs
(a measurement of its code+config vs a pinned baseline). **Shipped in `@xshieldai/aegis` 2.12.0:**
`aegis attest` measures a build and compares it to a baseline; `verifyAttestation` refuses a bad
identity (impostor), a measurement mismatch (tampered/wrong build), or **no baseline** (unknown is
refused, not trusted). The probe proves all three refusals against the real measurer; hermetic.

```
./red-team/attestation.battery.sh
```

Status: **green — the check.** Honest ceiling: a measurement is only as trustworthy as the measurer;
self-measurement can lie, so the launcher must measure the agent before exec, and hardware/remote
attestation (TPM/measured boot) is the ceiling. This is the measurer + boundary check; launcher-measured
integration is the next rung.

### `attestation-launcher` — the launcher measures the agent (closes the self-measurement gap)
`attestation` (above) is the check; its honest gap was that an agent measuring itself can lie. **Closed
in `@xshieldai/agent-kernel` 2.4.0:** the launcher (`apply-seccomp.py`) measures the agent's declared
code/config files **before exec** against a pinned baseline and **refuses to exec on a mismatch** — so
a compromised agent can't self-report a clean digest. The measure matches the TS `aegis attest` digest
byte-for-byte, so one baseline is portable across the pin tool and the enforcer. Opt-in
(`KAVACHOS_ATTEST_MANIFEST` + `_BASELINE`); half-configured refuses. The battery proves the cross-language
match and that a tampered agent is refused (exit 3) before it runs; hermetic.

```
./red-team/attestation-launcher.battery.sh
```

Status: **green.** Ceiling: the launcher and its baseline must themselves be trusted — a compromised
launcher or host root can still fake it; hardware/remote attestation (TPM/measured boot) is the root.

## Doctrine

A finding is not closed because we understand it. It is closed when its red test refuses the exploit
against an installed, versioned package — and the row in [Fixes landed](https://ankr.in/xshield-self-audit.html#fixes)
links to that version and the commit. We do not adjust a test to make a release pass.
