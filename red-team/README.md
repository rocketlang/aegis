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

## Doctrine

A finding is not closed because we understand it. It is closed when its red test refuses the exploit
against an installed, versioned package — and the row in [Fixes landed](https://ankr.in/xshield-self-audit.html#fixes)
links to that version and the commit. We do not adjust a test to make a release pass.
