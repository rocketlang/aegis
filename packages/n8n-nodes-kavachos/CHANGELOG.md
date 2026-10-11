# Changelog — @xshieldai/n8n-nodes

## 1.4.1 (2026-10-12)

- **The four node icons now exist.** Each node has always named an icon file; none was in the source or in the
  package, so n8n showed a placeholder.
- **Known, not changed here:** n8n's community-nodes screen only installs a package whose name (after the
  scope) starts with `n8n-nodes-`. This package is `@xshieldai/n8n-nodes`, so that screen refuses it
  ("Package name must start with n8n-nodes-"). Install it by hand into n8n's custom-extensions folder
  (`npm install @xshieldai/n8n-nodes` there) until it is published under a name n8n accepts.

## 1.4.0 (2026-10-12)

Found in our own review, not reported from outside.

### Fixed — Kavach Run said "enforced" whatever kavachos did, and stopped n8n while it ran

- **`enforced: true` was written whenever `kavachos` had been started.** A launch that kavachos refused (its
  exit 3) came back as ordinary output with `enforced: true`. A refused launch is now an error ("Nothing was
  run"). A launch kavachos reported as not egress-constrained now reads `enforced: false`, with
  `egress_constrained` and `path_jail_loaded` beside it. The command's own exit status 3 is still passed on.
- **The node blocked n8n for as long as the command ran**, with no time limit: every other workflow and n8n's
  own interface stopped. It now waits without blocking, and a new **Time Limit (seconds)** (default 300) stops
  the command and fails the node.
- **Output above 1 MB killed the command**, and in "warn" mode that was not reported. Up to 5 MB is kept, the
  rest is dropped with `output_truncated: true`, and the command is left to finish.

### Fixed — Kavach Gate

- **Only the boolean `true` is an allow.** Any other value in `allow` (the text "false", a number, an object)
  let the workflow on. An answer with no true/false `allow` is now an error: it is not the gate.
- **The node has its own wait, "Wait For A Decision (seconds)", default 660.** The request used to give up at
  about 300 s, while Aegis waits up to 600 s for an approver on the lowest level. No answer in time is a
  block (`decision: TIMEOUT`), as it is in Aegis.
- A server error and a redirect are reported as what they are. Both used to read "Cannot reach Aegis gate".
- Kavach Budget and Kavach Audit give up after 30 s, and say when the audit needs the API token.

`red-team/n8n-kavach-run.battery.sh` in the repository: 28 cases, 17 gaps on 1.3.0, none on 1.4.0.

## 1.3.0 (2026-10-12)

### Fixed — the binary's arguments could set kavachos's own options

`KavachRun` passed the binary and its arguments to `kavachos run` after the options, and `kavachos`
(through 2.4.0) read every word starting with `--` as its own option wherever it stood. An argument
value such as `--dry-run` made kavachos run nothing and exit 0, which this node then reported as an
enforced run; `--allow-unconstrained-egress` loosened the launch. The arguments of this node often come
from an expression, so the words may not be the workflow author's.

- The node now writes `kavachos run <options> -- <binary> <arguments>`: everything after `--` is passed
  on word for word. This also means the binary now receives its own `--` options, which were dropped before.
- **`@xshieldai/agent-kernel` 2.5.0 or later is required.** With an older `kavachos` the node refuses to run
  and says so; it does not fall back.
- Found in our own review, not reported from outside.

## 1.2.0 (2026-10-06)

### Changed — KavachRun now fails CLOSED by default (behaviour change)

`KavachRun`'s `On Non-Linux` default flips from `warn` to **`throw`**. When kernel
enforcement is unavailable (non-Linux host, or `kavachos` not installed) the node now
**halts the workflow by default** instead of running the binary unwrapped. A defense-in-depth
enforcement node should not silently execute an unenforced command.

- `warn` (run unwrapped, flagged `enforced:false`) and `skip` are still available — choose
  them explicitly if you want the old behaviour.
- If you relied on the previous default on macOS/Windows, set **On Non-Linux → Warn** on the
  node after upgrading.

No change to KavachGate, KavachBudget, KavachAudit, or the Aegis API credential.
