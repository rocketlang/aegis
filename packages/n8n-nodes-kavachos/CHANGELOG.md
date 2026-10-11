# Changelog — @xshieldai/n8n-nodes

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
