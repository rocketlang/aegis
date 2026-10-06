# Changelog — @xshieldai/n8n-nodes

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
