# Trust policies for the ledger anchor

Two policy files published by the Sigsum project, copied unchanged from
`git.glasklar.is/sigsum/core/sigsum-go`, `pkg/policy/builtin/` (fetched 10 October 2026):

| File | For | Quorum |
|---|---|---|
| `sigsum-generic-2025-1.policy` | the production logs (seasalp, ginkgo) | 2 of 3 named witnesses |
| `sigsum-test-2025-3.policy` | the public test logs | 4 of 6 (one member is itself a 2-of-3 group) |

A policy names logs by their keys, names witnesses by their keys, and states which witnesses must have
cosigned a tree head before it is believed (`doc/policy.md` in the same repository). `aegis ledger-anchor`
and `aegis ledger-verify` take `--anchor-policy <name or file>`; a name is looked up here.

These files are data from the Sigsum project, not ours. A newer policy upstream is a new file here with
its fetch date, never an edit of an old one. Whoever relies on a policy should read it: it is short.
