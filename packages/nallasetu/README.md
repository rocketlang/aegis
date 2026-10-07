# @xshieldai/nallasetu

Cross-org agent handshake — a capability-negotiation protocol for autonomous agents from
different trust domains. Before two agents work together, Nallasetu decides what their joint
session may do, and the session's capability is the **intersection** of what both sides hold and
the scope requested — never the union, never an escalation. An agent that claims every permission
still gets only what the other side already had.

> Status: **0.1.0**, early. This is a running service, not a drop-in library. It is published so the
> protocol can be read, run and checked in the open.

## Requires

**[Bun](https://bun.sh) ≥ 1.3** — the service uses `bun:sqlite` and is started with `bun`. It is not
a Node package.

## Run

```sh
npm install @xshieldai/nallasetu   # or: bun add @xshieldai/nallasetu
cd node_modules/@xshieldai/nallasetu
bun run start                 # serves POST /api/v2/nallasetu/handshake
```

The store is a local SQLite file at `$HOME/.ankr/nallasetu/nallasetu.db`.

## The five primitives

```
BRIDGE_HELLO → ATTEST_OFFER → INTERSECT_PROPOSE → SESSION_CREDENTIAL → SESSION_RECEIPT
```

Each party attests with an HMAC-SHA256 signature over a canonical payload (`src/crypto.ts`), keyed by
a secret held in a local registry (`src/db.ts`). The session mask is computed in `src/handshake.ts`:

```js
session_mask = initiator.trust_mask & responder.trust_mask & scope_mask;   // NLS-003, no escalation
```

Sessions carry a mandatory TTL, a PRAMANA-witnessed receipt, and revocation (`revokeKey` /
`reinstateKey`, sticky). A revoked partner is refused as either initiator or responder.

## Scope and limits

- Trust is a **shared-secret registry** (HMAC), not asymmetric PKI — cross-org trust is as strong as
  that registry's provisioning.
- An initiator's `trust_mask` is **self-asserted** in the request; the real ceiling is the responder's
  **registered** mask ∧ the requested scope.
- A service, not a drop-in library; proven over crafted handshakes, not a live two-org deployment.

## License

AGPL-3.0-only. See [LICENSE](./LICENSE).
