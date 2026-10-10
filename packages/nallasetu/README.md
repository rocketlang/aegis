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

Each party attests with an Ed25519 signature over a canonical payload (`src/crypto.ts`), made with its
own private key; the registry (`src/db.ts`) holds only public keys, so reading it does not let anyone
sign as another agent. The session mask is computed in `src/handshake.ts`:

```js
session_mask = initiator.trust_mask & responder.trust_mask & scope_mask;   // NLS-003, no escalation
```

Sessions carry a mandatory TTL, a PRAMANA-witnessed receipt, and revocation (`revokeKey` /
`reinstateKey`, sticky). A revoked partner is refused as either initiator or responder.

## Upgrading a registry created before 0.2.0

0.2.0 moved attestations from a shared secret to each agent's own Ed25519 key. A registry database created
before it kept working until the service was restarted on the new code, and then could not issue a session:
its registrations had no key pair, and its table still required the old secret column for every new row.

0.2.1 closes that without dropping or rebuilding any table:

- A registration this deployment made itself (`source = 'self'`), that is not revoked and has no public key,
  gets its key pair once, the first time it is needed. The condition is in the UPDATE statement's WHERE clause,
  so an existing public key is never replaced. A revoked agent and an agent registered from outside are left
  exactly as they were: such an agent must be registered again with its own public key.
- On a table that still declares the old secret column `NOT NULL`, a new row carries the fixed marker
  `retired:no-shared-secret` there. It is not a secret and nothing reads the column.

The re-keying is written once to the service's log as `nallasetu.registry.legacy_agent_rekeyed`.

## Scope and limits

- Trust rests on a **registry of public keys**: since 0.2.0 an attestation is signed with the agent's
  own Ed25519 key (before that, a shared secret). Cross-org trust is as strong as that registry's
  provisioning; there is no certificate chain behind a key.
- An initiator's `trust_mask` is **self-asserted** in the request; the real ceiling is the responder's
  **registered** mask ∧ the requested scope.
- A service, not a drop-in library; proven over crafted handshakes, not a live two-org deployment.

## License

AGPL-3.0-only. See [LICENSE](./LICENSE).
