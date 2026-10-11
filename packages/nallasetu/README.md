# @xshieldai/nallasetu

Cross-org agent handshake — a capability-negotiation protocol for autonomous agents from
different trust domains. Before two agents work together, Nallasetu decides what their joint
session may do, and the session's capability is the **intersection** of what both sides hold and
the scope requested — never the union, never an escalation. An agent that claims every permission
still gets only what the other side already had.

> Status: **0.4.0**, early. This is a running service, not a drop-in library. It is published so the
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

Settings, all optional: `PORT` (default 4898), `NALLASETU_RESPONDER_ID`, `NALLASETU_RATE_LIMIT` (handshakes a
second for one partner, default 10), `SUPER_EVENTS_URL`, `LOG_LEVEL`, and the four below.

## Who may reach it (0.4.0)

| Setting | Default | What it does |
|---|---|---|
| `NALLASETU_HOST` | `127.0.0.1` | The address to listen on. Was every interface through 0.3.0. |
| `NALLASETU_API_TOKEN` | none | 24 characters or more (`openssl rand -hex 24`). When set, every route but `/health` needs `Authorization: Bearer <token>`. |
| `NALLASETU_ALLOW_OPEN` | off | `1` accepts a listener that is reachable off this machine with no token. Without it such a start is refused. |
| `NALLASETU_CORS_ORIGIN` | none | One browser origin to allow. Cross-origin was allowed from anywhere through 0.3.0. |

Through 0.3.0 no route asked who was calling, and the server listened on every interface. Anyone who could
reach the port could read a session by its id, revoke it, run the expire-stale call, and have a session issued
for any new name. **If you run 0.3.0 or earlier on a reachable address, put it behind a firewall or upgrade.**
Found in our own review, not reported from outside.

**Upgrading:** a deployment that other machines call must now set `NALLASETU_HOST` and `NALLASETU_API_TOKEN`
(and give its callers the token), or it will listen on this machine only.

**What this does not give.** One shared token says "a permitted caller", not which one: every holder can read
and revoke any session whose id it knows, and the engine still registers an unknown initiator and signs for
it. Per-partner identity on the wire (each caller presenting its own signed attestation) is not built.

Checked by `red-team/nallasetu-http-behaviour.battery.sh` in the repository (50 cases): 14 of them are red on 0.3.0.

## Changed in 0.3.0 (12 October 2026)

- **fastify 4 → 5** (5.12.5), `@fastify/cors` 9 → 11, `@fastify/helmet` 11 → 13. The fastify 4 line carried
  published advisories whose fixes exist only in the 5 line. No line of the service had to change for it.
- **One answer differs:** a semicolon in an address is no longer read as the start of a query.
  `/health;x=1` answered like `/health`; it now matches no route (404).
- `NALLASETU_HOST` is new. The default is unchanged.
- `/health` and the state face reported version `0.1.0` in every release. They now report the version installed.
- Checked with `red-team/nallasetu-http-behaviour.battery.sh` in the repository: 34 answers, written and green
  on fastify 4 first (bar the semicolon line), then green on fastify 5.

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
