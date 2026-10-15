# @xshieldai/governed-turn-verify

The verifier of the Governed Turn Protocol (GTP). Part of the xShieldAI Posture Suite.

An agent's request carries a signed **envelope**: who is driving, under which session, which capability (a slug and its bit), whether it writes, and whether it may commit on its own. This package judges one envelope and returns a verdict that names the rule. It makes the same judgement wherever the envelope is checked:

- in HTTP headers at a gate;
- as JSON handed to a hook or a launcher.

So a flow that crosses both is checked the same way at every hop.

No model and no fetching: the caller passes in the key registry, the sessions and the capability catalog. The same inputs always give the same verdict.

```sh
npm install @xshieldai/governed-turn-verify
```

## What it checks

| Step | Refused with | Rule |
|---|---|---|
| An envelope is present | 428 | GTP-INV-3 |
| The signature (Ed25519) covers every GTP field, the method and the path | 401 | GTP-011 |
| **The signing key speaks only for the driver it is registered to.** A key registered to no driver identifies nobody | 401 | GTP-011 |
| `created` is within 300 s of now, either way, and the nonce has not been seen | 401 | GTP-YK-003 |
| The session exists | 401 | GTP-011 |
| The capability is in the catalog with the same bit and verb, and the bit is in the session's mask | 403 | GTP-006 |
| The bit is in the driver's own mask: a driver cannot use a capability it does not hold, and there is no "approved" input to say otherwise | 403 | GTP-INV-6 |
| The driver's mask is within its parent's | 403 | GTP-INV-2 |
| The sealed budget is not spent, and the envelope does not claim more than it | 402 / 403 | GTP-INV-1, GTP-010 |
| A write declares an intent | 403 | GTP-005 |
| The reversibility claimed matches the catalog | 403 | GTP-009 |
| An irreversible write is held for approval even if it asked to commit on its own | 423 | GTP-009, GTP-007 |

## Use

```js
import { checkTurn, envelopeFromHeaders, envelopeFromJson } from "@xshieldai/governed-turn-verify";

const substrate = {
  keyRegistry: { "ed25519:agent-1": { publicKey: PEM, driverId: "agent-1", driverType: "agent" } },
  sessions: async (cred) => lookUpSession(cred),     // or a plain object: { [cred]: { sessionMask, trustByDriver, sealedBudgetLeft } }
  catalog: { "loadboard.read": { bit: 12, verb: "can_read", reversibility: "reversible" } },
  level: "L1",                                       // "L0" records only: same verdict, enforced: false
  seenNonces: new Map(),                              // one map per checker
};

// at an HTTP gate
const r = await checkTurn(envelopeFromHeaders(req.method, req.url, req.headers), substrate);
// the same envelope, carried as JSON
const s = await checkTurn(envelopeFromJson(payload.gtp), substrate);

r.verdict  // { status: "PASS" | "PAUSED" | "REFUSED", httpCode, code, rule, detail }
```

`signEnvelope({ method, path, headers, privateKeyPem, keyid })` signs an envelope. It signs at the current time with a random nonce unless you pass `created` (seconds) and `nonce`; a checker accepts a `created` only within 300 s of its own clock, and a nonce only once. `verifyTurn(envelope, context)` is the decision alone (capability, authority, intent, reversibility, commit), for a caller that has done identity itself.

### At a hook: `gtp-check`

```sh
echo '{"gtp": {"method": "POST", "path": "/api/turn", "fields": { … }}}' \
  | GTP_SUBSTRATE=./substrate.json GTP_NONCES=./nonces.json npx gtp-check
```

| Exit | Meaning |
|---|---|
| 0 | The turn may go ahead: it passed, or the level is L0, which only records |
| 2 | Refused, or held for approval |
| 3 | Could not check: no substrate, or unreadable input |

The verdict is printed as JSON. `GTP_NONCES` keeps the nonces it has seen between runs; without it, a one-shot command cannot see a replay.

## What this does not give

- **Keys and sessions are what you pass in.** The verifier proves an envelope matches them. It does not prove the key registry, the sessions or the catalog are true.
- **The signature profile is simplified RFC 9421.** The covered fields are joined in a fixed order. It is not yet interoperable with general RFC 9421 libraries.
- **Replay protection lasts as long as the nonce map.** A gate that restarts forgets it. The 300-second window limits how old a replayed envelope can be.
- **The verifier never reads the request body** (GTP-INV-4). What the turn says is for the guards behind the gate.

## Licence

AGPL-3.0-only. See `LICENSE`.
