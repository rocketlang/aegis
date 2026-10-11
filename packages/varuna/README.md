# @xshieldai/varuna

Maritime OT posture — a service that scores vessel operational-technology traffic for anomalies.
Modbus, NMEA and AIS frames delivered to its routes are checked against per-rule detectors —
runaway-diesel precursors, diagnostic and function-code abuse, AIS and GPS spoofing,
autopilot-sentence injection — and each hit is flagged with a severity and a mapping from its own
rule to IACS UR E26/E27 and MITRE ATT&CK for ICS.

> Status: **0.3.0**, early. A running service (Fastify, Node), not a drop-in library. Published so
> the detection rules can be read, run and checked in the open.

## Run

```sh
npm install @xshieldai/varuna
PORT=4254 node node_modules/@xshieldai/varuna/dist/main.js
```

Node 20 or later. `PORT` must be set; the server does not pick one.

It serves its scoring and testbed routes over HTTP. Frames arrive over those routes; Varuna does not
sniff a wire itself.

## Changed in 0.3.0 (12 October 2026)

- **0.2.0 did not start as this page said.** Unless `NODE_ENV=production` was set it stopped with
  "unable to determine transport target", because it asked for a log formatter (`pino-pretty`) that is not
  among its dependencies. It now uses that formatter only if you have installed it, and logs JSON otherwise.
  The command above also lacked `PORT`.
- **fastify 4 → 5** (5.12.5), `@fastify/cors` 9 → 11, `@fastify/rate-limit` 9 → 11. The fastify 4 line
  carried published advisories whose fixes exist only in the 5 line. **Node 20 or later is now required.**
- **One answer differs:** a semicolon in an address is no longer read as the start of a query, so
  `/api/v2/forja/state;x=1` matches no route. `/health;x=1` was never treated as `/health` by the token check.
- `/health` and the state face reported version `0.1.0` in every release. They now report the version installed.
- The build now fails on a type error; before, it shipped whatever was produced.
- The PDF route passes its file names to `wkhtmltopdf` as an argument list.
- Checked with `red-team/varuna-http-behaviour.battery.sh` in the repository (71 cases): the token check,
  the rate limit, refusing to start open, and every one of the 46 routes asked on fastify 4 and again on
  fastify 5, with the same status and content type on each.

## What it detects

Per-rule detectors over three protocol families:

- **Modbus** — function-code allowlist, diagnostic/reset (FC-08) always-alert, baseline drift,
  runaway-diesel precursor (air-shutoff + HC-suppress coils within a window).
- **NMEA** — bad-checksum / injected sentences, autopilot heading-sentence injection.
- **AIS / GPS** — invalid MMSI, impossible position jumps (spoofing).

Each finding carries a severity and a declared cross-reference to IACS UR and MITRE ATT&CK for ICS.

## Scope and limits

- It detects over **frames delivered to its routes or its own testbed**, not a live-ship wire capture.
- Active OT tests are confined to an owned testbed by rule, never a live bus.
- The rule → IACS → MITRE mapping is a **declared cross-reference**, not an authority's ruling.

## License

AGPL-3.0-only. See [LICENSE](./LICENSE).
