# @xshieldai/varuna

Maritime OT posture — a service that scores vessel operational-technology traffic for anomalies.
Modbus, NMEA and AIS frames delivered to its routes are checked against per-rule detectors —
runaway-diesel precursors, diagnostic and function-code abuse, AIS and GPS spoofing,
autopilot-sentence injection — and each hit is flagged with a severity and a mapping from its own
rule to IACS UR E26/E27 and MITRE ATT&CK for ICS.

> Status: **0.1.0**, early. A running service (Fastify, Node), not a drop-in library. Published so
> the detection rules can be read, run and checked in the open.

## Run

```sh
npm install @xshieldai/varuna
node node_modules/@xshieldai/varuna/dist/main.js
```

It serves its scoring and testbed routes over HTTP. Frames arrive over those routes; Varuna does not
sniff a wire itself.

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
