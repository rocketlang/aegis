/**
 * runTestbed — the owned OT testbed harness (VRN-P1-1), watchable edition.
 *
 * Injects the canonical attack frames into the REAL detectors (../modbus/detector.ts) on an
 * in-memory `testbed-*` vessel — no live OT touched — then returns the resulting posture via
 * the factor seam. Every frame is `data_source=testbed` (VRN-ARCH-007 honesty floor); this is
 * a sim we own (VRN-041 active tests testbed-only). The frames carry real FC codes, real
 * register/coil semantics and real timing within the 60s runaway window (D2-1 fidelity bar).
 *
 * @rule:VRN-041 active tests testbed-only   @rule:VRN-044 two-coil runaway   @rule:VRN-009 FC allowlist
 */

import type { FastifyBaseLogger } from 'fastify';

import { checkFcAllowlist, checkRunawayDiesel, observeModbus } from '../modbus/detector.js';
import { getVessel, resetVessel } from '../store/vessel.js';

import type { VesselPosture } from './aggregate.js';
import { buildVesselPosture } from './posture.js';

// detectors take a logger only to emit SENSE; on the testbed we silence it.
const silent = {
  info() {},
  warn() {},
  error() {},
  debug() {},
  fatal() {},
  trace() {},
  child() {
    return silent;
  },
} as unknown as FastifyBaseLogger;

const AUTHORISED = ['10.0.0.5']; // the one authorised engineering station on the testbed

export interface TestbedRun {
  vessel_id: string;
  data_source: 'testbed';
  frames_emitted: number;
  scenarios: string[];
  posture: VesselPosture;
}

/**
 * Emit the canonical OT attack sequence to a fresh testbed vessel and read the posture.
 * @rule:VRN-044 runaway diesel is the wedge — engine = catastrophe.
 */
export function runTestbed(scopeId = 'demo'): TestbedRun {
  const vesselId = `testbed-${scopeId}`;
  resetVessel(vesselId);
  const vessel = getVessel(vesselId);
  const now = Date.now();
  let frames = 0;

  // lock the 7-day baseline so post-lock anomalies fire (testbed shortcut, real semantics).
  vessel.modbusBaselineLocked = true;
  vessel.modbusBaselineStarted = now - 8 * 24 * 60 * 60 * 1000;

  // 1) FC-allowlist bypass — a write FC (06) from an unauthorised source.
  checkFcAllowlist(
    silent,
    vesselId,
    {
      src_ip: '192.168.10.77',
      unit_id: 2,
      function_code: 6,
      register: 0x0042,
      value: 1,
      timestamp: now,
    },
    AUTHORISED
  );
  frames++;

  // 2) Always-alert diagnostic — FC 08 from anywhere.
  observeModbus(vesselId, {
    src_ip: '10.0.0.5',
    unit_id: 1,
    function_code: 8,
    register: 0,
    value: 0,
    timestamp: now + 1000,
  });
  frames++;

  // 3) Runaway-diesel two-coil sequence — air-shutoff disable + HC suppress within 60s.
  checkRunawayDiesel(silent, vesselId, {
    src_ip: '192.168.10.99',
    unit_id: 1,
    function_code: 5,
    register: 0x0001,
    value: 0x0000,
    timestamp: now + 2000,
  });
  checkRunawayDiesel(silent, vesselId, {
    src_ip: '192.168.10.99',
    unit_id: 1,
    function_code: 5,
    register: 0x0010,
    value: 0x0000,
    timestamp: now + 17000,
  });
  frames += 2;

  const posture = buildVesselPosture(vesselId, {
    data_source: 'testbed',
    authorised_sources: AUTHORISED,
  });
  return {
    vessel_id: vesselId,
    data_source: 'testbed',
    frames_emitted: frames,
    scenarios: ['FC_ALLOWLIST_BYPASS', 'ALWAYS_ALERT_FC08', 'RUNAWAY_DIESEL_SEQUENCE'],
    posture,
  };
}
