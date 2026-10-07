/**
 * Ship8x bit wire — flip Varuna capability bit in Ship8x trust_mask.
 * @rule:P3-004 Ship8x capability bit activation after Report Card generation
 * @rule:VRN-050 Continuous score feeds back into fleet trust layer
 */

const SHIP8X_URL = process.env['SHIP8X_URL'] ?? 'http://localhost:4260';

// bit_20 = IACS_COMPLIANCE in Ship8x trust_mask (maritime trust constants)
const VARUNA_CAPABILITY_BIT = 20;

// @rule:P3-004 Notify Ship8x that Varuna has completed assessment for this vessel
export async function notifyShip8xCapabilityActive(
  vessel_id: string,
  posture_score: number,
  log: { debug: (ctx: object, msg: string) => void; warn: (ctx: object, msg: string) => void }
): Promise<boolean> {
  try {
    const res = await fetch(`${SHIP8X_URL}/api/capabilities/activate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        vessel_id,
        capability_bit: VARUNA_CAPABILITY_BIT,
        source: 'xshieldai-varuna',
        posture_score,
        activated_at: new Date().toISOString(),
      }),
      signal: AbortSignal.timeout(3000),
    });
    if (res.ok) {
      log.debug({ vessel_id, bit: VARUNA_CAPABILITY_BIT }, '[ship8x] capability bit activated');
      return true;
    }
    log.warn({ vessel_id, status: res.status }, '[ship8x] capability activation rejected');
    return false;
  } catch {
    // Ship8x not running — graceful degradation
    log.debug({ vessel_id }, '[ship8x] not reachable — capability bit wire pending');
    return false;
  }
}
