/**
 * NMEA 0183 sentence parser + XOR checksum validator.
 * @rule:VRN-032 NMEA 0183 security — checksum per SHP-007
 */

export interface ParsedNMEA {
  raw: string;
  talker_id: string;
  sentence_type: string;
  fields: string[];
  checksum_valid: boolean;
  declared_checksum: string | null;
  computed_checksum: string;
}

// @rule:VRN-032 XOR checksum per SHP-007 — every NMEA sentence must be validated
export function parseNMEA(sentence: string): ParsedNMEA | null {
  const trimmed = sentence.trim();
  if (!trimmed.startsWith('$')) return null;

  // Split checksum
  const starIdx = trimmed.lastIndexOf('*');
  const declared_checksum =
    starIdx !== -1 ? trimmed.slice(starIdx + 1, starIdx + 3).toUpperCase() : null;
  const body = trimmed.slice(1, starIdx !== -1 ? starIdx : undefined);

  // XOR checksum of all bytes in body (between $ and *)
  let xor = 0;
  for (let i = 0; i < body.length; i++) xor ^= body.charCodeAt(i);
  const computed_checksum = xor.toString(16).toUpperCase().padStart(2, '0');
  const checksum_valid = declared_checksum === computed_checksum;

  // Parse talker + sentence type from first field
  const parts = body.split(',');
  const msg_id = parts[0] ?? '';
  const talker_id = msg_id.length >= 2 ? msg_id.slice(0, 2) : 'XX';
  const sentence_type = msg_id; // e.g. GPGGA, HEHDT, IIRSA

  return {
    raw: trimmed,
    talker_id,
    sentence_type,
    fields: parts.slice(1),
    checksum_valid,
    declared_checksum,
    computed_checksum,
  };
}

// Watchlist sentences whose injection could affect navigation safety
// @rule:VRN-032 Autopilot/ECDIS protection
// @rule:VRN-040 Autopilot heading injection
export const CRITICAL_SENTENCE_WATCHLIST = new Set([
  'GPGGA', // GPS fix
  'GPRMC', // Recommended minimum
  'HEHDT', // True heading
  'HEHDG', // Magnetic heading
  'IIRSA', // Rudder sensor angle
  'IIDBT', // Depth below transducer
  'WIMWV', // Wind speed and angle
]);
