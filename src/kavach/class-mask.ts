// KAVACH — class_mask: 9-bit resource class bitmask
// @rule:KAV-062 Level 1 enforcement gate — (class_mask & resource_class_bits) !== 0
// @rule:KAV-YK-011 Resource-to-class mapping

// ── Bit definitions ──────────────────────────────────────────────────────────

export const CLASS = {
  DEV:            0x0001,  // dev databases, /tmp, local test paths
  DEMO:           0x0002,  // demo databases and environments
  PROD:           0x0004,  // production databases and live services
  SECRET:         0x0008,  // .env, credentials, classified files
  MARITIME:       0x0010,  // vessel data, AIS, Watch8x telemetry
  FINANCIAL:      0x0020,  // payment records, invoices, billing data
  PERSONAL:       0x0040,  // PII, personal data
  INFRA:          0x0080,  // docker, nginx, system config, ports.json
  ANKR_INTERNAL:  0x0100,  // .ankr/ config, codex.json, services.json
} as const;

export type ClassBit = typeof CLASS[keyof typeof CLASS];

// ── Preset masks ─────────────────────────────────────────────────────────────

/** Dev-only — cannot access prod, secrets, or infrastructure. */
export const CLASS_DEV_ONLY = CLASS.DEV;

/** Standard agent — dev + demo + infrastructure + ANKR internal. */
export const CLASS_STANDARD =
  CLASS.DEV | CLASS.DEMO | CLASS.INFRA | CLASS.ANKR_INTERNAL;

/** Privileged agent — all except financial and personal data. */
export const CLASS_PRIVILEGED =
  CLASS.DEV | CLASS.DEMO | CLASS.PROD |
  CLASS.INFRA | CLASS.ANKR_INTERNAL | CLASS.MARITIME;

/** Admin — all resource classes. */
export const CLASS_ADMIN = 0x01FF;

// ── Resource classification ───────────────────────────────────────────────────

const SECRET_PATTERNS = [
  /\.env($|\.)/i,
  /credentials/i,
  /secret/i,
  /\.pem$/i,
  /\.key$/i,
  /api[_-]?key/i,
  /token/i,
  /password/i,
  /private[_-]?key/i,
];

const INFRA_PATTERNS = [
  /docker-compose/i,
  /dockerfile/i,
  /nginx/i,
  /\/etc\//,
  /ports\.json$/i,
  /\.yml$|\.yaml$/i,
  /systemd/i,
];

const ANKR_INTERNAL_PATTERNS = [
  /\.ankr\//,
  /codex\.json$/i,
  /services\.json$/i,
  /databases\.json$/i,
  /ankr-config/i,
  /ankr-ctl/i,
];

const MARITIME_PATTERNS = [
  /watch8x/i,
  /ais/i,
  /vessel/i,
  /maritime/i,
  /ship/i,
  /nmea/i,
  /modbus/i,
];

const FINANCIAL_PATTERNS = [
  /payment/i,
  /invoice/i,
  /billing/i,
  /finance/i,
  /ledger/i,
  /stripe/i,
];

const PERSONAL_PATTERNS = [
  /\bpii\b/i,
  /personal/i,
  /\bdob\b/i,
  /\bssn\b/i,
  /passport/i,
];

/**
 * Classify a file path or resource name into class_mask bits.
 * Returns CLASS.DEV if no other class matches.
 * @rule:KAV-YK-011
 */
export function classifyResource(resource: string): number {
  let mask = 0;

  if (SECRET_PATTERNS.some((p) => p.test(resource)))      mask |= CLASS.SECRET;
  if (INFRA_PATTERNS.some((p) => p.test(resource)))        mask |= CLASS.INFRA;
  if (ANKR_INTERNAL_PATTERNS.some((p) => p.test(resource))) mask |= CLASS.ANKR_INTERNAL;
  if (MARITIME_PATTERNS.some((p) => p.test(resource)))     mask |= CLASS.MARITIME;
  if (FINANCIAL_PATTERNS.some((p) => p.test(resource)))    mask |= CLASS.FINANCIAL;
  if (PERSONAL_PATTERNS.some((p) => p.test(resource)))     mask |= CLASS.PERSONAL;

  // Production path indicators
  if (/\/var\/www\/|_prod\b|\.prod\.|production/i.test(resource)) mask |= CLASS.PROD;

  // Demo path indicators
  if (/_demo\b|\.demo\.|demo/i.test(resource)) mask |= CLASS.DEMO;

  // Default: dev
  if (mask === 0) mask = CLASS.DEV;
  return mask;
}

/**
 * Classify a database name by its suffix class.
 * Reads from the `class` field pattern in database names.
 */
export function classifyDatabase(dbName: string): number {
  if (/_prod$|_production$/.test(dbName))  return CLASS.PROD;
  if (/_demo$/.test(dbName))               return CLASS.DEMO;
  if (/_dev$|_test$|_e2e$/.test(dbName))  return CLASS.DEV;
  return CLASS.DEV; // unknown DB names are treated as dev-class
}

/**
 * Extract file path from a tool input for class classification.
 * Handles Read (file_path), Write (file_path), Edit (file_path), Bash (command).
 */
export function extractResourceFromToolInput(
  toolName: string,
  toolInput: Record<string, unknown>
): string | null {
  switch (toolName) {
    case "Read":
    case "Write":
    case "Edit":
      return (toolInput.file_path as string) ?? null;
    case "Bash": {
      const cmd = toolInput.command as string;
      if (!cmd) return null;
      // Extract first file-like argument
      const match = cmd.match(/(?:cat|less|head|tail|vi|nano|rm|cp|mv)\s+(\S+)/);
      return match?.[1] ?? null;
    }
    default:
      return null;
  }
}

// ── Human-readable rendering ──────────────────────────────────────────────────

const CLASS_NAMES: [number, string][] = Object.entries(CLASS).map(
  ([name, bit]) => [bit as number, name]
);

export function renderClassMask(mask: number): string {
  if (mask === 0) return "NONE";
  const names = CLASS_NAMES
    .filter(([bit]) => (mask & bit) !== 0)
    .map(([, name]) => name);
  return names.join(" | ");
}
