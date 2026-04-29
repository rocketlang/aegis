// KAVACH — perm_mask: 32-bit agent capability bitmask
// @rule:KAV-061 Level 0 enforcement gate — (perm_mask & required_bit) !== 0
// @rule:KAV-065 Child perm_mask = parent.effective & requested (AND invariant)
// @rule:KAV-068 Default perm_mask at spawn is PERM_STANDARD

// ── Bit definitions ──────────────────────────────────────────────────────────

export const PERM = {
  // Bits 0-7: Tool capabilities
  READ:         0x00000001,  // Read tool
  WRITE:        0x00000002,  // Write + Edit tools
  EXEC_BASH:    0x00000004,  // Bash tool
  SPAWN_AGENTS: 0x00000008,  // Agent tool
  NETWORK:      0x00000010,  // curl/wget/ssh/nc in Bash
  DB_WRITE:     0x00000020,  // INSERT/UPDATE/prisma generate
  DB_READ:      0x00000040,  // SELECT queries
  DB_SCHEMA:    0x00000080,  // DROP/ALTER/TRUNCATE/prisma db push/migrate

  // Bits 8-15: Operation scope
  FS_CREATE:    0x00000100,  // create new files or directories
  FS_DELETE:    0x00000200,  // rm / delete files
  SERVICE_OP:   0x00000400,  // ankr-ctl start/stop/restart
  SECRET_READ:  0x00000800,  // read .env, credentials, secrets
  CONFIG_WRITE: 0x00001000,  // write config files (ports.json, .ankr/*)
  GIT_WRITE:    0x00002000,  // git commit/push/reset --hard
  EXTERNAL_API: 0x00004000,  // call external APIs (non-Bash)
  PRIVILEGED:   0x00008000,  // sudo / root operations

  // Bits 16-23: Admin capabilities (rarely granted)
  POLICY_ADMIN: 0x00010000,  // modify agent policies
  MASK_ADMIN:   0x00020000,  // modify trust_mask in codex.json
  AUDIT_WRITE:  0x00040000,  // write audit / violation records
  CROSS_SVC:    0x00080000,  // call other ANKR services programmatically
  PRODUCTION:   0x00100000,  // access production-class resources

  // Bits 24-31: reserved for future allocation
} as const;

export type PermBit = typeof PERM[keyof typeof PERM];

// ── Preset masks ─────────────────────────────────────────────────────────────

/** Read-only agent — may only observe, never modify. */
export const PERM_READ_ONLY =
  PERM.READ | PERM.DB_READ;

/** Standard agent — normal development work, no destructive or admin ops. @rule:KAV-068 */
export const PERM_STANDARD =
  PERM.READ | PERM.WRITE | PERM.EXEC_BASH |
  PERM.DB_READ | PERM.DB_WRITE |
  PERM.FS_CREATE | PERM.NETWORK |
  PERM.GIT_WRITE | PERM.EXTERNAL_API;

/** Privileged agent — includes schema ops and service management. */
export const PERM_PRIVILEGED =
  PERM_STANDARD |
  PERM.DB_SCHEMA | PERM.FS_DELETE |
  PERM.SERVICE_OP | PERM.CONFIG_WRITE | PERM.PRIVILEGED;

/** Admin agent — all non-reserved bits. For founder/root sessions only. */
export const PERM_ADMIN =
  PERM_PRIVILEGED |
  PERM.SECRET_READ | PERM.SPAWN_AGENTS |
  PERM.POLICY_ADMIN | PERM.MASK_ADMIN |
  PERM.AUDIT_WRITE | PERM.CROSS_SVC | PERM.PRODUCTION;

/** All bits set (32-bit unsigned max). */
export const PERM_FULL = 0x001FFFFF;

// ── Required bits per tool + command ─────────────────────────────────────────

/** @rule:KAV-YK-010 — map tool name to minimum required perm_mask bits */
export function requiredBitsForTool(
  toolName: string,
  command?: string
): number {
  switch (toolName) {
    case "Read":
      return PERM.READ;
    case "Write":
      return PERM.WRITE | PERM.FS_CREATE;
    case "Edit":
      return PERM.WRITE;
    case "Agent":
      return PERM.SPAWN_AGENTS;
    case "Bash": {
      let bits = PERM.EXEC_BASH;
      if (!command) return bits;
      const cmd = command.toLowerCase();
      if (/\b(curl|wget|nc|ncat|ssh|scp|rsync)\b/.test(cmd)) bits |= PERM.NETWORK;
      if (/\brm\s+-rf?\b/.test(cmd))                          bits |= PERM.FS_DELETE;
      if (/\bsudo\b/.test(cmd))                               bits |= PERM.PRIVILEGED;
      if (/\b(prisma\s+db\s+push|prisma\s+migrate|drop\s+table|drop\s+schema|truncate|alter\s+table.*drop)/i.test(command)) bits |= PERM.DB_SCHEMA;
      if (/\bgit\s+(push|reset\s+--hard|clean\s+-f)\b/.test(cmd)) bits |= PERM.GIT_WRITE;
      if (/\bankr-ctl\s+(start|stop|restart|kill)\b/.test(cmd)) bits |= PERM.SERVICE_OP;
      if (/\bcat\s+.*\.env\b|\bcat\s+.*credentials/.test(cmd)) bits |= PERM.SECRET_READ;
      return bits;
    }
    default:
      return 0; // unknown tool — no perm bits required (allow)
  }
}

// ── Spawn-time AND computation ────────────────────────────────────────────────

/**
 * Compute child declared_perm_mask at spawn time.
 * @rule:KAV-065 — child = parent.effective & requested
 * Bits the parent doesn't hold are silently cleared. No error thrown.
 */
export function computeChildPermMask(
  parentEffectiveMask: number,
  requestedMask: number
): number {
  return parentEffectiveMask & requestedMask;
}

/**
 * Detect privilege escalation: child has bits parent doesn't.
 * @rule:KAV-065 — (child & ~parent) !== 0 → escalation attempt
 */
export function detectEscalation(
  parentEffectiveMask: number,
  childDeclaredMask: number
): boolean {
  return (childDeclaredMask & ~parentEffectiveMask) !== 0;
}

// ── Human-readable rendering ──────────────────────────────────────────────────

const BIT_NAMES: [number, string][] = Object.entries(PERM).map(
  ([name, bit]) => [bit as number, name]
);

export function renderPermMask(mask: number): string {
  if (mask === 0) return "NONE";
  const names = BIT_NAMES
    .filter(([bit]) => (mask & bit) !== 0)
    .map(([, name]) => name);
  return names.join(" | ");
}
