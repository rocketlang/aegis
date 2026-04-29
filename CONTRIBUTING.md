<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Contributing to AEGIS

AEGIS is AGPL-3.0 open source. Contributions are welcome — especially:

- New DAN Gate patterns (destructive command detection)
- Provider adapters (Cursor, Copilot, Devin, Windsurf)
- Dashboard improvements
- Documentation fixes

---

## Before you start

1. Read [SECURITY.md](SECURITY.md) — AEGIS is a trust tool. Changes to gate logic, hook behavior, or outbound network calls get extra scrutiny.
2. Check open issues for context on what's already being discussed.
3. For significant changes, open an issue first to align on approach before writing code.

---

## Setup

```bash
git clone https://github.com/rocketlang/aegis
cd aegis
bun install
bun run build
```

Run the test suite:

```bash
bun test
```

---

## Code style

- TypeScript with strict mode
- No runtime dependencies beyond `bun:sqlite`, `fastify`, and `@fastify/*`
- Every gate check must exit 0 (allow) or 2 (block) — never 1 (error blocks silently in Claude Code hooks)
- Default-safe: when in doubt, BLOCK not ALLOW
- SPDX header on every `.ts` file: `// SPDX-License-Identifier: AGPL-3.0-only`

---

## Adding a DAN Gate pattern

Destructive patterns live in two places:

1. **`rules/destructive-rules.json`** — file-level rules loaded at hook time (HIGH/MEDIUM/CRITICAL severities)
2. **`src/kavach/gate.ts` `LEVEL_RULES`** — in-process classification for the full KAVACH approval flow (L1–L4)

For a new pattern:
1. Add to `LEVEL_RULES` with the appropriate level and a clear `consequence` message
2. Add a matching entry to `destructive-rules.json` at the corresponding severity
3. Write a test in `src/kavach/gate.test.ts` confirming it classifies correctly

The consequence message is what a human reads on Telegram at 2 AM. Write it in plain English. No jargon.

---

## Adding a provider adapter

Adapters live in `src/monitor/providers/`. Each adapter exports:

```typescript
export interface ProviderAdapter {
  name: string;
  detect(): boolean;                // returns true if provider files exist
  watchPaths(): string[];           // file paths to watch
  parseEvent(line: string): UsageRecord | null;  // parse one JSONL line
}
```

See `src/monitor/providers/claude.ts` for the reference implementation.

---

## Pull request checklist

- [ ] Tests pass: `bun test`
- [ ] SPDX header on new `.ts` files
- [ ] No new outbound network calls without documentation in `SECURITY.md`
- [ ] Gate changes tested with real command strings (not just regex unit tests)
- [ ] `CHANGELOG.md` entry added under `[Unreleased]`

---

## License

By contributing, you agree your changes will be licensed under AGPL-3.0-only.

Any modified version run as a network service must publish source under the same license.
