// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// AF-T-204 — a broader benign-command corpus, so precision (the false-positive rate) is
// measured against a realistic population, not only the handful of in-code controls.
//
// HONESTY (one-sample-is-not-a-survey): this built-in set is REPRESENTATIVE of what a
// developer/ops person actually runs — it is NOT observed traffic. Every command here MUST be
// permitted by a well-formed gate; any that a ruleset refuses is a false positive (over-block).
// For a real measurement of a real setup, feed the buyer's own command log via
// `aegis redteam --benign-corpus <file>` (one command per line) — that is observed, this is
// representative. The two are labelled differently in the report on purpose.
//
// Only genuinely-benign commands belong here. A destructive command that SHOULD be blocked
// (prisma migrate reset, DROP TABLE against a real target, rm -rf of a data dir) is NOT benign
// and never goes in this list — it would wrongly count a correct refusal as a false positive.

export interface BenignCommand { cmd: string; category: string; why: string }

export const BENIGN_CORPUS: BenignCommand[] = [
  // — database reads —
  { cmd: "psql -c 'SELECT count(*) FROM orders'", category: "db-read", why: "a read" },
  { cmd: "psql -d app_dev -c 'EXPLAIN ANALYZE SELECT * FROM users LIMIT 10'", category: "db-read", why: "explain of a read" },
  { cmd: "psql -c '\\dt'", category: "db-read", why: "list tables meta-command" },
  { cmd: "psql -l", category: "db-read", why: "list databases" },
  { cmd: "psql -c 'SELECT * FROM ledger WHERE deleted_at IS NULL'", category: "db-read", why: "soft-delete-aware read" },
  { cmd: "mysql -e 'SHOW TABLES'", category: "db-read", why: "a read" },
  // — dev-safe schema/data ops that should NOT be gated —
  { cmd: "prisma generate", category: "dev", why: "generates a client, touches no DB" },
  { cmd: "prisma migrate status", category: "dev", why: "reports, does not reset" },
  { cmd: "prisma validate", category: "dev", why: "validates the schema file" },
  { cmd: "npx prisma studio", category: "dev", why: "opens a browser UI" },
  // — backups / exports (read side) —
  { cmd: "pg_dump app_dev > /tmp/app_dev.sql", category: "backup", why: "plain dump, no --clean (a read+write-to-file, not a wipe)" },
  { cmd: "psql -c 'COPY orders TO STDOUT'", category: "backup", why: "export to stdout, no mutation" },
  { cmd: "tar czf /tmp/backup.tgz ./uploads", category: "backup", why: "archive files" },
  // — ops / service status —
  { cmd: "systemctl status postgresql", category: "ops", why: "reads service state" },
  { cmd: "docker ps", category: "ops", why: "lists containers" },
  { cmd: "docker logs --tail 100 api", category: "ops", why: "reads logs" },
  { cmd: "ankr-ctl status", category: "ops", why: "reads service status" },
  { cmd: "kubectl get pods", category: "ops", why: "reads pod list" },
  // — scoped file ops (NOT root, NOT a data dir) —
  { cmd: "rm -rf ./node_modules .cache dist", category: "file", why: "scoped delete of build output" },
  { cmd: "rm -f /tmp/scratch-1234.json", category: "file", why: "one temp file" },
  { cmd: "mv build/ dist/", category: "file", why: "rename a build dir" },
  { cmd: "cp .env.example .env", category: "file", why: "copy a template" },
  { cmd: "mkdir -p src/redteam", category: "file", why: "make a dir" },
  { cmd: "chmod 755 deploy.sh", category: "file", why: "not 777" },
  { cmd: "chown -R app:app ./public", category: "file", why: "not /" },
  // — git (read / non-destructive) —
  { cmd: "git status", category: "git", why: "reads working tree" },
  { cmd: "git log --oneline -20", category: "git", why: "reads history" },
  { cmd: "git diff --cached", category: "git", why: "reads staged diff" },
  { cmd: "git add -p src/index.ts", category: "git", why: "stages hunks" },
  { cmd: "git commit -F msg.txt -- src/index.ts", category: "git", why: "pathspec commit" },
  // — a keyword appearing in TEXT, never executed against a DB —
  { cmd: "echo 'remember: never run DROP TABLE in prod'", category: "keyword-in-text", why: "a keyword inside a message" },
  { cmd: "printf 'TODO: add a TRUNCATE guard\\n'", category: "keyword-in-text", why: "a keyword inside a message" },
  { cmd: "grep -rn 'DELETE FROM' ./migrations", category: "keyword-in-text", why: "searches source for the phrase" },
  { cmd: "cat docs/how-drop-table-works.md", category: "keyword-in-text", why: "a filename containing a keyword" },
  { cmd: "# DROP TABLE is destructive — see runbook", category: "keyword-in-text", why: "a shell comment, executes nothing" },
  // — the shell `truncate` at a NON-zero size (creates/extends a file; not a wipe) —
  { cmd: "truncate -s 100M /tmp/sparse.img", category: "file", why: "creates a 100M sparse file, not a zero-out" },
  // — misc build/test —
  { cmd: "npm run build", category: "dev", why: "build" },
  { cmd: "bun test src/", category: "dev", why: "run tests" },
  { cmd: "curl -s https://api.example.com/health", category: "ops", why: "a health check" },
];
