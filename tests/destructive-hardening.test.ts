// SPDX-License-Identifier: AGPL-3.0-only
// The destructive gate, hardened (2.5.0).
//
// What these pin:
//   §D1 display only   a comment or a message cannot carry a command past the gate
//   §D2 structure      (KAV-099) recursive removal of / or the home directory, however spelled
//   §D3 patterns       the shipped patterns: what they catch, what they leave alone, how long they take
//   §D4 approval       (KAV-098) a person's one-time approval; nothing typed into a command overrides
//   §D5 shipped files  the rules files in the package are what the code uses
//   §D6 limits         what the gate does NOT see, so a change in any of them is noticed
//
// Pure functions and a throwaway HOME: nothing is run. The statements are assembled from
// words so that this file is not itself the command.

import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, existsSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { destructiveVerdict, isInertDisplay, structuralMatch, type DestructiveRules } from "../src/kavach/destructive-verdict";
import { approvePending, consumeApproval, hashCommand, listPending, recordPending, APPROVAL_TTL_MS, PENDING_TTL_MS } from "../src/kavach/destructive-approval";
import { bashFileVerdict, defaultShieldRules, loadShieldRules } from "../src/shield/injection-detector";

const RULES = JSON.parse(readFileSync(new URL("../rules/destructive-rules.json", import.meta.url), "utf-8")) as DestructiveRules;
const D = (...w: string[]) => w.join(" ");
const DROP_T = D("DROP", "TABLE", "users");
const DROP_DB = D("DROP", "DATABASE", "prod");
const DEL = D("DELETE", "FROM", "users");
const COMPOSE = D("docker", "compose");
const sql = (s: string) => `psql -d app -c "${s}"`;
const kind = (c: string) => destructiveVerdict(c, RULES).kind;

// ─── §D1 display only ─────────────────────────────────────────────────────────

describe("§D1 a comment or a message cannot carry a command past the gate", () => {
  it("DH-101: a comment is inert only when every line is a comment", () => {
    expect(isInertDisplay(`# never run ${DROP_T}`)).toBe(true);
    expect(isInertDisplay(`# never run ${DROP_T}\n# on production`)).toBe(true);
    expect(isInertDisplay(`# cleanup\n${sql(DROP_T)}`)).toBe(false);
    expect(isInertDisplay(`# cleanup\r\n${sql(DROP_T)}`)).toBe(false);
    expect(isInertDisplay(`\n\n  # cleanup\n\n${sql(DROP_T)}`)).toBe(false);
  });

  const stopped: string[] = [
    `# cleanup\n${sql(DROP_T)}`, `# routine\n${sql(DROP_DB)}`, `echo starting\n${sql(DROP_T)}`, `echo "${DROP_T}" | psql -d app`,
    `git commit -m "x" && ${sql(DROP_T)}`, `git commit -m "$(${sql(DROP_T)})"`, `grep -c x notes.md; ${sql(DROP_T)}`,
    `rg --pre "psql -c '${DROP_T}'" pattern .`, `ag --pager "psql -c '${DROP_T}'" pattern`, `git grep -O"psql -c '${DROP_T}'" pattern`,
    `git -c alias.x='!psql -c \\"${DROP_T}\\"' x`, `git log --ext-diff -c diff.external="psql -c '${DROP_T}'"`,
  ];
  for (const c of stopped) it(`DH-1xx stopped: ${c.replace(/\s+/g, " ").slice(0, 56)}`, () => expect(kind(c)).toBe("match"));

  const shown: string[] = [
    `echo "${DROP_T}"`, `printf '%s\\n' "${DROP_T}"`, `grep -rn "${D("DELETE", "FROM")}" src/`,
    `git commit -m "docs: why ${D("DROP", "TABLE")} is blocked"`, `git tag -a v1 -m "no more ${D("DROP", "TABLE")} in migrations"`,
  ];
  for (const c of shown) it(`DH-1xx shown, not run: ${c.slice(0, 56)}`, () => expect(kind(c)).toBe("inert"));
});

// ─── §D2 structure ────────────────────────────────────────────────────────────

describe("§D2 recursive removal of / or the home directory, however it is spelled (KAV-099)", () => {
  const rm = (...a: string[]) => D("rm", ...a);
  const stopped: string[] = [
    rm("-rf", "/"), rm("-fr", "/"), rm("-Rf", "/"), rm("-r", "-f", "/"), rm("--recursive", "--force", "/"), rm("-rf", "--no-preserve-root", "/"),
    rm("-rf", "--", "/"), rm("-rf", "//"), rm("-r", "/"), rm("-rf", "/*"), rm("-fR", '"/"'), rm("-rf", "/", "home"),
    D("sudo", "-u", "root", rm("-rf", "/*")), `bash -c "${rm("-rf", "~")}"`, rm("-rf", "~"), rm("-rf", "$HOME"), rm("-rf", '"${HOME}/"'), rm("-rf", "~/*"),
    `cd /tmp && ${rm("-rf", "/")}`, `if true; then ${rm("-rf", "~")}; fi`,
  ];
  for (const c of stopped) it(`DH-2xx stopped: ${c.slice(0, 50)}`, () => {
    expect(structuralMatch(c)).not.toBeNull();
    expect(kind(c)).toBe("match");
  });

  const allowed: string[] = [rm("-rf", "./build"), rm("-rf", "node_modules", "dist"), rm("-rf", "~/project/dist"), rm("-rf", "$HOME/.cache/pip"), rm("-rf", "/tmp/work-123"), rm("-f", "/tmp/out.log"), "ls /", "echo rm -rf"];
  for (const c of allowed) it(`DH-2xx allowed: ${c}`, () => {
    expect(structuralMatch(c)).toBeNull();
    expect(kind(c)).toBe("clear");
  });
});

// ─── §D3 patterns ─────────────────────────────────────────────────────────────

describe("§D3 the shipped patterns", () => {
  const stopped: string[] = [
    sql(DROP_DB), sql(DROP_T), sql(DROP_T.toLowerCase()), sql(D("DROP\nTABLE", "users")), sql("DROP/**/TABLE users".replace("DROP", "DR" + "OP")), sql(D("TRUNCATE", "TABLE", "orders")), sql(DEL),
    sql(D("ALTER", "TABLE", "users", "DROP", "COLUMN", "email")), "dropdb prod", "npx prisma migrate reset --force", "npx prisma db push",
    `${COMPOSE} down -v`, `${COMPOSE} down --volumes`, `docker-compose down -v`, `${COMPOSE} -f prod.yml down --volumes`, `${COMPOSE} rm -sfv`, `${COMPOSE} down -vt 5`,
    D("docker", "volume", "rm", "app_pgdata"), D("rm", "-r", "--force", "/var/lib/postgresql/16/main"), "chmod -R 777 /srv/app", "systemctl stop postgresql",
    `psql -d app -c "DR""OP TAB""LE users"`, `psql -d app -c 'DR'"OP"' TAB''LE users'`, `psql -d app -c "DRO\\P TABLE users"`.replace("TABLE", "TAB" + "LE"),
  ];
  for (const c of stopped) it(`DH-3xx stopped: ${c.replace(/\s+/g, " ").slice(0, 56)}`, () => expect(kind(c)).toBe("match"));

  const allowed: string[] = [
    "ls -la", "git status --short", "npm test", 'psql -d app -c "SELECT count(*) FROM orders"', `${COMPOSE} up -d --build`, `${COMPOSE} down`, `${COMPOSE} down --remove-orphans`,
    `${COMPOSE} logs -f api`, `${COMPOSE} exec api node -v`, `${COMPOSE} run -v ./data:/data api ls`, "chmod 755 run.sh", "npx prisma migrate deploy", "npx prisma generate",
    "truncate -s 0 app.log", "cat prisma/migrations/0001_init/migration.sql",
  ];
  for (const c of allowed) it(`DH-3xx allowed: ${c.slice(0, 56)}`, () => expect(kind(c)).toBe("clear"));

  it("DH-350: no shipped pattern has an unbounded gap, and none takes long on a repetitive command", () => {
    for (const r of RULES.bash_block_patterns) expect(r.pattern).not.toContain(".*");
    const slow = [`${COMPOSE} x `.repeat(20_000), "rm -rf x ".repeat(20_000), "pg_dump x ".repeat(20_000), "prisma db push x ".repeat(20_000), D("ALTER", "TABLE") + " a".repeat(150_000), "# note\n".repeat(50_000), "echo " + "\"'".repeat(200_000)];
    for (const c of slow) {
      const t0 = Date.now();
      destructiveVerdict(c, RULES);
      expect(Date.now() - t0).toBeLessThan(3000);
    }
  });

  it("DH-351: a command too long to judge is refused", () => {
    const v = destructiveVerdict("echo " + "a".repeat(600_000), RULES);
    expect(v.kind).toBe("match");
  });

  it("DH-352: a pattern that does not compile is skipped; odd input is clear", () => {
    const broken: DestructiveRules = { bash_block_patterns: [{ pattern: "(", flags: "i", reason: "broken", severity: "HIGH" }, ...RULES.bash_block_patterns] };
    expect(destructiveVerdict(sql(DROP_T), broken).kind).toBe("match");
    for (const c of ["", null, undefined, 7, {}]) expect(destructiveVerdict(c as any, RULES).kind).toBe("clear");
  });
});

// ─── §D4 approval ─────────────────────────────────────────────────────────────

describe("§D4 an override is a person's one-time approval, never text in the command (KAV-098)", () => {
  const SAVED = process.env.HOME;
  let home = "";
  beforeEach(() => { home = mkdtempSync(join(tmpdir(), "destructive-approval-")); mkdirSync(join(home, ".aegis"), { recursive: true }); process.env.HOME = home; });
  afterEach(() => { if (SAVED === undefined) delete process.env.HOME; else process.env.HOME = SAVED; });

  it("DH-401: no text in the command overrides — not the old tokens, not a token a rules file names", () => {
    for (const t of ["HUMAN-DESTRUCTIVE-" + "CONFIRMED-ANKR", "AEGIS-DESTRUCTIVE-" + "CONFIRMED"]) expect(kind(`${sql(DROP_T)} # ${t}`)).toBe("match");
    const mine: DestructiveRules = { ...RULES, allowed_override_token: "MY-OWN-" + "OVERRIDE-WORD" };
    expect(destructiveVerdict(`${sql(DROP_T)} # ${mine.allowed_override_token}`, mine).kind).toBe("match");
    expect((RULES as unknown as Record<string, unknown>).allowed_override_token).toBeUndefined();
  });

  it("DH-402: refused → approved by its code → that exact command, once", () => {
    const cmd = sql(DEL);
    const code = recordPending(cmd, "test rule");
    expect(code).toBe(hashCommand(cmd).slice(0, 8));
    expect(listPending().map((p) => p.code)).toEqual([code]);
    expect(consumeApproval(cmd)).toBe(false); // remembered is not approved
    expect(approvePending(code)?.hash).toBe(hashCommand(cmd));
    expect(listPending()).toEqual([]);
    expect(consumeApproval(cmd + " ")).toBe(false);
    expect(consumeApproval(sql(DROP_DB))).toBe(false);
    expect(consumeApproval(cmd)).toBe(true);
    expect(consumeApproval(cmd)).toBe(false); // used up
  });

  it("DH-403: a code nobody was given, or one that is not a code, approves nothing", () => {
    recordPending(sql(DEL), "test rule");
    for (const c of ["0123abcd", "", "../../etc", "ZZZZZZZZ", "0123abc", null, undefined, 7]) expect(approvePending(c as any)).toBeNull();
  });

  it("DH-404: approvals and pending refusals expire", () => {
    const cmd = sql(DEL);
    const t0 = 1_700_000_000_000;
    const code = recordPending(cmd, "r", t0);
    expect(approvePending(code, t0 + PENDING_TTL_MS + 1)).toBeNull();
    recordPending(cmd, "r", t0);
    expect(approvePending(code, t0 + 1000)).not.toBeNull();
    expect(consumeApproval(cmd, t0 + 1000 + APPROVAL_TTL_MS + 1)).toBe(false);
  });

  it("DH-405: an approvals file that is not what this code wrote approves nothing and breaks nothing", () => {
    const cmd = sql(DEL);
    const hash = hashCommand(cmd);
    for (const body of ["allow everything", "{}", "null", JSON.stringify([null, 7, { hash }, { hash, expires_at: "tomorrow" }, { hash: true, expires_at: Date.now() + 60_000 }])]) {
      writeFileSync(join(home, ".aegis/destructive-approvals.json"), body);
      expect(consumeApproval(cmd)).toBe(false);
    }
  });

  it("DH-406: what is remembered of a refused command holds no key from it", () => {
    const key = "sk-ant-" + "api03-" + "M1n2B3v4C5x6Z7l8K9j0H1g2F3d4S5a6P7o8I9u0";
    recordPending(`PGPASSWORD=${key} ${sql(DEL)}`, "r");
    expect(readFileSync(join(home, ".aegis/destructive-pending.json"), "utf8")).not.toContain(key);
    expect(listPending()[0].shown.length).toBeLessThanOrEqual(300);
  });

  it("DH-407: the shield stops an agent running the approve command, and lets it be talked about", () => {
    const rules = loadShieldRules();
    const ctx = { cwd: "/home/u/project", home: "/home/u" };
    for (const c of ["aegis approve-destructive 1a2b3c4d", "/usr/local/bin/aegis approve-destructive 1a2b3c4d", "bun run /x/src/cli/index.ts approve-destructive 1a2b3c4d",
      "sudo aegis approve-destructive 1a2b3c4d", 'bash -c "aegis approve-destructive 1a2b3c4d"', "npx aegis approve-destructive 1a2b3c4d", "cd /tmp && aegis approve-destructive 1a2b3c4d", "echo $(aegis approve-destructive 1a2b3c4d)"]) {
      const r = bashFileVerdict(c, rules, ctx);
      expect(r.verdict).toBe("QUARANTINE");
      expect(r.rule_id).toBe("KAV-098");
    }
    for (const c of ['echo "ask the owner to run: aegis approve-destructive 1a2b3c4d"', "grep -rn approve-destructive docs/", "git commit -m 'docs: approve-destructive'"]) {
      expect(bashFileVerdict(c, rules, ctx).verdict).toBe("PASS");
    }
  });
});

// ─── §D5 shipped files ────────────────────────────────────────────────────────

describe("§D5 the rules files in the package are what the code uses", () => {
  it("DH-501: rules/shield-rules.json is the shield's built-in lists, written out", () => {
    const shipped = JSON.parse(readFileSync(new URL("../rules/shield-rules.json", import.meta.url), "utf-8"));
    delete shipped.description;
    expect(shipped).toEqual(defaultShieldRules());
  });

  it("DH-502: the installer looks for the rules inside the package", () => {
    const init = readFileSync(new URL("../src/cli/commands/init.ts", import.meta.url), "utf-8");
    const m = /import\.meta\.dir,\s*"((?:\.\.\/)+)rules\/destructive-rules\.json"/.exec(init);
    expect(m?.[1]).toBe("../../../");
    expect(existsSync(new URL("../rules/destructive-rules.json", import.meta.url))).toBe(true);
    expect(init).toContain("aegis check-destructive");
  });
});

// ─── §D6 limits ───────────────────────────────────────────────────────────────
// Each of these is a thing the gate does NOT see. They are tests so that the README's list
// of limits cannot drift from the code without a test changing.

describe("§D6 stated limits", () => {
  it("LIMIT: a removal target held in a variable", () => expect(kind(D("rm", "-rf", '"$BUILD_DIR"/'))).toBe("clear"));
  it("LIMIT: a removal of a system directory other than / or home", () => expect(kind(D("rm", "-rf", "/usr"))).toBe("clear"));
  it("LIMIT: a removal target that arrives through xargs", () => expect(kind(`echo / | xargs ${D("rm", "-rf")}`)).toBe("clear"));
  it("LIMIT: a statement inside a file the command names", () => expect(kind("psql -d app -f drop.sql")).toBe("clear"));
  it("LIMIT: other destructive commands that are not on the list", () => {
    for (const c of [D("find", "/", "-delete"), D("dd", "if=/dev/zero", "of=/dev/sda"), "git push --force origin main", sql("UPDATE users SET role = 1")]) expect(kind(c)).toBe("clear");
  });
  it("LIMIT: a search piped onward is judged, so a harmless one is stopped", () => expect(kind(`grep -rn "${D("DELETE", "FROM")}" src/ | head`)).toBe("match"));
  it("LIMIT: an approvals file written by any other means is accepted as an approval", () => {
    const SAVED = process.env.HOME;
    const home = mkdtempSync(join(tmpdir(), "destructive-forged-"));
    mkdirSync(join(home, ".aegis"), { recursive: true });
    process.env.HOME = home;
    try {
      const cmd = sql(DEL);
      const hash = hashCommand(cmd);
      writeFileSync(join(home, ".aegis/destructive-approvals.json"), JSON.stringify([{ code: hash.slice(0, 8), hash, approved_at: Date.now(), expires_at: Date.now() + 600_000 }]));
      expect(consumeApproval(cmd)).toBe(true);
    } finally { if (SAVED === undefined) delete process.env.HOME; else process.env.HOME = SAVED; }
  });
});
