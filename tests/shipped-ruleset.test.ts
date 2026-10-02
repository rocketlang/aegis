// SPDX-License-Identifier: AGPL-3.0-only
// The SHIPPED ruleset (rules/destructive-rules.json), held to both outcomes.
//
// Two of its patterns were narrowed on 2026-10-02 so that prose and a shell tool's flag
// form stop matching. A narrowed rule is only acceptable if it still refuses every way of
// reaching the statement, so those ways are listed here and each must be refused. The
// benign shapes are listed too, and each must pass. If a later edit to the rules file
// drops a form from the first list, this fails.
import { describe, it, expect } from "bun:test";
import { readFileSync } from "fs";
import { join } from "path";
import { destructiveVerdict, type DestructiveRules } from "../src/kavach/destructive-verdict";
import { runRedteam } from "../src/redteam/runner";
import { BENIGN_CORPUS } from "../src/redteam/benign-corpus";

const RULES = JSON.parse(readFileSync(join(import.meta.dir, "../rules/destructive-rules.json"), "utf-8")) as DestructiveRules;
const refused = (cmd: string) => destructiveVerdict(cmd, RULES).kind === "match";

const T = "TRUNCATE", D = "DROP", TB = "TABLE";

const MUST_REFUSE: string[] = [
  // bare, keyworded, quoted, qualified
  `psql -c "${T} users"`, `psql -c '${T} ${TB} users'`, `psql -c "${T} ONLY users"`,
  `psql -c "${T} users, orders CASCADE"`, `psql -c "${T} \\"Users\\""`, `psql -c '${T} "Users"'`,
  `psql -c "${T} public.users RESTART IDENTITY"`,
  // whitespace and case
  `psql -c "${T.toLowerCase()}\tusers"`, `psql <<EOF\n${T}\n  users\nEOF`, `psql -c "${T}   users"`,
  // names supplied by a variable or built in code
  `psql -c "${T} $TBL"`, `psql -c "${T} \${TBL}"`, `mysql -e '${T} \`t\`'`,
  `python3 -c 'cur.execute("${T} " + t)'`, `python3 -c "cur.execute('${T} %s' % t)"`,
  `node -e 'q(\`${T} \${t}\`)'`, `psql -c "${T} :\\"t\\""`, `sqlcmd -Q "${T} ${TB} #tmp"`,
  // a comment wedged in (closed by the normalizer)
  `psql -c "${T} -- c\n users"`, `psql -c "${T} /* c */ users"`,

  `psql -c "${D} ${TB} users"`, `psql -c '${D} ${TB} IF EXISTS users'`, `psql -c "${D} ${TB} \\"Users\\""`,
  `psql -c '${D} ${TB}"Users"'`, `psql -c "${D}\t${TB}\tusers"`, `psql <<EOF\n${D} ${TB}\n  users;\nEOF`,
  `psql -c "${D} ${TB} $T"`, `psql -c "${D} ${TB} public.users CASCADE"`, `mysql -e '${D} ${TB} \`t\`'`,
  `sqlcmd -Q "${D} ${TB} [dbo].[t]"`, `python3 -c 'cur.execute("${D} ${TB} " + t)'`, `python3 -c "x('${D} ${TB} %s' % t)"`,
  `psql -c "${D} ${TB} -- c\n users"`, `psql -c "${D} ${TB} /* c */ users"`, `psql -c "${D}  ${TB}   users"`,
  `psql -c "${D.toLowerCase()} ${TB.toLowerCase()} users"`,
];

const MUST_PASS: string[] = [
  `truncate -s 0 /var/log/app.log`,
  `truncate -s 100M sparse.img`,
  `sudo truncate  -s 0 x.log`,
  `cat > n.md <<EOF\nthe pixels truncate — the chip ellipsises\nEOF`,
  `cat > n.md <<EOF\nreset · ${D}/${T} · mkfs\nEOF`,
  `cat >> n.md <<EOF\nthe gate refuses ${D} ${TB} ... as text\nEOF`,
  `grep -rniE "${D.toLowerCase()} ${TB.toLowerCase()}|other" src`,
];

// What a pattern cannot tell apart, stated rather than hidden: a word after the keyword
// looks the same whether it is a table name or the next word of a sentence.
const STILL_REFUSED_THOUGH_BENIGN: string[] = [
  `cat > n.md <<EOF\n${T.toLowerCase()} ftruncate fsync umask\nEOF`,
  `cat > n.md <<EOF\n${D} ${TB} is a phrase in this note\nEOF`,
];

describe("shipped destructive ruleset", () => {
  it("refuses every way of reaching the two narrowed statements", () => {
    const missed = MUST_REFUSE.filter((c) => !refused(c));
    expect(missed).toEqual([]);
  });

  it("passes the shell tool's flag form and keyword-then-punctuation prose", () => {
    const blocked = MUST_PASS.filter((c) => refused(c));
    expect(blocked).toEqual([]);
  });

  it("still refuses a keyword followed by an ordinary word — a pattern cannot tell", () => {
    expect(STILL_REFUSED_THOUGH_BENIGN.filter((c) => !refused(c))).toEqual([]);
  });

  it("has no catchable gap and no over-block on the representative benign corpus", () => {
    const r = runRedteam(RULES, { precisionCorpus: BENIGN_CORPUS, precisionSource: "representative" } as any) as any;
    expect(r.catchableGaps).toEqual([]);
    expect(r.falsePositives).toEqual([]);
    expect(r.precision.falsePositives).toEqual([]);
  });
});
