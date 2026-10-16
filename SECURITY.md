# KAVACH Security & Trust

KAVACH is a security tool. Security tools require a higher trust standard than ordinary software.
This document tells you exactly what KAVACH does and does not do on your machine.

---

## What KAVACH can see

KAVACH sits as a PreToolUse hook in Claude Code. Before any Bash command executes, KAVACH
receives the full command string. It classifies it against destructive patterns.

**KAVACH sees every Bash command your agent tries to run.**

This is intentional — it is the mechanism. A gate that cannot see the command cannot block it.

---

## What KAVACH does with what it sees

| Action | Does KAVACH do this? |
|---|---|
| Stores commands in local SQLite | ✅ Yes — `~/.aegis/aegis.db` — your machine only |
| Sends commands to any remote server | ❌ No |
| Sends commands to AnkrClaw (notification) | Only the command string in the Telegram notification, sent to YOUR configured chat_id |
| Logs commands to files | Only `~/.aegis/` — local, under your control |
| Trains models on your commands | ❌ No |

---

## Outbound network calls — complete list

KAVACH makes exactly three types of outbound calls. All are opt-in or user-configured:

### 1. KAVACH Gate notification (user-configured)
When a destructive command is intercepted, KAVACH POSTs to:
```
POST http://localhost:4150/api/notify    ← your local AnkrClaw instance
```
This sends the command string and consequence text to **your configured Telegram or WhatsApp**.
The `notify_telegram_chat_id` and `ankrclaw_url` are set by you in `~/.aegis/config.json`.
No external server is involved unless you configure one.

### 2. Install stats beacon (opt-in only)
Only sent if you run `aegis init --send-stats`:
```
POST https://kavach.xshieldai.com/install
Body: { version, platform, arch, node, ts }   ← no commands, no paths, no credentials
```
Opt-in. Default is no network call. Run `aegis init` (without `--send-stats`) to confirm this.

### 3. Nothing else
There are no background daemons calling home. No heartbeat. No analytics SDKs.
`grep -r "fetch\|http" src/` to verify.

---

## How to verify this yourself

```bash
# Clone and read the source
git clone https://github.com/rocketlang/aegis
grep -rn "fetch(" aegis/src/           # all outbound calls — three locations
grep -rn "kavach.xshieldai.com" aegis/ # beacon URL — only in init.ts, only on --send-stats

# Run with network blocked (verify nothing calls home)
unshare -n aegis init                  # Linux: network namespace isolation
# If it errors on network → something unexpected is calling out. Report it.
```

---

## The rogue operator problem

You are right to ask: what if KAVACH's author goes rogue, inserts a backdoor, or is compelled
to by a legal order?

**AGPL-3.0 is the structural answer.** The license requires that any distributed version — including
modified versions run as a network service — must publish full source. A backdoor in a published
build would be visible in the diff between the published source and the repo.

**Reproducible builds** are the next layer. We publish SHA-256 hashes of each npm release.
Verify your installed version matches: `npm view @rocketlang/aegis dist.shasum`

**Fork rights.** You have the right under AGPL-3.0 to fork, audit, and run your own build.
A security-conscious team should do exactly this before deploying to production.

---

## What xShieldAI (the commercial layer) adds

xShieldAI Enterprise Edition adds multi-tenant dashboard, SSO, SIEM export, and managed hosting.
The core gate logic — the code that intercepts commands — is identical to the OSS build.
EE adds governance around the gate. It does not modify the gate's behaviour.

---

## Acknowledgments

**Andrey Lazarev** reviewed aegis independently in October 2026 and ran our tests on his own throwaway hosts.
Each finding below is fixed in a published package, and each fix is tracked, with its commit and the test that
judges it, at [ankr.in/xshield-self-audit.html#fixes](https://ankr.in/xshield-self-audit.html#fixes). The tests that
reproduce his findings are public under [`red-team/`](red-team/).

| Finding | Fixed in |
|---|---|
| Review point 1: the agent's own uid could approve its own destructive command | `@xshieldai/aegis` 2.9.0 · signing-key leg `@xshieldai/aegis-guard` 0.6.0 |
| Review point 4: an approval bound to a label, not to the act | `@xshieldai/aegis-guard` 0.6.0 |
| The Varuna listener accepted open, unauthenticated ingest | `@xshieldai/varuna` 0.2.0 |
| Nallasetu attestations used a shared secret (forgery, repudiation) | `@xshieldai/nallasetu` 0.2.0 |
| The egress firewall failed open when the cgroup join failed | `@xshieldai/agent-kernel` 2.2.0 |
| The strict-exec allowlist could be raced between check and run | `@xshieldai/agent-kernel` 2.3.0 (Landlock) |
| The uid-boundary test passed one check for the wrong reason (found on a throwaway host, 11 Oct) | `@xshieldai/aegis` 2.17.1 |
| The read-only agent's Falco ruleset did not compile, so its monitoring never started (clean-bench run, 16 Oct) | `@xshieldai/agent-kernel` 2.6.2; cause closed in 2.6.3 |
| A `*` prefix rule in the exec allowlist was matched as text, so `..` and symlinks escaped it (clean-bench run, 16 Oct) | `@xshieldai/agent-kernel` 2.6.2 |

## Reporting a security issue

Email: **captain@ankr.in**

Do not open a public GitHub issue for security vulnerabilities. We will respond within 48 hours.
