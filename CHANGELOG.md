# Changelog

All notable changes to AEGIS will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [2.23.0] — 2026-10-15

### Fixed — every session shared one envelope, and a revocation lasted only until a resume

- **No session had a root envelope of its own.** The session hook recorded the envelope in one file for the whole machine (`~/.aegis/ase_session_id`) and asked for a new one only while that file was missing. Once it existed, every later session reused that one envelope. **`aegis flow-start`**, a new SessionStart hook, gives each Claude Code session its own root envelope, requested naming the session's mandate (GTP-017/019), kept at `~/.aegis/flows/<session>.json`. The older hook and its budget check are unchanged.
- **A session start replaced a revoked mandate.** `ensureMandateForSession` issued a new mandate whenever the current one was not valid, revoked included. So resuming the session undid a person's revocation. A revoked or malformed mandate is now never replaced for the same session (GTP-022). An expired one is still renewed at session start, and a new session still gets its own.
- **A child agent started from the session's shell became a new root.** Its mandate was issued fresh: wider than its parent's, still valid after the parent's was revoked. A child naming a parent that did not exist was made a root as well. That was the route for laundering an action through another agent. Now `aegis flow-start` hands the flow to the session's later shell commands: it appends `export AEGIS_FLOW='<session>:<mandate id>'` to the file Claude Code names in `CLAUDE_ENV_FILE`. A session started with `AEGIS_FLOW` set is that flow's child:
  - its mandate is the parent's mask AND its own, for the parent's principal, and names its parent (GTP-020);
  - a mandate is valid only while every mandate above it is, so revoking the parent refuses the child's next call in enforce mode (GTP-022);
  - a parent that cannot be found issues nothing (GTP-021);
  - the child's root envelope is requested as a child of the parent's envelope.

  An agent that unsets `AEGIS_FLOW` leaves the flow and starts a new root, which is recorded. Containing that is the kernel launcher's job.
- All three were shown by a failing test before the fix.

### Added — flow receipts form a signed chain (gap 3, the part on this machine)

- Every flow receipt now names the one before it: `chain: {seq, prev}`, where `prev` is the SHA-256 of the previous receipt file. It is signed with that link in it, and listed in `~/.aegis/flow-receipts/chain.jsonl`. Sessions closing at the same moment take turns through a short lock, so the chain never forks. If the lock stays busy, the receipt is written unchained and says so; it never holds an agent up.
- **`aegis flow-receipts verify`** walks the chain: order, links, file hashes, the link inside each receipt, and signatures. It names each break (exit 0 holds, 1 broken). **`aegis flow-receipts head`** prints the newest link.
- **Publishing the head: `aegis flow-receipts anchor --key <file>`** sends the chain's head to Sigstore's public transparency log (Rekor), as one `hashedrekord` entry signed with a key of your own. `aegis flow-receipts keygen --out <file>` makes that key (ECDSA P-256, owner-only, refuses to overwrite) and prints the public half to publish. The command:
  - refuses a chain that does not verify, a key others can read, or a missing key;
  - checks that the log's reply holds our hash under our key before recording it;
  - never sends the same head twice;
  - with `--dry-run`, sends nothing.

  Once a head is published, `verify` also fails if the chain no longer holds it at its place. Every entry is permanent and public.
- **What this does not give:** the chain is kept and signed on this machine. Cutting off its end leaves a shorter chain that still verifies, back to the last published head. A key on this machine is as safe as the machine. The entry format was carried over from a sender tested only against a stand-in log; Sigstore's acceptance is shown by the first real anchor, and the command checks the reply either way.

## [2.22.0] — 2026-10-15

### Added — the end of a flow is checked against its mandate (GTP-025, P5)

- **`aegis flow-close`, a Claude Code Stop hook.** At the end of every turn it grades the agent's last message with show-me-the-receipts (0.5.0, MIT, now a dependency). It grades from the session record only: no command is run, and `receipts.config.json` is ignored here. It judges the grade against the flow's mandate and writes a signed flow receipt to `~/.aegis/flow-receipts/` (owner-only). The receipt holds the mandate, the flow's tool calls, refusals and subagents, the proof result, and hanumang's return-with-proof axis.
- **A mandate now says what proof it requires.** `required_return_proof` is `receipts` by default for new mandates (it was `none-declared`), or `receipts-strict`, or `none-declared`. Set it with `kavach.mandate_return_proof`.
- **Refusing is opt-in, as for mandates.** Only when both `enforcement.mode` and `kavach.mandate` are `"enforce"` is the agent sent back, once, when its last message has a FALSE or STALE claim or a bare "done". After that it is let go and the receipt says the flow is open. Otherwise the result is only recorded. A flow with no mandate is recorded open and never blocked. Any fault in the hook lets the agent stop.
- The hook is not wired by `aegis init`: add it under `"Stop"` in `~/.claude/settings.json`.
- Not yet: anchoring the flow receipt in a public log, and showing it on `/flows/:id`.

## [2.21.0] — 2026-10-15

Whole-flow guardrails, first three phases (governed-turn-protocol §19, GTP-017…024). Nothing new refuses unless you turn it on.

### Fixed — a child envelope could name a parent that does not exist

- **`POST /api/v1/aegis/session` with a `parent_session_id` that matched no envelope** issued the child with the whole mask it asked for (a request for `0xffff` got `65535`), because the narrowing by the parent was skipped when the parent was not found. It is now refused with 422 (GTP-021). A child whose parent exists is narrowed by it, as before.

### Added — every tool call is a recorded step of a flow

- **`aegis check-shield` records each decision** (allowed or stopped, and the rule) as a flow event in `~/.aegis/flow-events.db`, owner-only. One Claude Code session is one flow, one tool call one turn, and a subagent hangs under the tool call that spawned it. The tool's input, paths and reasons are never stored. `AEGIS_FLOW_EVENTS=off` turns it off. It costs a few milliseconds per call.
- **The public cockpit stream never serves an event that belongs to a flow.**
- **`/flows` and `/flows/:id`** (and `/api/flows`, `/api/flows/:id`) show the flows as trees. On a dashboard with a password set they need a login, like every page that is not public.
- ACC events take five optional fields (`flow_id`, `turn_id`, `parent_turn_id`, `mandate_id`, `session_ref`). The store adds the columns; existing events stay valid.

### Added — a mandate as the root of each flow (records only, unless you opt in)

- At a session's first tool call the shield issues a **mandate**: who authorised the flow (the first owner in the approvers file named by `AOS_APPROVERS_FILE`), a trust mask from the repository's remote, a 24-hour life. It is signed with this machine's Mudrika secret and kept under `~/.aegis/mandates/` (folder 700, files 600). It is never reissued inside the same session.
- Every later call is judged against it, and the verdict is recorded with the flow event.
- A root envelope (`POST /api/v1/aegis/session` with no parent) can name it as `mandate_id`; the answer says the mandate's status and the mask it would cap to.
- **`aegis mandate list | show <id> | revoke <id> [reason]`.** Revoking is a person's act: it writes into the aegis directory, which the shield keeps tool calls out of.

### Behaviour you must opt in to

- **Mandates refuse only when both `enforcement.mode` and `kavach.mandate` are `"enforce"`.** Then a call with no mandate is refused (GTP-017), and so is one whose mandate is revoked or expired (GTP-022). A root envelope without a valid mandate is refused, and one with a mandate is capped to its mask (GTP-019). Without `kavach.mandate`, a box in enforce mode behaves exactly as on 2.20.x. This is so an upgrade never starts refusing a box that has no approvers file.
- **Before you turn it on:** a session that runs past 24 hours is refused until a new session starts, because the mandate is not renewed mid-session. Read the masks with `aegis mandate list` first; a repository the box does not know gets the most conservative mask.

### Not in this release

- The session-start hook does not issue the mandate yet, so a root envelope requested at session start cannot name it.
- aegis mirrors the judging rule of `@xshieldai/flow` (0.1.3) rather than depending on it.

## [2.20.1] — 2026-10-14

The README, which is the npm page. No code changes.

- **The README now describes this package.** Its first heading names `@xshieldai/aegis`; the 2026-05-17 rename table lists the old names under the retired `@rocketlang/` scope without writing them as installable names; and five links to files the package does not ship (`MIGRATION.md`, `PROOF-STACK.md`, `DAILY-LOG.md` and two test files) now point at the repository on GitHub, so they no longer break on npm.
- **The release checks it.** `release.yml` now runs `scripts/check-readme.mjs`, the check the primitives' releases already ran, and refuses a README that does not match the package it ships in. The main package's release had never run it, which is how this README drifted.

## [2.20.0] — 2026-10-14

Plain Node can use the library. Nothing changes under Bun.

- **The five library entry points (`.`, `./lite`, `./sdk`, `./acc/bus`, `./acc/types`) import under plain Node.** Until 2.19.1 they were TypeScript, and two of them imported `bun:sqlite` at load time, so only Bun could import the package. The release now builds them for Node into `lib/`. Under Bun the `bun` export condition still points at the TypeScript source, exactly as before.
- **SQLite on both runtimes.** `src/core/sqlite.ts` opens `bun:sqlite` under Bun, unchanged, and `node:sqlite` under Node 22.5+, wrapped to keep Bun's conventions: bindings may be one array, true/false bind as 1/0, undefined binds as NULL, and `get()` with no row is `null`. The driver loads when a database is opened, so on Node older than 22.5 the library imports and only database use fails, with a message that says so.
- **The CLIs (`aegis`, `aegis-monitor`, `aegis-dashboard`, `kavachos`) still need Bun**, as their launchers say: they use Bun's server, process and file APIs throughout.
- Depends on the Node-importable primitives: hanumang-mandate 0.4.x, aegis-guard 0.6.2, chitta-detect 0.3.2, lakshmanrekha 0.4.2.
- Found while testing this release: aegis keeps `aegis.db` under `$HOME/.aegis` whatever `AEGIS_DIR` says (that variable moves only the ACC event store). A test that sets only `AEGIS_DIR` writes into the real database. Test under a scratch `HOME`.

## [2.19.1] — 2026-10-12

Our own review, the last items. Nothing here was reported from outside.

- **`@xshieldai/agent-kernel` left out two things its own code reaches for** (2.6.1 ships them):
  - `dns-proxy.py`, which the egress supervisor loads from beside itself. Without it the supervisor leaves name lookups denied, so an agent under egress enforcement from that package could resolve nothing. This is read from the code; we did not launch an agent under enforcement to watch it.
  - the AppArmor profile and its install script.
- **The launcher's warning about the path jail named `src/kernel/apparmor/install.sh`**, a path an installed package does not have. It now names the script beside the module that prints it, in this package and in agent-kernel alike.
- The AppArmor profile is written for a root home (`/root/.aegis/…`). On another account, edit the paths before loading it.
- New battery `red-team/kavachos-bundle-files.battery.sh` (5 cases; 5 gaps on agent-kernel 2.6.0). `@xshieldai/n8n-nodes` 1.4.1 ships its four icons.

## [2.19.0] — 2026-10-12

Our own review, continued. Nothing here was reported from outside.

### Fixed — under the proxy, certificate checking was switched off for the whole agent

- **`kavachos run` with `KAVACHOS_PROXY_URL` set gave the agent `NODE_TLS_REJECT_UNAUTHORIZED=0` and `PYTHONHTTPSVERIFY=0`**: no certificate checking to any host, to make one self-signed certificate acceptable. The agent is now handed the proxy's certificate as an extra trust root, and checking stays on.
- **The proxy's certificate and key were two fixed names in `/tmp`, reused if already there.** They are made fresh on every start under `<aegis home>/kernel/proxy/` (folder `700`, key `600`).
- **The proxy listened on every interface.** It listens on `127.0.0.1` unless `--host=` or `KAVACHOS_PROXY_HOST` is given.
- The certificate now names `localhost` and `127.0.0.1` (it named no host, so nothing could verify it) and is valid 30 days: restart the proxy at least that often.
- The AppArmor profile denies the agent the proxy's key file.
- A `kavachos run` line without `--` now says it will be refused from agent-kernel 3.0.
- The same code ships as `@xshieldai/agent-kernel` 2.6.0. New battery `red-team/kavachos-proxy-trust.battery.sh` (10 cases; 9 gaps on agent-kernel 2.5.0).

### Changed — the gate audit is no longer open to anyone (behaviour change)

- **`GET /api/v1/kavach/audit` answered without a login, even on a dashboard exposed with a password set.** It returns the text of every command that reached the gate, and commands carry paths, host names and sometimes credentials.
- On a dashboard with a password set it now needs a login session, or `Authorization: Bearer <token>` where the token is `dashboard.auth.api_token` in `~/.aegis/config.json` (24 characters or more; `openssl rand -hex 24`). The token opens this one route and nothing else. A shorter token is ignored, and the dashboard says so at start.
- **If you use the n8n audit node or the LangChain adapter's `audit()` against a dashboard with a password:** set `api_token` in the config and give the same value to the adapter (the n8n credential's "API Token"; `AEGIS_TOKEN` for the Python adapter). Both have always sent it; until now nothing read it.
- A dashboard on loopback with no password is unchanged: nothing there needs a session.
- The gate itself (`POST /api/v1/kavach/gate`), the budget state and the health probe stay open to adapters.
- `red-team/dashboard-login-check.battery.sh` grows to 56 cases (3 gaps on 2.18.1), `dashboard-http-behaviour.battery.sh` to 45.

## [2.18.1] — 2026-10-12

Our own review of the kernel launcher. Nothing here was reported from outside.

### Fixed — `kavachos run` read the agent's arguments as its own options

- **Every word starting with `--` was read as a kavachos option wherever it stood on the line**, and removed from what the agent received. The agent lost its own options (`kavachos run bun agent.ts --port 4900` handed it `4900`). And whoever supplied the agent's arguments could set kavachos's: `--dry-run` (nothing runs, exit 0), `--allow-unconstrained-egress`, `--needs=`, `--depth=`, `--session-id=`, and a trust mask when none was given.
- **A bare `--` now ends kavachos's options.** `kavachos run [options] -- <agent> [its arguments]`: everything after it is the agent's, word for word. A command word before `--` is refused (exit 2).
- A line without `--` is read the old way, so existing launch lines keep working; each option found after the agent's binary is named in a warning. A caller that passes on arguments it did not write must use `--`.
- A dry run also prints the command that would be launched and the choices it would be launched under.
- The same command ships in `@xshieldai/agent-kernel` 2.5.0. `@xshieldai/n8n-nodes` 1.3.0 uses `--` and refuses an older `kavachos`.
- New: `red-team/kavachos-run-args.battery.sh` (9 cases, dry runs only; 7 gaps on agent-kernel 2.4.0), `red-team/n8n-kavach-run.battery.sh` (5 cases; 5 gaps on n8n-nodes 1.2.0), `tests/kavachos-run-args.test.ts` (7).

## [2.18.0] — 2026-10-12

The dashboard moves to fastify 5. Our own review of the dependencies, not a report from outside.

### Changed — the web framework under the dashboard

- **fastify 4.29.1 → 5.12.5**, `@fastify/static` 7 → 10, `@fastify/cors` 9 → 11, `@fastify/formbody` 7 → 9. The fastify 4 line and its router carried 12 published advisories whose fixes exist only in the 5 line. We found none of them reachable in 2.17.2 as shipped (no custom not-found handler, no schema-driven content types, no proxy trust), but a dashboard that holds a login should not sit on a line that no longer receives fixes.
- **Node 20 or later is now required** (it was 18). fastify 5 does not run on Node 18. Bun is unaffected.
- Two lines of ours changed: the redirect to the login page used the argument order fastify 5 removed (with no change it answered 500 to every browser without a session), and the trailing-slash option moved to `routerOptions`.

### How it was checked

- New battery `red-team/dashboard-http-behaviour.battery.sh` (37 answers): where a refusal sends the browser, what a login sets and where it lands, what a logout clears, the type a static file is served with, what a climbing or malformed address gets, what an unreadable body gets. Written and green on fastify 4 first, then run on fastify 5.
- `red-team/dashboard-login-check.battery.sh` (53 cases) green on both.
- Every route the dashboard registers (102) was asked on fastify 4 and on fastify 5, reading routes with a session and writing routes without one: the status and content type are the same on all 102.

### One answer differs

- **A semicolon is no longer read as the start of a query.** `/demo;x=1` reached the public demo page on fastify 4; on fastify 5 it matches no route (404, or the login page when a password is set). No protected route is affected: `/api/status;x=.js` was refused before and is refused now.

### Known, not changed here

- `/metrics` answers 500 (`no such table: kernel_profiles`) on a home where the monitor has never run. It did so on 2.17.2 as well.

## [2.17.2] — 2026-10-11

A second pass over 2.17.1 by us, attacking our own code. Nothing here was reported from outside. Each item has a case in a battery that is red on the published 2.17.1.

### Fixed — a person could approve something other than what their screen showed

- **Characters a terminal acts on were printed to the approving person as they came.** A refused command could carry escape sequences that erase its own line and write another, hide text, or run it right to left; `aegis approve-destructive` printed them raw. What the person read need not have been the command. They are now written out (`\x1b`) where the command is stored and again where it is printed. The same for the rule text, which is the asker's own.
- **An approval was for the text of a command, not for where it ran.** `rm -rf ./build` approved for one folder went through once in any folder, and the person was not shown a folder at all. The gate now sends the folder the harness reports; the approval is for the command in that folder, and the list shows it. With no folder reported (an older gate) it is the text alone, as before, and the list says so.
- `red-team/approval-unseen.battery.sh` grows to 7 cases (2 new gaps on 2.17.1).

### Fixed — who may ask for a dated anchor, and whose anchor is sent

- **Any asker on the consume socket could have the authority sign a dated statement.** That is the socket every gate uses. The statement is true, but the first dated leaf in a public log switches that ledger to one leaf a day for good, and a leaf needs only the ledger key's signature to be taken as the ledger's own: whoever could ask could throw the switch, and nothing on the box showed who. A dated anchor is now given on the **approve socket** only (`approver-daemon --dated-anchor-on-consume` restores the old behaviour). An undated anchor is given where it was.
  - `aegis ledger-anchor --dated`, refused on the consume socket, asks the approve socket: `--anchor-socket`, `AEGIS_LEDGER_ANCHOR_SOCKET`, `AEGIS_APPROVER_APPROVE_SOCKET`, or `approve.sock` beside the consume socket. **The account that runs the daily anchor must be able to open the approve socket.** If it cannot, the run stops with exit 2 and sends nothing.
- **`aegis ledger-anchor` checked the anchor against the key the socket itself had just handed over.** The socket is found through the environment or a pointer file the gates' own account can write. Whatever answered there could have its own statement sent with the box's token and written into the receipts as today's leaf, while the real ledger got none that day; a missed day cannot be filled afterwards. With a ledger key pinned, what answers must hold that key, or nothing is sent (exit 2). With none pinned the command says it could not tell.
- **A gate name, a rule or a session id went into a signed row with any characters in it**, and from there into what `ledger-verify` prints, and so into mail and briefs. Each unseen character is now stored as `?`, by the authority and by the gate's own check of the answer. `ledger-verify --local` writes out what it quotes from the local file.
- `aegis ledger-pin` refuses a key file owned by the account `sudo` was run from (`--own-file` if that is right), and prints the owner.
- New battery: `red-team/ledger-anchor-asker.battery.sh` (7 cases; 5 gaps on 2.17.1). `tests/unseen-characters.test.ts` (6).

**Upgrade the authority and the gates together.** A 2.17.2 gate whose refusal carries an unseen character is told "not signed" by an older authority, aloud. An authority of 2.17.2 refuses a dated anchor to a `ledger-anchor` older than 2.17.2 that asks on the consume socket: the daily run then stops with exit 2. Upgrade the copy the daily run uses in the same step.

**What this does not give.**
- The folder is the one the harness reports to the gate. A command that changes folder inside itself (`cd /x && …`) is shown as written; read it.
- An approval is for a command's text and folder, not for what the files it names contain at the moment it runs. `bash cleanup.sh`, approved, runs whatever `cleanup.sh` holds by then.
- A dated anchor on the approve socket is for whoever can open that socket: the approver account, its group, and root.
- On a box that pins a key, the tests that run a throwaway authority are skipped under `bun test`; the batteries run them in a private mount namespace.

## [2.17.1] — 2026-10-11

### Fixed — an authority with no pinned key ran unchecked and said nothing

Reported by Andrey Lazarev on 11 October 2026 against 2.17.0. He is right on each point.

- **Nothing in the package pinned the ledger key.** The step was one sentence in the 2.16.3 notes, so an install with an authority and no `/etc/aegis/ledger-signing.pub` accepted any answer, marked the local row "unchecked", and said nothing. His probe (a socket of the agent's own answering "ok, 42") still passed quietly there.
  - **The gate now says so each time**: with a socket configured and no key pinned, stderr carries "this refusal's number was NOT CHECKED" and how to pin. `AEGIS_LEDGER_UNPINNED_QUIET=1` stops the line, not the row's "unchecked".
  - **`aegis ledger-pin --from <public key file>`**, as root, is the missing step. The key comes from the file the person names, never from the socket: the authority is only asked whether that is its key and whether it answers with receipts (2.16.3 or later). It refuses a key the authority does not own, an older authority, a key file its group or anyone can write, a link, and another key over an existing pin (`--replace`). `--unchecked` pins without asking, for a box where the authority is not running yet.
  - **The authority's log says at start** whether the pinned key is its own, is missing, or is another key.
  - **`docs/hardened-setup.md`**: the setup of the separate account, start to finish. It was written down nowhere, and three messages named `aegis init` for it, which does not do it. They now name the page.
- **`aegis ledger-verify` says which key it used**, and looks for the pinned key before the copy in the aegis home, which the gates' own account can write. A key the runner names (`AEGIS_LEDGER_PUBKEY`, `AEGIS_LEDGER_PUBKEY_FILE`) still comes first.
- **The uid-boundary test passed for the wrong reason.** `red-team/point1-uid-boundary.disposable.sh` set the socket folder to 750, so the agent's account never reached the sockets: the approve-socket check passed at the folder, and the consume check failed as a false gap. Now 711, with the approve check accepting only a permission refusal on a socket the agent can see. **Not run by us since the change**: it needs a disposable host.
- **`approver-daemon --consume-mode 660|666`.** The daemon set both sockets to 660 and left widening the consume socket to whoever provisioned the box. It is now the daemon's stated setting (default 660, unchanged). The approve socket is always 660.
- New battery: `red-team/ledger-unpinned.battery.sh` (12 cases; 5 gaps on 2.17.0).

### Fixed — a person could approve more than they were shown

Found by reading our own approval path after the review; not reported from outside. Both concern the one-time approval of a refused destructive command (`aegis approve-destructive <code>`), in every mode that has approvals.

- **A refused command was shown as its first 300 characters, and the approval covered all of it.** A command whose destructive part came after the 300th character was approved with that part unseen. Now 2,000 characters are shown, the list says when that is not the whole command (or when a secret was taken out of it), and such a command is **not approved** unless the person adds `--unseen-tail`, which says they read it where it was refused.
- **The approval code was 8 characters of the command's hash, and of two waiting commands with the same code the older was approved.** Making a second command share a code is about four thousand million hashes. An agent could have a destructive command refused, then a harmless one with the same code, and a person approving the code beside the harmless one approved the destructive one. Now a command whose code is held by another gets a longer code of its own, and a code held by two commands approves neither.
- New battery: `red-team/approval-unseen.battery.sh` (5 cases; 3 gaps on 2.17.0). The pair with one code is not computed there; the store is given the two rows a collision leaves. `tests/approval-shown-whole.test.ts` (6).

**Upgrade the authority too.** The approval checks are made where the store is: with a separate-account approver that is the daemon, so a 2.17.1 `approve-destructive` talking to an older daemon is not protected.

**What this does not give.**
- The rule a refusal "matched" is the asker's word: an agent that asks the authority directly can put any 120 characters there. It is printed beside the command; the command is what to read.
- `--unseen-tail` is a person's statement. Nothing checks that they read the rest.
- Line breaks in a command are shown as spaces.
- A gate that breaks while judging (the shield, by design) lets the call through and says so on stderr only; that leaves no row in the ledger.
- Where the agent runs as root, the pinned key is a file it can rewrite, as before.

## [2.17.0] — 2026-10-11

### Added — dated anchors: a quiet ledger and a dead authority no longer look the same in the public log

Andrey Lazarev's second finding against 2.16.2, listed as a limit in 2.16.3 and built here. An anchor said "this ledger stands at row N with hash H" and carried no time, so a ledger that had not grown added no leaf: from the log alone, a week with no refusals and an authority switched off a week ago were the same.

- **`aegis ledger-anchor --dated`** (or `AEGIS_ANCHOR_DATED=1`) asks the authority for a dated statement: "on this UTC day, this ledger stands at row N with hash H". One leaf a day, grown or not. The day is the authority's own clock; the asker says only whether, never which day, so nobody can have it sign for tomorrow or for yesterday. At most one leaf is sent for a day: a second run the same day sends nothing, even if the ledger has grown (the next day's leaf states it).
- **The first dated leaf in a log is the switch.** From that day on `aegis ledger-verify --anchor-log` expects one for every day and names the days that have none:
  - `SILENT SINCE <day>`, exit 1: no dated leaf since the last one, up to yesterday. As far as the log shows, the authority has not spoken since.
  - `UNVERIFIABLE for N day(s)`, exit 2: a past day with no leaf, after which the authority spoke again. `--anchor-known-holes <day,day>` names days a person has looked at; they are still printed.
  - `DATED IN THE FUTURE`, exit 1: a statement for a day that has not come.
  - `DAY FILLED IN LATE`, exit 1: a statement for a day earlier than a leaf already before it in the log; or, with `--anchor-policy`, a leaf whose earliest tree head cosigned by the policy's witnesses is from a later day than its own day or the day after.
  - `UNVERIFIABLE as to time`, exit 2: with `--anchor-policy`, a dated leaf for which the receipts hold no cosigned tree head showing it in the log.
- **A dated leaf must be a (row, day) the file can account for:** row N can have been the tail on day D only if row N was written by then and row N+1 not before it, by the rows' own signed times. Anything else is a state the file does not contain, as before.
- **Receipts keep the whole cosigned tree head** (the log's signature and each cosignature with its time), so that when a leaf reached the log can be checked again later on the witnesses' signatures. The log itself serves only its newest head. The receipt file is not trusted: the head in it is rebuilt and every signature checked.
- Undated anchors made before the switch verify as before, and `ledger-anchor` without `--dated` behaves as before.
- New battery: `red-team/ledger-quiet-or-dead.battery.sh`, real processes against a stand-in log whose witnesses' clock the probe sets (11 cases; 10 are gaps on 2.16.3). `tests/ledger-anchor-dated.test.ts` (14).

**Before the first dated leaf, install 2.17.0 wherever the ledger is verified.** A verifier of 2.16.3 or older knows only the undated form and reads a dated leaf as `TRUNCATION OR REWRITE`. The authority must be 2.17.0 too: asked for a dated anchor, an older one answers with an undated one, and `ledger-anchor --dated` then stops with exit 2 and sends nothing.

**What a dated leaf does not show.**
- That this box or this daemon was alive: only that the holder of the ledger key signed that day.
- A missed day, afterwards. The authority signs for today only, so a day lost to a log that could not be reached stays a hole for good.
- Anything to a reader who does not hold the ledger's tail (row number and hash): the leaf is a hash. Someone given the tail once can check each later quiet day alone.
- When a leaf reached the log, from the log alone. That rests on the receipts kept at submission; a dated leaf with no such receipt is dated on the key holder's word, and the check says so.
- An empty ledger still has nothing to anchor, dated or not.
- The log is checked here against a stand-in written from the protocol. No dated leaf has been sent to a public log as of this release.

Still open: the request limit on the authority's socket bounds one connection, not the number of connections.

## [2.16.3] — 2026-10-11

### Fixed — the dashboard's login check could be walked past

- **A protected dashboard address was served without a session if it ended in `.js`, `.css`, `.png` or `.ico`, and a query string counted as the end.** The session guard compared the whole request address with its public list, so `/api/status?x=.js` passed as a static file. A route parameter ending that way passed too. The guard now decides on the route the server matched (`src/dashboard/public-routes.ts`), which the guard and the handler cannot disagree about. Which routes are public is unchanged. **Upgrade if your dashboard can be reached by anyone you would not give the password.** A dashboard bound to 127.0.0.1 (the default) was reachable only from the same machine.
- **A public page with anything after it got the login page.** `/demo?utm_source=…` (a tracking tag added by a link shortener or a social network) and `/demo/` were not on the list. Both now reach the page.
- New battery: `red-team/dashboard-login-check.battery.sh` starts the dashboard with a password and asks without a session. 34 gaps on 2.16.2, none now.

### Fixed — the signed refusal ledger: an answer that was not the authority's was taken as signed

Reported by Andrey Lazarev on 11 October 2026 against 2.16.2, with a probe. Both of his findings are right.

- **A gate believed any reply that said "ok" and carried a number.** The gate finds the authority by a socket path (the environment, or the pointer file `ledger-socket` in the aegis home, which the agent's own account can write). A socket of the agent's own answering `{"ok":true,"value":{"seq":42}}` produced a local row reading `authority_seq: 42`, with no error and nothing on stderr, while the real ledger never saw the refusal: no gap in the signed ledger, no stall at the witness, no leaf in the public log. With the pointer file deleted, the local row carried no number and no reason.
  - **The authority now returns the signed row and a receipt**: its signature over the gate's own fresh nonce, the row's number and the row's hash.
  - **The gate checks both against a pinned public key**: `/etc/aegis/ledger-signing.pub` if it exists (nothing in the environment or the aegis home can replace it), else `AEGIS_LEDGER_PUBKEY` / `AEGIS_LEDGER_PUBKEY_FILE` from the environment the harness gives the gate. The copy in the aegis home is not read for this. An answer that does not verify is written as NOT signed and said on stderr; so is a refusal made with a key pinned and no socket configured. A verified row says `authority_check: "verified"`.
  - **With no key pinned the gate cannot check.** It accepts the answer as before and writes `authority_check: "unchecked"`, so the row never claims more than it has.
  - **`aegis ledger-verify --local <file>`** compares the gates' local copy with the signed ledger: a local row naming a number the ledger does not hold, or holds as another refusal, exits 1; so does a local row written after the ledger's first row with no number and no reason (`--local-since <time>` for a period when an operator had switched the authority off).
  - New battery: `red-team/ledger-fake-authority.battery.sh` (a real authority and four false ones: a bare number, a copied genuine answer, another key, no socket).
- **To turn the check on:** install the authority from 2.16.3 first, then pin its public key, for example `install -D -m 644 <store>/ledger-signing.pub /etc/aegis/ledger-signing.pub` as root. A gate with a pinned key refuses the answer of an authority older than 2.16.3, because that answer carries no signed row.
- **What this does not give.** Where the gate runs as root, or as the account that owns the key file, the pin is a file that account can rewrite. The local file is written by the gates' own account: a refusal removed from it as well leaves nothing to compare. A gate that refuses and never asks still leaves no row.

### Documented — a quiet ledger and a dead authority look the same in the public log

The anchor statement carries no time, so a ledger that has not grown adds no leaf. Someone who reads only the public log cannot tell a week with no refusals from an authority switched off a week ago; the stall alarm that tells them apart lives with the witness. This was not among the listed limits (pointed out by Andrey Lazarev). It is now, in `src/core/ledger-anchor.ts`. A dated statement, one leaf a day, would close it and is not built.

Still open: the request limit on the authority's socket bounds one connection, not the number of connections.

## [2.16.2] — 2026-10-10

### Fixed — two answers that said the wrong thing

Both were listed as open under 2.16.1.

- **`aegis ledger-verify --anchor-log` given the wrong `--source` no longer cries truncation without saying why.** An anchor commits to the ledger's name as well as its row and hash, and the log holds only a hash, so under a wrong name every genuine anchor looks like a state the file does not contain. Now, when NO anchor matches, the names in this box's own anchor receipts (`--receipts`, default `<aegis home>/ledger-anchors.jsonl`) are tried. A receipt is not believed: the anchors are recomputed under that name, and only a full match counts. If one matches, the answer is `UNVERIFIABLE under the name '…'` with the name to use, exit 2. If none does, it is still `TRUNCATION OR REWRITE`, exit 1, and the message now says that a wrong name would look the same. When some anchors match and others do not, nothing changes: that is a cut or rewritten ledger whatever the receipts say.
- **`aegis ledger-anchor` answers `COULD NOT ANCHOR`, exit 2, for a log that cannot be reached, is slow, or does not answer as the log it was named as.** It said `BROKE`, exit 3. Nothing is wrong on this side in those cases, and the command can be run again without sending a second leaf.

Still open: the request limit on the authority's socket bounds one connection, not the number of connections.

## [2.16.1] — 2026-10-10

### Fixed — three faults found by running the package the way a user gets it, and by breaking things under it

All three came out of one afternoon's trial (10 October 2026): the published 2.16.0 was installed from npm into an empty folder and driven with throwaway daemons, a filling disk, a misbehaving log and a hostile local asker.

- **The 2.16.0 dashboard did not start from an npm install.** `package.json` still asked for `@xshieldai/aegis-guard ^0.4.0`. The repository maps that name to its own folder (0.6.0), so every test and CI run used 0.6.0, while npm installed 0.4.0, which lacks two functions the dashboard's demo route began using in 2.16.0: `SyntaxError: Export named 'verifyActionApprovalToken' not found`. The range is now `^0.6.0`. **2.16.0's dashboard is broken for anyone who installed it from npm; 2.15.0 and earlier loaded.**
- **Underneath that, and older:** every npm install of aegis up to 2.16.0 ran aegis-guard 0.4.0. The protections added in 0.5.0 and 0.6.0 (minting an approval is an authority action; an approval is bound to one action) were in the repository and on the registry, and not in what an aegis install pulled in.
- **A full disk left half a row in the signed ledger.** The asker was told the refusal had not been recorded, which was true. The fragment stayed, the next row was written onto the same line, and so a refusal that HAD been acknowledged could not be read and `ledger-verify` reported UNVERIFIABLE from then on. Three runs of three. A row is now written whole or not at all (`appendWholeLine`: the file's length is noted first and the file is cut back to it if the write fails). If even that fails the error says so, and the next row starts on a new line. A partial last line left by an older version is not removed (the authority removes nothing from this file); the next row is no longer glued to it, and such a ledger still reads UNVERIFIABLE, as it should.
- **The authority kept an unfinished request without limit.** 69 MB sent with no newline took the daemon from 55 MB to 125 MB, and the memory did not come back. A request is now refused past 64 KB and the connection closed; a connection that says nothing is closed after 10 seconds (`AEGIS_APPROVER_IDLE_MS`).

### Upgrading from an npm install

With aegis-guard 0.6.0 the dashboard **refuses to start unless it is told it is the minting authority**: set `AEGIS_MINT_AUTHORITY=1` for the dashboard process (and only for it). The refusal names the setting. This is 0.6.0's design, and it reaches npm installs of aegis for the first time with this release.

### Added — so these cannot come back unseen

- `tests/dependency-ranges.test.ts` fails when a declared `@xshieldai/*` range does not admit the version in `packages/`.
- `red-team/installed-package.battery.sh` packs the tree, installs the tarball into an empty folder with its dependencies from the registry, and starts the dashboard from it.
- `red-team/ledger-disk-full.battery.sh` runs a real authority on a 160 KB filesystem in a private mount namespace, fills it, and checks nothing but the unwritten row is lost. RED on 2.16.0 (five gaps), green here.
- `tests/ledger-hardening.test.ts` forces the half-written row, the fragment that cannot be removed, the oversized request, the silent connection and a request sent in two pieces.

**Still open:** `ledger-verify` given a `--source` name other than the authority's reports every genuine anchor as TRUNCATION OR REWRITE, and the message does not mention the name. `ledger-anchor` exits 3 for an unreachable log where 2 would be the honest code. The request limit bounds one connection; it does not bound the number of connections.

## [2.16.0] — 2026-10-10

### Added — the anchor now checks the log's cosigning witnesses

2.15.0 checked a tree head against the log's own key and said, in its output and here, that the witnesses were not checked. A log that showed one tree to us and another to somebody else would have passed. A witness cosigns a tree head only when it is consistent with every head it has seen, so a quorum of independent witnesses is what closes that.

- **Trust policies** in Sigsum's own policy-file format (`parsePolicy`, `src/core/ledger-anchor.ts`): logs and witnesses by key, groups (`all`, `any`, `k` of n, nested), one quorum line. Parsed strictly: an unknown line, a name used before it is defined, a name or key listed twice, a count the members cannot meet, or a missing quorum line is an error, never a guess.
- **Cosignatures verified** (`checkCosignatures`): each `cosignature` line of the tree head is checked against the named witness's key over `cosignature/v1`, the time, and the checkpoint the log signed. Lines by keys the policy does not name are ignored; a named witness whose signature does not verify is not counted; the same witness twice is one witness.
- **`aegis ledger-anchor --policy <name|file>`**: the anchor is not reported done until the inclusion proof is against a tree head cosigned by the policy's quorum. The receipt records which witnesses verified. Without the quorum: exit 1, no receipt; running it again once the quorum is there finishes the job without a second leaf.
- **`aegis ledger-verify --anchor-policy <name|file>`**: the tree head that was read must carry the quorum, or the result is UNVERIFIABLE (exit 2). A cut or rewritten ledger is still exit 1 when the quorum is also missing.
- **Two published policies ship unchanged** from the Sigsum project (`src/core/anchor-policies/`, fetched 10 October 2026) and can be given by name: `sigsum-generic-2025-1` (production logs; 2 of 3 witnesses) and `sigsum-test-2025-3` (test logs; 4 of 6). A policy that does not name the log's key is refused.

**Checked on 10 October 2026 against the real logs, read-only:** the current tree head of `seasalp` verified under `sigsum-generic-2025-1` with all three named witnesses, and the test log `barreleye` under `sigsum-test-2025-3` with all eight; no cosignature by a named witness failed to verify.

**Where the trust sits now, and what is still open:**
- The trust is in the policy's choice of witnesses. Two of three witnesses that agreed to lie together, with the log, would not be caught.
- Without `--policy` / `--anchor-policy` nothing above applies and the output says the cosignatures were not checked.
- A cosignature's time is reported in the code but no age limit is enforced: an old, valid cosignature on the head that was read still counts.
- Rows after the last anchor, a cut before the first anchor, and a partial read (`--anchor-from`) are as before.

## [2.15.0] — 2026-10-10

### Added — the signed refusal ledger, anchored in a public transparency log

A witness on the same box is a second copy. Whoever can cut the ledger's tail there can cut the witness's copy too. A public append-only log is somebody else's machine. This release puts a statement of where the ledger stands into a Sigsum log, signed with the ledger's own key, and teaches the verifier to read the log back.

- **The authority signs an anchor; it submits nothing.** New socket op `anchor` (`src/core/ledger-anchor.ts`, `LedgerAuthority.anchor()`): a Sigsum leaf whose message is the hash of `{"anchor":1,"source":S,"max_seq":N,"tail_hash":H}`. The asker supplies nothing, so the key signs no bytes of anybody else's choosing. The authority needs no network and holds no log token. An empty ledger has nothing to anchor and the op says so.
- **`aegis ledger-anchor --log <url> --log-key <hex> [--token-file <path>]`** asks for the anchor, rebuilds and checks it, submits it with the log's rate-limit token, and does not report "anchored" until an inclusion proof verifies against a tree head the log's own key signed. The proof is kept as a line in `ledger-anchors.jsonl`. The statement carries no time, so a ledger that has not grown yields the same leaf and nothing is sent again. `--dry-run` sends nothing. The token is read from a file and never printed. Exit 0 anchored / already anchored / empty; 1 the log refused or did not prove it; 2 could not ask; 3 broke.
- **`aegis ledger-verify <path> --anchor-log <url> --anchor-log-key <hex>`** works out the leaf each row of the file would have produced, reads the log for leaves under the ledger's key, and checks every genuine one is a state the file contains. One that it cannot produce is `TRUNCATION OR REWRITE`, exit 1. By default the whole log is read and its root rebuilt against the signed tree head, so the log cannot have left a leaf out; `--anchor-from <index>` reads part of it, faster, and says that omission is then not ruled out. No anchor found is UNVERIFIABLE (exit 2), not clean. The finding is combined with `--witness`: a break from either is exit 1.

**Rehearsed on 10 October 2026 against the public test log** (`test.sigsum.org/barreleye`) with a throwaway ledger: two anchors logged and proven, the same tail not sent twice, a file cut back below an anchor caught (exit 1), the whole log (234,228 leaves) read and its root rebuilt in 18 seconds.

**Where the trust sits now, and what is still open:**
- **The log's cosigning witnesses are not checked.** The tree head is checked against the log's own key only. A log that shows different trees to different readers is not caught by this code.
- Rows added after the last anchor are not covered until the next one. A file cut back only to its last anchor reads clean, and there is a test that says so.
- A ledger cut back before its first anchor leaves nothing in the log to contradict it.
- A partial read (`--anchor-from`) cannot rule out a leaf the log did not show.
- On a box where the agent can read the ledger key, the agent can sign an anchor for a state that never existed and raise a false alarm. It cannot use an anchor to hide a cut.
- Nothing here runs the anchor on a schedule. That is the operator's to set up, as an account that can read the token.

## [2.14.1] — 2026-10-09

### Added — two things a one-box install needs

- **Pointer file for the ledger authority.** With neither `AEGIS_LEDGER_SOCKET` nor the approver's consume socket set, a gate reads the socket path from the first line of `ledger-socket` in the aegis home (`~/.aegis/ledger-socket`). An operator can switch every running session over, or back by deleting the file, without restarting them. Like the env var, it is writable by the gate's own uid: it says where to ask and proves nothing.
- **`aegis witness --host <addr>`** (or `AEGIS_WITNESS_HOST`) — bind address. Absent, it listens on every interface as before. On one box, `127.0.0.1` keeps it off the network.

- **`aegis ledger-verify` on a path that does not exist** now exits 2 (UNVERIFIABLE, "nothing was checked"). It used to print "OK — 0 row(s)", which read as clean.

A witness on the same host as the authority is a second copy, not a second trust domain.

## [2.14.0] — 2026-10-08

### Changed — the signed ledger and the witness are wired in, and two claims are corrected

2.10.0 and 2.11.0 shipped the signing functions, the verifier and the witness, but **nothing called them**: no gate signed a row, nothing sent a row to a witness, the witness kept its high-water-mark in memory only, and the running `aegis witness` had no route that could raise a truncation alarm. The entries below for those versions said more than the code did ("streams each signed refusal", "keeps its own append-only copy"). This release makes those sentences true.

- **One writer, off the agent's uid.** The separate-uid approver daemon is now also the ledger authority (`src/core/ledger-authority.ts`). It makes and holds the signing key in its own store, and it alone numbers, times, chains and signs each row into `refusals.signed.jsonl`. One process numbers the rows, so two gates refusing together cannot take the same number.
- **The gates ask; they do not sign.** With `AEGIS_LEDGER_SOCKET` (or the approver's consume socket) set, every recorded refusal is sent to the authority (new socket op `refusal`). The gate's own plain row stays as the copy its uid can read, and now carries `authority_seq`, or `authority_error` when the authority could not be reached. A refusal that could not be signed says so on stderr. The verdict never changes either way.
- **The witness keeps a copy.** `aegis witness` appends every accepted row to `rows-<source>.jsonl` and reads it back at start; a restart no longer forgets what it held.
- **A signed heartbeat that carries the tail.** The authority sends `{source, max_seq, tail_hash, ts}` signed (new `POST /heartbeat/<source>`). The authority ahead of the witness is a `gap` (a row that never arrived is not quiet); behind it is a `truncation`; a different tail is a `chain` alarm; a replayed heartbeat does not keep a source alive. Rows are sent in order and resent until held.
- **`aegis ledger-verify <path> --witness <url> --source <name>`** compares the file's last number with what the witness holds: a cut-off tail exits 1.
- **New `ledger-status` socket op** — row count, last number, public key, and what the witness is known to hold.

**Where the trust sits now, and what is still open:**
- The row's content is what the gate said. The authority attests order and time, not that the gate told the truth.
- **A gate that refuses and never asks leaves no row and no gap.** The heartbeat carries on. This is not closed.
- The boundary is the operating system's: it holds only when the daemon runs as an account the agent cannot use. On one uid the agent can read the key.
- A witness on the same host is a second copy, not a second trust domain. It is one machine and not attested.
- Not configured means not signed: with no socket set, behaviour is exactly as before and `ledger-verify` reads UNVERIFIABLE.

Tests: `tests/ledger-authority.test.ts` — a real gate refusal through a real authority and a real witness process; five refusals at once; authority unreachable; witness restart; on-box truncation; silence; heartbeat cases. Battery `red-team/ledger-authority-wired`. From the exchange with Shyan-Ming Perng (JieGou).

## [2.13.0] — 2026-10-08

### Added — control center shows integrity (concealment + attestation in one view)

The Agentic Control Center (`aegis-dashboard` → `/control-center`) gains an **Integrity** panel surfacing the session's new security state at a glance:

- **Refusal ledger** — tamper-evidence via the signed ledger (`whole · N rows` / a **gap/chain/signature** break = concealment detected / **unverifiable** when no authority key).
- **Off-box witness** — alarms it has raised (silence / gap / truncation / forgery), or "no witness configured".
- **Attestation** — whether an agent identity and a pinned baseline are provisioned.

Read-only, honest empty states (ACC-002). With `@xshieldai/aegis-suite` 0.3.0's one-shot CLI, this completes the "one install, one cockpit" shape — and every package stays standalone (the suite and cockpit are a convenience front door, never a runtime coupling).

## [2.12.0] — 2026-10-08

### Added — attestation: identify a malformed or impostor agent

Prove WHO an agent is and WHAT it is running, and refuse what doesn't match:

- **WHO** — the attestation is signed by the agent's own Ed25519 identity key (the Nallasetu model); a verifier holds only the public key and cannot be impersonated.
- **WHAT** — a deterministic **measurement** (`measureFiles`, sha256 over a sorted manifest of code+config files) compared to a pinned **baseline**. Tampered code, a swapped config, or a different build → a different digest → refused.
- **`aegis attest <path...> [--baseline <hex>]`** — measures a build and prints the digest to pin, or compares against a baseline and exits non-zero on a mismatch. `verifyAttestation` refuses on a bad identity, a measurement mismatch, or **no baseline at all** (unknown is refused, not trusted).
- **Honest ceiling:** a measurement is only as trustworthy as the thing that took it — self-measurement can lie, so the launcher must measure the agent's files before exec, and the real root of trust is hardware/remote attestation (TPM/measured boot). This ships the measurer + the boundary check; launcher-measured integration is the next rung. Red test `red-team/attestation` proves tampered/impostor/unpinned are all refused.

Credit: Andrey Lazarev (identity/attestation direction, point 1's "evidence about the governor") and the Nallasetu asymmetric-identity model.

## [2.11.0] — 2026-10-08

### Added — off-box witness (concealment rung 3)

Rung 2 makes an edited or deleted middle row detectable on-box, but it cannot catch **tail truncation** (chopping off the latest rows) or an agent that goes **silent** — the on-box record is the only record. The witness is an independent collector, meant to run in a trust domain the agent can't write as.

- **`aegis witness`** — receives the governor's signed, sequenced rows, keeps its own append-only copy + a per-source high-water-mark, and raises an **alarm** on: `gap` (a suppressed row), `chain`/`signature` (reorder/tamper/forgery), `stall` (a source silent past the heartbeat window — *silence is the alarm*), and `truncation` (an on-box ledger that now shows fewer rows than the witness holds). Holds only the authority **public** key — it verifies, never forges; refuses to start without it.
- **`sendToWitness`** (`src/core/witness-client.ts`) — the governor streams each signed refusal and a periodic heartbeat; fire-and-forget with a short timeout, because a dropped send surfaces as the witness's own `stall`, not a swallowed error.
- **Honest ceiling:** a fully compromised agent can stop sending — which trips `stall`, so going quiet is loud. The witness can't be made to accept a forged row or lose a row it holds; full non-equivocation needs the witness itself attested/replicated. Red test `red-team/witness-offbox` proves gap/silence/forgery/truncation all alarm.

Credit: Shyan-Ming Perng (JieGou).

## [2.10.0] — 2026-10-08

### Added — sequenced, signed, hash-chained refusal ledger (concealment rung 2)

A refusal row the agent itself can write is evidence against accidents, not against concealment (the point Shyan-Ming Perng of JieGou made in "The Log Only Keeps the Yes"). The refusal ledger can now be made tamper-evident:

- Each row carries a monotonic `seq`, the `prev_hash` of the previous row, and an Ed25519 `sig` by an authority key held **off the agent's uid** (`src/core/ledger-sign.ts`, `appendSignedRefusal`).
- **`aegis ledger-verify [path]`** reports the first break: a **sequence gap** (a suppressed refusal), a **chain break** or **bad signature** (an edited/forged row), or **UNVERIFIABLE** (an unsigned/legacy ledger — which never reads as "OK"). Exit `0` clean · `1` tamper/concealment · `2` unverifiable · `3` broke.
- **Honest limit:** this detects edits, deletions and forgeries of a row, but not **tail truncation** (removing the most recent rows); the verifier returns `maxSeq` so an off-box witness that knows the true high-water-mark catches that (rung 3). The signed path is opt-in (an authority key must be provisioned and new rows signed through it); the legacy best-effort `recordRefusal` stays, and `ledger-verify` reports it UNVERIFIABLE rather than clean.

Credit: Shyan-Ming Perng (JieGou), and Andrey Lazarev (point 1 — authority off the agent's uid), which this builds on.

## [2.9.0] — 2026-10-07

### Changed — destructive-gate approvals: separation by default (security, KAV-098)

Closes review finding "point 1" (self-approval) for the destructive gate. The one-time approval that lets a refused destructive command through is no longer a file the agent's own uid can write.

- **Separation is the default.** With no approver configured, the gate honours **no** same-account override at all — an agent cannot approve its own command on any box. The worst case is "you cannot override until an approver is set up," the safe failure.
- **Hardened mode** — a separate-uid approver daemon (`aegis approver-daemon`, run as a dedicated account) owns the store and signs over two unix sockets: a consume socket agents may ask on, and an approve socket only a person (in the approver group) can open. The gate asks the daemon, never the local file. In hardened mode, if the approver is unreachable the gate **refuses** (fail loud, ANU-004) — it never falls back to the writable file.
- **Insecure single-box mode** is the explicit opt-out: the old forgeable file override returns only when `AEGIS_ALLOW_INSECURE_LOCAL_APPROVAL` is set.

Breaking for anyone who relied on `aegis approve-destructive` on a single box with no flag: set up the approver, or set `AEGIS_ALLOW_INSECURE_LOCAL_APPROVAL=1`. Red tests: `red-team/point1-self-approval.probe.ts` (routing, any host) and `red-team/point1-uid-boundary.disposable.sh` (the uid boundary, disposable host). The aegis-guard signing-key leg (self-mint) is a separate, later increment.

## [2.8.0] — 2026-10-06

### Changed — dashboard posture (security)

The dashboard now binds **`127.0.0.1` (loopback) by default** instead of `0.0.0.0`, and **refuses to start when exposed without real authentication**.

- New `dashboard.host` (default `127.0.0.1`) — the dashboard is no longer reachable off the machine unless you set it explicitly.
- If `dashboard.host` is non-loopback, the server **refuses to start** unless `dashboard.auth.enabled` is `true` with a real password. You can no longer run it reachable-and-open.
- The shipped default password `changeme` is retired: the default config ships `dashboard.auth.password: ""`, and enabling auth with `""` or `"changeme"` refuses to start.
- Localhost stays **auth-optional** (local-dev convenience; it is not network-reachable).

Only the package default changed — an existing `~/.aegis/config.json` is untouched. Behind an nginx reverse proxy (e.g. `aegis.ankr.in`) nothing changes: nginx connects to loopback on the same host.

## [2.7.0] — 2026-10-06

`@xshieldai/aegis`. The dashboard and `aegis status` now start from a public install, and
the session-cookie secret is no longer a value that is public in the source.

### Fixed
- **`aegis status` and the dashboard server would not start from an npm install.** Both
  imported `isEE`/`eeStatus` from `ee/license` — the enterprise module, which is not in the
  package's shipped files — as a static value import, so each threw "Cannot find module
  ee/license" the moment it loaded. A shipped shim (`src/core/ee-gate.ts`) now provides
  these (deferring to `ee/license` when an enterprise build has it); the two value imports
  point at the shim.
- **The dashboard imported the four primitive packages by a monorepo-relative path**
  (`../../../packages/{chitta-detect,lakshmanrekha,hanumang-mandate,aegis-guard}`), which do
  not exist in a single-package install, so the server could not boot even after the first
  fix. They are now imported by name and declared as dependencies; `enforcement.ts` takes
  the signing functions from the `@xshieldai/aegis-guard` index rather than a deep
  `src/signing` path.

### Changed (AGPL-3.0)
- **The dashboard session-cookie secret, when `AEGIS_SESSION_SECRET` is unset, is now a
  per-install random value** kept at `~/.aegis/session-secret` (mode 600) instead of the
  fixed string `aegis-dashboard-session-v1` that was present in the public source. Where
  dashboard auth is on but no secret was set, a cookie could previously be forged from that
  constant; it no longer can. An explicit `AEGIS_SESSION_SECRET` still wins, and an
  unwritable `~/.aegis` falls back to a per-process random secret, never the constant.

### Added
- `@xshieldai/chitta-detect`, `@xshieldai/lakshmanrekha`, `@xshieldai/hanumang-mandate`,
  `@xshieldai/aegis-guard` as dependencies (the dashboard uses them).

### Not changed (posture — unchanged here by intent)
- Dashboard auth is still off by default, the shipped password is still `changeme`, and the
  server still binds `0.0.0.0`. These are deployment choices, documented, not altered by
  this release.

## [2.6.0] — 2026-10-05

`@xshieldai/aegis`. The budget and spawn hooks (`aegis check-budget`, `aegis check-spawn`).
Checks that were written but did not run in a harness now run: read "Changed".

### Changed (AGPL-3.0)
- **Both hooks learn the session from the hook's payload (rule KAV-100):** `session_id`,
  and `agent_id` for a subagent; then `CLAUDE_SESSION_ID`, `CLAUDE_CODE_SESSION_ID`, and
  the transcript's file name. They read only `CLAUDE_SESSION_ID` before, which a harness
  does not set, so the per-agent cap, the spawn limit, the stop request, the depth and the
  expiry checks all ran against a session called "unknown".
- **`check-spawn` reads its input from file descriptor 0.** It read the `/dev/stdin` path,
  which cannot be opened when stdin is a socket, so under a harness the delegation check
  was skipped. On a pipe it ran and, not knowing the session, refused every spawn in
  enforce mode.
- **The Level 0 valve check in `check-spawn` runs only when `kavach.perm_mask_levels` is
  `"live"`**, as Levels 0 and 1 of `check-destructive` already do. It ran unconditionally in
  the code and never in practice. Set the switch to have it.
- **In the default mode a spent week is warned about** (it was silent).
- **A hook that could not run its checks says so on stderr**, and so does one running on
  the default settings because `config.json` could not be read. Both still let the call
  through.
- `aegis init`: the hook script passes the payload to `check-budget`.

### Added
- `src/cli/hook-input.ts`: `readHookInput()`, `whoIsCalling()`. `configFileProblem()`.
- `tests/budget-spawn-hardening.test.ts`: 19 tests on a real socket. 1088 tests in the
  repository.
- README: "The budget and spawn hooks".

### Not covered, and pinned by tests
- The hooks do not count spawns or spend (the monitor does); a limit of 0 means no limit; a
  mode spelled any other way than `enforce` is `alert`; both hooks fail open.

## [2.5.0] — 2026-10-05

`@xshieldai/aegis`. The destructive-command gate (`aegis check-destructive`) and the
installer. **The override token is gone**: read "Changed" before upgrading.

### Changed (AGPL-3.0)
- **Nothing typed into a command overrides the destructive gate (rule KAV-098).** The token
  that did is no longer read, from the code or from a rules file, and no message prints one.
  A person approves one refused command with `aegis approve-destructive <code>`; the same
  command then goes through once, within ten minutes, and the use is recorded.
- **A comment is display-only when every line is a comment.** A command that began with a
  comment line used to pass whole.
- **Recursive removal of the root or the home directory is recognised from the command's
  structure (rule KAV-099):** any spelling of the flags, with `--no-preserve-root`, after
  `sudo`, inside `bash -c`.
- **Shipped patterns:** five gaps bounded (no pattern has an unbounded one); the compose
  rule names the subcommand and reads the volumes flag in its long form, inside combined
  flags, and for the hyphenated command; a version flag after `exec` is no longer a match.
  Keywords with quotes or backslashes spliced in are matched. `rules/destructive-rules.json`
  is version 1.3.0; a rules file already in `~/.aegis/` is left as it is.
- **Display-only now also covers `grep` and a commit or tag message**, when the command has
  no pipe, redirect, chain or substitution.
- **Input the gate cannot read is refused** (it was allowed), as is a command over 512,000
  characters.
- **`aegis init`:** finds the rules inside the package (it looked one folder too high and
  seeded nothing); wires `check-destructive` into the hook script it writes; leaves each
  gate's message on stderr, where the harness shows it to the agent; starts only commands
  that are on the PATH and no longer ends with an error when one is missing. It no longer
  seeds a `shield-rules.json`: the shield's lists are built in.
- `rules/shield-rules.json` is the shield's built-in lists, written out (it held the lists
  of 2.3).

### Added
- `aegis approve-destructive [code]`; `src/kavach/destructive-approval.ts`;
  `structuralMatch()`, `dequoteForMatch()`, `defaultShieldRules()`.
- The shield stops `approve-destructive` arriving as a tool call.
- `tests/destructive-hardening.test.ts`: 104 tests. 1069 tests in the repository.

### Not covered, and pinned by tests
- The gate reads the text of a command: a statement in a file, a target in a variable or
  from `xargs`, and destructive commands not on the list are not seen. An approvals file
  written by any other means is accepted as an approval.

## [2.4.1] — 2026-10-05

`@xshieldai/aegis`. The first published version of the 2.4 line; the code is that of 2.4.0.

### Fixed
- 2.4.0 was tagged and never published: the registry's front-end filter refused the publish
  request because the README, which travels in it as plain text, quoted one shell idiom
  literally. The README now describes it in words. Nothing else changed.

## [2.4.0] — 2026-10-05 (tagged, not published — see 2.4.1)

`@xshieldai/aegis`. The shield hook (`aegis check-shield`) stops more and stops less: read
"Changed" before upgrading, in particular if you keep a `~/.aegis/shield-rules.json`.

### Changed (AGPL-3.0)
- **Path rules match the resolved path, on whole segments (rule KAV-094).** `~`, relative
  paths, `/./`, `/../` and symlinks are resolved first. A rule is its segments, ending at
  the end of the path or at `/`; a rule ending in `/` is a folder and everything under it.
  `.env.example`, `docs/secrets-management.md`, `docs/.bashrc-explained.md` and a folder
  named `.profiles` are no longer stopped. **A rule in your own rules file that relied on
  substring matching must be rewritten**; the one legacy entry `/etc/cron` is still read as
  the cron files and folders.
- **Credential files are recognised by name, built in:** `.env` and its variants (not the
  `.example` / `.sample` / `.template` ones), ssh private keys, anything in `~/.ssh`,
  `~/.gnupg`, `~/.aws` that is not one of their public files, `credentials.*` / `secrets.*`
  data files, data files in a `secrets/` or `credentials/` folder, `.netrc`,
  `.git-credentials`, `.pgpass`, `.npmrc`, `.pypirc`, service-account keys.
- **The file rules read shell commands too (rule KAV-095).** A credential file whose content
  a command would show or copy, a persistence target it would write, a crontab it would
  install: stopped, as for the Read and Write tools. Ordinary uses are let through
  (`ssh -i`, `ssh-add`, `source .env`, `--env-file`, `chmod`, `cp .env.example .env`).
  `/etc/passwd` stays stopped for the Read tool and is not stopped in a shell command.
- **A network tool is the program that runs, wherever it stands:** `/usr/bin/curl`, `;curl`,
  `&&curl`, `$(curl …)`, `sudo curl`, `bash -c "curl …"`, after `then` or `do`. A program
  whose name only begins like one (`ncdu`) is no longer taken for it.
- **The shield's own files cannot be written through the tools it watches (rule KAV-096):**
  everything in `~/.aegis/`, and `~/.claude/settings.json` / `settings.local.json`. A rules
  file cannot switch this off, nor the built-in credential names.
- **Text is made comparable before it is matched (rule KAV-097):** full-width letters are
  folded and invisible characters removed. The override patterns accept "the", "prior",
  "earlier", "any", "all of the". Every built-in pattern is bounded, so no input makes one
  run for seconds. The bare word "jailbreak" is no longer a pattern.
- **Replies are read at any depth**, and in `tool_response` (a PostToolUse payload).
- **"Large read, then upload" can fire:** the size of a read is looked up (the hook passed 0).
- `MultiEdit` and `NotebookEdit` are covered. A rules file with a field of the wrong shape
  keeps the shipped value for that field.
- When the shield lets a call through unchecked (input that is not JSON, an internal
  error), it says so on stderr. It still fails open; the source no longer says otherwise.

### Added
- `src/shield/paths.ts`, `src/shield/bash-scan.ts`; `bashFileVerdict()`, `detectBashFiles()`,
  `isShieldOwnFile()`.
- `src/shield/hardening.test.ts`: 165 tests. 963 tests in the repository.
- README: "What the shield stops, and what it does not".
- Release workflows wait up to 15 minutes for the registry to list a new version (was 5).

### Not covered, and pinned by tests
- The shield reads the text of a call. A path or program in a variable, built at run time,
  expanded by a glob, or inside a script or an interpreter's own code is not seen. The lists
  are lists; the phrases are wording. It fails open.

## [aegis-suite 0.2.5] — 2026-10-05

`@xshieldai/aegis-suite`.

### Changed (AGPL-3.0)
- Depends on aegis-guard `^0.4.0` (was `^0.3.1`, which does not admit it). Some calls that
  passed are now refused and minting no longer makes a key; see its entry below.

## [aegis-guard 0.4.0] — 2026-10-05

`@xshieldai/aegis-guard`. Some calls that passed are now refused, and minting no longer
makes a key; read "Changed" and the README's "Upgrading from 0.3.x" before upgrading.

### Changed (AGPL-3.0)
- **Minting never makes a key; a verifier never makes its own (rule AEG-HG-2B-007).**
  `mintApprovalToken()` and `signApprovalJwt()` throw on a box with no private key.
  `ensureSigningKeypair()` throws on a box that holds a public key (file or
  `AEGIS_APPROVAL_PUBKEY_PEM`) and no private key, and writes nothing there. The authority
  calls `ensureSigningKeypair()` once, at boot.
- **Keys that disagree are not trusted.** The private key, the public file and the
  environment PEM must all be the same Ed25519 key, or every verification is refused with a
  reason. A change of the environment PEM is picked up without a restart.
- **`verifyApprovalToken()` checks types (rule AEG-HG-2B-008).** `expires_at` must be a
  number; `issued_at`, when present, a number not after `expires_at`; `status`, when
  present, exactly `approved`; `nonce`, when present, text; the expected service,
  capability and operation non-empty text. A token that is not text, or whose body is not a
  JSON object, is refused with `IrrNoApprovalError`. The signature segment must be exactly
  the 64 bytes in base64url.
- **`verifyScopedApprovalToken()`** refuses a scope field with no value, compares only the
  token's own fields, and refuses a scope that is not an object of fields.
- **`verifyAndConsumeNonce()`** needs a text nonce and a payload in date, and counts the
  nonce as consumed only when the store answers exactly `true`.
- **`checkIdempotency()` (rule AEG-HG-2B-009):** a duplicate is a safe no-op only when both
  fingerprints are present and equal. Without a stored fingerprint it is `safeNoOp: false`
  with the new field `comparable: false` and a `lock.idempotency.unverifiable` receipt.
- **`buildIdempotencyFingerprint()`** sorts keys at every depth; keeps `NaN`, `±Infinity`,
  `bigint`, `Map` and `Set` distinct; throws a plain error for a payload that is not an
  object of fields or that contains itself. Flat payloads fingerprint as before.
- **`emitAegisSenseEvent()`** digests an `approval_token_ref` that is not already a digest,
  before the transport and the bus see it.
- **`meetsHgQualityRequirement()`** is false for a mask that is not a whole number of bits
  0–11 and for a group not in the table. `HG_REQUIRED_MASKS` is frozen.
- **`verifyEnvelope()` and `issueEnvelope()` (rule ASE-016)** read the answer strictly:
  verified only on exactly `true` for the session asked about; drift unless the answer says
  exactly `false` with an empty list; an answer with no session id or seal throws; http and
  https addresses only. The budget is read from the names the audit route uses.

### Added
- `tests/hardening.test.ts`: 107 tests. 177 tests in the package.
- README: "Keys — who signs, who verifies", "Upgrading from 0.3.x", "What this does not do".

### Fixed
- The quickstart and the dashboard demo minted a token with no `expires_at`. Both now set
  one; the quickstart uses a throwaway key in a temp directory.

### Not covered, and pinned by tests
- No upper limit on a token's life; no revocation list; the nonce call checks no signature;
  a key file swapped under a running process is not noticed until restart; the fingerprint
  is the payload encoded, not a hash; only the reference field of a SENSE event is digested.

## [aegis-suite 0.2.4] — 2026-10-05

`@xshieldai/aegis-suite`.

### Changed (AGPL-3.0)
- Depends on lakshmanrekha `^0.4.0` (was `^0.3.1`, which does not admit it). Verdicts and the
  refusal rate change for some inputs; see its entry below.

## [lakshmanrekha 0.4.0] — 2026-10-05

`@xshieldai/lakshmanrekha`. Verdicts and the refusal rate change for some inputs; read
"Changed" before upgrading.

### Changed (AGPL-3.0)
- **A reply is `refused` only on a first-person refusal (rule ASMAI-S-011).** "I can't",
  "I won't", "we are unable to", "I must decline", "I'm not comfortable", "that goes against
  my guidelines". A cautious word on its own is not a refusal, and neither is "I can't
  believe", "I won't lie" or "I cannot refuse". Curly apostrophes are read as straight ones.
- **A refusal followed by an answer is `partial`.** An answer is a list, a code block, an
  announced answer, or text after the refusing sentence that contains a value, a path, code
  or a quoted passage. A refusal followed by a reason or an offer stays `refused`.
- **A reply with no marker either way is `inconclusive`**, as is a reply that is not text.
- **The refusal rate is over replies (rule ASMAI-S-012).** An errored probe is not in the
  denominator. `partial` and `inconclusive` count as not refused. With no replies,
  `computeRefusalRate()` returns `NaN` (was `0`).
- **A body with no message in it is `errored`** (was classified as an empty reply).
- **`maskKey()` returns `****` for a key under 16 characters** (was 8 or fewer) or one that
  is not text.
- **`endpoint_url` must be `http:` or `https:`.**

### Added
- `summariseVerdicts()`: counts by verdict, `responded`, `total`, and `refusal_rate`
  (`null` when no probe got a reply).
- The API key is removed, as sent and URL-encoded, from `response_snippet`, `error` and the
  receipt summary before the text is cut to length (rule ASMAI-S-005).
- `tests/hardening.test.ts`: 49 tests. 109 tests in the package.

### Not covered, and pinned by tests
- The classifier reads English and matches wording, not meaning. A refusal quoted inside a
  complying answer gives `partial`; an answer with no marker words gives `inconclusive`.
- A key of fewer than six characters, or one the endpoint has altered, is not scrubbed.

## [aegis-suite 0.2.3] — 2026-10-05

`@xshieldai/aegis-suite`.

### Changed (AGPL-3.0)
- Depends on chitta-detect `^0.3.0` and hanumang-mandate `^0.3.0` (was `^0.2.0`, which does
  not admit them). Both change results for some inputs; see their entries below.

## [hanumang-mandate 0.3.0] — 2026-10-05

`@xshieldai/hanumang-mandate`. Results change for callers who pass incomplete or malformed
input; read "Changed" before upgrading.

### Changed (AGPL-3.0)
- **`verifyMudrika()` checks types and ranges, and never throws (rule HNG-S-012).** Text
  fields must be text; `ttl_seconds` must be a finite number above 0 and at most one year;
  `issued_at` may not be more than five minutes ahead of the clock; `trust_mask` must be a
  whole number; `pramana_chain` must be a list of text; `mudrika_version`, when present,
  must be a version 1; an expected agent id must be non-empty text; only the credential's
  own fields count. Anything else is `FAIL` with a reason.
- **Missing evidence is a FAIL on each axis (rule HNG-S-013).** `mandate_bounds` and
  `no_overreach` need their masks; `proportional_force` needs a mode of 1, 2 or 3; flags
  must be `true`, not text; an unknown axis scores 0. `mandate_bounds` without scope
  evidence is a WARN.
- **Masks are compared whole.** Bits above 31 are no longer dropped.
- **`computePostureScore()` grades all seven axes, each once.** An absent axis, a
  duplicate, an unknown axis and a score outside 0–100 each count as a violation. An
  entry's outcome is recomputed from its score. An empty list is grade F (was D).

### Added
- `signature_verified: false` on every `verifyMudrika()` result. The signature is still not
  checked; the field says so where the result is read.
- `axes_missing` and `axes_invalid` on the posture score; `MAX_TTL_SECONDS` and
  `CLOCK_SKEW_MS` exported.
- `tests/hardening.test.ts`: 52 tests. 98 tests in the package.

### Fixed
- The README's credential example used a fixed date and so returned `EXPIRED`, not the
  `PASS` it showed. It now issues the credential at the time it runs.

### Not covered, and pinned by tests
- The signature is not verified. The scorer grades the evidence it is given and does not
  verify it.

## [chitta-detect 0.3.0] — 2026-10-05

`@xshieldai/chitta-detect`. Verdicts change in this version; read "Changed" before upgrading.

### Added (AGPL-3.0)
- **Disguised attacks are matched.** Before matching, text is read as a person would see
  it: invisible characters, look-alike letters, accents, tags, markdown emphasis and line
  breaks between words, letters spelled out with a separator, digits for letters, base64,
  hex, HTML entities and URL-encoding are undone (`src/normalize.ts`, rule CG-014). The
  original text is never changed.
- `tests/evasion.test.ts`: 47 tests for disguised attacks, ordinary text, and the stated
  limits. 108 tests in the package.

### Changed
- **Ambiguous phrases are flagged, not withheld (rule CG-015).** "You can now …", "you now
  have access to …", "you are now …", "your role has changed" and the role-instruction
  phrases return `ADVISORY` on their own, where 0.2.x returned `INJECT_SUSPECT` for most of
  them. They return `INJECT_SUSPECT` when two of them sit in different places and are about
  different things, when the source is untrusted, or under `ELEVATED_SCRUTINY`.
  Unambiguous phrases decide as before. The single-detector scanners (`imperative.scan`,
  `fingerprint.scan`) report the same weights as before.
- A match that exists only because punctuation between words was collapsed
  (`ignore_previous`, `system-override`) is treated as ambiguous.
- A scan costs more: about 0.8 ms for a 2 KB document, up from about 0.02 ms.

### Fixed
- **CG-YK-006 is recorded** when `ELEVATED_SCRUTINY` is what promoted a verdict to
  `INJECT_SUSPECT`. The branch that recorded it was unreachable (CD-049b); the verdict was
  right and its reason was missing.

### Not caught, and pinned by tests
- The same intent in other words, other languages, a keyword split by a space, rot13 and
  reversed text.

## [packages, README and import fixes] — 2026-10-05

`@xshieldai/aegis-guard` 0.3.1 · `@xshieldai/aegis-suite` 0.2.2 · `@xshieldai/chitta-detect`
0.2.3 · `@xshieldai/hanumang-mandate` 0.2.3 · `@xshieldai/lakshmanrekha` 0.3.1 ·
`@xshieldai/n8n-nodes` 1.1.2

### Fixed (AGPL-3.0)
- **`@xshieldai/aegis-suite` can be imported.** `wireAllToBus()` imported its four
  primitives under the pre-rename package names, which the package does not depend on, so
  importing the suite failed. It now imports the `@xshieldai` packages it declares, and
  `AEGIS_SUITE_BUNDLED_PACKAGES` lists them by their current names.
- **aegis-suite depends on aegis-guard `^0.3.1` and lakshmanrekha `^0.3.1`** (was `^0.2.0`,
  which did not admit the current versions).
- **Each README names the package it ships in.** Titles, install lines and example imports
  said `@rocketlang/...` (or `@ankr/...` for n8n-nodes) and now say `@xshieldai/...`.
- README links to files that are in the repository and not in the npm package (quickstart
  examples, PROOF-STACK, aegis-guard's tests) now point at the repository and say so.
- Test counts in the READMEs match what the suites run: aegis-guard 70, lakshmanrekha 60.
- chitta-detect README: three stated example outputs corrected to what the package returns
  (confidence 0.95 and 0.65; `matched_patterns` includes `IDENTITY_CLAIM`). All 15 stated
  outputs were run against this version.
- n8n-nodes: the example workflow's node type and the "CLI not found" hint use the current
  package names.
- `homepage` links point at a branch that exists.

### Added
- The release workflow refuses a package whose README names another package or links to a
  file that is not in the tarball (`scripts/check-readme.mjs`), and refuses one that cannot
  be imported under its own name after being installed from its packed tarball.

## [python packages] — 2026-10-05

`xshieldai-langchain` 1.0.1 · `xshieldai-crewai` 1.0.1 (PyPI)

### Changed (AGPL-3.0)
- **Published by a release workflow, from a tag, with attestations**
  (`.github/workflows/release-pypi.yml`; tags `<project>-v<version>`). PyPI holds an
  attestation for every file, naming this repository and the commit.
- The Repository link on each PyPI page pointed at a branch that does not exist; it now
  points at `master`.
- No change to the code since 1.0.0 other than the version string. The workflow refuses
  a release whose `__version__` disagrees with `pyproject.toml`.

## [packages] — 2026-10-05

`@xshieldai/aegis-guard` 0.3.0 · `@xshieldai/aegis-suite` 0.2.1 · `@xshieldai/chitta-detect`
0.2.2 · `@xshieldai/hanumang-mandate` 0.2.2 · `@xshieldai/lakshmanrekha` 0.3.0 ·
`@xshieldai/n8n-nodes` 1.1.1

### Changed (AGPL-3.0)
- **All six are published by one release workflow, from a tag, with npm provenance**
  (`.github/workflows/release-package.yml`; tags `<package>-v<version>`). The workflow runs
  the package's tests before it publishes.
- **`npm publish` refuses outside a release workflow** (`scripts/publish-guard.mjs` in
  `prepublishOnly`); a dry run is allowed.
- aegis-suite, chitta-detect, hanumang-mandate and n8n-nodes: no change to the code since
  the previous version; the new version exists so that a provenance attestation does.
- aegis-guard 0.3.0 and lakshmanrekha 0.3.0 are first published to npm in this release.
- n8n-nodes: the LICENSE file its manifest lists is now in the package.

## [2.3.1] — 2026-10-05

`@xshieldai/aegis`. The 2.3.0 changes below, first published to npm in this version, plus how
the package is published.

### Changed (AGPL-3.0)
- **Published by the release workflow, from a tag, with npm provenance.** The registry holds an
  attestation naming this repository, the workflow file and the commit.
- **`npm publish` refuses outside the release workflow.** `prepublishOnly` runs
  `scripts/publish-guard.mjs`; a dry run is allowed.
- **A manual workflow run from a branch packs only.** Only a tag publishes, and the tag must
  equal the version in `package.json`.
- `bin` paths written in the form npm stores, so the manifest in the tarball equals the
  registry listing.

### Fixed
- The self-governance test harness spawned hooks from a literal path. It now uses the
  repository's own location, so the suite runs from any checkout.

### Reproducing the tarball
The package ships its source; there is no build. From a clean checkout of the tag, `npm pack`
gives a tarball whose shasum should equal the one the registry lists.

## [agent-kernel 2.1.1] — 2026-10-05

`@xshieldai/agent-kernel`. No change to what the kernel enforces since 2.1.0; this release is
about how the package is published.

### Changed (KAVACH-KERNEL — AGPL-3.0)
- **Published by the release workflow, from a tag, with npm provenance.** The registry holds an
  attestation naming this repository, the workflow file and the commit.
- **`npm publish` refuses outside the release workflow.** `prepublishOnly` runs
  `scripts/publish-guard.mjs` first; a dry run is allowed.
- **A manual workflow run from a branch builds and packs only.** Only a tag publishes.
- **The workflow refuses if the build changed a tracked file**, and prints the sha256 of each
  built file so a rebuild can be compared.
- `bin` path written as `bin/kavachos`, the form npm stores, so the manifest in the tarball
  equals the registry listing.

### Reproducing the build
From a clean checkout of the tag, with bun 1.3.9 and no `bun install`:
`cd packages/kavachos && bun run build && npm pack`. The tarball's shasum should equal the one
the registry lists.

## [2.3.0] — 2026-09-25 — the answerability release

> **Can you answer what your agents touched?** This release makes that one command.

### Added (AGPL-3.0)
- **`aegis touched [--since 24h|7d|<ISO>] [--json]`** — the answerability report: per principal,
  what was refused, what the staged invariants observed, what was published under which mandate,
  what tripwires saw, and whether the principal's receipt hash-chain still verifies. The ceiling
  is printed every run: host-computed evidence survives a lying agent, not a compromised host;
  an empty report means nothing *ledgered*, never "nothing happened".
- **`aegis rehearse-chain [--report <out.json>]`** — walks an eleven-step agent-incident chain
  (undeclared egress, credential read, read-then-exfiltrate, unmandated publish, hidden-payload
  SQL at a production target, intrusion tells, staged containment, identity-absent act) against
  the SAME pure decision functions the live hooks run. Strings and synthetic state only; every
  step carries a `live_stage` label so "alerted in shadow" is never dressed as "blocked";
  digest-sealed evidence pack.
- **`aegis quarterly-report [--since 90d] [--out] [--prev] [--dir]`** — the period report:
  answerability leads, then rehearsal, destructive-gate posture, shield/exfil faces, CI audit;
  with `--prev`, the diff opens on regressions first.
- **`aegis publish-mandate grant|list|revoke`** — an outward write (npm/gem/PyPI/docker/release)
  is a gated capability: named, time-bounded consent, and every publish attempt leaves a
  provenance record, permitted or refused. New anumati invariant ships observe-first.
- **`aegis ci-audit [--dir]`** — every publish step in `.github/workflows` must be declared in
  `.github/ankr-ci-declarations.json`; undeclared publishes fail; `uses:` actions are reported
  as a scoped null, never implied coverage.
- **`aegis tripwire-mode | tripwire-clear | tripwire-stage`** — staged containment with a sealed
  mode switch (a hand edit can never arm enforcement), human-only de-escalation with a recorded
  reason, and evidence-gated escalation that never reaches revoke without a verified capture.
- **`aegis redteam --face exfil`** — credential-read + exfil-sequence detectors driven through
  their pure decision cores, with authored scenarios and honest over-flag reporting.
- **Firewall Cockpit** — `/firewall` on the dashboard (behind login): containment mode with a
  typed named-consent flip, tripwire watchlist with clear-with-reason, publish mandates. Every
  button calls the same functions as the CLI.
- New anumati invariants ANU-I-007 (egress capability-over-target), ANU-I-008 (filesystem path
  class), ANU-I-009 (quarantined principal), ANU-I-010 (publish mandate), ANU-I-011 (act-class
  identity) — all enter in observe stage; promotion is a human decision on ledger evidence.

## [2.1.0] — 2026-09-22

### Fixed (KAVACH-KERNEL — AGPL-3.0)
- **Cgroup egress now constrains the agent.** The cgroup is prepared before the launch and the
  agent joins it before `exec`, so membership is inherited through `exec` and by anything it
  spawns. The previous ordering attached by pid after launch, which is the wrong handle: a
  short-lived agent has already exited, and on the notify path the real agent is a fork child
  created before the attach. `cgroup-egress.py --prepare` supervises by cgroup **membership**
  rather than by pid. A failed join is loud — an unconstrained run must never look constrained.
- **Exec allowlist is fail-closed.** The allowlist is parsed once before the fork and validated;
  if `strict_exec` was requested and it cannot be read, the agent does not start. A gate that
  cannot read its own rules refuses. Also removes a JSON parse from the `execve` hot path.
- **Syscall coverage** — `statx`, `rseq`, `prlimit64`, `vfork`, `getppid` added to the baseline.
  Each had a sibling already allowed, so denying them gated nothing and broke ordinary binaries
  (`sh: Cannot fork`, coreutils exiting 2).
- **Build** — `@aws-sdk/client-s3` is a dynamic, optional import and is now marked external
  rather than resolved; the bundle build had been failing on it.

### Added
- **`--needs=PORT,PORT`** — loopback ports an agent legitimately needs, so a broad loopback allow
  can be narrowed. Without it, a deny inside that range is readmitted by the broader rule and is
  therefore decorative; the compiler now says so rather than letting it look enforced.
- **Portable state roots** — `ANKR_CONFIG_DIR`, `ANKR_STATE_DIR`, `AEGIS_HOME`. Defaults unchanged.
  Relocating a root is deliberately **not silent**: these are the files the policy is derived from,
  so a non-default root is printed with every refusal, recorded in the compiled policy, and folded
  into its digest.

### Changed
- Egress goes from never-enforcing to enforcing. This is a real behaviour change for anyone whose
  agents were unconstrained while appearing governed, which is why this is a minor and not a patch.

## [2.0.0] — 2026-04-30

### Added (KAVACH-KERNEL — Phase 1, AGPL-3.0)
- **seccomp-bpf profile generator** — `trust_mask` + domain → libseccomp JSON profile; `src/kernel/seccomp-profile-generator.ts`
- **Falco 0.43.1 integration** — `falco-rule-generator.ts` (maritime/freight/general rules) + `falco-watcher.ts` (stdout → PRAMANA receipts + gate-valve escalation)
- **SCMP_ACT_NOTIFY supervisor** — kernel pauses blocked syscall → Telegram ALLOW/STOP → transparent resume or EPERM; `apply-seccomp.py` fork architecture
- **Cgroup BPF egress skeleton** — domain egress allowlist types wired; BPF program in Phase 1E
- **KavachOS CLI** — `kavachos run/generate/profile/audit/rules/init/version` — published `@rocketlang/kavachos@2.0.0`
- **Profile versioning** — SHA-256 hash + `profile_store.ts` in `aegis.db`; drift detection on session start

### Added (Framework Adapters — Phase 6A)
- **HTTP Gate API** — `POST /api/v1/kavach/gate`, `GET /api/v1/kavach/health`, `GET /api/v1/kavach/state`, `GET /api/v1/kavach/audit` — all unauthenticated for adapter-safe access
- **`@rocketlang/n8n-nodes-kavachos@1.1.0`** — 4 community nodes: KavachGate, KavachRun, KavachBudget, KavachAudit; `AegisApi` credential
- **`langchain-kavachos@1.0.0`** — `KavachGateCallback` (duck-typed, `on_tool_start` intercept); `AegisClient` stdlib-only; `KavachGateError` typed exception; zero mandatory deps

### Added (AGPL3/EE Split — Phase 8)
- **`ee/` directory** — BSL-1.1 EE modules: PRAMANA receipts, HanumanG EE, dual-control, Slack notifier, maritime signatures, multi-tenant
- **`ee/license.ts`** — `isEE()` reads `AEGIS_EE_LICENSE_KEY` env var; graceful degradation when absent
- **`@rocketlang/kavachos-ee@1.0.0`** — EE package with BSL-1.1 (converts to AGPL-3.0 after 4 years)
- **EE status** in `aegis status` output and dashboard health badge

### Changed
- Package description updated to reflect KavachOS scope
- README updated with AGPL3/EE two-layer table and roadmap

---

## [0.2.0] — 2026-04-29

### Added
- **`aegis init` auto-patch**: automatically wires `PreToolUse` hook and `statusLine` into `~/.claude/settings.json` on first run — no manual JSON editing required.
- **Bitmask-native context** (Phase 1c): `perm_mask`, `class_mask`, `violation_mask` as integers on every agent record. Bit-check O(1) gate runs before string-match enforcers.
- **Gate valve**: `narrowMask()` progressively clears permission bits on violations without quarantine. `aegis restore-mask` for human restoration.
- **KAVACH DAN gate** (Phase 1b/1c): Telegram/WhatsApp approval flow for dangerous actions (L1–L4). Dual-control for L4.
- **Forja protocol**: STATE, TRUST, SENSE, PROOF endpoints at `/api/v2/forja/` — 100% rule annotation coverage.
- **Agent policy schema docs**: `docs/agent-policy-schema.md` — full schema reference for `aegis-agent-policy-v1`.
- **Three example policies**: `examples/agents/example-worker.json`, `example-compliance-auditor.json`, `example-unknown-agent.json`.
- **`aegis cost`**: cost attribution tree with parent/child nesting and risk flags.
- **`aegis mask-log <id>`**: gate valve history per agent.
- **`aegis restore-mask <id>`**: human-only perm_mask restoration.

### Changed
- Config field `notify_via_ankrclaw` → `notify_via_webhook`, `ankrclaw_url` → `webhook_url` (old names still accepted via migration shim).
- Default `auto_restart_services` is now `[]` — configure your own services in `enforcement.auto_restart_services`.
- Default `registry_admin_key` is now `null`.
- Dashboard `/commands` page: replaced infrastructure-specific cards with generic AEGIS CLI, Quarantine Management, Agent Management, and KAVACH DAN Gate cards.
- Override token for destructive commands: `# AEGIS-DESTRUCTIVE-CONFIRMED` (was `# HUMAN-DESTRUCTIVE-CONFIRMED-ANKR`).

## [0.1.2] — 2026-04-29

### Added
- **Heartbeat detection** (AEG-T023): session log watcher now classifies each session as `attended` / `unattended` / `abandoned` based on time since last user input. Fires `heartbeat_timeout` alert and SSE event when a session goes abandoned. Respects `heartbeat.action` config (`alert` / `pause` / `kill`). Health endpoint now returns per-session heartbeat mode and idle time. Resumed sessions clear the abandoned state automatically.
- **Slack EE notification channel** (AEG-T042): new `kavach.slack_enabled` + `kavach.slack_webhook_url` config fields. When enabled, sends Block Kit messages to Slack for: budget/anomaly/heartbeat alerts (via enforcer) and KAVACH DAN gate interceptions (via gate). Slack is read-only — responses still go via primary channel (Telegram/WhatsApp). Set `KAVACH_SLACK_WEBHOOK_URL` env var or configure directly in `~/.aegis/config.json`.

### Changed
- Monitor health endpoint (`/health`) now includes `heartbeat.sessions[]` array showing all tracked sessions with `idle_ms` and `mode`.
- `onUserActivity` now clears abandoned state and emits `heartbeat_resumed` SSE event when a user returns to a stale session.

### Known limitations
- Cannot see claude.ai web usage (no public Anthropic API)
- Token-to-USD conversion for Max Plan is approximate (Anthropic doesn't publish exact pricing)
- Mobile device sessions (Termux) only visible if running on the same machine

---

## [0.1.0] — 2026-04-17

### Added
- Initial release
- Monitor daemon that watches Claude Code (`~/.claude/projects/`) and OpenAI Codex (`~/.codex/sessions/`) session logs
- CLI with `status`, `budget`, `kill`, `pause`, `resume`, `check-budget`, `check-spawn`, `init` commands
- Fastify-based dashboard at http://localhost:4850 with SSE real-time updates
- SQLite persistence (`~/.aegis/aegis.db`)
- Tiered warnings at 80% / 90% / 100% budget
- Max Plan mode (tracks messages + tokens per 5-hour rolling window)
- API Plan mode (tracks dollars per day/week/month)
- Alert-only default (does not auto-kill processes)
- PID exclusion list to prevent killing AEGIS itself or user's active session
- Claude Code `PreToolUse` hook integration for pre-flight budget enforcement
- Vendor-neutral JSONL parser (supports Claude Code + Codex + generic formats)
- Agent spawn governance (blocks Agent tool above configured limit)
- Anomaly detection (alerts on 5x spend rate spikes)

### Known limitations
- Cannot see claude.ai web usage (no public Anthropic API)
- Token-to-USD conversion for Max Plan is approximate (Anthropic doesn't publish exact pricing)
- Mobile device sessions (Termux) only visible if running on the same machine
- Heartbeat detection stub (does not yet auto-pause on user absence)
