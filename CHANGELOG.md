# Changelog

All notable changes to AEGIS will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
