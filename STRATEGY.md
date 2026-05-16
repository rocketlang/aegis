# ANKR / @rocketlang — Strategy (one page)

**Status:** Locked 2026-05-16 evening, supersedes earlier ambiguous "open-core with broad EE" framing.

---

## The one paragraph

ANKR is **pre-revenue**. Founder is **frugal** and has **intermittent sale revenue** sufficient to **survive indefinitely without external capital**. This is **patient capital** by definition. The strategy that fits patient capital + pre-revenue + a 200+ service surface is **aggressive OSS extraction first, monetize via domain SaaS later** — not EE feature gating. EE exists only for operational leverage customers cannot self-host.

---

## Why this stance, not the alternatives

**Why not EE-feature-gating as primary revenue?**
Because there is no current revenue to protect. EE gating slows adoption to protect a future revenue stream that may never materialise *without* adoption. Pre-revenue companies that gate aggressively starve themselves. Pre-revenue companies that open aggressively buy lottery tickets on the adoption curve. With patient capital we can hold the tickets long enough for them to compound.

**Why not pure no-monetization OSS?**
Because eventual revenue matters. The domain applications (Mari8x AOS / Watch8X / ShipLLM for maritime; future ones for healthcare / finance / defense) are the path. Selling managed, branded, regulated, domain-integrated software to enterprises who don't want to self-host. The OSS substrate doesn't compete with those domain products — it amplifies their reach.

**Why now and not in 6 months?**
Three reasons. (1) The Fin Operator launch (2026-05-15) opened a category window — the trade press is framing "agent governance" as a fundable category. Shipping while the window is open is cheap; shipping in 6 months is into established competitors. (2) Patient capital means there's no quarterly pressure forcing the wait. (3) The boundary doc has been getting incrementally clearer all day; locking the strategy before the next campaign starts costs less than retro-fitting it later.

---

## The model

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                   │
│  OSS SUBSTRATE                                                    │
│  @rocketlang/*  (AGPL-3.0)                                        │
│  Governance primitives — aegis, kavachos, chitta-detect,          │
│  lakshmanrekha, hanumang-mandate, aegis-guard, aegis-suite,       │
│  + ~150 more over 2-3 years                                       │
│                                                                   │
│  Revenue: $0. Purpose: ADOPTION.                                  │
│                                                                   │
└──────────────────┬──────────────────────────────────────────────┘
                    │ consumes
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                                                                   │
│  DOMAIN SaaS                                                      │
│  xshieldai.com (live, $0 revenue today)                           │
│  Mari8x AOS / Watch8X / ShipLLM (maritime, building)              │
│  Future: healthcare / finance / defense (if pursued)              │
│                                                                   │
│  Revenue: target $$$ once adoption builds substrate trust.        │
│                                                                   │
└──────────────────┬──────────────────────────────────────────────┘
                    │ consumes (when ANKR runs the infra)
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                                                                   │
│  EE — NARROW OPERATIONAL LEVERAGE                                 │
│  @rocketlang/kavachos-ee  (BSL-1.1, private)                      │
│  ~5 items: hosted attestation registry, multi-tenant isolation,   │
│  cross-customer baselines, SOC2 packaging, maintained connectors  │
│                                                                   │
│  Revenue: $$ from customers who can't self-host. Not the          │
│  primary revenue path; bridge revenue only.                       │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘

TRADE SECRETS (never in any of the three layers)
ankrSLM internals · base weights · Layer-1 architecture · classified
```

---

## Pace + capacity

- **Extraction pace: 1-2 OSS packages per week, sustained.** Not bursts. Today's 5-publishes-in-2-hours was a sprint; the long game is steady.
- **Two-to-three year arc to harvest ~150 primitives** from the 500+ Verdaccio + 200+ services. Roughly the primitive-shaped third of the total surface.
- **Solo maintenance is OK until year 2.** By then, package count + adoption growth exceeds solo bandwidth. At that point: hire a maintainer / deprecate low-traction packages / recruit cohort co-maintainers. Don't pre-optimise; revisit in year 2.
- **Cohort model as multiplier.** The Mari8x AI Cohort (Saurabh + Bhargavi as founding, others later) is the substrate for eventual co-maintenance. Apprentices who use the OSS in their Track 2 work develop the muscle to maintain it.

---

## The honesty discipline (load-bearing)

1. **Verify before claim.** Check registries, codex, code before proposing extraction work. Today saved duplicate work 3× because of this discipline (see `[[feedback_check_registry_before_extraction]]`).
2. **Boundary doc + code change together.** Every new `@rocketlang/*` package = same-PR boundary doc update. No silent drift.
3. **README names Phase-1 limits explicitly.** Signature crypto deferred? Say so. ROE honor-system? Say so. No test suite for v0.1? Say so. Honest packages compound trust; over-claimed packages compound mistrust.
4. **Trade secrets stay off the table.** No "we could OSS this for adoption" cleverness with SLM internals. The trade secret rules are absolute.
5. **EE is operational leverage, never primitive gating.** When in doubt about EE-vs-OSS, default OSS. The §4 criteria in boundary doc enforce this.

---

## Risks we're accepting

1. **No revenue arrives for 18-36 months.** Patient capital is the input that lets us accept this. If runway tightens, EE bridge revenue becomes more attractive — boundary doc rebalances.
2. **A competitor self-hosts OSS + builds polished UX.** AGPL prevents closed-source modifications, doesn't prevent operational competition. The moat is domain knowledge + brand + relationships + implementation expertise, not the code itself. This is the right moat for a maritime captain founding a maritime AI company.
3. **Solo maintenance burnout at year 2.** Naming it now means we plan for it. Cohort co-maintainers, deprecation of low-traction packages, eventual paid maintainer hire — all options.
4. **Brand sprawl from 150 packages.** Mitigated by meta-packages (today's `@rocketlang/aegis-suite`), suite naming conventions, and a clean directory structure in github.com/rocketlang/aegis.

---

## What this strategy explicitly is NOT

- **Not anti-revenue** — revenue is the eventual goal, just not the immediate one.
- **Not anti-EE** — EE exists for genuine operational gaps. It's just narrower than I drafted in earlier boundary doc versions.
- **Not anti-discipline** — aggressive OSS *requires* more discipline, not less. Verify-before-claim, doc-and-code-together, honest READMEs, narrow trade-secret rules.
- **Not Mongo / Elastic** — those companies started open and tightened when adoption hit. We start open and stay open for the primitives; the operational layer (which Mongo/Elastic monetised via license tightening) we monetise via domain SaaS instead.

---

## Resolution path

This document is locked v1.0 as of 2026-05-16 late evening. Updates when:
- The strategy materially changes (e.g., revenue arrives early and changes EE incentives)
- Runway tightens and EE bridge revenue becomes attractive
- An external investor / partner changes the calculus

Every update bumps the version, dates the change, and explains the trigger. Like the boundary doc, strategy is the running contract not a snapshot.

---

*Companion docs: `OPEN-CORE-BOUNDARY.md` (the what) · `EXTRACTION-QUEUE.md` (the next list).*
