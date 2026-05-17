# Migration — `@rocketlang/*` → `@xshieldai/*`

**Date:** 2026-05-17
**Reason:** brand consolidation under **xShieldAI Posture Suite** umbrella. Same code, same maintainers, same license (AGPL-3.0), new home.

---

## TL;DR — one-liner migrations

### npm

```bash
# AEGIS dashboard + Agentic Control Center
npm uninstall @rocketlang/aegis
npm install   @xshieldai/aegis

# Agent Kernel (formerly KavachOS)
npm uninstall @rocketlang/kavachos
npm install   @xshieldai/agent-kernel

# n8n community nodes
npm uninstall @rocketlang/n8n-nodes-kavachos
npm install   @xshieldai/n8n-nodes

# Five Locks SDK
npm uninstall @rocketlang/aegis-guard
npm install   @xshieldai/aegis-guard

# Memory poisoning detection
npm uninstall @rocketlang/chitta-detect
npm install   @xshieldai/chitta-detect

# LLM endpoint probe suite
npm uninstall @rocketlang/lakshmanrekha
npm install   @xshieldai/lakshmanrekha

# Mudrika verifier + posture scorer
npm uninstall @rocketlang/hanumang-mandate
npm install   @xshieldai/hanumang-mandate

# Meta-package (single-install bundle)
npm uninstall @rocketlang/aegis-suite
npm install   @xshieldai/aegis-suite
```

### PyPI

```bash
# LangChain integration
pip uninstall langchain-kavachos
pip install   xshieldai-langchain

# CrewAI integration
pip uninstall crewai-kavachos
pip install   xshieldai-crewai
```

---

## Full mapping

| Old name | New name | Version |
|---|---|---|
| `@rocketlang/aegis` | `@xshieldai/aegis` | 2.2.0 |
| `@rocketlang/kavachos` | `@xshieldai/agent-kernel` | 2.0.2 |
| `@rocketlang/n8n-nodes-kavachos` | `@xshieldai/n8n-nodes` | 1.1.0 |
| `@rocketlang/aegis-guard` | `@xshieldai/aegis-guard` | 0.2.0 |
| `@rocketlang/chitta-detect` | `@xshieldai/chitta-detect` | 0.2.0 |
| `@rocketlang/lakshmanrekha` | `@xshieldai/lakshmanrekha` | 0.2.0 |
| `@rocketlang/hanumang-mandate` | `@xshieldai/hanumang-mandate` | 0.2.0 |
| `@rocketlang/aegis-suite` | `@xshieldai/aegis-suite` | 0.2.0 |
| `langchain-kavachos` (PyPI) | `xshieldai-langchain` (PyPI) | 1.0.0 |
| `crewai-kavachos` (PyPI) | `xshieldai-crewai` (PyPI) | 1.0.0 |

Versions match exactly. Internal code is identical at the rename moment — purely a name/scope change.

---

## What changed under the hood

**npm-side:**
- New `@xshieldai/*` packages published at the same version numbers their `@rocketlang/*` predecessors held at the moment of rename.
- All `@rocketlang/*` packages are **marked deprecated** on npm (`npm deprecate`) with a redirect message pointing at the new name.
- Old packages still install for backward compatibility — existing CI pipelines, lockfiles, and frozen environments continue to work. `npm install` against `@rocketlang/*` shows a deprecation warning.
- `@xshieldai/aegis-suite@0.2.0` has its internal dependencies re-pointed to `@xshieldai/*` siblings (no `@rocketlang/*` deps in the new graph).

**Two cosmetic name changes within the suite (not just scope swap):**
- `@rocketlang/kavachos` → `@xshieldai/agent-kernel` (kept the `kavachos` binary name for CLI users — `npx kavachos run` still works as a command)
- `@rocketlang/n8n-nodes-kavachos` → `@xshieldai/n8n-nodes` (n8n node class names unchanged so existing n8n workflows continue to work)

**PyPI-side:**
- New `xshieldai-langchain` + `xshieldai-crewai` published at v1.0.0 (matching old version).
- Old `langchain-kavachos` + `crewai-kavachos` remain on PyPI under their last version (PyPI has no `npm deprecate` equivalent). Existing `pip install` against the old names still works.
- `xshieldai-crewai` depends on `xshieldai-langchain>=1.0.0` (same dependency relationship as the previous pair).
- Python import names changed: `from langchain_kavachos import X` → `from xshieldai_langchain import X` (same for crewai).

---

## What did NOT change

- License: still **AGPL-3.0-only** for every package
- Public API: identical — no method signatures, type shapes, or behavior changed at the rename moment
- Maintainers + governance: same
- Repository: still `github.com/rocketlang/aegis` (the GitHub org rename is a separate, longer-horizon decision)
- The Agentic Control Center shipped in v2.2.0: all routes (`/control-center`, `/agent/:id`, `/suite`, `/api/acc/*`) and all AOS panels unchanged
- Event bus contracts (`setEventBus()`, `wireAllToBus()`, `AccReceipt` shape): identical
- PRAMANA OSS Merkle ledger: still in `src/kernel/merkle-ledger.ts` of `@xshieldai/aegis`

---

## Why we did this

`@rocketlang` was the npm scope of historical accident — it grew traction (~2,700 monthly installs across npm + PyPI) before we'd decided the long-term brand umbrella. **xShieldAI** is the natural product umbrella: the live brand at `xshieldai.com`, the conceptual home for posture / governance / kernel-enforcement primitives. As of v0.6 of `OPEN-CORE-BOUNDARY.md`, package descriptions already named "xShieldAI Posture Suite" as the umbrella; this rename formalises that.

Internally, the trade-off was: rename today and reset SEO/discoverability on ~2,700 monthly installs, **or** wait until traction grew bigger (and the rename cost grew with it). Choosing now while the absolute number is small is the lower-pain option.

---

## Backwards compatibility & timeline

- **`@rocketlang/*`** packages stay installable forever — npm doesn't unpublish; we won't either.
- **Deprecation warnings** fire on every `npm install` against any `@rocketlang/*` package.
- No **planned removal date** for `@rocketlang/*` — they'll just stop receiving new versions.
- **CI / lockfile users:** your pinned versions keep working. Migrate at your next dep refresh.
- **PyPI users:** same — `langchain-kavachos` / `crewai-kavachos` stay installable. We'll add deprecation warnings in a follow-up patch (v1.0.1 of each).

---

## Questions

File an issue at https://github.com/rocketlang/aegis/issues. Migration help is high-priority triage.
