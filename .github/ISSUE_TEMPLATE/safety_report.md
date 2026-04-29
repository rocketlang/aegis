---
name: Safety / security report
about: KAVACH gate bypass, false negative, or trust violation
title: "[SAFETY] "
labels: safety, security
assignees: rocketlang
---

> **For critical vulnerabilities** — please email capt.anil.sharma@powerpbox.org with subject `[AEGIS SAFETY]` before opening a public issue. See [SECURITY.md](../../SECURITY.md).

**What happened?**
Describe the gate miss, bypass, or unexpected allow.

**Command or pattern that slipped through**
```
<paste the command>
```

**Expected KAVACH level**
L1 / L2 / L3 / L4 — and why.

**Actual behavior**
Did it ALLOW silently? Classify incorrectly? Crash? Timeout?

**AEGIS version**
Run `aegis --version` and paste here.

**Impact assessment**
Was any data lost or system modified as a result?

**Suggested fix (if known)**
Pattern addition to `destructive-rules.json`? New `LEVEL_RULES` entry in `gate.ts`?
