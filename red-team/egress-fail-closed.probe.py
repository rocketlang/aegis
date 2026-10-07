#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# aegis red-team — EGRESS fails OPEN when the cgroup join fails (review finding, 2026-10-08).
#
# The kernel prepares an egress cgroup and attaches the BPF firewall, then the launcher
# (apply-seccomp.py) must JOIN the agent process into that cgroup before exec. Before the fix, if
# that join failed the launcher logged a warning and exec'd the agent anyway — an UNCONSTRAINED run
# that looked constrained (the review's "fails open"). The fix: fail CLOSED — refuse to exec on a
# join failure, unless the operator declared an unconstrained run (KAVACHOS_ALLOW_UNCONSTRAINED_EGRESS).
#
# This drives the REAL _join_egress_cgroup() from the published launcher source, with a bogus cgroup
# path so the join fails. No root, no BPF, no seccomp profile — hermetic. GAP = it proceeded (fail
# open). Exit 0 when the default refuses and the opt-out proceeds.
#
# Runs against repo source (public): src/kernel/apply-seccomp.py.
import importlib.util, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
APPLY = os.path.join(HERE, "..", "src", "kernel", "apply-seccomp.py")

spec = importlib.util.spec_from_file_location("applyseccomp_probe", APPLY)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)  # top-level sets up libseccomp bindings; main() is __main__-guarded

gaps = 0
def SAFE(id_, ok, detail):
    global gaps
    print(f"  [{'safe' if ok else 'GAP '}] {id_} — {detail}")
    if not ok: gaps += 1

BOGUS = "/nonexistent-cgroup/xyz"  # open(.../cgroup.procs,'w') will raise here

def run_join(cgroup, optout):
    """Call the real join; return 'exit:<code>' if it sys.exit'd, else 'proceeded'."""
    os.environ.pop("KAVACHOS_EGRESS_CGROUP", None)
    os.environ.pop("KAVACHOS_ALLOW_UNCONSTRAINED_EGRESS", None)
    if cgroup is not None:
        os.environ["KAVACHOS_EGRESS_CGROUP"] = cgroup
    if optout:
        os.environ["KAVACHOS_ALLOW_UNCONSTRAINED_EGRESS"] = "1"
    try:
        mod._join_egress_cgroup()
        return "proceeded"
    except SystemExit as e:
        return f"exit:{e.code}"

# 1) DEFAULT: the cgroup was meant to be joined, the join fails → refuse to exec (fail closed)
r = run_join(BOGUS, optout=False)
SAFE("default: a failed join refuses to exec", r.startswith("exit:") and r != "exit:0",
     f"join to a bad cgroup → {r} (the agent does NOT run unconstrained)")

# 2) OPT-OUT: an operator who declared --allow-unconstrained-egress proceeds, by choice
r = run_join(BOGUS, optout=True)
SAFE("opt-out: declared unconstrained run proceeds", r == "proceeded",
     f"join fails but KAVACHOS_ALLOW_UNCONSTRAINED_EGRESS=1 → {r} (deliberate, logged)")

# 3) CONTROL: no egress cgroup set at all → nothing to join, launcher proceeds normally
r = run_join(None, optout=False)
SAFE("control: no egress requested proceeds", r == "proceeded",
     f"no KAVACHOS_EGRESS_CGROUP → {r} (egress not in play; not a refusal)")

print(f"\n  egress-fail-closed: {gaps} gap(s)" + (" — a failed join refuses to exec ✓" if gaps == 0 else " (RED until fixed)"))
sys.exit(1 if gaps else 0)
