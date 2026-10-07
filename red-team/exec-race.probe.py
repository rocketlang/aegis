#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# aegis red-team — EXEC-CHECK RACE (TOCTOU) on the strict-exec allowlist (review finding, 2026-10-08).
#
# The supervisor allowlists execve by reading the path from the agent's memory (_read_procmem_str,
# arg0) and, on ALLOW, answers SECCOMP_USER_NOTIF_FLAG_CONTINUE — which makes the KERNEL RE-READ the
# path pointer and run whatever is there now. Between the supervisor's read (CHECK) and the kernel's
# re-read (USE), another thread of the agent can overwrite the pointer → a binary the supervisor
# never approved executes. This is the documented seccomp_unotify CONTINUE TOCTOU: the man page says
# CONTINUE "cannot be used to implement security policy" for pointer arguments.
#
# This probe proves the window deterministically against the REAL decision code (check_exec +
# load_exec_allowlist), modelling the agent's swap as two successive reads — the first the supervisor
# sees, the second the kernel re-reads on CONTINUE. It does NOT need to win a live race (that is
# inherently flaky and belongs on a disposable host). GAP = an un-allowlisted binary would run under
# an ALLOW verdict. Runs against repo source (public): src/kernel/apply-seccomp.py.
import importlib.util, os, sys, json, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
APPLY = os.path.join(HERE, "..", "src", "kernel", "apply-seccomp.py")
spec = importlib.util.spec_from_file_location("applyseccomp_exec_probe", APPLY)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)  # top-level: libseccomp bindings + _NR_EXECVE resolve; main() guarded

gaps = 0
def SAFE(id_, ok, detail):
    global gaps
    print(f"  [{'safe' if ok else 'GAP '}] {id_} — {detail}")
    if not ok: gaps += 1

ALLOWED = "/usr/bin/allowed-tool"
EVIL    = "/usr/bin/EVIL"

d = tempfile.mkdtemp()
alpath = os.path.join(d, "exec-allowlist.json")
json.dump({"agent_type": "test", "allow": [{"path": ALLOWED}]}, open(alpath, "w"))
mod._EXEC_ALLOWLIST = mod.load_exec_allowlist(alpath)

# 0) sanity: the allowlist works — EVIL is denied, ALLOWED is allowed (deny path is safe: EPERM)
mod._read_procmem_str = lambda pid, addr, max_len=512: EVIL
deny, _ = mod._auto_decide_exec(1234, mod._NR_EXECVE, (0xdead, 0, 0, 0, 0, 0), alpath)
SAFE("control: a non-allowlisted path is denied", deny is False, f"_auto_decide_exec('{EVIL}') → allow={deny} (deny = EPERM, the syscall never runs — safe)")
mod._read_procmem_str = lambda pid, addr, max_len=512: ALLOWED
allow, _ = mod._auto_decide_exec(1234, mod._NR_EXECVE, (0xdead, 0, 0, 0, 0, 0), alpath)
SAFE("control: the allowlisted path is allowed", allow is True, f"_auto_decide_exec('{ALLOWED}') → allow={allow}")

# 1) THE ATTACK — swap the pointer between the supervisor's read and the kernel's re-read.
# First read (what the supervisor CHECKS) = ALLOWED. Second read (what the kernel RE-READS on
# CONTINUE, after a racing thread overwrote the pointer) = EVIL.
seq = iter([ALLOWED, EVIL])
mod._read_procmem_str = lambda pid, addr, max_len=512: next(seq, EVIL)

approved, reason = mod._auto_decide_exec(1234, mod._NR_EXECVE, (0xdead, 0, 0, 0, 0, 0), alpath)   # supervisor's CHECK → reads ALLOWED
# On ALLOW the supervisor answers CONTINUE, so the kernel re-reads the pointer and runs the current value:
allow_uses_continue = (mod.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 1)   # the flag the ALLOW branch sends (apply-seccomp.py:518)
executed = mod._read_procmem_str(1234, 0xdead)  # the kernel's re-read → EVIL
executed_allowed = executed in mod._EXEC_ALLOWLIST["_paths"] or any(executed.startswith(p) for p in mod._EXEC_ALLOWLIST["_prefixes"])

# GAP: the supervisor APPROVED (based on ALLOWED), answered CONTINUE, and a NON-allowlisted binary ran.
toctou_open = (approved is True) and allow_uses_continue and (not executed_allowed)
SAFE("exec-check race (TOCTOU)", not toctou_open,
     f"supervisor approved '{ALLOWED}' and answered CONTINUE → kernel re-read and ran '{executed}', which is NOT allowlisted"
     if toctou_open else "the approved path binds what executes (no re-read window)")

print(f"\n  exec-race: {gaps} gap(s)" + (" — exec decision binds what runs ✓" if gaps == 0
      else " (RED — the ALLOW verdict does not bind the executed binary; closure is an off-CONTINUE / non-TOCTOU enforcement, proved on a disposable host)"))
sys.exit(1 if gaps else 0)
