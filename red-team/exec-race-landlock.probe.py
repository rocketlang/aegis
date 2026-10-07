#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# aegis red-team — EXEC-RACE closure: Landlock exec confinement (review finding, 2026-10-08).
#
# The seccomp CONTINUE path cannot bind the executed binary (exec-race.probe.py proves that TOCTOU).
# The fix enforces the exec allowlist with LANDLOCK, checked by the kernel on the ACTUAL file —
# inherited across exec, irrevocable, immune to a pointer swap. This proves it: a child applies the
# real _apply_landlock_exec_confinement (allowlisting ONLY a temp copy), then tries to exec a
# NON-allowlisted binary — the kernel denies it (EACCES), while the allowlisted one still runs.
#
# SAFE on any host: Landlock restrict_self is PER-PROCESS; each attempt runs in a fork()ed child and
# confines only that child, never this session. GAP = the non-allowlisted binary runs anyway.
# Runs against repo source (public): src/kernel/apply-seccomp.py.
import importlib.util, os, sys, json, tempfile, errno, shutil, stat

HERE = os.path.dirname(os.path.abspath(__file__))
APPLY = os.path.join(HERE, "..", "src", "kernel", "apply-seccomp.py")
spec = importlib.util.spec_from_file_location("applyseccomp_ll_probe", APPLY)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

gaps = 0
def SAFE(id_, ok, detail):
    global gaps
    print(f"  [{'safe' if ok else 'GAP '}] {id_} — {detail}")
    if not ok: gaps += 1

# ALLOWED = our own copy of `true` (exits 0). DENIED = the real /usr/bin/true (also exits 0 if it
# runs) — NOT in the allowlist and NOT the agent command, so run(0) vs EACCES(42) is unambiguous.
src_true = shutil.which("true") or "/usr/bin/true"
d = tempfile.mkdtemp()
ALLOWED = os.path.join(d, "allowed-tool")
shutil.copy2(src_true, ALLOWED); os.chmod(ALLOWED, 0o755)
DENIED = src_true
json.dump({"agent_type": "test", "allow": [{"path": ALLOWED}]}, open(os.path.join(d, "al.json"), "w"))
AL = os.path.join(d, "al.json")

def attempt(target: str, confine: bool) -> int:
    sys.stdout.flush(); sys.stderr.flush()   # don't let a child re-flush our buffer
    pid = os.fork()
    if pid == 0:
        try:
            if confine:
                mod._EXEC_ALLOWLIST = mod.load_exec_allowlist(AL)
                mod._apply_landlock_exec_confinement(ALLOWED)   # agent command = the allowed copy
            os.execv(target, [target])
        except OSError as e:
            os._exit(42 if e.errno == errno.EACCES else 43)
        except BaseException:
            os._exit(45)
        os._exit(44)  # unreachable after execv
    _, st = os.waitpid(pid, 0)
    return os.WEXITSTATUS(st) if os.WIFEXITED(st) else -1

# availability: if the kernel lacks Landlock, say so rather than claim a pass
probe_fd = mod._libc.syscall(mod.ctypes.c_long(mod._NR_LANDLOCK_CREATE),
                             mod.ctypes.create_string_buffer(mod.struct.pack("<Q", mod.LANDLOCK_ACCESS_FS_EXECUTE), 8),
                             mod.ctypes.c_size_t(8), mod.ctypes.c_uint(0))
if probe_fd < 0:
    print(f"  BROKE — Landlock unavailable on this host (errno={mod.ctypes.get_errno()})"); sys.exit(3)
os.close(probe_fd)

SAFE("control: unconfined, a non-allowlisted binary runs", attempt(DENIED, False) == 0,
     "execv(real /usr/bin/true) unconfined → runs (exit 0) — the baseline")
SAFE("allowlisted binary still runs under confinement", attempt(ALLOWED, True) == 0,
     "execv(the allowlisted copy) under Landlock → runs (shared libs load via the runtime dir rules)")
r = attempt(DENIED, True)
SAFE("non-allowlisted binary is blocked by the kernel", r == 42,
     f"execv(non-allowlisted /usr/bin/true) under Landlock → {'EACCES' if r == 42 else 'exit ' + str(r)} "
     f"— a swapped-in / dropped binary cannot run; enforced on the real file, not a re-read pointer")

print(f"\n  exec-race-landlock: {gaps} gap(s)" + (" — the exec allowlist binds the real file (TOCTOU closed) ✓" if gaps == 0 else " (RED until fixed)"))
sys.exit(1 if gaps else 0)
