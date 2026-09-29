#!/bin/sh
# Answers one question: does apply-seccomp.py resolve execve/execveat correctly HERE?
# On aarch64 the right answers are execve=221 and execveat=281. The old hardcoded
# x86_64 constants were 59 and 322 — and 59 is pipe2 on this architecture.
echo "arch:   $(uname -m)"
echo "kernel: $(uname -r)"
echo "libseccomp: $(ls /usr/lib/*/libseccomp.so.2 2>/dev/null | head -1)"
echo
python3 - <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("aps", "/hostshare/apply-seccomp.py")
m = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(m)
except SystemExit as e:
    print(f"FAIL: module refused to load (exit {e.code}) — see the FATAL line above")
    sys.exit(1)

fails = 0
def check(label, got, want):
    global fails
    ok = got == want
    print(f"  [{'ok  ' if ok else 'FAIL'}] {label}: got {got}, want {want}")
    if not ok: fails += 1

check("execve resolves to the aarch64 number",   m._NR_EXECVE,   221)
check("execveat resolves to the aarch64 number", m._NR_EXECVEAT, 281)
check("59 is NOT execve here (it is pipe2)",     m.syscall_name(59), "pipe2")
check("221 names execve",                        m.syscall_name(221), "execve")
check("281 names execveat",                      m.syscall_name(281), "execveat")
print(f"  [info] syscall name table entries: {len(m._NR_TO_NAME)}")
if not m._NR_TO_NAME:
    print("  [FAIL] name table is EMPTY"); fails += 1

print()
print("  what the OLD hardcoded constants would have done on this machine:")
print(f"    _NR_EXECVE = 59  → would have guarded {m.syscall_name(59)!r}, not execve")
print(f"    _NR_EXECVEAT = 322 → would have guarded {m.syscall_name(322)!r}")
print()
print(f"RESULT: {fails} failure(s)")
sys.exit(1 if fails else 0)
PY
