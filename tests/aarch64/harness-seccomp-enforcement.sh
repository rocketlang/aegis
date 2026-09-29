#!/bin/sh
# Does the seccomp layer actually ENFORCE on aarch64 — and does strict_exec really
# block, now that execve resolves per architecture?
#
# The second question is the point. A hardcoded x86_64 execve number would have made
# strict_exec watch pipe2 here and wave every exec through while reporting success.
# harness-syscall-resolution proves the NUMBER is right; this proves the GUARD bites.
echo "arch:   $(uname -m)"
echo "kernel: $(uname -r)"
echo

fails=0
for f in /usr/lib/aarch64-linux-gnu/libseccomp.so.2 /usr/bin/python3; do
  if [ -e "$f" ]; then echo "  [ok  ] prerequisite present: $f"
  else echo "  [FAIL] prerequisite MISSING: $f — this run would measure nothing"; fails=$((fails+1)); fi
done
[ "$fails" -eq 0 ] || { echo; echo "RESULT: $fails failure(s) — prerequisites"; exit 1; }

WORK=/tmp/seccomp-harness; rm -rf $WORK; mkdir -p $WORK

# A minimal profile: everything a tiny python needs, minus one syscall we will probe for.
# `chroot` is the probe — never used by the runtime under test, unmistakable when blocked.
# NOTE: sendmsg/recvmsg are not optional. The notify tier hands its listener fd to the
# supervisor over SCM_RIGHTS; omit them and _send_fd is refused, the supervisor never
# receives the fd, and the gate collapses (closed, but as a traceback). Keep the comment
# OUT of the string below — words inside it get parsed as syscall names.
python3 - > $WORK/profile.json <<'PY'
import json
allowed = """read write openat close fstat newfstatat lseek mmap munmap mprotect brk
rt_sigaction rt_sigprocmask rt_sigreturn ioctl pread64 pwrite64 readv writev access
pipe2 dup dup3 fcntl getdents64 getcwd chdir rename mkdirat rmdir unlinkat readlinkat
clock_gettime clock_nanosleep gettimeofday getpid getppid getuid geteuid getgid getegid
sysinfo uname exit exit_group wait4 kill futex set_tid_address set_robust_list prlimit64
getrandom statx faccessat faccessat2 epoll_create1 epoll_ctl epoll_pwait ppoll
socket connect sendto recvfrom setsockopt getsockopt bind listen accept4 getsockname
socketpair sendmsg recvmsg sendmmsg recvmmsg shutdown poll select pselect6
clone clone3 execve execveat vfork madvise mremap sigaltstack rseq membarrier
truncate ftruncate fsync umask nanosleep tgkill restart_syscall""".split()
print(json.dumps({
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_AARCH64"],
  "syscalls": [
     {"names": sorted(set(allowed) - {"execve", "execveat"}), "action": "SCMP_ACT_ALLOW"},
     # strict_exec is decided INSIDE the notify supervisor (KOS-047). A profile without
     # this tier loads, prints "strict_exec active", and enforces nothing — the first
     # version of this harness did exactly that and scored it as a pass.
     {"names": ["execve", "execveat"], "action": "SCMP_ACT_NOTIFY"},
  ],
}, indent=1))
PY

# ── 1. a syscall NOT on the allowlist is refused, and one ON it still works ──
cat > $WORK/probe.py <<'PY'
import ctypes, os, sys
libc = ctypes.CDLL("libc.so.6", use_errno=True)
# allowed path: getpid() must still work, or the filter is simply breaking everything
print(f"getpid={os.getpid()}", flush=True)
# denied path: chroot is not on the allowlist -> SCMP_ACT_ERRNO should give EPERM
rc = libc.chroot(b"/tmp")
err = ctypes.get_errno()
print(f"chroot rc={rc} errno={err} ({os.strerror(err) if err else 'none'})", flush=True)
sys.exit(0 if (rc != 0 and err == 1) else 7)   # 1 == EPERM
PY
timeout 120 python3 /hostshare/apply-seccomp.py $WORK/profile.json -- python3 $WORK/probe.py > $WORK/probe.out 2>&1
prc=$?
[ "$prc" -eq 124 ] && echo '        (syscall probe TIMED OUT after 120s)'
sed 's/^/        /' $WORK/probe.out
if grep -q "getpid=" $WORK/probe.out; then echo "  [ok  ] an ALLOWED syscall still works under the filter"
else echo "  [FAIL] the filter broke an allowed syscall — a firewall that blocks everything is not a firewall"; fails=$((fails+1)); fi
if [ "$prc" -eq 0 ]; then echo "  [ok  ] a DENIED syscall is refused with EPERM (SCMP_ACT_ERRNO enforcing)"
else echo "  [FAIL] denied syscall was NOT refused (probe exit=$prc)"; fails=$((fails+1)); fi

# ── 2. strict_exec: the guard the arm64 syscall bug would have silently disabled ──
printf '%s\n' '{"allow":[{"path":"/usr/bin/python3","note":"the one permitted binary"}]}' > $WORK/allowlist.json
export KAVACHOS_EXEC_ALLOWLIST=$WORK/allowlist.json

timeout 120 python3 /hostshare/apply-seccomp.py $WORK/profile.json -- /usr/bin/python3 -c 'print("ALLOWED-BINARY-RAN")' > $WORK/e1.out 2>&1
e1rc=$?; [ "$e1rc" -eq 124 ] && echo '        (allowlisted-exec probe TIMED OUT after 120s)'
if grep -q "ALLOWED-BINARY-RAN" $WORK/e1.out; then echo "  [ok  ] strict_exec permits an allowlisted binary"
elif [ "${e1rc:-0}" -eq 124 ]; then echo "  [FAIL] strict_exec HUNG on an allowlisted binary — supervisor never decided"; fails=$((fails+1))
else echo "  [FAIL] strict_exec blocked an ALLOWLISTED binary"; sed 's/^/        /' $WORK/e1.out; fails=$((fails+1)); fi

cat > $WORK/execprobe.py <<'PY2'
import subprocess, sys
# Distinguish the two outcomes that both look like "nonzero exit":
#   exec DENIED  -> execve itself fails, Python raises PermissionError/OSError, no output
#   child KILLED -> the binary DID run, then died under the filter
try:
    r = subprocess.run(["/usr/bin/id"], capture_output=True, timeout=20)
except PermissionError as e:
    print(f"EXEC-DENIED PermissionError {e}"); sys.exit(0)
except OSError as e:
    print(f"EXEC-DENIED OSError errno={e.errno}"); sys.exit(0)
out = (r.stdout or b"").decode(errors="replace").strip()
if out:
    print(f"EXEC-RAN rc={r.returncode} output={out[:60]!r}")
else:
    print(f"EXEC-INCONCLUSIVE rc={r.returncode} — no output, cannot tell denial from a filtered death")
sys.exit(1)
PY2
timeout 120 python3 /hostshare/apply-seccomp.py $WORK/profile.json -- /usr/bin/python3 $WORK/execprobe.py > $WORK/e2.out 2>&1
e2rc=$?; [ "$e2rc" -eq 124 ] && echo '        (exec probe TIMED OUT after 120s — the supervisor never decided)'
sed 's/^/        /' $WORK/e2.out
if grep -q "EXEC-DENIED" $WORK/e2.out; then
  echo "  [ok  ] strict_exec BLOCKS a non-allowlisted binary on aarch64 (execve itself refused)"
elif grep -q "EXEC-RAN" $WORK/e2.out; then
  echo "  [FAIL] a non-allowlisted binary EXECUTED — strict_exec is guarding nothing here"; fails=$((fails+1))
elif [ "${e2rc:-0}" -eq 124 ]; then
  echo "  [FAIL] exec probe HUNG — the supervisor did not recognise execve and waited for an approval that cannot come"; fails=$((fails+1))
else
  echo "  [FAIL] INCONCLUSIVE — cannot distinguish a denied exec from a child killed by the filter"; fails=$((fails+1))
fi

echo
echo "RESULT: $fails failure(s)"
exit $([ "$fails" -eq 0 ] && echo 0 || echo 1)
