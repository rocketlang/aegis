# aarch64 test bed

Answers ARM questions with measurements instead of reasoning. Built 2026-09-29 because
the xshield edge port had no way to test anything, and a defect had already been found
that only misbehaves on ARM (`apply-seccomp.py` hardcoded the x86_64 `execve` number; on
the asm-generic table arm64 uses, that number is `pipe2`).

## Why a full VM

`qemu-user` and a docker `arm64` image both keep the **host x86 kernel**. seccomp filters
and cgroup BPF are kernel objects, so on either of those we would be testing x86
enforcement behind an ARM userspace and reporting it as an ARM result — the same
"measured the wrong thing and reported success" failure the bed exists to catch. A full
VM is slower and is the only honest option. There is no KVM for an arm64 guest on an x86
host, so this is pure TCG emulation.

## Use

```
./provision-aarch64-testbed.sh                                  # once; idempotent
./run-aarch64-testbed.sh <harness.sh> [payload-to-copy ...]     # per run
```

The harness runs as root in the guest, finds its payload in `/hostshare`, and its exit
code is the run's exit code. No login, no ssh, no guest network needed: a systemd oneshot
mounts a 9p share, runs the harness, records the exit code and powers off.

**A harness that produces no output is a FAILED run, not a passed one.** The launcher
treats a missing `console.log` as failure and prints the boot log, because "the check did
not run" scoring as green is the defect class this whole workstream keeps meeting.

## Guest

Debian 13 (trixie) nocloud arm64, kernel 6.12 — has `python3`, `libseccomp.so.2`, cgroup
v2 and the 9p modules already. Images live in `/var/lib/ankr-testbed/aarch64`, outside
any git tree; only these scripts are tracked.

## Measured so far (2026-09-29)

| harness | fixed code | pre-fix code |
|---|---|---|
| `harness-syscall-resolution.sh` | 0 failures | **6 failures** |

Both directions forced. On the pre-fix code the guest reports `execve` resolving to 59
(it is `pipe2` there), `execveat` to 322, and a syscall name table with **0 entries** —
so every audit line, receipt and operator prompt would have shown a bare number. That
empty table was predicted from the headers and is now measured.

## Not yet measured

seccomp filter *enforcement*, `SCMP_ACT_NOTIFY` supervision, cgroup BPF `connect4` egress,
and the AppArmor path jail (no AppArmor in this guest; the target OS is SELinux anyway).
Those are the next harnesses. Until one exists for a claim, the claim is unmeasured.
