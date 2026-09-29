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
./provision-aarch64-testbed.sh --no-deps                        # skip the guest apt step
./run-aarch64-testbed.sh <harness.sh> [payload-to-copy ...]     # per run
```

Three images, on purpose:

| image | what it is |
|---|---|
| `base.qcow2` | pristine download, never booted |
| `staged.qcow2` | base + the runner unit + guest test deps (clang, bpftool, libbpf-dev) |
| `test.qcow2` | a throwaway overlay on staged, **recreated by every run** |

Runs are therefore hermetic. A harness cannot leave state for the next one to find,
which is how a test starts passing for a reason nobody chose.

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
| `harness-egress-enforcement.sh` | **0 failures** (6 checks) | **1 failure** with attach neutered |

Both directions forced. On the pre-fix code the guest reports `execve` resolving to 59
(it is `pipe2` there), `execveat` to 322, and a syscall name table with **0 entries** —
so every audit line, receipt and operator prompt would have shown a bare number. That
empty table was predicted from the headers and is now measured.

### `harness-egress-enforcement.sh`

The load-bearing claim of the edge port: everything else in that layer is userspace, and
this is the part that is a kernel object and could therefore behave differently on another
architecture.

Hermetic — two TCP listeners on loopback, one port in the policy and one not. No internet,
no DNS, nothing external in the assertion path. It checks, in order: the prerequisites are
genuinely present; `_is_available()` is True; the BPF program loads and attaches; an
**allowed** destination still connects; a **denied** destination is refused; and after
cleanup the block is gone.

**Why the first two steps exist.** `cgroup-egress.py` degrades gracefully when clang,
bpftool or cgroup v2 are missing — it writes `UNAVAILABLE` and exits 0. That is correct in
production and fatal in a test: a guest without the tools would sail through a naive
harness while measuring nothing at all. The escape hatch is proven closed before any later
result is allowed to mean anything.

**Why it tests both directions.** A firewall that blocks everything passes a deny-test and
is still broken.

**Measured 2026-09-29, aarch64, kernel 6.12.107:** the BPF program loads and attaches
(`prog_id=42`), an allowed destination connects, **a denied destination is refused with
`PermissionError` — EPERM from the kernel, real enforcement on ARM** — and after cleanup
the same destination connects again, so the block does not outlive its session.

**Negative control**, because a harness that has only ever passed proves nothing: a build
with `_cgroup_attach` replaced by a silent `return True` was run through the same harness
and produced exactly one failure, on the deny check. The harness catches a firewall that
loads, reports success and enforces nothing — which is the shape of the defect this
workstream keeps finding.

**A harness bug this caught, worth recording.** The first version asserted that the denied
port would be *unreachable* after cleanup, reasoning the listeners were closed. They were
not: their accept threads still hold a reference, so `close()` never frees the port. The
correct outcome — connect succeeds, proving the block is gone — was scored as a failure.
The test was wrong, not the firewall. Forcing both directions is what surfaced it.

## Not yet measured

seccomp filter *enforcement*, `SCMP_ACT_NOTIFY` supervision, IPv6 egress, and the AppArmor
path jail (no AppArmor in this guest; the target OS is SELinux anyway). Those are the next
harnesses. Until one exists for a claim, the claim is unmeasured.
