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
| `harness-seccomp-enforcement.sh` | **0 failures** (6 checks) | **4 failures**, all timeouts (pre-fix build) |
| `harness-no-toolchain.sh` | **0 failures** (2 checks) | n/a — it *is* the control |
| `harness-prog-tag.sh` | **0 failures** (9 checks) | n/a — it measures a kernel property |
| `harness-prebuilt-no-clang.sh` | **0 failures** (5 checks) | tampered object → refused |
| `harness-tag-vs-bytes.sh` | **0 failures** (5 checks) | n/a — it settles a design question |

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

### `harness-seccomp-enforcement.sh`

Proves the filter refuses a syscall that is not on the allowlist while still permitting
one that is, and — the point — that **`strict_exec` actually blocks on aarch64**, which is
the guard the hardcoded-syscall bug would have silently disabled.

**Two harness bugs it caught before it caught anything else**, both kept here because the
shape recurs:

1. The first version put no `SCMP_ACT_NOTIFY` tier in the profile. `strict_exec` is
   decided *inside* the notify supervisor (KOS-047), so the profile loaded, printed
   `strict_exec active`, enforced nothing, and the harness scored it green — against both
   the fixed and the broken build. **A test that passes on the broken build is not
   testing what its name says.**
2. The exec probe originally read a non-zero exit as "blocked". A non-zero exit also
   means "the binary ran and then died under the filter". It now distinguishes
   `EXEC-DENIED` (execve itself refused, no output) from `EXEC-RAN` (output produced) and
   refuses to score an ambiguous result as either.

Every probe is bounded by `timeout 120`, and a timeout is its own named outcome.

**Negative control, measured 2026-09-29 on the pre-fix build:** 4 failures, every one a
timeout, launcher exit 1. The pre-fix code does **not** fail open here — it **hangs**,
because the supervisor's `nr in (_NR_EXECVE, _NR_EXECVEAT)` does not match (execve is 221
on this architecture, the constant said 59), so exec falls through to the human-approval
path that nobody can answer. The same run prints:

```
[kavachos:supervisor] GATED syscall=fadvise64 pid=511 approval=KOS-D8AA17AA
```

`fadvise64` is 221's name **on x86**. So an operator watching a hardened ARM device would
be asked to approve a syscall that is not the one being made. **Confidently wrong labels
are worse than missing ones** — and this is why the earlier description of the bug as
"lets every exec through" was wrong, and is corrected here: the mechanism is
hang-and-mislabel.

### `harness-no-toolchain.sh`

Answers whether the egress layer can run on a hardened production image with no compiler,
by taking `clang` away and asking. **Measured: it cannot.** `_is_available()` returns
False, and the layer disables itself by writing `UNAVAILABLE` and exiting 0 — quietly,
completely, and by design. Shipping to such an image needs a **precompiled BPF object**
rather than runtime compilation. That is a design consequence, not a bug.

### `harness-prog-tag.sh`

Asks whether a runtime receipt could carry a digest the **kernel** computed rather than
the supervisor's word for what it loaded — the load-bearing assumption under an
rc13-shaped design for runtime policy. In a TPM quote the PCR values come from hardware,
not from the software being attested; the runtime analogue would be the BPF program tag.

**Measured 2026-09-29, aarch64:** the kernel reports `tag=927b5c5e18d0c7ee`, 64-bit,
addressable by the id it assigned, and **identical across two separate loads** of the same
program (ids 42 and 54; the tag does not change). That is exactly the property a published
reference needs — a value fixed in advance that a device can be compared against.

**And the gap it found, which matters more than the confirmation:** the tag covers the
instruction stream, **not the maps**. Policy lives in the maps, so two programs with
identical bytecode and completely different allowlists share a tag. A runtime manifest
must therefore digest map contents separately — the program tag alone would attest the
enforcement *mechanism* while saying nothing about the *policy* being enforced.

### `harness-prebuilt-no-clang.sh` — the shipping blocker, closed

`harness-no-toolchain` showed the egress layer disables itself without a compiler, which
ruled it out of exactly the images that most need it ("read-only rootfs, root locked, no
SSH, no debug tooling"). The layer now prefers a **prebuilt BPF object**, and
`_is_available()` requires clang only when there is nothing prebuilt to load.

**Measured:** an object built on **x86_64** loads and attaches on **aarch64**, an allowed
destination connects, and a denied one is refused with `PermissionError` — with **clang
moved off the machine entirely**. BPF bytecode is architecture-neutral between
little-endian targets, so one CI build serves both.

**Loading bytes somebody else compiled moves trust**, so each object ships with a
`.sha256` sidecar. A mismatch is **refused outright** and never compiled around — a silent
fallback to clang would hide precisely the substitution the sidecar exists to catch.
Measured both ways: untampered accepted, one flipped byte refused, and tampered-plus-no-
compiler reports UNAVAILABLE rather than passing quietly.

### `harness-tag-vs-bytes.sh` — what a manifest can publish

An object compiled on a different host has **different bytes** (different clang, different
paths in debug info). If a reference manifest published a byte digest, an operator who
rebuilt from source would see a mismatch and reasonably conclude tampering.

**Measured:** x86-built `c6c1a262…`, natively-built `147bef39…` — different. Both load,
and **both report the same kernel tag `927b5c5e18d0c7ee`.**

So the publishable value is the **tag**: it survives a rebuild on a different host, the
bytes do not. Combined with `harness-prog-tag`'s finding that the tag does not cover the
maps, a runtime manifest needs **tag + separate map digest**.

## One run at a time

The launcher takes an exclusive `flock`. Every run recreates the share directory and the
overlay, so two overlapping runs destroy each other's results — measured on 2026-09-29
when a negative control came back empty because another harness had started underneath
it. A collision is now a loud refusal (exit 3), never a lost result.

## Not yet measured

IPv6 egress, the DNS-steering path (KOS-046), and the AppArmor
path jail (no AppArmor in this guest; the target OS is SELinux anyway). Those are the next
harnesses. Until one exists for a claim, the claim is unmeasured.
