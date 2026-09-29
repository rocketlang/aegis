#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
#
# test-e1e2e3-v6-egress.py — the three IPv6 egress defects found 2026-09-29, each
# forced in BOTH directions against a REAL loaded BPF program.
#
#   E-1  the v6 allowlist matched 32 of 128 bits, so an attacker inside their own /64
#        could collide with any allowed address. Widened to the full address.
#   E-2  v6 arming failed open at four points and setup() still returned True.
#   E-3  connect6 had no port-53 case, so the resolver channel connect4 closes was open.
#
# WHY THIS RUNS THE KERNEL RATHER THAN ASSERTING ON PYTHON
#
# The fix changes a map key's LAYOUT. Python writes the key bytes and the BPF program
# computes the key it looks up; nothing in either half proves the two agree. A layout
# mismatch fails closed — every lookup misses, everything is denied — which is the safe
# direction and also completely invisible to a test that only checks Python. So the
# allow cases here matter as much as the deny cases: they are what proves the encoding
# round-trips through the kernel.
#
# EPERM is the signal. A cgroup/connect6 program returning 0 fails connect() with EPERM
# immediately; anything else (timeout, ENETUNREACH, success) means the program allowed
# it and the packet met the ordinary network. The documentation prefix 2001:db8::/32 is
# unroutable, which is exactly why it makes a clean collider: allowed -> ENETUNREACH,
# denied -> EPERM, and the two are never confused.
#
# Needs root, cgroup v2 and bpftool. Exits 0 pass, 1 a check failed, 2 refused to run,
# 3 the harness itself broke.

import errno
import importlib.util
import json
import os
import socket
import subprocess
import sys
import tempfile

CE = "/root/aegis/src/kernel/cgroup-egress.py"
SESSION = "e1e2e3-selftest"

ALLOWED_V6  = "2606:4700:4700::1111"      # allowlisted
COLLIDER_V6 = "2001:db8:dead:beef::1111"  # same LOW 32 BITS, must NOT be allowed
OTHER_V6    = "2001:db8:dead:beef::2222"  # different low 32, baseline deny
ALLOWED_V4  = "1.1.1.1"                   # allowlisted, reached as ::ffff:1.1.1.1

results = []
def check(name, got, want):
    ok = got == want
    results.append((ok, name, got, want))
    print(f"  {'ok  ' if ok else 'FAIL'} {name}: got {got}, want {want}")
    return ok


def load_module():
    spec = importlib.util.spec_from_file_location("ce", CE)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


# ── the probe that runs INSIDE the cgroup ────────────────────────────────────
PROBE = r'''
import errno, json, socket, sys
cg, targets = sys.argv[1], json.loads(sys.argv[2])
open(cg + "/cgroup.procs", "w").write(str(__import__("os").getpid()))
out = {}
for name, (fam, host, port) in targets.items():
    s = socket.socket(socket.AF_INET6 if fam == 6 else socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    try:
        s.connect((host, port))
        out[name] = "CONNECTED"
    except PermissionError:
        out[name] = "EPERM"
    except OSError as e:
        out[name] = "EPERM" if e.errno == errno.EPERM else f"other:{errno.errorcode.get(e.errno, e.errno)}"
    finally:
        s.close()
print(json.dumps(out))
'''


def main():
    if os.geteuid() != 0:
        print("refused: needs root to load BPF and manage cgroups", file=sys.stderr)
        return 2
    ce = load_module()
    if not ce._is_available():
        print("refused: egress prerequisites unavailable on this host", file=sys.stderr)
        return 2

    # ── the prebuilt objects must match THIS source ─────────────────────────
    #
    # Learned the hard way while fixing E-1: the source was edited, the tests were run,
    # and the deny cases all passed — while the kernel was still loading a prebuilt
    # object compiled from the OLD source. _prebuilt_obj() checks an object against its
    # own sidecar, which proves it was not corrupted; it cannot prove it is current.
    # Integrity is not freshness, and a stale prebuilt makes a source fix a no-op.
    print("freshness  the prebuilt objects must match this source")
    import hashlib
    for name, src in (("connect4", ce._BPF_CONNECT4_C), ("connect6", ce._BPF_CONNECT6_C)):
        pre = ce._prebuilt_obj(name)
        if pre is None:
            check(f"{name}.o prebuilt present", False, True)
            continue
        with tempfile.NamedTemporaryFile(suffix=".o", delete=False) as t:
            fresh = t.name
        if not ce._compile_bpf(src, fresh):
            check(f"{name} source compiles", False, True)
            continue
        same = hashlib.sha256(open(pre, "rb").read()).hexdigest() == \
               hashlib.sha256(open(fresh, "rb").read()).hexdigest()
        os.unlink(fresh)
        if not check(f"{name}.o is built from the current source", same, True):
            print("       -> run aegis/tests/aarch64/build-bpf-objects.sh", file=sys.stderr)

    # ── E-2, both directions, before touching the kernel ─────────────────────
    # A session that cannot arm IPv6 must REFUSE unless v4-only was declared.
    print("\nE-2  a v6 failure must refuse, unless v4-only is declared")
    real_obtain = ce._obtain_bpf

    def obtain_no_v6(src, name, out):
        return False if name == "connect6" else real_obtain(src, name, out)

    ce._obtain_bpf = obtain_no_v6
    s_refuse = ce.EgressSession(SESSION + "-refuse")
    try:
        armed = s_refuse.setup({"allow": []}, None)
    finally:
        s_refuse.cleanup()
    check("undeclared v6 failure refuses to arm", armed, False)

    s_declared = ce.EgressSession(SESSION + "-v4only", v4_only=True)
    try:
        armed4 = s_declared.setup({"allow": []}, None)
        fam4 = s_declared.enforced_families()
    finally:
        s_declared.cleanup()
    check("declared v4-only still arms", armed4, True)
    check("and the receipt says ipv6 was not enforced", fam4.get("ipv6"), False)
    check("and still reports itself complete, because it was declared", fam4.get("complete"), True)
    ce._obtain_bpf = real_obtain

    # ── the real session ─────────────────────────────────────────────────────
    print("\nE-1/E-3  against a loaded program")
    policy = {"allow": [
        {"host": ALLOWED_V6, "port": 443, "note": "allowlisted v6"},
        {"host": ALLOWED_V4, "port": 443, "note": "allowlisted v4, reached dual-stack"},
        # E-3 is only tested if the resolver IS allowlisted. Without this entry the
        # DNS check passes because port 53 was never on the list — true, and no
        # evidence at all about a port-53 rule. Measured: on the original build, with
        # this entry present, v6 DNS was PERMITTED.
        {"host": ALLOWED_V6, "port": 53, "note": "a resolver on the allowlist"},
    ]}
    sess = ce.EgressSession(SESSION)
    try:
        if not sess.setup(policy, None):
            print("harness could not arm the session", file=sys.stderr)
            return 3
        fam = sess.enforced_families()
        check("both families enforced", fam.get("complete") and fam.get("ipv6"), True)

        targets = {
            "allowed v6":                 (6, ALLOWED_V6, 443),
            "E-1 collider (low 32 match)": (6, COLLIDER_V6, 443),
            "unrelated v6":               (6, OTHER_V6, 443),
            "E-3 dns over v6":            (6, ALLOWED_V6, 53),
            "allowed v4 as ::ffff:":      (6, "::ffff:" + ALLOWED_V4, 443),
        }
        r = subprocess.run([sys.executable, "-c", PROBE, sess.cgroup_path, json.dumps(targets)],
                           capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            print(f"probe failed: {r.stderr[:400]}", file=sys.stderr)
            return 3
        got = json.loads(r.stdout.strip().splitlines()[-1])

        # The allow cases prove the key encoding round-trips; the deny cases prove the
        # widening bites. Both are required — a layout bug would pass the deny cases.
        check("allowed v6 is NOT blocked (encoding round-trips)", got["allowed v6"] != "EPERM", True)
        check("E-1: the low-32 collider is DENIED",               got["E-1 collider (low 32 match)"], "EPERM")
        check("unrelated v6 is denied",                           got["unrelated v6"], "EPERM")
        check("E-3: DNS over v6 is refused",                      got["E-3 dns over v6"], "EPERM")
        check("v4-mapped allowed host is NOT blocked",            got["allowed v4 as ::ffff:"] != "EPERM", True)
    finally:
        sess.cleanup()

    failed = [r for r in results if not r[0]]
    print(f"\n{len(results) - len(failed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except BaseException as e:
        print(f"\nthe harness could not complete: {type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(3)
