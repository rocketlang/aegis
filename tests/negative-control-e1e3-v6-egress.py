#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
#
# Run this whenever test-e1e2e3-v6-egress.py is changed. A test that passes on the
# broken build is not testing what its name says, and this is the only thing that
# proves it does. Exits 0 when the ORIGINAL build reproduces both defects.
#
# NEGATIVE CONTROL for E-1/E-3. Rebuilds the ORIGINAL connect6 program (32-bit key, no
# port-53 case), loads it for real, populates it the way the original _populate did, and
# runs the same probe. If the harness has teeth, the collider is ALLOWED here.
import importlib.util, json, os, subprocess, sys, tempfile

spec = importlib.util.spec_from_file_location("ce", "/root/aegis/src/kernel/cgroup-egress.py")
ce = importlib.util.module_from_spec(spec); spec.loader.exec_module(ce)

OLD_C = r'''
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u64);
    __type(value, __u8);
} egress_allow_v6 SEC(".maps");
SEC("cgroup/connect6")
int connect6(struct bpf_sock_addr *ctx) {
    __u32 addr_last = bpf_ntohl(ctx->user_ip6[3]);
    __u16 dst_port  = bpf_ntohs((__u16)ctx->user_port);
    __u64 key = ((__u64)addr_last << 32) | dst_port;
    __u8 *v = bpf_map_lookup_elem(&egress_allow_v6, &key);
    if (v && *v) return 1;
    __u64 wildcard = (__u64)addr_last << 32;
    v = bpf_map_lookup_elem(&egress_allow_v6, &wildcard);
    if (v && *v) return 1;
    return 0;
}
char _license[] SEC("license") = "GPL";
'''

SID = "e1-negative-control"
ALLOWED, COLLIDER = "2606:4700:4700::1111", "2001:db8:dead:beef::1111"

PROBE = r'''
import errno, json, os, socket, sys
cg, targets = sys.argv[1], json.loads(sys.argv[2])
open(cg + "/cgroup.procs", "w").write(str(os.getpid()))
out = {}
for name, (host, port) in targets.items():
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM); s.settimeout(2)
    try:
        s.connect((host, port)); out[name] = "CONNECTED"
    except PermissionError: out[name] = "EPERM"
    except OSError as e:
        out[name] = "EPERM" if e.errno == errno.EPERM else "other"
    finally: s.close()
print(json.dumps(out))
'''

obj = tempfile.mktemp(suffix=".o")
assert ce._compile_bpf(OLD_C, obj), "old program failed to compile"
print(f"  built the ORIGINAL connect6: {os.path.getsize(obj)} bytes")

cg = ce._create_cgroup(SID)
pin_dir = os.path.join(ce.BPF_PIN_ROOT, SID)
os.makedirs(pin_dir, exist_ok=True)
pid6 = ce._prog_load(obj, os.path.join(pin_dir, "connect6"))
assert pid6, "old program failed to load"
assert ce._cgroup_attach(cg, pid6, "connect6"), "attach failed"

# populate exactly as the ORIGINAL _populate did: last 32 bits only
import socket as sk, struct
m = ce._map_id_for_prog(pin_dir, "egress_allow_v6")
last32 = struct.unpack(">I", sk.inet_pton(sk.AF_INET6, ALLOWED)[12:16])[0]
ce._map_update(m, (last32 << 32) | 443, 1)
# E-3 needs the resolver to BE allowlisted — that is the stated precondition. Without
# this the old build denies :53 merely because it is not on the list, which proves
# nothing about a port-53 rule.
ce._map_update(m, (last32 << 32) | 53, 1)
print(f"  allowlisted {ALLOWED}:443 AND :53 under the original 32-bit key")

try:
    r = subprocess.run([sys.executable, "-c", PROBE, cg, json.dumps({
        "allowed": (ALLOWED, 443), "collider": (COLLIDER, 443), "dns": (ALLOWED, 53)})],
        capture_output=True, text=True, timeout=60)
    got = json.loads(r.stdout.strip().splitlines()[-1])
    print(f"\n  allowed  {ALLOWED}:443 -> {got['allowed']}")
    print(f"  COLLIDER {COLLIDER}:443 -> {got['collider']}")
    print(f"  dns      {ALLOWED}:53  -> {got['dns']}")
    bad = []
    if got["collider"] == "EPERM": bad.append("collider was denied — the control did not reproduce E-1")
    if got["dns"] == "EPERM":      bad.append("dns was denied — the control did not reproduce E-3")
    print()
    if bad:
        for b in bad: print("  UNEXPECTED:", b)
        sys.exit(1)
    print("  CONFIRMED: on the ORIGINAL build the collider is permitted and v6 DNS is permitted.")
    print("  The harness fails on the broken build and passes on the fixed one.")
finally:
    ce._cgroup_detach(cg, pid6, "connect6")
    subprocess.run(["rm", "-rf", pin_dir], check=False)
    ce._destroy_cgroup(cg) if hasattr(ce, "_destroy_cgroup") else os.rmdir(cg)
    os.unlink(obj)
