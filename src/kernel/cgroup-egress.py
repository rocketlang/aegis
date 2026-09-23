#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
# @rule:KOS-040 cgroup BPF CONNECT4/6 — egress denied before socket established
# @rule:KOS-041 per-session cgroup under /sys/fs/cgroup/kavachos/{session_id}/
# @rule:KOS-043 BPF map populated at launch — no runtime expansion permitted
# @rule:KOS-045 cgroup cleanup mandatory at session end

"""
cgroup-egress.py — KavachOS Phase 1E: cgroup BPF egress firewall

Architecture:
  1. Compile BPF program (clang -target bpf) — or use pre-compiled .o
  2. Create per-session cgroup
  3. bpftool prog load → pin to /sys/fs/bpf/kavachos/{session_id}/
  4. bpftool cgroup attach → connect4/connect6 on session cgroup
  5. bpftool map update → populate IP:port allowlist from egress policy JSON
  6. Move agent PID into cgroup
  7. Wait for agent exit → bpftool cgroup detach → cleanup

Uses clang + bpftool (available on this host). More stable than bcc for
cgroup_sock_addr programs due to expected_attach_type API differences across
bcc versions. (KOS-YK-006)

Usage: python3 cgroup-egress.py <session_id> <policy.json> <agent_pid>
"""

import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import List, Optional, Tuple

CGROUP_ROOT  = "/sys/fs/cgroup/kavachos"
BPF_PIN_ROOT = "/sys/fs/bpf/kavachos"
_SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))

# ── BPF C source ─────────────────────────────────────────────────────────────
# Compiled once per session; deterministic for same key schema.

_BPF_CONNECT4_C = r"""
// @rule:KOS-040 cgroup BPF connect4 — deny before socket established
// @rule:INF-KOS-009 empty map = deny-all
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Key: ((ip_be32) << 32) | port_host
// ip_be32 is as returned by ctx->user_ip4 (big-endian u32)
// port_host is host-byte-order port number
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, __u64);
    __type(value, __u8);
} egress_allow_v4 SEC(".maps");

// @rule:KOS-046 the port of this session's resolving proxy, or 0 when there is none.
// A single-entry array so the loader can set it after the program is attached.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} dns_proxy_port SEC(".maps");

SEC("cgroup/connect4")
int connect4(struct bpf_sock_addr *ctx) {
    // user_ip4 is NBO; bpf_ntohl converts to host order matching Python's key
    __u32 dst_ip   = bpf_ntohl(ctx->user_ip4);
    // user_port stores the BE16 port in the *lower* 16 bits (not upper)
    __u16 dst_port = bpf_ntohs((__u16)ctx->user_port);

    // @rule:KOS-046 — DNS is STEERED, not merely permitted. Any connect() to port 53
    // is rewritten to this session's resolving proxy on loopback, which answers only
    // for names the egress policy already permits connecting to. Without this the
    // resolver is an open exfiltration channel: an agent that can reach nothing
    // interesting can still carry data out one query name at a time, and to this
    // program that is a permitted packet to a permitted resolver on a permitted port.
    //
    // Verified by strace that glibc connect()s its UDP socket rather than using
    // sendto(), which is why a connect4 hook alone is enough to catch every query.
    if (dst_port == 53) {
        __u32 zero = 0;
        __u32 *pport = bpf_map_lookup_elem(&dns_proxy_port, &zero);
        if (pport && *pport) {
            ctx->user_ip4  = bpf_htonl(0x7F000001);          // 127.0.0.1
            ctx->user_port = bpf_htons((__u16)*pport);
            return 1;
        }
        // No proxy for this session means DNS is DENIED, never quietly allowed.
        // @rule:INF-KOS-009 — a missing instrument refuses.
        return 0;
    }

    // Exact match: ip + port
    __u64 key = ((__u64)dst_ip << 32) | dst_port;
    __u8 *v = bpf_map_lookup_elem(&egress_allow_v4, &key);
    if (v && *v) return 1;

    // Wildcard: any port for this ip (port=0 key)
    __u64 wildcard = (__u64)dst_ip << 32;
    v = bpf_map_lookup_elem(&egress_allow_v4, &wildcard);
    if (v && *v) return 1;

    return 0;  // deny
}
char _license[] SEC("license") = "GPL";
"""

_BPF_CONNECT6_C = r"""
// @rule:KOS-040 cgroup BPF connect6
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Key: last 32 bits of IPv6 address (BE) << 32 | port_host
// Sufficient for ::1 loopback matching
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u64);
    __type(value, __u8);
} egress_allow_v6 SEC(".maps");

SEC("cgroup/connect6")
int connect6(struct bpf_sock_addr *ctx) {
    // user_ip6[3] is NBO; bpf_ntohl converts to host order matching Python's key
    __u32 addr_last = bpf_ntohl(ctx->user_ip6[3]);
    // user_port stores the BE16 port in the *lower* 16 bits (not upper)
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
"""

# ── Availability checks ───────────────────────────────────────────────────────

def _has_tool(name: str) -> bool:
    return shutil.which(name) is not None

def _has_cgroupv2() -> bool:
    try:
        with open("/proc/mounts") as f:
            return any("cgroup2" in l for l in f)
    except Exception:
        return False

def _is_available() -> bool:
    ok = True
    if not _has_tool("clang"):
        sys.stderr.write("[kavachos:egress] clang not found — egress firewall disabled\n")
        ok = False
    if not _has_tool("bpftool"):
        sys.stderr.write("[kavachos:egress] bpftool not found — egress firewall disabled\n")
        ok = False
    if not _has_cgroupv2():
        sys.stderr.write("[kavachos:egress] cgroupv2 not available — egress firewall disabled\n")
        ok = False
    return ok

# ── Compilation ────────────────────────────────────────────────────────────────

def _compile_bpf(src: str, out_path: str) -> bool:
    """Compile BPF C source to object file via clang."""
    arch = subprocess.check_output(["uname", "-m"], text=True).strip()
    include_dir = f"/usr/include/{arch}-linux-gnu"
    result = subprocess.run(
        ["clang", "-O2", "-target", "bpf", "-g", "-c",
         f"-I{include_dir}", "-I/usr/include/bpf",
         "-x", "c", "-", "-o", out_path],
        input=src.encode(),
        capture_output=True,
    )
    if result.returncode != 0:
        sys.stderr.write(f"[kavachos:egress] BPF compile error:\n{result.stderr.decode()[:400]}\n")
        return False
    return True

# ── DNS resolution ────────────────────────────────────────────────────────────

def _resolve(host: str) -> List[str]:
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', host) or ":" in host:
        return [host]
    try:
        return list({r[4][0] for r in socket.getaddrinfo(host, None)})
    except socket.gaierror:
        return []

def _ip4_be32(ip: str) -> Optional[int]:
    try:
        return struct.unpack(">I", socket.inet_aton(ip))[0]
    except Exception:
        return None

def _ip6_last32_be(ip: str) -> Optional[int]:
    try:
        packed = socket.inet_pton(socket.AF_INET6, ip)
        return struct.unpack(">I", packed[12:16])[0]
    except Exception:
        return None

# ── bpftool helpers ───────────────────────────────────────────────────────────

def _bpftool(*args, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["bpftool"] + list(args), capture_output=True, text=True, check=check)

def _prog_load(obj_path: str, pin_path: str) -> Optional[int]:
    """Load BPF program, pin to bpffs. Returns program ID."""
    r = _bpftool("prog", "load", obj_path, pin_path, "pinmaps",
                 os.path.dirname(pin_path), check=False)
    if r.returncode != 0:
        sys.stderr.write(f"[kavachos:egress] prog load failed: {r.stderr[:300]}\n")
        return None
    # Get the prog ID from 'prog show pinned <path>'
    r2 = _bpftool("prog", "show", "pinned", pin_path, "--json", check=False)
    if r2.returncode == 0:
        try:
            data = json.loads(r2.stdout)
            return data[0]["id"] if isinstance(data, list) else data.get("id")
        except Exception:
            pass
    return None

def _map_id_for_prog(pin_dir: str, map_name: str) -> Optional[int]:
    """Get the map ID for a pinned map."""
    pin = os.path.join(pin_dir, map_name)
    r = _bpftool("map", "show", "pinned", pin, "--json", check=False)
    if r.returncode == 0:
        try:
            data = json.loads(r.stdout)
            return (data[0] if isinstance(data, list) else data).get("id")
        except Exception:
            pass
    return None

def _map_update(map_id: int, key_u64: int, value: int) -> None:
    """Update BPF hash map: key (u64 little-endian bytes) → value (u8)."""
    # bpftool map update id <id> key hex <8 LE bytes> value hex <1 byte>
    key_bytes = " ".join(f"{(key_u64 >> (i*8)) & 0xff:02x}" for i in range(8))
    val_hex = f"{value:02x}"
    r = _bpftool("map", "update", "id", str(map_id), "key", "hex",
                 *key_bytes.split(), "value", "hex", val_hex, check=False)
    if r.returncode != 0:
        sys.stderr.write(f"[kavachos:egress] map update failed for key {key_u64:#018x}: {r.stderr[:100]}\n")

def _start_resolving_proxy(sess, policy: dict, session_id: str) -> None:
    """
    Bring up this session's resolving proxy and point the BPF redirect at it. KOS-046.

    Runs HERE rather than in the launcher because this process already owns the session
    lifetime, already holds the policy, and lives outside the cgroup — so its own upstream
    query is ungoverned, which is exactly what a proxy for a governed agent needs.

    Every failure leaves dns_proxy_port at 0, and the BPF program denies port 53 when it
    is 0. So a proxy that will not start costs the agent name resolution; it never leaves
    the channel open. @rule:INF-KOS-009
    """
    try:
        import importlib.util
        here = os.path.dirname(os.path.abspath(__file__))
        spec = importlib.util.spec_from_file_location(
            "kavachos_dns_proxy", os.path.join(here, "dns-proxy.py"))
        dp = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(dp)

        upstream = dp.first_upstream()
        if upstream is None:
            sys.stderr.write("[kavachos:dns] no IPv4 upstream in resolv.conf — DNS stays denied\n")
            return

        names = dp.allowed_names(policy)
        # Every verdict is recorded. A refused name is the only direct evidence that
        # something tried to use the resolver as a channel, so it must survive the session.
        ledger = os.environ.get("KAVACHOS_DNS_LEDGER", "/root/.aegis/kernel/dns-queries.jsonl")
        proxy = dp.ResolvingProxy(names, upstream, bind_port=0,
                                  ledger_path=ledger, session_id=session_id)
        port = proxy.start()
        if not sess.set_dns_proxy_port(port):
            proxy.stop()
            return
        sess.dns_proxy = proxy
        sys.stderr.write(
            f"[kavachos:dns] resolving proxy up on 127.0.0.1:{port} — "
            f"{len(names)} name(s) permitted, upstream {upstream[0]}\n")
    except Exception as e:
        sys.stderr.write(f"[kavachos:dns] proxy not started ({e}) — DNS stays denied\n")


def _map_update_u32(map_id: int, key: int, value: int) -> bool:
    """
    Update a BPF ARRAY map: u32 key → u32 value, both little-endian on x86.

    Separate from _map_update because that one writes a u64 key and a u8 value for the
    allow hash. Reusing it here would silently write the wrong widths — the map would
    accept four bytes of a port as one byte of a verdict and the redirect would look
    configured while pointing nowhere.
    """
    kb = " ".join(f"{(key >> (i*8)) & 0xff:02x}" for i in range(4))
    vb = " ".join(f"{(value >> (i*8)) & 0xff:02x}" for i in range(4))
    r = _bpftool("map", "update", "id", str(map_id), "key", "hex", *kb.split(),
                 "value", "hex", *vb.split(), check=False)
    if r.returncode != 0:
        sys.stderr.write(f"[kavachos:egress] dns proxy port update failed: {r.stderr[:160]}\n")
        return False
    return True

def _cgroup_attach(cgroup_path: str, prog_id: int, attach_type: str) -> bool:
    r = _bpftool("cgroup", "attach", cgroup_path, attach_type, "id", str(prog_id), check=False)
    if r.returncode != 0:
        sys.stderr.write(f"[kavachos:egress] cgroup attach {attach_type} failed: {r.stderr[:200]}\n")
        return False
    return True

def _cgroup_detach(cgroup_path: str, prog_id: int, attach_type: str) -> None:
    _bpftool("cgroup", "detach", cgroup_path, attach_type, "id", str(prog_id), check=False)

# ── Cgroup management ─────────────────────────────────────────────────────────

def _create_cgroup(session_id: str) -> str:
    path = os.path.join(CGROUP_ROOT, session_id)
    os.makedirs(path, exist_ok=True)
    return path

def _move_pid(cgroup_path: str, pid: int) -> None:
    with open(os.path.join(cgroup_path, "cgroup.procs"), "w") as f:
        f.write(str(pid))

def _destroy_cgroup(session_id: str) -> None:
    path = os.path.join(CGROUP_ROOT, session_id)
    if not os.path.exists(path):
        return
    # Evacuate any remaining processes to parent cgroup
    try:
        child_procs = os.path.join(path, "cgroup.procs")
        parent_procs = os.path.join(CGROUP_ROOT, "cgroup.procs")
        with open(child_procs) as f:
            pids = f.read().strip().split()
        for p in pids:
            try:
                with open(parent_procs, "w") as f:
                    f.write(p)
            except Exception:
                pass
    except Exception:
        pass
    try:
        os.rmdir(path)
    except Exception as e:
        sys.stderr.write(f"[kavachos:egress] cgroup rmdir warning: {e}\n")

# ── Main session class ─────────────────────────────────────────────────────────

class EgressSession:
    """Lifetime: agent session. Load → attach → populate → wait → cleanup."""

    def __init__(self, session_id: str):
        self.session_id  = session_id
        self.cgroup_path = os.path.join(CGROUP_ROOT, session_id)
        self.pin_dir     = os.path.join(BPF_PIN_ROOT, session_id)
        self.prog_id_v4  = -1
        self.prog_id_v6  = -1
        self._tmp        = []  # temp files to clean up
        self.dns_proxy   = None  # @rule:KOS-046 — owned here so cleanup() always stops it
        # @rule:KOS-047 — this session may only tear down what IT created. The session id
        # is a global namespace with no ownership: the cgroup, the BPF pins and the ready
        # file are all keyed by it alone, so two sessions on one id share all three.
        self._owns       = False
        self.collided    = False

    def setup(self, policy: dict, agent_pid: Optional[int]) -> bool:
        """
        agent_pid=None is PREPARE mode: create the cgroup and attach the BPF program,
        but do not move anyone in. The launcher joins before exec instead, so the agent
        inherits membership. Moving a pid after the fact never worked here — a short
        agent was gone before the move, and a long one had already forked the real
        agent outside the cgroup, so the supervisor was moved and the agent was not.
        """
        # @rule:KOS-047 GUARD 1 — an id already in use is refused BEFORE anything is
        # created, and nothing belonging to the incumbent is touched. It must run BEFORE the
# makedirs and _create_cgroup below: placed after them it saw the cgroup it had itself
# just created and refused every launch, including the first.
        #
        # This collision used to be discovered by failing to pin, after which cleanup()
        # ran and deleted the INCUMBENT's pins — measured 2026-09-23: a live session's
        # connect4 pin went from present to GONE because a second session on its id failed
        # to start. The victim kept running and believed itself governed. Refusing without
        # collateral is the whole point of refusing.
        existing_pin = os.path.join(self.pin_dir, "connect4")
        if os.path.exists(existing_pin) or os.path.isdir(self.cgroup_path):
            self.collided = True
            sys.stderr.write(
                f"[kavachos:egress] REFUSING session {self.session_id}: that id is already in "
                f"use. Not touching it — another session may be running under it.\n")
            return False

        os.makedirs(CGROUP_ROOT, exist_ok=True)
        os.makedirs(BPF_PIN_ROOT, exist_ok=True)
        os.makedirs(self.pin_dir, exist_ok=True)
        _create_cgroup(self.session_id)

        # Compile BPF programs to /tmp — bpffs doesn't support regular file writes
        v4_obj = f"/tmp/kavachos-{self.session_id}-connect4.o"
        v6_obj = f"/tmp/kavachos-{self.session_id}-connect6.o"
        self._tmp.extend([v4_obj, v6_obj])

        if not _compile_bpf(_BPF_CONNECT4_C, v4_obj):
            return False
        _compile_bpf(_BPF_CONNECT6_C, v6_obj)  # v6 failure is non-fatal

        # Load + pin
        v4_pin = os.path.join(self.pin_dir, "connect4")
        # _prog_load returns None on failure while this field is an int sentinel. Two
        # things have to hold at once, and an earlier fix got one by breaking the other:
        #
        #   cleanup() must never see None      — it compared None > 0 and raised, so a
        #                                        session that failed to arm also failed to
        #                                        tear itself down, and one failure became
        #                                        permanent.
        #   setup() must ABORT on a failed load — `= _prog_load(...) or -1` satisfied the
        #                                        first and silently made the `is None`
        #                                        check below it dead code, so setup walked
        #                                        on and attached prog id -1. A session that
        #                                        could not load then reported itself ready.
        #
        # So test the load result BEFORE normalising, and normalise on both paths.
        loaded_v4 = _prog_load(v4_obj, v4_pin)
        if loaded_v4 is None:
            self.prog_id_v4 = -1
            return False
        self.prog_id_v4 = loaded_v4
        self._owns = True      # @rule:KOS-047 — from here, and only from here, teardown is ours

        if os.path.exists(v6_obj):
            v6_pin = os.path.join(self.pin_dir, "connect6")
            self.prog_id_v6 = _prog_load(v6_obj, v6_pin) or -1   # v6 failure is non-fatal

        # Attach to cgroup
        if not _cgroup_attach(self.cgroup_path, self.prog_id_v4, "connect4"):
            return False
        if self.prog_id_v6 > 0:
            _cgroup_attach(self.cgroup_path, self.prog_id_v6, "connect6")

        # Populate allowlist maps
        self._populate(policy)

        # Move agent into cgroup — legacy path only.
        if agent_pid is not None:
            try:
                _move_pid(self.cgroup_path, agent_pid)
            except Exception as e:
                sys.stderr.write(f"[kavachos:egress] move_pid failed: {e}\n")
                return False

        allow_len = len(policy.get("allow", []))
        who = f"pid={agent_pid}" if agent_pid is not None else "awaiting join"
        sys.stderr.write(
            f"[kavachos:egress] Phase 1E active: session={self.session_id} "
            f"{who} hosts={allow_len}\n"
        )
        return True

    def procs(self) -> list:
        """Pids currently inside the cgroup."""
        try:
            with open(os.path.join(self.cgroup_path, "cgroup.procs")) as f:
                return [int(x) for x in f.read().split() if x.strip()]
        except Exception:
            return []

    def _populate(self, policy: dict) -> None:
        """Fill BPF maps with allowlist entries. @rule:KOS-043"""
        map_v4 = _map_id_for_prog(self.pin_dir, "egress_allow_v4")
        map_v6 = _map_id_for_prog(self.pin_dir, "egress_allow_v6") if self.prog_id_v6 > 0 else None

        for entry in policy.get("allow", []):
            host = entry.get("host", "")
            port = entry.get("port", 0)
            note = entry.get("note", host)
            ips = _resolve(host)
            if not ips:
                sys.stderr.write(f"[kavachos:egress] WARNING: unresolvable host skipped: {host}\n")
                continue

            for ip in ips:
                be32 = _ip4_be32(ip)
                if be32 is not None and map_v4 is not None:
                    # Key: ip_be32 << 32 | port_host (stored little-endian for bpftool)
                    key = (be32 << 32) | port
                    _map_update(map_v4, key, 1)
                    continue

                last32 = _ip6_last32_be(ip)
                if last32 is not None and map_v6 is not None:
                    key = (last32 << 32) | port
                    _map_update(map_v6, key, 1)

    def set_dns_proxy_port(self, port: int) -> bool:
        """
        Point this session's connect4 DNS redirect at the resolving proxy. @rule:KOS-046

        Until this is set the map holds 0, and the BPF program DENIES port 53 outright
        rather than letting it through — so a proxy that failed to start costs the agent
        name resolution, never the other way round.
        """
        map_id = _map_id_for_prog(self.pin_dir, "dns_proxy_port")
        if map_id is None:
            sys.stderr.write("[kavachos:egress] dns_proxy_port map not found — DNS stays denied\n")
            return False
        if not _map_update_u32(map_id, 0, int(port)):
            return False
        sys.stderr.write(f"[kavachos:egress] DNS steered to the resolving proxy on 127.0.0.1:{port}\n")
        return True

    def cleanup(self) -> None:
        """Detach BPF, remove cgroup. @rule:KOS-045"""
        # Stop the resolver FIRST. Every exit path reaches cleanup(), which is why the
        # proxy is owned by the session rather than by main() — a proxy outliving its
        # session would keep answering for a policy that no longer governs anything.
        if self.dns_proxy is not None:
            try:
                self.dns_proxy.stop()
                sys.stderr.write(
                    f"[kavachos:dns] served={self.dns_proxy.served_count} "
                    f"refused={self.dns_proxy.refused_count}\n")
            except Exception:
                pass
            self.dns_proxy = None
        # Guarded rather than trusted: cleanup runs on every exit path INCLUDING the one
        # where setup failed, so it must survive fields that never got a real value.
        if (self.prog_id_v4 or -1) > 0:
            _cgroup_detach(self.cgroup_path, self.prog_id_v4, "connect4")
        if (self.prog_id_v6 or -1) > 0:
            _cgroup_detach(self.cgroup_path, self.prog_id_v6, "connect6")
        # @rule:KOS-047 GUARD 2 — containment. Guard 1 stops the collision we know about;
        # this stops every other route to the same damage. Previously these two steps were
        # guarded by os.path.exists — existence, never ownership — so any session that
        # reached cleanup() destroyed whatever happened to be sitting under that id.
        if not self._owns:
            sys.stderr.write(
                f"[kavachos:egress] cleanup: session {self.session_id} created nothing — "
                f"leaving the cgroup and pins alone\n")
            return
        _destroy_cgroup(self.session_id)
        # Remove pinned programs from bpffs
        for name in ["connect4", "connect6", "egress_allow_v4", "egress_allow_v6", "dns_proxy_port"]:
            p = os.path.join(self.pin_dir, name)
            if os.path.exists(p):
                try:
                    os.unlink(p)
                except Exception:
                    pass
        try:
            os.rmdir(self.pin_dir)
        except Exception:
            pass
        # Remove tmp .o files
        for tmp in self._tmp:
            if os.path.exists(tmp):
                try:
                    os.unlink(tmp)
                except Exception:
                    pass
        sys.stderr.write(f"[kavachos:egress] Session {self.session_id} cleaned up\n")

# ── Entry point ────────────────────────────────────────────────────────────────

# How long to wait for the launcher to join the cgroup before concluding it never will.
JOIN_TIMEOUT_S = 30.0


def main() -> None:
    if len(sys.argv) < 4:
        sys.stderr.write(
            "Usage: cgroup-egress.py <session_id> <policy.json> <agent_pid|--prepare> [ready_file]\n"
        )
        sys.exit(1)

    session_id = sys.argv[1]
    policy_path = sys.argv[2]
    prepare = sys.argv[3] == "--prepare"
    agent_pid = None if prepare else int(sys.argv[3])
    ready_file = sys.argv[4] if len(sys.argv) > 4 else None

    if not _is_available():
        # Tell the launcher not to wait for a cgroup that will never exist.
        if ready_file:
            try:
                with open(ready_file, "w") as f:
                    f.write("UNAVAILABLE\n")
            except Exception:
                pass
        sys.exit(0)  # graceful degradation — log already written above

    with open(policy_path) as f:
        policy = json.load(f)

    sess = EgressSession(session_id)
    ok = sess.setup(policy, agent_pid)
    if ok:
        _start_resolving_proxy(sess, policy, session_id)
    if not ok:
        if ready_file:
            try:
                with open(ready_file, "w") as f:
                    f.write("FAILED\n")
            except Exception:
                pass
        sess.cleanup()
        sys.exit(0)  # graceful degradation

    if prepare:
        # Publish the cgroup path, then supervise by membership rather than by pid:
        # wait for someone to join, then wait for the cgroup to drain.
        if ready_file:
            with open(ready_file, "w") as f:
                f.write(sess.cgroup_path + "\n")

        deadline = time.time() + JOIN_TIMEOUT_S
        while not sess.procs() and time.time() < deadline:
            time.sleep(0.05)
        if not sess.procs():
            sys.stderr.write(
                f"[kavachos:egress] nobody joined {session_id} within {JOIN_TIMEOUT_S:.0f}s — tearing down\n"
            )
            sess.cleanup()
            sys.exit(0)
        while sess.procs():
            time.sleep(0.2)
        sess.cleanup()
        return

    # Wait for agent to exit.
    # The agent is typically NOT our direct child (runner.ts spawned it) so
    # waitpid() raises ChildProcessError immediately — fall back to PID-probe loop.
    try:
        os.waitpid(agent_pid, 0)
    except Exception:
        while True:
            try:
                os.kill(agent_pid, 0)  # raises ProcessLookupError when PID gone
                time.sleep(0.5)
            except (ProcessLookupError, PermissionError):
                break

    sess.cleanup()


if __name__ == "__main__":
    main()
