#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
#
# KavachOS — the resolving proxy.
#
# @rule:KOS-046 A governed agent resolves ONLY the names its egress policy permits.
#               Every other query is REFUSED and recorded.
#
# WHY THIS EXISTS
#
# Adding the system resolvers to the egress allowlist (08e8ee4) fixed a real bug —
# allowlisted hosts were unreachable by name — but it left the honest gap that fix
# documented: a resolver is an exfiltration channel. An agent forbidden from connecting
# anywhere interesting can still carry data out in the NAMES it asks to look up, one
# query at a time, because the resolver forwards them and an attacker reads them at an
# authoritative server they control. Nothing in the egress map sees that: to BPF it is a
# permitted packet to a permitted resolver on a permitted port.
#
# This closes it. The proxy answers for names in the session's policy and REFUSES the
# rest, so the channel narrows from "any name" to "the handful of names the policy
# already allows connecting to" — which carries no information an attacker did not
# already have from reading the policy.
#
# HOW THE AGENT REACHES IT
#
# Not by configuration. Rewriting the agent's /etc/resolv.conf needs a mount namespace,
# and this codebase has none. Instead cgroup/connect4 rewrites any connect() to port 53
# so it lands here — verified by strace that glibc's resolver connect()s its UDP socket
# rather than using sendto(), which is why a connect4 hook alone is sufficient.
#
# WHAT IT IS NOT
#
# It is not a validating or caching resolver, and it does not inspect answers. An allowed
# name's response is forwarded verbatim. The only decision it makes is whether the QUESTION
# was permitted, because that is the only decision that closes the channel.

import json
import os
import socket
import struct
import sys
import threading
import time
from typing import Optional, Set, Tuple

REFUSED = 5          # RCODE 5, RFC 1035 — "the name server refuses to perform"
NOERROR = 0
HEADER = 12          # bytes


# ── wire format ───────────────────────────────────────────────────────────────

def parse_qname(packet: bytes) -> Optional[str]:
    """
    The question name from a query, lowercased, without the trailing dot.

    Returns None on anything malformed. A query we cannot parse is not given the
    benefit of the doubt — the caller refuses it, because "unparseable" is exactly
    what a tunnelling client would aim for if refusal were the fallback for failure.
    """
    if len(packet) < HEADER + 2:
        return None
    qdcount = struct.unpack_from("!H", packet, 4)[0]
    if qdcount != 1:
        return None                      # multi-question queries are not a thing we serve
    labels = []
    off = HEADER
    while True:
        if off >= len(packet):
            return None
        n = packet[off]
        if n == 0:
            break
        if n & 0xC0:
            return None                  # compression pointer in a question — malformed
        off += 1
        if off + n > len(packet):
            return None
        labels.append(packet[off:off + n].decode("ascii", "replace"))
        off += n
        if len(labels) > 64:
            return None
    if not labels:
        return None
    return ".".join(labels).lower()


def refusal_for(packet: bytes) -> bytes:
    """A REFUSED answer echoing the query's id and question. No answer records."""
    if len(packet) < HEADER:
        return b""
    tid = packet[0:2]
    # QR=1 (response), RD copied from the query, RA=0, RCODE=REFUSED
    rd = packet[2] & 0x01
    flags = struct.pack("!H", (1 << 15) | (rd << 8) | REFUSED)
    qdcount = struct.unpack_from("!H", packet, 4)[0]
    rest = packet[HEADER:] if qdcount else b""
    return tid + flags + struct.pack("!HHHH", qdcount, 0, 0, 0) + rest


# ── the decision ──────────────────────────────────────────────────────────────

def permitted(qname: Optional[str], allowed: Set[str]) -> bool:
    """
    Pure, and the whole policy of this proxy lives here.

    A name is permitted when the egress policy names it exactly. Nothing else: no
    parent-domain matching, no wildcards. "*.example.com" would re-open the channel
    it exists to close, because every distinct subdomain is a message.

    glibc appends search domains and will ask for e.g. "github.com.tail155a71.ts.net"
    before the absolute name. That variant is refused and glibc falls through to the
    absolute query, which succeeds — so a refusal here is normal traffic, not an
    incident on its own. What matters is the name that was NOT in the policy at all.
    """
    if qname is None:
        return False
    return qname in allowed


def allowed_names(policy: dict) -> Set[str]:
    """
    The hostnames the egress policy permits connecting to.

    Literal IP entries are skipped: nobody resolves an address, and carrying them here
    would only widen the set.
    """
    out: Set[str] = set()
    for entry in policy.get("allow", []):
        host = str(entry.get("host", "")).strip().lower().rstrip(".")
        if not host:
            continue
        if _is_ip_literal(host):
            continue
        out.add(host)
    return out


def _is_ip_literal(host: str) -> bool:
    for fam in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(fam, host)
            return True
        except OSError:
            pass
    return False


# ── the server ────────────────────────────────────────────────────────────────

class ResolvingProxy:
    def __init__(self, allowed: Set[str], upstream: Tuple[str, int],
                 bind_host: str = "127.0.0.1", bind_port: int = 0,
                 ledger_path: Optional[str] = None, session_id: str = "") -> None:
        self.allowed = allowed
        self.upstream = upstream
        self.ledger_path = ledger_path
        self.session_id = session_id
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((bind_host, bind_port))
        self.port = self.sock.getsockname()[1]
        self.refused_count = 0
        self.served_count = 0
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def _record(self, qname: Optional[str], verdict: str) -> None:
        if not self.ledger_path:
            return
        try:
            with open(self.ledger_path, "a") as f:
                f.write(json.dumps({
                    "ts": time.time(),
                    "session_id": self.session_id,
                    "qname": qname,
                    "verdict": verdict,
                }) + "\n")
        except OSError:
            pass  # a ledger that cannot be written must not take the resolver down

    def _handle(self, packet: bytes, peer) -> None:
        qname = parse_qname(packet)
        if not permitted(qname, self.allowed):
            self.refused_count += 1
            self._record(qname, "refused")
            sys.stderr.write(f"[kavachos:dns] REFUSED {qname or '<unparseable>'}\n")
            sys.stderr.flush()
            reply = refusal_for(packet)
            if reply:
                self.sock.sendto(reply, peer)
            return

        try:
            up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            up.settimeout(5.0)
            up.sendto(packet, self.upstream)
            answer, _ = up.recvfrom(65535)
            up.close()
        except OSError:
            # Upstream unreachable is NOT an open door: refuse rather than fail silent.
            self.refused_count += 1
            self._record(qname, "upstream-failed")
            reply = refusal_for(packet)
            if reply:
                self.sock.sendto(reply, peer)
            return

        self.served_count += 1
        self._record(qname, "served")
        self.sock.sendto(answer, peer)

    def _loop(self) -> None:
        self.sock.settimeout(0.5)
        while not self._stop.is_set():
            try:
                packet, peer = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                self._handle(packet, peer)
            except Exception as e:                      # one bad query never stops the proxy
                sys.stderr.write(f"[kavachos:dns] handler error: {e}\n")

    def start(self) -> int:
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return self.port

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2.0)
        try:
            self.sock.close()
        except OSError:
            pass


def first_upstream(resolv_conf: str = "/etc/resolv.conf") -> Optional[Tuple[str, int]]:
    """The first IPv4 nameserver in resolv.conf. None when there is none to be had."""
    try:
        with open(resolv_conf) as f:
            text = f.read()
    except OSError:
        return None
    for line in text.split("\n"):
        parts = line.strip().split()
        if len(parts) >= 2 and parts[0] == "nameserver":
            try:
                socket.inet_pton(socket.AF_INET, parts[1])
                return (parts[1], 53)
            except OSError:
                continue
    return None


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="KavachOS resolving proxy (KOS-046)")
    ap.add_argument("--policy", required=True, help="path to the session egress policy json")
    ap.add_argument("--port", type=int, default=0, help="bind port (0 = ephemeral)")
    ap.add_argument("--session-id", default="")
    ap.add_argument("--ledger", default=None, help="jsonl path for query verdicts")
    ap.add_argument("--print-port", action="store_true", help="print the bound port and keep running")
    args = ap.parse_args()

    try:
        with open(args.policy) as f:
            policy = json.load(f)
    except (OSError, ValueError) as e:
        sys.stderr.write(f"[kavachos:dns] FATAL: policy unreadable: {e}\n")
        return 2

    allowed = allowed_names(policy)
    upstream = first_upstream()
    if upstream is None:
        # @rule:INF-KOS-009 — no upstream is not a reason to answer freely.
        sys.stderr.write("[kavachos:dns] FATAL: no IPv4 nameserver in resolv.conf\n")
        return 2

    proxy = ResolvingProxy(allowed, upstream, bind_port=args.port,
                           ledger_path=args.ledger, session_id=args.session_id)
    port = proxy.start()
    sys.stderr.write(
        f"[kavachos:dns] resolving proxy on 127.0.0.1:{port} — "
        f"{len(allowed)} name(s) permitted, upstream {upstream[0]}\n"
    )
    if args.print_port:
        print(port, flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        proxy.stop()
        sys.stderr.write(
            f"[kavachos:dns] served={proxy.served_count} refused={proxy.refused_count}\n"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
