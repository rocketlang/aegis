#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
# @rule:KOS-011 kavachos run — only approved agent launch path
# @rule:KOS-006 seccomp filter applied before exec — inherited by children, immutable after
# @rule:KOS-028 NOTIFY supervisor — kernel pauses syscall, operator decides before ALLOW/DENY

"""
apply-seccomp.py — KavachOS libseccomp launcher + NOTIFY supervisor

Phase 1A (stable): load profile, exec agent under SCMP_ACT_ERRNO default.
Phase 1D (this):   notify_syscalls in profile → supervisor forks, kernel pauses
                   those syscalls, Telegram ALLOW/DENY before proceeding.

Architecture (Phase 1D):
  1. Build libseccomp context with ALLOW + NOTIFY rules (before fork).
  2. socketpair() for fd transfer.
  3. fork():
       CHILD  → seccomp_load(ctx) → seccomp_notify_fd(ctx) → send fd to parent
              → exec(agent)           [seccomp filter now active on agent]
       PARENT → receive notify_fd from child
              → run supervisor loop (no seccomp filter — unrestricted)
              → waitpid(child) → exit with child's status

Usage:
  python3 apply-seccomp.py <profile.json> -- <agent_command> [args...]

Backward compatible: profiles without notify_syscalls run exactly as before
(no fork, exec directly).
"""

import array
import ctypes
import ctypes.util
import fcntl
import json
import os
import select
import socket
import sqlite3
import struct
import sys
import time
import threading
import urllib.request
import urllib.error
from typing import List, Optional, Tuple

# ── libseccomp bindings ────────────────────────────────────────────────────────

_LIB_PATH = ctypes.util.find_library("seccomp")
if not _LIB_PATH:
    _LIB_PATH = "libseccomp.so.2"

try:
    _lib = ctypes.CDLL(_LIB_PATH)
except OSError as e:
    sys.stderr.write(f"[kavachos] FATAL: cannot load libseccomp: {e}\n")
    sys.exit(1)

# Action constants
SCMP_ACT_KILL   = ctypes.c_uint32(0x00000000)
SCMP_ACT_NOTIFY = ctypes.c_uint32(0x7fc00000)
SCMP_ACT_ERRNO  = ctypes.c_uint32(0x00050001)  # ERRNO(EPERM=1)
SCMP_ACT_ALLOW  = ctypes.c_uint32(0x7fff0000)

_lib.seccomp_init.restype  = ctypes.c_void_p
_lib.seccomp_init.argtypes = [ctypes.c_uint32]

_lib.seccomp_rule_add.restype  = ctypes.c_int
_lib.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]

_lib.seccomp_load.restype  = ctypes.c_int
_lib.seccomp_load.argtypes = [ctypes.c_void_p]

_lib.seccomp_release.restype  = None
_lib.seccomp_release.argtypes = [ctypes.c_void_p]

_lib.seccomp_syscall_resolve_name.restype  = ctypes.c_int
_lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]

# @rule:KOS-028 seccomp_notify_fd — get notify fd after seccomp_load
_lib.seccomp_notify_fd.restype  = ctypes.c_int
_lib.seccomp_notify_fd.argtypes = [ctypes.c_void_p]

_libc_path = ctypes.util.find_library("c") or "libc.so.6"
_libc = ctypes.CDLL(_libc_path)
_libc.prctl.restype  = ctypes.c_int
_libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]

# ioctl via libc for unsigned request codes > 2^31
_libc.ioctl.restype  = ctypes.c_int
_libc.ioctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_void_p]

PR_SET_NO_NEW_PRIVS = 38

# ── NOTIFY supervisor constants ────────────────────────────────────────────────

# IOWR('!', nr, size) on x86_64
# = (3 << 30) | (ord('!') << 8) | nr | (size << 16)
_SECCOMP_IOC_MAGIC = ord('!')

def _IOWR(nr: int, size: int) -> int:
    return (3 << 30) | (_SECCOMP_IOC_MAGIC << 8) | nr | (size << 16)

# struct seccomp_notif  — 80 bytes:  id(Q) pid(I) flags(I) nr(i) arch(I) ip(Q) args(6Q)
# struct seccomp_notif_resp — 24 bytes: id(Q) val(q) error(i) flags(I)
_NOTIF_PACK = "=QIIiIQ6Q"
_RESP_PACK  = "=QqiI"
_NOTIF_SIZE = struct.calcsize(_NOTIF_PACK)   # 80
_RESP_SIZE  = struct.calcsize(_RESP_PACK)    # 24

SECCOMP_IOCTL_NOTIF_RECV = _IOWR(0, _NOTIF_SIZE)  # 0xC0502100
SECCOMP_IOCTL_NOTIF_SEND = _IOWR(1, _RESP_SIZE)   # 0xC0182101
SECCOMP_USER_NOTIF_FLAG_CONTINUE = 1               # allow syscall to proceed

# ── Syscall name lookup ────────────────────────────────────────────────────────

# Build a reverse map: syscall_nr → name from /usr/include (fallback: libseccomp)
def _build_nr_to_name() -> dict:
    mapping: dict = {}
    try:
        import os as _os
        path = "/usr/include/x86_64-linux-gnu/asm/unistd_64.h"
        if not _os.path.exists(path):
            path = "/usr/include/asm/unistd_64.h"
        if _os.path.exists(path):
            with open(path) as f:
                for line in f:
                    if line.startswith("#define __NR_"):
                        parts = line.split()
                        if len(parts) >= 3:
                            name = parts[1].replace("__NR_", "")
                            try:
                                nr = int(parts[2])
                                mapping[nr] = name
                            except ValueError:
                                pass
    except Exception:
        pass
    return mapping

_NR_TO_NAME = _build_nr_to_name()

def syscall_name(nr: int) -> str:
    return _NR_TO_NAME.get(nr, f"syscall#{nr}")

# ── fd passing via SCM_RIGHTS ──────────────────────────────────────────────────

def _send_fd(sock: socket.socket, fd: int) -> None:
    """Send a file descriptor over a Unix socket using SCM_RIGHTS."""
    fds = array.array("i", [fd])
    sock.sendmsg([b"\x00"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fds)])


def _recv_fd(sock: socket.socket, timeout: float = 5.0) -> int:
    """Receive a file descriptor from a Unix socket."""
    sock.settimeout(timeout)
    msg, ancdata, _flags, _addr = sock.recvmsg(1, socket.CMSG_LEN(array.array("i", [0]).itemsize))
    for cmsg_level, cmsg_type, cmsg_data in ancdata:
        if cmsg_level == socket.SOL_SOCKET and cmsg_type == socket.SCM_RIGHTS:
            fds = array.array("i")
            fds.frombytes(cmsg_data[: fds.itemsize])
            return fds[0]
    raise RuntimeError("[kavachos] No fd received from child")

# ── Notify supervisor loop ─────────────────────────────────────────────────────

def _read_aegis_config() -> dict:
    """Load ~/.aegis/config.json — returns {} if absent."""
    config_path = os.path.join(os.environ.get("HOME", "/root"), ".aegis", "config.json")
    try:
        with open(config_path) as f:
            return json.load(f)
    except Exception:
        return {}


def _aegis_db_path() -> str:
    return os.path.join(os.environ.get("HOME", "/root"), ".aegis", "aegis.db")


def _create_approval(db_path: str, approval_id: str, session_id: str,
                     syscall: str, pid: int, domain: str) -> None:
    """Insert a pending approval record into aegis.db."""
    try:
        conn = sqlite3.connect(db_path, timeout=5)
        conn.execute("""
            INSERT OR IGNORE INTO kavach_approvals
              (id, created_at, command, tool_name, level, consequence, session_id, timeout_ms, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')
        """, (
            approval_id,
            time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            f"syscall:{syscall} pid:{pid}",
            f"kavachos:supervisor_ambiguous",
            3,
            f"Agent syscall {syscall} requires operator approval (KOS-028)",
            session_id,
            600_000,
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        sys.stderr.write(f"[kavachos:supervisor] DB write failed: {e}\n")


def _poll_approval(db_path: str, approval_id: str,
                   timeout_s: float = 600.0) -> bool:
    """
    Poll aegis.db until the approval is decided. Returns True=ALLOW, False=DENY.
    @rule:KOS-026 silence = STOP (DENY)
    """
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            conn = sqlite3.connect(db_path, timeout=5)
            row = conn.execute(
                "SELECT status FROM kavach_approvals WHERE id = ?", (approval_id,)
            ).fetchone()
            conn.close()
            if row and row[0] == "allowed":
                return True
            if row and row[0] in ("stopped", "timed_out"):
                return False
        except Exception:
            pass
        time.sleep(2)
    sys.stderr.write(f"[kavachos:supervisor] Approval {approval_id} timed out → DENY\n")
    return False


def _send_telegram(config: dict, message: str, approval_id: Optional[str]) -> None:
    """
    POST message to AnkrClaw /api/notify (same as kernel-notifier.ts sendViaAnkrClaw).
    Silent on failure — Telegram is best-effort; the DB poll is authoritative.
    """
    kc = config.get("kavach", {})
    if not kc.get("enabled"):
        return
    url = kc.get("webhook_url") or kc.get("ankrclaw_url", "")
    if not url:
        return
    channel = kc.get("notify_channel", "telegram")
    to = kc.get("notify_telegram_chat_id") if channel == "telegram" else kc.get("notify_phone", "")
    if not to:
        return
    payload = json.dumps({
        "to": to,
        "message": message,
        "service": "KAVACHOS",
        "channel": channel,
        "approval_id": approval_id,
    }).encode()
    try:
        req = urllib.request.Request(
            f"{url.rstrip('/')}/api/notify",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        sys.stderr.write(f"[kavachos:supervisor] Telegram send failed: {e}\n")


def _build_notify_message(syscall: str, agent_id: str, session_id: str,
                          domain: str, pid: int, approval_id: str) -> str:
    plain_map = {
        "ptrace": "attach to and control another process (debugger)",
        "bpf": "load a BPF kernel program",
        "mount": "mount a filesystem",
        "umount2": "unmount a filesystem",
        "userfaultfd": "register a userspace page-fault handler",
        "perf_event_open": "open a performance monitoring counter",
        "setns": "join a Linux namespace",
        "capset": "modify Linux capability flags",
    }
    plain = plain_map.get(syscall, f'call restricted syscall "{syscall}"')
    return "\n".join([
        "🟠 KavachOS — Syscall Gated (Action Required)",
        "",
        f"Agent: {agent_id}  |  Domain: {domain}",
        f"Session: {session_id}  |  Agent PID: {pid}",
        "",
        "What happened:",
        f"The agent tried to {plain}.",
        "This syscall is in the supervised (NOTIFY) tier. The kernel has paused it.",
        "",
        "Technical detail:",
        f"syscall: {syscall}  |  rule: KOS-028 SCMP_ACT_NOTIFY tier",
        "",
        "Reply with one word:",
        f"  ALLOW {approval_id} — permit this call, agent continues",
        f"  STOP {approval_id}  — deny, agent receives EPERM",
        "",
        "Expires: 10 min (silence = STOP)",
    ])


def _notify_recv(notify_fd: int) -> Optional[Tuple[int, int, int, Tuple[int, ...]]]:
    """
    Read one pending seccomp notification.
    Returns (notif_id, pid, syscall_nr, syscall_args_6tuple) or None on error.
    syscall_args_6tuple mirrors the 6 args in struct seccomp_notif.
    Blocks until a notification arrives (caller should poll first).
    """
    buf = bytearray(_NOTIF_SIZE)
    arr = (ctypes.c_uint8 * _NOTIF_SIZE).from_buffer(buf)
    ret = _libc.ioctl(notify_fd, ctypes.c_ulong(SECCOMP_IOCTL_NOTIF_RECV), arr)
    if ret != 0:
        errno = ctypes.get_errno()
        sys.stderr.write(f"[kavachos:supervisor] NOTIF_RECV failed: errno={errno}\n")
        return None
    # struct seccomp_notif: id(Q) pid(I) flags(I) nr(i) arch(I) ip(Q) args[0..5](6Q)
    fields = struct.unpack(_NOTIF_PACK, bytes(buf))
    notif_id, _pid, _flags, nr = fields[0], fields[1], fields[2], fields[3]
    syscall_args = tuple(fields[6:12])  # 6 syscall arguments
    return notif_id, _pid, nr, syscall_args


def _read_procmem_str(pid: int, addr: int, max_len: int = 512) -> Optional[str]:
    """
    Read a null-terminated string from tracee process memory.
    Used to resolve execve pathname from syscall arg0. @rule:KOS-047
    """
    if addr == 0:
        return None
    try:
        with open(f"/proc/{pid}/mem", "rb") as f:
            f.seek(addr)
            data = f.read(max_len)
        null_pos = data.find(b"\x00")
        chunk = data[:null_pos] if null_pos >= 0 else data
        return chunk.decode("utf-8", errors="replace")
    except Exception:
        return None


# Syscall numbers for execve/execveat on x86_64
_NR_EXECVE    = 59
_NR_EXECVEAT  = 322


def _auto_decide_exec(
    pid: int,
    syscall_nr: int,
    syscall_args: Tuple[int, ...],
    allowlist_path: Optional[str],
) -> Tuple[bool, str]:
    """
    Auto-ALLOW/DENY execve/execveat from the exec allowlist. @rule:KOS-047
    Returns (allow: bool, reason: str).
    No Telegram escalation — exec decisions are too fast for human-in-loop.
    """
    if allowlist_path is None:
        return True, "no allowlist configured — allow (strict_exec not active)"

    # Resolve binary path.
    # execve:  arg0 = filename ptr in tracee memory.
    # execveat: arg1 = filename ptr; arg0 = dirfd; arg4 = flags.
    #   Special case: AT_EMPTY_PATH (0x1000) — path is empty, binary is the dirfd itself.
    #   Must resolve via /proc/{pid}/fd/{dirfd} readlink, not from arg1 (which is empty/null).
    AT_EMPTY_PATH = 0x1000
    binary: Optional[str] = None

    if syscall_nr == _NR_EXECVEAT:
        flags = syscall_args[4] if len(syscall_args) > 4 else 0
        if flags & AT_EMPTY_PATH:
            dirfd = syscall_args[0]
            try:
                binary = os.readlink(f"/proc/{pid}/fd/{dirfd}")
            except Exception:
                binary = None
        else:
            addr = syscall_args[1]
            binary = _read_procmem_str(pid, addr)
    else:
        addr = syscall_args[0]
        binary = _read_procmem_str(pid, addr)

    if not binary:
        # Fallback: read /proc/{pid}/exe (the *current* binary, not the target —
        # only useful for sub-exec chains, but better than denying blindly)
        try:
            binary = os.readlink(f"/proc/{pid}/exe")
        except Exception:
            pass

    if not binary:
        return False, "DENY: could not resolve binary path"

    try:
        with open(allowlist_path) as f:
            allowlist = json.load(f)
        allowed_paths = {e["path"] for e in allowlist.get("allow", [])}
        prefixes = [e["path"][:-1] for e in allowlist.get("allow", []) if e["path"].endswith("*")]
    except Exception as e:
        sys.stderr.write(f"[kavachos:exec] allowlist load error: {e} — allow by default\n")
        return True, f"allowlist error — allow: {e}"

    if binary in allowed_paths:
        return True, f"ALLOW: {binary} in exec allowlist"
    if any(binary.startswith(p) for p in prefixes):
        return True, f"ALLOW: {binary} matches prefix allowlist"

    return False, f"DENY: {binary!r} not in exec allowlist for agent_type={allowlist.get('agent_type','?')}"


def _notify_send(notify_fd: int, notif_id: int, allow: bool) -> None:
    """
    Respond to kernel: ALLOW (continue) or DENY (EPERM).
    @rule:KOS-026 silence = STOP — caller must call this; never let it time out silently.
    """
    if allow:
        resp = struct.pack(_RESP_PACK, notif_id, 0, 0, SECCOMP_USER_NOTIF_FLAG_CONTINUE)
    else:
        resp = struct.pack(_RESP_PACK, notif_id, 0, -1, 0)  # error=-EPERM
    arr = (ctypes.c_uint8 * _RESP_SIZE).from_buffer(bytearray(resp))
    ret = _libc.ioctl(notify_fd, ctypes.c_ulong(SECCOMP_IOCTL_NOTIF_SEND), arr)
    if ret != 0:
        errno = ctypes.get_errno()
        # ENOENT means the tracee already died — not an error
        if errno != 2:
            sys.stderr.write(f"[kavachos:supervisor] NOTIF_SEND failed: errno={errno}\n")


def run_supervisor(notify_fd: int, agent_pid: int,
                   session_id: str, agent_id: str, domain: str,
                   exec_allowlist_path: Optional[str] = None) -> int:
    """
    @rule:KOS-028 supervisor loop — runs in parent process, no seccomp filter.
    Uses poll() so POLLHUP (child exited) is detected cleanly without racing
    against waitpid(WNOHANG) — the root cause of the POLLHUP infinite-loop bug.
    Returns child exit code.
    """
    import random, string

    config = _read_aegis_config()
    db_path = _aegis_db_path()

    sys.stderr.write(
        f"[kavachos:supervisor] Phase 1D active — agent_pid={agent_pid} "
        f"session={session_id} domain={domain}\n"
    )

    poller = select.poll()
    poller.register(notify_fd, select.POLLIN | select.POLLHUP | select.POLLERR)

    while True:
        try:
            events = poller.poll(200)  # 200 ms
        except (ValueError, OSError):
            break  # fd closed externally

        for _fd, event in events:
            if event & (select.POLLHUP | select.POLLERR):
                # Child exited — collect it (blocking is safe; it's already gone)
                try:
                    _, wstatus = os.waitpid(agent_pid, 0)
                    code = os.WEXITSTATUS(wstatus) if os.WIFEXITED(wstatus) else 1
                except ChildProcessError:
                    code = 0
                os.close(notify_fd)
                return code

            if event & select.POLLIN:
                result = _notify_recv(notify_fd)
                if result is None:
                    continue  # ioctl failed (e.g. EINTR) — retry

                notif_id, pid, nr, syscall_args = result
                syscall = syscall_name(nr)
                approval_id = "KOS-" + "".join(random.choices(string.hexdigits.upper(), k=8))

                # @rule:KOS-047 execve/execveat: auto-ALLOW/DENY from exec allowlist
                # No Telegram — exec decisions are sub-millisecond, no human-in-loop possible.
                if nr in (_NR_EXECVE, _NR_EXECVEAT):
                    allow, reason = _auto_decide_exec(pid, nr, syscall_args, exec_allowlist_path)
                    sys.stderr.write(
                        f"[kavachos:exec] AUTO {'ALLOW' if allow else 'DENY'} "
                        f"syscall={syscall} pid={pid} — {reason}\n"
                    )
                    _notify_send(notify_fd, notif_id, allow)
                    continue  # no Telegram, no approval record — just log

                sys.stderr.write(
                    f"[kavachos:supervisor] GATED syscall={syscall} pid={pid} "
                    f"approval={approval_id}\n"
                )

                # Escalate in a daemon thread so the main loop stays responsive
                # to further notifications or POLLHUP.
                def _escalate(aid=approval_id, sc=syscall, p=pid, nid=notif_id):
                    _create_approval(db_path, aid, session_id, sc, p, domain)
                    msg = _build_notify_message(sc, agent_id, session_id, domain, p, aid)
                    _send_telegram(config, msg, aid)
                    allow = _poll_approval(db_path, aid)
                    verb = "ALLOW" if allow else "DENY"
                    sys.stderr.write(f"[kavachos:supervisor] {verb} {aid} — syscall={sc}\n")
                    _notify_send(notify_fd, nid, allow)

                threading.Thread(target=_escalate, daemon=True).start()

        if not events:
            # Timeout — backup liveness check in case POLLHUP was missed
            try:
                wpid, wstatus = os.waitpid(agent_pid, os.WNOHANG)
                if wpid == agent_pid:
                    os.close(notify_fd)
                    return os.WEXITSTATUS(wstatus) if os.WIFEXITED(wstatus) else 1
            except ChildProcessError:
                os.close(notify_fd)
                return 0

    # Unreachable in normal operation — belt-and-suspenders cleanup
    try:
        os.close(notify_fd)
    except OSError:
        pass
    try:
        _, wstatus = os.waitpid(agent_pid, os.WNOHANG)
        return os.WEXITSTATUS(wstatus) if os.WIFEXITED(wstatus) else 1
    except ChildProcessError:
        return 0

# ── Profile context builder ────────────────────────────────────────────────────

def resolve_syscall(name: str) -> int:
    return _lib.seccomp_syscall_resolve_name(name.encode())


_NO_FREEZE_REQUIRED = {"exit_group", "exit", "futex", "rt_sigreturn", "restart_syscall"}


def build_ctx(profile: dict):
    """
    Build (but do NOT load) a libseccomp context from a KavachOS profile.
    Returns (ctx, has_notify) — ctx must be loaded in the child after fork.
    """
    if profile.get("defaultAction") == "SCMP_ACT_KILL":
        sys.stderr.write("[kavachos] FATAL: defaultAction SCMP_ACT_KILL is banned — use SCMP_ACT_ERRNO\n")
        sys.exit(1)

    allowed: List[str] = []
    notify_names: List[str] = []

    for entry in profile.get("syscalls", []):
        action = entry.get("action", "")
        names  = entry.get("names", [])
        if action == "SCMP_ACT_ALLOW":
            allowed.extend(names)
        elif action == "SCMP_ACT_NOTIFY":
            notify_names.extend(names)

    if not allowed:
        sys.stderr.write("[kavachos] FATAL: profile has no allowed syscalls\n")
        sys.exit(1)

    allowed_set = set(allowed)
    missing = _NO_FREEZE_REQUIRED - allowed_set
    if missing:
        sys.stderr.write(
            f"[kavachos] FATAL: profile missing no-freeze syscalls: {', '.join(sorted(missing))}\n"
        )
        sys.exit(1)

    kavachos_meta = profile.get("_kavachos", {})
    sys.stderr.write(
        f"[kavachos] Building seccomp context: trust_mask=0x{kavachos_meta.get('trust_mask', 0):08x} "
        f"domain={kavachos_meta.get('domain', 'unknown')} "
        f"allow={len(allowed)} notify={len(notify_names)}\n"
    )

    if _libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        sys.stderr.write("[kavachos] WARNING: PR_SET_NO_NEW_PRIVS failed\n")

    ctx = _lib.seccomp_init(SCMP_ACT_ERRNO)
    if not ctx:
        sys.stderr.write("[kavachos] FATAL: seccomp_init returned NULL\n")
        sys.exit(1)

    unknown: List[str] = []
    added = 0

    for name in allowed:
        nr = resolve_syscall(name)
        if nr < 0:
            unknown.append(name)
            continue
        ret = _lib.seccomp_rule_add(ctx, SCMP_ACT_ALLOW, nr, 0)
        if ret == 0:
            added += 1

    for name in notify_names:
        nr = resolve_syscall(name)
        if nr < 0:
            continue
        _lib.seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, nr, 0)

    if unknown:
        sys.stderr.write(f"[kavachos] INFO: {len(unknown)} unknown syscalls skipped: {', '.join(unknown[:10])}\n")

    return ctx, len(notify_names) > 0


def load_ctx_and_get_notify_fd(ctx) -> int:
    """
    Load the seccomp context (applies filter to calling process).
    Returns notify_fd if NOTIFY rules were added, else -1.
    Must be called in the CHILD after fork.
    """
    ret = _lib.seccomp_load(ctx)
    if ret != 0:
        sys.stderr.write(f"[kavachos] FATAL: seccomp_load failed: errno={-ret}\n")
        _lib.seccomp_release(ctx)
        sys.exit(1)

    notify_fd = _lib.seccomp_notify_fd(ctx)
    _lib.seccomp_release(ctx)

    # notify_fd == -22 (EINVAL) means no NOTIFY rules were added
    return notify_fd if notify_fd >= 0 else -1

# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    args = sys.argv[1:]

    try:
        sep_idx = args.index("--")
    except ValueError:
        sys.stderr.write("Usage: apply-seccomp.py <profile.json> -- <command> [args...]\n")
        sys.exit(1)

    profile_path = args[sep_idx - 1] if sep_idx > 0 else None
    exec_args = args[sep_idx + 1:]

    if not profile_path or not exec_args:
        sys.stderr.write("Usage: apply-seccomp.py <profile.json> -- <command> [args...]\n")
        sys.exit(1)

    if not os.path.exists(profile_path):
        sys.stderr.write(f"[kavachos] FATAL: profile not found: {profile_path}\n")
        sys.exit(1)

    with open(profile_path) as f:
        profile = json.load(f)

    # Build context before fork (pre-flight checks + libseccomp ctx allocation)
    ctx, has_notify = build_ctx(profile)

    session_id          = os.environ.get("KAVACHOS_SESSION_ID",      "unknown")
    agent_id            = os.environ.get("KAVACHOS_AGENT_ID",        session_id)
    domain              = os.environ.get("KAVACHOS_DOMAIN",          "unknown")
    # @rule:KOS-047 exec allowlist path — written by runner.ts when strict_exec=true
    exec_allowlist_path = os.environ.get("KAVACHOS_EXEC_ALLOWLIST")  # None = strict_exec off

    if not has_notify:
        # ── Phase 1A path (no NOTIFY syscalls) — load and exec directly ──────
        ret = _lib.seccomp_load(ctx)
        _lib.seccomp_release(ctx)
        if ret != 0:
            sys.stderr.write(f"[kavachos] FATAL: seccomp_load failed: errno={-ret}\n")
            sys.exit(1)
        sys.stderr.write(f"[kavachos] seccomp active (no notify tier)\n")
        try:
            os.execvp(exec_args[0], exec_args)
        except FileNotFoundError:
            sys.stderr.write(f"[kavachos] FATAL: command not found: {exec_args[0]}\n")
            sys.exit(1)
        except PermissionError as e:
            sys.stderr.write(f"[kavachos] FATAL: permission denied: {e}\n")
            sys.exit(1)
        return  # unreachable after execvp

    # ── Phase 1D path — fork, child loads+execs, parent supervises ───────────
    # socketpair for notify_fd transfer (SCM_RIGHTS)
    sock_recv, sock_send = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)

    pid = os.fork()

    if pid == 0:
        # ── CHILD: load seccomp, send notify_fd to parent, exec agent ────────
        sock_recv.close()

        notify_fd = load_ctx_and_get_notify_fd(ctx)

        if notify_fd >= 0:
            _send_fd(sock_send, notify_fd)
            os.close(notify_fd)

        sock_send.close()

        sys.stderr.write(
            f"[kavachos] seccomp active (Phase 1D — notify tier live, supervisor pid={os.getppid()})\n"
        )

        try:
            os.execvp(exec_args[0], exec_args)
        except FileNotFoundError:
            sys.stderr.write(f"[kavachos] FATAL: command not found: {exec_args[0]}\n")
            os._exit(1)
        except PermissionError as e:
            sys.stderr.write(f"[kavachos] FATAL: permission denied: {e}\n")
            os._exit(1)
        os._exit(1)  # unreachable

    else:
        # ── PARENT: receive notify_fd, supervise, wait for child ──────────────
        sock_send.close()
        _lib.seccomp_release(ctx)

        try:
            notify_fd = _recv_fd(sock_recv, timeout=10.0)
        except Exception as e:
            sys.stderr.write(f"[kavachos:supervisor] Could not receive notify_fd: {e}\n")
            # Fall back: just wait for child (no notify supervision)
            sock_recv.close()
            _, wstatus = os.waitpid(pid, 0)
            sys.exit(os.WEXITSTATUS(wstatus))

        sock_recv.close()

        exit_code = run_supervisor(notify_fd, pid, session_id, agent_id, domain, exec_allowlist_path)
        sys.exit(exit_code)


if __name__ == "__main__":
    main()
