#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
# @rule:KOS-011 kavachos run — only approved agent launch path
# @rule:KOS-006 seccomp filter applied before exec — inherited by children, immutable after

"""
apply-seccomp.py — KavachOS libseccomp launcher

Reads a KavachOS seccomp profile JSON, builds a libseccomp filter,
applies it via prctl(PR_SET_SECCOMP), then exec()s the agent command.

Usage: python3 apply-seccomp.py <profile.json> -- <agent_command> [args...]

The profile must be in Docker/OCI seccomp format with a KavachOS _kavachos metadata block.
Unknown syscalls are resolved via seccomp_syscall_resolve_name() — no hardcoded numbers.
"""

import ctypes
import ctypes.util
import json
import os
import sys
from typing import List

# --- libseccomp bindings ---

_LIB_PATH = ctypes.util.find_library("seccomp")
if not _LIB_PATH:
    _LIB_PATH = "libseccomp.so.2"  # fallback direct path

try:
    _lib = ctypes.CDLL(_LIB_PATH)
except OSError as e:
    sys.stderr.write(f"[kavachos] FATAL: cannot load libseccomp: {e}\n")
    sys.exit(1)

# Action constants (from seccomp.h)
SCMP_ACT_KILL   = ctypes.c_uint32(0x00000000)
SCMP_ACT_ERRNO  = ctypes.c_uint32(0x00050001)  # ERRNO(EPERM=1)
SCMP_ACT_ALLOW  = ctypes.c_uint32(0x7fff0000)

# seccomp_init(uint32_t def_action) -> scmp_filter_ctx (void*)
_lib.seccomp_init.restype  = ctypes.c_void_p
_lib.seccomp_init.argtypes = [ctypes.c_uint32]

# seccomp_rule_add(ctx, action, syscall_nr, arg_cnt) -> int
_lib.seccomp_rule_add.restype  = ctypes.c_int
_lib.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]

# seccomp_load(ctx) -> int
_lib.seccomp_load.restype  = ctypes.c_int
_lib.seccomp_load.argtypes = [ctypes.c_void_p]

# seccomp_release(ctx) -> void
_lib.seccomp_release.restype  = None
_lib.seccomp_release.argtypes = [ctypes.c_void_p]

# seccomp_syscall_resolve_name(name) -> int (syscall number, -1 if unknown)
_lib.seccomp_syscall_resolve_name.restype  = ctypes.c_int
_lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]

# prctl(PR_SET_NO_NEW_PRIVS, ...) via libc
_libc_path = ctypes.util.find_library("c") or "libc.so.6"
_libc = ctypes.CDLL(_libc_path)
_libc.prctl.restype  = ctypes.c_int
_libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
PR_SET_NO_NEW_PRIVS = 38


def resolve_syscall(name: str) -> int:
    nr = _lib.seccomp_syscall_resolve_name(name.encode())
    return nr  # -1 means unknown — caller decides whether to skip or abort


def apply_profile(profile_path: str) -> None:
    with open(profile_path) as f:
        profile = json.load(f)

    if profile.get("defaultAction") != "SCMP_ACT_ERRNO":
        sys.stderr.write(f"[kavachos] WARNING: profile defaultAction is {profile.get('defaultAction')}, expected SCMP_ACT_ERRNO\n")

    # Collect allowed syscall names from profile
    allowed: List[str] = []
    for entry in profile.get("syscalls", []):
        if entry.get("action") == "SCMP_ACT_ALLOW":
            allowed.extend(entry.get("names", []))

    if not allowed:
        sys.stderr.write("[kavachos] FATAL: profile has no allowed syscalls\n")
        sys.exit(1)

    kavachos_meta = profile.get("_kavachos", {})
    sys.stderr.write(
        f"[kavachos] Applying seccomp profile: trust_mask=0x{kavachos_meta.get('trust_mask', 0):08x} "
        f"domain={kavachos_meta.get('domain', 'unknown')} "
        f"syscalls={len(allowed)}\n"
    )

    # PR_SET_NO_NEW_PRIVS=1 is required before loading a seccomp filter without CAP_SYS_ADMIN
    if _libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        sys.stderr.write("[kavachos] WARNING: PR_SET_NO_NEW_PRIVS failed — may need elevated privileges\n")

    # Build the seccomp filter with default ERRNO action
    ctx = _lib.seccomp_init(SCMP_ACT_ERRNO)
    if not ctx:
        sys.stderr.write("[kavachos] FATAL: seccomp_init returned NULL\n")
        sys.exit(1)

    unknown = []
    added = 0
    for name in allowed:
        nr = resolve_syscall(name)
        if nr < 0:
            unknown.append(name)
            continue
        ret = _lib.seccomp_rule_add(ctx, SCMP_ACT_ALLOW, nr, 0)
        if ret != 0:
            sys.stderr.write(f"[kavachos] WARNING: seccomp_rule_add failed for {name} (syscall {nr}): errno {-ret}\n")
        else:
            added += 1

    if unknown:
        sys.stderr.write(f"[kavachos] INFO: {len(unknown)} unknown syscalls skipped: {', '.join(unknown[:10])}\n")

    # Load (apply) the filter — after this point the filter is active
    ret = _lib.seccomp_load(ctx)
    _lib.seccomp_release(ctx)

    if ret != 0:
        sys.stderr.write(f"[kavachos] FATAL: seccomp_load failed: errno {-ret}\n")
        sys.exit(1)

    sys.stderr.write(f"[kavachos] seccomp active: {added} syscalls allowed, {len(unknown)} unknown skipped\n")


def main() -> None:
    args = sys.argv[1:]

    # Find the '--' separator
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

    # Apply the seccomp filter
    apply_profile(profile_path)

    # exec() the agent — filter is now active and inherited
    # @rule:KOS-006 exec replaces this process, filter is inherited by the new image
    try:
        os.execvp(exec_args[0], exec_args)
    except FileNotFoundError:
        sys.stderr.write(f"[kavachos] FATAL: command not found: {exec_args[0]}\n")
        sys.exit(1)
    except PermissionError as e:
        sys.stderr.write(f"[kavachos] FATAL: permission denied executing {exec_args[0]}: {e}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
