#!/usr/bin/env bash
# Build the egress BPF objects once, for shipping to targets with no toolchain.
#
# BPF bytecode is architecture-neutral between little-endian targets, so an object built
# here loads on aarch64 as readily as on x86_64 — which is the point: a hardened image
# with "no debug tooling" can still enforce.
#
# Writes <name>.o and <name>.o.sha256 beside each other. The runtime refuses an object
# whose sidecar does not match, and refuses it OUTRIGHT rather than falling back to
# clang: a silent fallback would hide the substitution the sidecar exists to catch.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-$HERE/../../src/kernel/bpf}
mkdir -p "$OUT"
command -v clang >/dev/null || { echo "clang required to BUILD (never to run)"; exit 2; }

python3 - "$OUT" "$HERE/../../src/kernel/cgroup-egress.py" <<'PY'
import importlib.util, os, subprocess, sys, hashlib
# __file__ is "<stdin>" inside a heredoc, so the path comes from the shell, where it is
# known. Deriving it here silently resolved to "/src/kernel/..." and failed.
out, src_path = sys.argv[1], sys.argv[2]
spec = importlib.util.spec_from_file_location("ce", os.path.abspath(src_path))
ce = importlib.util.module_from_spec(spec); spec.loader.exec_module(ce)

for name, src in (("connect4", ce._BPF_CONNECT4_C), ("connect6", ce._BPF_CONNECT6_C)):
    obj = os.path.join(out, f"{name}.o")
    if not ce._compile_bpf(src, obj):
        print(f"  {name}: COMPILE FAILED"); sys.exit(1)
    d = hashlib.sha256(open(obj, "rb").read()).hexdigest()
    open(obj + ".sha256", "w").write(d + f"  {name}.o\n")
    print(f"  {name}.o  {os.path.getsize(obj)} bytes  sha256={d}")
PY
echo "built into $OUT"
