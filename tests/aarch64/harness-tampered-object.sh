#!/bin/sh
# A prebuilt object whose digest does not match must be REFUSED — never used, and never
# silently compiled around, because a quiet fallback to clang would hide exactly the
# substitution the sidecar exists to catch.
OBJDIR=/tmp/kavachos-bpf; rm -rf $OBJDIR; mkdir -p $OBJDIR
cp /hostshare/bpf/* $OBJDIR/
echo "arch: $(uname -m)"
echo
python3 - <<'PY'
import importlib.util, os, sys
spec = importlib.util.spec_from_file_location("ce", "/hostshare/cgroup-egress.py")
ce = importlib.util.module_from_spec(spec); spec.loader.exec_module(ce)
os.environ["KAVACHOS_BPF_OBJ_DIR"] = "/tmp/kavachos-bpf"
ce.BPF_OBJ_DIR = "/tmp/kavachos-bpf"

fails = 0
def check(label, ok, detail=""):
    global fails
    print(f"  [{'ok  ' if ok else 'FAIL'}] {label}" + (f" — {detail}" if detail else ""))
    if not ok: fails += 1

check("an untampered object is accepted", bool(ce._prebuilt_obj("connect4")))

# flip one byte in the middle of the instruction stream
p = "/tmp/kavachos-bpf/connect4.o"
b = bytearray(open(p, "rb").read()); b[len(b)//2] ^= 0xFF
open(p, "wb").write(bytes(b))

check("a TAMPERED object is refused", ce._prebuilt_obj("connect4") is None)

# and with no compiler to fall back to, the layer must report itself unavailable
clang = None
for d in os.environ.get("PATH", "").split(":"):
    c = os.path.join(d, "clang")
    if os.path.exists(c): clang = c; break
if clang:
    os.rename(clang, clang + ".hidden")
    try:
        check("tampered object + no compiler = UNAVAILABLE, not a silent pass",
              ce._is_available() is False)
    finally:
        os.rename(clang + ".hidden", clang)
else:
    check("clang present for the control", False, "not found")

print()
print(f"RESULT: {fails} failure(s)")
sys.exit(1 if fails else 0)
PY
