#!/bin/sh
# What belongs in a runtime reference manifest: the object's bytes, or the kernel's tag?
#
# An object compiled on a different host has different bytes — different clang, different
# paths baked into debug info. If the manifest published a byte digest, an operator who
# rebuilt from source would see a mismatch and conclude tampering. The kernel's program
# tag is computed from the loaded instruction stream, so it may be stable where the bytes
# are not. This decides which value is publishable in advance.
echo "arch: $(uname -m)"
echo
python3 - <<'PY'
import hashlib, importlib.util, json, os, subprocess, sys
spec = importlib.util.spec_from_file_location("ce", "/hostshare/cgroup-egress.py")
ce = importlib.util.module_from_spec(spec); spec.loader.exec_module(ce)

fails = 0
def check(label, ok, detail=""):
    global fails
    print(f"  [{'ok  ' if ok else 'FAIL'}] {label}" + (f" — {detail}" if detail else ""))
    if not ok: fails += 1

def tag_of(objpath):
    pin = "/sys/fs/bpf/tagprobe"
    subprocess.run(["rm", "-rf", pin], capture_output=True)
    r = subprocess.run(["bpftool", "prog", "load", objpath, pin], capture_output=True, text=True)
    if r.returncode != 0:
        return None, r.stderr.strip()[:120]
    s = subprocess.run(["bpftool", "-j", "prog", "show", "pinned", pin],
                       capture_output=True, text=True)
    subprocess.run(["rm", "-rf", pin], capture_output=True)
    if s.returncode != 0:
        return None, s.stderr.strip()[:120]
    return json.loads(s.stdout).get("tag"), None

x86_obj = "/tmp/x86.o"
import shutil; shutil.copyfile("/hostshare/bpf/connect4.o", x86_obj)
x86_bytes = hashlib.sha256(open(x86_obj, "rb").read()).hexdigest()

native = "/tmp/native.o"
built = ce._compile_bpf(ce._BPF_CONNECT4_C, native)
check("the same source compiles natively on aarch64", built)
if not built:
    print(f"\nRESULT: {fails} failure(s)"); sys.exit(1)
native_bytes = hashlib.sha256(open(native, "rb").read()).hexdigest()

check("the two objects have DIFFERENT bytes (so bytes are not publishable)",
      x86_bytes != native_bytes, f"x86 {x86_bytes[:16]}… vs native {native_bytes[:16]}…")

t1, e1 = tag_of(x86_obj)
t2, e2 = tag_of(native)
check("x86-built object loads and reports a tag", bool(t1), t1 or e1)
check("natively-built object loads and reports a tag", bool(t2), t2 or e2)
if t1 and t2:
    same = t1 == t2
    check("the kernel TAG is identical across build hosts" if same
          else "the kernel tag DIFFERS across build hosts (so the tag is not publishable either)",
          True, f"x86={t1} native={t2}")
    print()
    print("  VERDICT for a runtime reference manifest:")
    if same:
        print("    publish the TAG. It survives a rebuild on a different host; the object")
        print("    bytes do not. An operator can rebuild from source and still match.")
    else:
        print("    neither the bytes nor the tag survive a rebuild on a different host, so")
        print("    a manifest must pin the SHIPPED OBJECT and say so — an operator cannot")
        print("    confirm it by rebuilding, only by comparing against what was published.")
print()
print(f"RESULT: {fails} failure(s)")
sys.exit(1 if fails else 0)
PY
