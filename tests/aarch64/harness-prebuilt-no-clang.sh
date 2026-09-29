#!/bin/sh
# The shipping question: does the egress firewall ENFORCE on aarch64 using a BPF object
# built on x86_64, with no compiler present at all?
#
# If yes, this layer can live on a hardened image whose production profile is "read-only
# rootfs, root locked, no SSH, no debug tooling" — the class of image that most needs it
# and, until now, was the one class it could not run on.
echo "arch:   $(uname -m)"
echo "kernel: $(uname -r)"

OBJDIR=/tmp/kavachos-bpf; rm -rf $OBJDIR; mkdir -p $OBJDIR
cp /hostshare/bpf/* $OBJDIR/ 2>/dev/null || { echo "  [FAIL] no prebuilt objects supplied"; exit 1; }
echo "supplied objects (built on x86_64):"
for f in $OBJDIR/*.o; do echo "    $(basename $f) $(wc -c < $f) bytes"; done
echo

CLANG=$(command -v clang)
[ -n "$CLANG" ] || { echo "  [FAIL] clang missing before we could remove it"; exit 1; }
mv "$CLANG" "$CLANG.hidden"
trap 'mv "$CLANG.hidden" "$CLANG" 2>/dev/null' EXIT
command -v clang >/dev/null && { echo "  [FAIL] clang still on PATH"; exit 1; }
echo "  [ok  ] clang removed — there is no compiler on this machine now"

KAVACHOS_BPF_OBJ_DIR=$OBJDIR python3 - <<'PY'
import importlib.util, os, socket, sys, threading
spec = importlib.util.spec_from_file_location("ce", "/hostshare/cgroup-egress.py")
ce = importlib.util.module_from_spec(spec); spec.loader.exec_module(ce)

fails = 0
def check(label, ok, detail=""):
    global fails
    print(f"  [{'ok  ' if ok else 'FAIL'}] {label}" + (f" — {detail}" if detail else ""))
    if not ok: fails += 1

check("_is_available() is True with NO compiler (a prebuilt object satisfies it)", ce._is_available())
check("the prebuilt connect4.o is accepted (digest matches)", bool(ce._prebuilt_obj("connect4")))

def listener(port):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port)); s.listen(4)
    threading.Thread(target=lambda: [s.accept() for _ in iter(int, 1)], daemon=True).start()
    return s
la, ld = listener(9301), listener(9302)

sess = ce.EgressSession("prebuilt-no-clang")
try:
    ok = sess.setup({"allow": [{"host": "127.0.0.1", "port": 9301}]}, os.getpid())
    check("an x86-built BPF object loads and attaches on aarch64", ok, f"prog_id={sess.prog_id_v4}")
    if ok:
        def conn(p):
            s = socket.socket(); s.settimeout(3)
            try: s.connect(("127.0.0.1", p)); return None
            except Exception as e: return type(e).__name__
            finally: s.close()
        a, d = conn(9301), conn(9302)
        check("ALLOWED destination connects", a is None, a or "connected")
        check("DENIED destination refused — ENFORCING with no compiler present",
              d is not None, d or "CONNECTED, not enforcing")
finally:
    try: sess.cleanup()
    except Exception: pass
    la.close(); ld.close()

print()
print(f"RESULT: {fails} failure(s)")
sys.exit(1 if fails else 0)
PY
rc=$?
echo; echo "  (clang restored on exit)"
exit $rc
