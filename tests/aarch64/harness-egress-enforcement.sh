#!/bin/sh
# Does the cgroup BPF connect4 egress firewall actually ENFORCE on aarch64?
#
# The load-bearing claim of the edge port. Everything else about this layer is
# userspace; this is the part that is a kernel object and therefore the part that
# could behave differently on another architecture.
#
# Hermetic: two TCP listeners on loopback, one port allowed by policy and one not.
# No internet, no DNS, no external dependency in the assertion path.
echo "arch:   $(uname -m)"
echo "kernel: $(uname -r)"
echo

# ── Prerequisites are ASSERTED, never assumed ────────────────────────────────
# cgroup-egress.py degrades gracefully when clang/bpftool/cgroupv2 are missing:
# it writes UNAVAILABLE and exits 0. That is right for production and fatal for a
# test — a guest without the tools would "pass" this harness while measuring
# nothing. So the harness proves the tools are there before it proves anything else.
fails=0
for t in clang bpftool python3; do
  if command -v "$t" >/dev/null; then echo "  [ok  ] prerequisite present: $t"
  else echo "  [FAIL] prerequisite MISSING: $t — this run would measure nothing"; fails=$((fails+1)); fi
done
if grep -q cgroup2 /proc/mounts; then echo "  [ok  ] cgroup v2 mounted"
else echo "  [FAIL] cgroup v2 NOT mounted"; fails=$((fails+1)); fi
[ "$fails" -eq 0 ] || { echo; echo "RESULT: $fails failure(s) — prerequisites"; exit 1; }

python3 - <<'PY'
import importlib.util, json, os, socket, subprocess, sys, tempfile, threading, time

spec = importlib.util.spec_from_file_location("ce", "/hostshare/cgroup-egress.py")
ce = importlib.util.module_from_spec(spec); spec.loader.exec_module(ce)

fails = 0
def check(label, ok, detail=""):
    global fails
    print(f"  [{'ok  ' if ok else 'FAIL'}] {label}" + (f" — {detail}" if detail else ""))
    if not ok: fails += 1

# The escape hatch must be proven CLOSED before any result below means anything.
check("_is_available() is True (the firewall is not silently disabled)", ce._is_available())
if fails: print(f"\nRESULT: {fails} failure(s)"); sys.exit(1)

ALLOW_PORT, DENY_PORT = 9101, 9102
def listener(port):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port)); s.listen(8)
    threading.Thread(target=lambda: [s.accept() for _ in iter(int, 1)], daemon=True).start()
    return s
la, ld = listener(ALLOW_PORT), listener(DENY_PORT)

policy = {"allow": [{"host": "127.0.0.1", "port": ALLOW_PORT, "note": "the one permitted destination"}]}
pf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False); json.dump(policy, pf); pf.close()

sess = ce.EgressSession("arm64-harness")
try:
    ok = sess.setup(policy, os.getpid())     # move THIS process into the cgroup
    check("BPF program loads and attaches on aarch64", ok)
    if not ok:
        print(f"\nRESULT: {fails} failure(s)"); sys.exit(1)
    check("connect4 program id is real", sess.prog_id_v4 > 0, f"prog_id={sess.prog_id_v4}")

    def try_connect(port):
        s = socket.socket(); s.settimeout(3)
        try:
            s.connect(("127.0.0.1", port)); s.close(); return None
        except Exception as e:
            return type(e).__name__
        finally:
            try: s.close()
            except Exception: pass

    # BOTH directions, which is the whole point: a firewall that blocks everything
    # passes a deny-test and is still broken.
    allowed_err = try_connect(ALLOW_PORT)
    denied_err  = try_connect(DENY_PORT)
    check("an ALLOWED destination still connects", allowed_err is None,
          f"got {allowed_err}" if allowed_err else "connected")
    check("a DENIED destination is refused by the kernel", denied_err is not None,
          f"blocked with {denied_err}" if denied_err else "CONNECTED — the firewall did not enforce")
finally:
    try: sess.cleanup()
    except Exception as e: print(f"  [warn] cleanup raised {type(e).__name__}: {e}")
    for s in (la, ld):
        try: s.close()
        except Exception: pass
    os.unlink(pf.name)

# After cleanup the same connect must SUCCEED — proving the refusal above came from
# this attachment and not from something ambient in the guest. A block that outlives
# its session is a leak, and would show up here as PermissionError.
#
# The listeners are deliberately still up: their accept threads hold a reference, so
# close() does not free the port. The first version of this check assumed the opposite
# and scored the correct outcome as a failure — the harness was wrong, not the firewall.
s = socket.socket(); s.settimeout(3)
try:
    s.connect(("127.0.0.1", DENY_PORT))
    check("after cleanup the previously denied port connects (no leaked block)", True, "connected")
except PermissionError:
    check("after cleanup the previously denied port connects (no leaked block)", False,
          "PermissionError — the BPF block OUTLIVED the session")
except Exception as e:
    check("after cleanup the previously denied port connects (no leaked block)", False,
          f"inconclusive: {type(e).__name__}")
finally:
    s.close()

print()
print(f"RESULT: {fails} failure(s)")
sys.exit(1 if fails else 0)
PY
