#!/bin/sh
# Do the IPv6 egress fixes (E-1, E-2, E-3) actually ENFORCE on aarch64?
#
# The x86_64 suite (aegis/tests/test-e1e2e3-v6-egress.py) proved these on the host that
# wrote them. This asks the only question that matters for the edge port: does a real
# arm64 kernel behave the same? seccomp and cgroup BPF are kernel objects, and the v6
# key is a struct laid out in memory — the one thing in this fix that could plausibly
# differ across architectures is exactly the thing being changed.
#
# Hermetic. Two loopback listeners, no internet, no DNS in the assertion path.
#
#   ::1          low 32 bits = 0x00000001
#   2001:db8::1  low 32 bits = 0x00000001   <- the E-1 collider, unroutable by design
#
# Under the ORIGINAL 32-bit key those two were the SAME allowlist entry. Under the fix
# the collider must be refused while ::1 still connects.
#
# NO PREBUILT OBJECT IS STAGED, deliberately: the guest compiles from the source under
# test, so this cannot pass against a stale object the way the host run first did.
echo "arch:   $(uname -m)"
echo "kernel: $(uname -r)"
echo

fails=0
for t in clang bpftool python3; do
  if command -v "$t" >/dev/null; then echo "  [ok  ] prerequisite present: $t"
  else echo "  [FAIL] prerequisite MISSING: $t — this run would measure nothing"; fails=$((fails+1)); fi
done
if grep -q cgroup2 /proc/mounts; then echo "  [ok  ] cgroup v2 mounted"
else echo "  [FAIL] cgroup v2 NOT mounted"; fails=$((fails+1)); fi
[ "$fails" -eq 0 ] || { echo; echo "RESULT: $fails failure(s) — prerequisites"; exit 1; }

python3 - <<'PY'
import importlib.util, os, socket, sys, threading, time

spec = importlib.util.spec_from_file_location("ce", "/hostshare/cgroup-egress.py")
ce = importlib.util.module_from_spec(spec); spec.loader.exec_module(ce)

fails = 0
def check(label, ok, detail=""):
    global fails
    print(f"  [{'ok  ' if ok else 'FAIL'}] {label}" + (f" — {detail}" if detail else ""))
    if not ok: fails += 1

# ── the escape hatches, proven shut before anything below means anything ────
check("_is_available() is True (the firewall is not silently disabled)", ce._is_available())
check("no prebuilt connect6.o is being used (the guest compiles the source under test)",
      ce._prebuilt_obj("connect6") is None,
      "a prebuilt would let this pass against code that is not in the tree")

# An IPv6 stack must actually exist, or every 'denied' below is just a broken stack.
try:
    _p = socket.socket(socket.AF_INET6, socket.SOCK_STREAM); _p.close()
    check("AF_INET6 sockets work in this guest", True)
except Exception as e:
    check("AF_INET6 sockets work in this guest", False, f"{type(e).__name__}")
if fails:
    print(f"\nRESULT: {fails} failure(s) — preconditions"); sys.exit(1)

V6_ALLOW, V6_DENY, V4_PORT = 9201, 9202, 9203
COLLIDER = "2001:db8::1"      # same low 32 bits as ::1

def listen(family, addr, port):
    s = socket.socket(family, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((addr, port)); s.listen(8)
    threading.Thread(target=lambda: [s.accept() for _ in iter(int, 1)], daemon=True).start()
    return s

held = [listen(socket.AF_INET6, "::1", V6_ALLOW),
        listen(socket.AF_INET6, "::1", V6_DENY),
        listen(socket.AF_INET,  "127.0.0.1", V4_PORT)]
time.sleep(0.3)

def attempt(host, port, family=socket.AF_INET6):
    s = socket.socket(family, socket.SOCK_STREAM); s.settimeout(3)
    try:
        s.connect((host, port)); return "CONNECTED"
    except PermissionError:
        return "EPERM"
    except OSError as e:
        import errno as E
        return "EPERM" if e.errno == E.EPERM else f"other:{E.errorcode.get(e.errno, e.errno)}"
    finally:
        s.close()

# ── E-2, before arming anything for real ────────────────────────────────────
real = ce._obtain_bpf
ce._obtain_bpf = lambda src, name, out: False if name == "connect6" else real(src, name, out)
s_ref = ce.EgressSession("arm64-v6-refuse")
try:
    armed = s_ref.setup({"allow": []}, None)
finally:
    s_ref.cleanup()
check("E-2: an undeclared v6 failure REFUSES to arm", armed is False, f"setup() returned {armed}")

s_v4 = ce.EgressSession("arm64-v6-v4only", v4_only=True)
try:
    a4 = s_v4.setup({"allow": []}, None)
    fam4 = s_v4.enforced_families()
finally:
    s_v4.cleanup()
check("E-2: a DECLARED v4-only session still arms", a4 is True)
check("E-2: and its receipt records ipv6 as not enforced", fam4.get("ipv6") is False)
ce._obtain_bpf = real

# ── the real session ────────────────────────────────────────────────────────
policy = {"allow": [
    {"host": "::1",       "port": V6_ALLOW, "note": "v6 loopback, allowed"},
    {"host": "127.0.0.1", "port": V4_PORT,  "note": "v4 loopback, reached dual-stack"},
    # E-3 is only tested if the resolver IS on the list. Without this the refusal below
    # would merely mean "port 53 was never allowed", which proves nothing.
    {"host": "::1",       "port": 53,       "note": "a resolver on the allowlist"},
]}
sess = ce.EgressSession("arm64-v6-keywidth")
armed = sess.setup(policy, None)
check("the session arms with both families", armed is True)
if not armed:
    sess.cleanup(); print(f"\nRESULT: {fails} failure(s)"); sys.exit(1)

fam = sess.enforced_families()
check("both address families are enforced", fam.get("complete") and fam.get("ipv6"))

open(os.path.join(sess.cgroup_path, "cgroup.procs"), "w").write(str(os.getpid()))
try:
    # The ALLOW cases are not decoration: a key-layout mismatch fails CLOSED, so a
    # deny-only harness passes while enforcing nothing. These prove the struct written
    # by Python is the struct the arm64 kernel looks up.
    r = attempt("::1", V6_ALLOW)
    check("allowed [::1]:%d CONNECTS (the 20-byte key round-trips on arm64)" % V6_ALLOW,
          r == "CONNECTED", r)

    r = attempt("::ffff:127.0.0.1", V4_PORT)
    check("a v4-mapped allowed host CONNECTS (dual-stack not broken by the widening)",
          r == "CONNECTED", r)

    r = attempt(COLLIDER, V6_ALLOW)
    check("E-1: the low-32 collider %s is DENIED" % COLLIDER, r == "EPERM", r)

    r = attempt("::1", V6_DENY)
    check("an unlisted v6 port is denied", r == "EPERM", r)

    r = attempt("::1", 53)
    check("E-3: DNS over v6 is refused even though the resolver is allowlisted",
          r == "EPERM", r)
finally:
    sess.cleanup()

# The block must not outlive its session, or a 'denied' above could be ambient.
r = attempt("::1", V6_DENY)
check("after cleanup the denied port connects again (no leaked block)", r == "CONNECTED", r)

for h in held:
    try: h.close()
    except Exception: pass

print()
print(f"RESULT: {fails} failure(s)")
sys.exit(1 if fails else 0)
PY
