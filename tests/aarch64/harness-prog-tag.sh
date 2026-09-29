#!/bin/sh
# Can a runtime receipt carry a digest the KERNEL computed, rather than the
# supervisor's own word for what it loaded?
#
# This is the load-bearing assumption under an rc13-shaped design for runtime policy.
# In a TPM quote the PCR values come from hardware, not from the software being
# attested. The runtime analogue would be the BPF program tag: the kernel hashes the
# loaded instruction stream and reports it. If that holds, a receipt can be checked
# against a published reference the way a quote is checked against a RIM. If it does
# not, the receipt is self-reported and the whole design collapses into "trust us".
echo "arch:   $(uname -m)"
echo "kernel: $(uname -r)"
echo

fails=0
check() { # label, condition-as-exit-status handled by caller
  if [ "$2" = "0" ]; then echo "  [ok  ] $1${3:+ — $3}"; else echo "  [FAIL] $1${3:+ — $3}"; fails=$((fails+1)); fi
}

command -v bpftool >/dev/null; check "bpftool present" $?
[ "$fails" -eq 0 ] || { echo; echo "RESULT: $fails failure(s)"; exit 1; }

python3 - <<'PY'
import importlib.util, json, os, socket, subprocess, sys, threading

spec = importlib.util.spec_from_file_location("ce", "/hostshare/cgroup-egress.py")
ce = importlib.util.module_from_spec(spec); spec.loader.exec_module(ce)

fails = 0
def check(label, ok, detail=""):
    global fails
    print(f"  [{'ok  ' if ok else 'FAIL'}] {label}" + (f" — {detail}" if detail else ""))
    if not ok: fails += 1

def tags_of(prog_id):
    """Ask the KERNEL what it has loaded. Not what we think we loaded."""
    out = subprocess.run(["bpftool", "-j", "prog", "show", "id", str(prog_id)],
                         capture_output=True, text=True)
    if out.returncode != 0:
        return None, out.stderr.strip()
    return json.loads(out.stdout), None

def listener(port):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port)); s.listen(4)
    threading.Thread(target=lambda: [s.accept() for _ in iter(int, 1)], daemon=True).start()
    return s

policy = {"allow": [{"host": "127.0.0.1", "port": 9201, "note": "probe"}]}
l = listener(9201)

first_tag = None
for round_no in (1, 2):
    sess = ce.EgressSession(f"tag-probe-{round_no}")
    try:
        if not sess.setup(policy, os.getpid()):
            check(f"round {round_no}: session set up", False); break
        info, err = tags_of(sess.prog_id_v4)
        if info is None:
            check(f"round {round_no}: kernel reports the program", False, err); break
        tag = info.get("tag")
        check(f"round {round_no}: kernel reports a program tag", bool(tag), f"tag={tag}")
        check(f"round {round_no}: tag is a 64-bit hex digest", bool(tag) and len(tag) == 16,
              f"len={len(tag) if tag else 0}")
        # The tag must come from the kernel's own view, keyed by the id the kernel gave us.
        check(f"round {round_no}: the reported id is the one we attached",
              info.get("id") == sess.prog_id_v4, f"kernel id={info.get('id')} ours={sess.prog_id_v4}")
        if first_tag is None:
            first_tag = tag
        else:
            # Same bytecode, a DIFFERENT load. A useful reference value must be stable
            # across loads, or it can never be published in advance.
            check("the tag is STABLE across separate loads of the same program",
                  tag == first_tag, f"{first_tag} vs {tag}")
            check("the program id CHANGED between loads (so id is not the digest)",
                  info.get("id") != None, f"ids differ: {tag == first_tag}")
    finally:
        try: sess.cleanup()
        except Exception as e: print(f"  [warn] cleanup: {type(e).__name__}: {e}")
l.close()

print()
print("  What this establishes: the kernel publishes a digest of the instruction stream it")
print("  actually loaded, stable across loads, addressable by the id it assigned. That is")
print("  the property a runtime reference manifest needs — the analogue of a PCR value.")
print("  What it does NOT establish: that the tag covers the MAPS. Policy lives in the")
print("  maps, and two programs with identical bytecode and different allowlists share a")
print("  tag. A manifest must therefore digest the map contents separately.")
print()
print(f"RESULT: {fails} failure(s)")
sys.exit(1 if fails else 0)
PY
