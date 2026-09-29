#!/bin/sh
# The whole chain, once, on real ARM: enforce → read the KERNEL's own values → emit a
# receipt. The host then verifies that receipt against a signed manifest it published
# BEFORE the guest ran.
#
# Every piece has been tested alone. Unit tests and a design document can both be true
# while the pieces do not fit, and "built end to end" is an assertion until something
# has run end to end. This is that run.
#
# The split is the real topology, not a convenience: the DEVICE produces evidence, and
# somebody ELSE verifies it somewhere else, offline.
echo "arch:   $(uname -m)"
echo "kernel: $(uname -r)"
echo

OUT=/hostshare/out
fails=0
say() { if [ "$2" = "0" ]; then echo "  [ok  ] $1${3:+ — $3}"; else echo "  [FAIL] $1${3:+ — $3}"; fails=$((fails+1)); fi; }

OBJDIR=/tmp/kavachos-bpf; rm -rf $OBJDIR; mkdir -p $OBJDIR
cp /hostshare/bpf/* $OBJDIR/ 2>/dev/null || { echo "  [FAIL] no prebuilt objects"; exit 1; }

KAVACHOS_BPF_OBJ_DIR=$OBJDIR python3 - "$OUT" "${POLICY_VARIANT:-declared}" <<'PY'
import hashlib, importlib.util, json, os, socket, subprocess, sys, threading

out_dir, variant = sys.argv[1], sys.argv[2]
spec = importlib.util.spec_from_file_location("ce", "/hostshare/cgroup-egress.py")
ce = importlib.util.module_from_spec(spec); spec.loader.exec_module(ce)

face = json.load(open("/hostshare/policy-face.json"))
allow = face["egress"]

# The negative control: enforce something OTHER than what was published. Nothing else
# about the run changes — same program, same device, same receipt shape.
if variant == "tampered":
    allow = allow + [{"host": "127.0.0.9", "port": 9999, "note": "added on the device",
                      "source": "external_egress"}]

policy = {"allow": [{"host": a["host"], "port": a["port"], "note": a["note"]} for a in allow]}

# The digest is computed from what is ACTUALLY being installed, not from the file we were
# handed. A receipt that echoes the manifest back proves nothing.
lines = sorted("\u0000".join([a["host"], str(a["port"]), a["source"], a["note"]]) for a in allow)
policy_digest = hashlib.sha256("\n".join(lines).encode()).hexdigest()

sess = ce.EgressSession("e2e")
receipt = None
try:
    ok = sess.setup(policy, os.getpid())
    print(f"  [{'ok  ' if ok else 'FAIL'}] the compiled policy loads and attaches")
    if ok:
        j = subprocess.run(["bpftool", "-j", "prog", "show", "id", str(sess.prog_id_v4)],
                           capture_output=True, text=True)
        tag = json.loads(j.stdout).get("tag") if j.returncode == 0 else None
        print(f"  [{'ok  ' if tag else 'FAIL'}] the KERNEL reports a program tag — {tag}")
        receipt = {
            "schema": "ankr-launch-receipt-v1",
            "service": face.get("service", "e2e-service"),
            "release": "v1.0.0",
            "observed": {"progTag": tag, "policyDigest": policy_digest},
            "identity": {"id": "e2e-device", "instance": "boot-e2e", "counter": 1,
                         "voucher": "registrar-statement"},
        }
finally:
    try: sess.cleanup()
    except Exception: pass

os.makedirs(out_dir, exist_ok=True)
json.dump(receipt or {}, open(f"{out_dir}/receipt.json", "w"), indent=2)
print(f"  [{'ok  ' if receipt else 'FAIL'}] receipt written for the host to verify"
      f"{' — variant=' + variant if variant != 'declared' else ''}")
sys.exit(0 if receipt else 1)
PY
rc=$?
echo
echo "RESULT: $rc failure(s) producing the receipt (the VERDICT is the host's to give)"
exit $rc
