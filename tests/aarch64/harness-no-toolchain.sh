#!/bin/sh
# Can the egress layer run on a HARDENED PRODUCTION image — one with no compiler?
#
# TactiQ OS's stated production profile is "read-only rootfs, root account locked, no SSH
# server, no debug tooling". Our egress layer compiles its BPF program at runtime with
# clang. If clang is absent, _is_available() returns False and the firewall disables
# itself — correctly, quietly, and completely. This harness measures that rather than
# assuming it, because the answer decides whether the layer can ship to such an image
# at all.
echo "arch: $(uname -m)"
echo

CLANG=$(command -v clang)
[ -n "$CLANG" ] || { echo "  [FAIL] clang absent to begin with — cannot run the control half"; exit 1; }

fails=0
run_check() {
  python3 - "$1" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("ce", "/hostshare/cgroup-egress.py")
ce = importlib.util.module_from_spec(spec); spec.loader.exec_module(ce)
print("AVAILABLE" if ce._is_available() else "UNAVAILABLE")
PY
}

a=$(run_check with-clang 2>/dev/null | tail -1)
if [ "$a" = "AVAILABLE" ]; then echo "  [ok  ] with a toolchain present: $a"
else echo "  [FAIL] expected AVAILABLE with clang present, got $a"; fails=$((fails+1)); fi

# Take the compiler away — exactly what a no-debug-tooling production image looks like.
mv "$CLANG" "$CLANG.hidden"
b=$(run_check no-clang 2>/dev/null | tail -1)
mv "$CLANG.hidden" "$CLANG"

if [ "$b" = "UNAVAILABLE" ]; then
  echo "  [ok  ] with NO compiler: $b — the layer disables itself"
  echo "         MEASURED CONSEQUENCE: on an image without a toolchain this firewall"
  echo "         does not run. It does not fail loudly either — it writes UNAVAILABLE"
  echo "         and exits 0. Shipping to such an image requires a PRECOMPILED BPF"
  echo "         object, not runtime compilation."
else
  echo "  [FAIL] expected UNAVAILABLE without clang, got $b"; fails=$((fails+1))
fi

echo
echo "RESULT: $fails failure(s)"
exit $([ "$fails" -eq 0 ] && echo 0 || echo 1)
