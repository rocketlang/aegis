# kavachos-agent — file-path jail for governed agent launches (KOS-011 path)
#
# seccomp (apply-seccomp.py) filters SYSCALLS but cannot see file PATHS. This
# AppArmor profile is the path layer stacked on top: the agent — and every child
# it execs (ix inheritance) — is allowed everything EXCEPT the ANKR signing and
# secret material. A hijacked agent can no longer read the AEGIS approval-signing
# key (and mint approvals), the mudrika secret (and forge agent identity), or
# /root/.ankr/secrets (IAM app keys — a token from those walks through kika-gate).
#
# Deny beats allow in AppArmor: the broad file rule below grants everything,
# the deny rules carve out the key material. Write/append are denied too — key
# REPLACEMENT is as bad as key theft.
#
# Attached only via `aa-exec -p kavachos-agent` at agent launch (runner.ts).
# Loading this profile confines NOTHING by itself — additive, FP-012 safe.
#
# Install: src/kernel/apparmor/install.sh  (apparmor_parser -r)
# @rule:KGT-002 fail-closed key custody · @rule:KGT-006 violations train the armor

abi <abi/3.0>,

profile kavachos-agent flags=(attach_disconnected,mediate_deleted) {
  # ── allow everything by default ──────────────────────────────────────────
  capability,
  network,
  mount,
  umount,
  pivot_root,
  ptrace,
  signal,
  unix,
  # all file access, exec inherits THIS profile (ix) so children stay jailed
  / mrwlkix,
  /** mrwlkix,

  # ── except the key material (deny overrides allow) ───────────────────────
  deny /root/.aegis/approval-signing.key mrwkl,
  deny /root/.aegis/mudrika.secret mrwkl,
  deny /root/.ankr/secrets/ mrwkl,
  deny /root/.ankr/secrets/** mrwkl,
}
