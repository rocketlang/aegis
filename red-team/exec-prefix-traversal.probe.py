#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# aegis red-team — a '*' prefix rule in the exec allowlist must not pass a path that leaves the prefix.
# Review point 2 (clean-bench run, Andrey Lazarev, 2026-10-16): with '/opt/agent/*' allowed,
# '/opt/agent/../../usr/bin/EVIL' passed the text prefix check while the kernel runs /usr/bin/EVIL.
# A symlink under the prefix that points out of it is the same escape. Hermetic: calls the real
# _auto_decide_exec with a fake tracee path; executes nothing. GAP = an escaped path is allowed.
import importlib.util, json, os, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
APPLY = os.path.join(HERE, "..", "src", "kernel", "apply-seccomp.py")
spec = importlib.util.spec_from_file_location("applyseccomp_prefix_probe", APPLY)
mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)

gaps = 0
def decide(path, allow):
    d = tempfile.mkdtemp()
    al = os.path.join(d, "exec-allowlist.json")
    json.dump({"agent_type": "test", "allow": [{"path": p} for p in allow]}, open(al, "w"))
    mod._EXEC_ALLOWLIST = mod.load_exec_allowlist(al)
    mod._read_procmem_str = lambda pid, addr, max_len=512: path
    return mod._auto_decide_exec(1234, mod._NR_EXECVE, (0xdead, 0, 0, 0, 0, 0), al)

def CHECK(id_, want_allow, path, allow):
    global gaps
    got, reason = decide(path, allow)
    bad = got != want_allow
    print(f"  [{'GAP ' if bad else 'ok  '}] {id_} — {path!r} -> allow={got} ({reason})")
    if bad: gaps += 1

root = tempfile.mkdtemp()
agent = os.path.join(root, "agent")
os.makedirs(os.path.join(agent, "bin"))
open(os.path.join(agent, "bin", "tool"), "w").close()
os.symlink("/usr/bin/env", os.path.join(agent, "bin", "out"))      # points out of the prefix
os.symlink(agent, os.path.join(root, "agent-link"))                # the prefix dir itself is a link
P = agent + "/*"

CHECK("traversal out of a prefix rule is denied", False, f"{agent}/../../usr/bin/EVIL", [P])
CHECK("'.' segments under a prefix rule are denied (non-normal form)", False, f"{agent}/./bin/tool", [P])
CHECK("symlink under the prefix pointing out of it is denied", False, f"{agent}/bin/out", [P])
CHECK("plain file under the prefix is allowed", True, f"{agent}/bin/tool", [P])
CHECK("prefix dir that is itself a symlink still allows its files", True,
      f"{root}/agent-link/bin/tool", [f"{root}/agent-link/*"])
CHECK("exact rule: non-canonical form is denied", False, "/usr/bin/../bin/python3", ["/usr/bin/python3"])
CHECK("exact rule: exact path is allowed", True, "/usr/bin/python3", ["/usr/bin/python3"])

print(f"\n  exec-prefix-traversal: {gaps} gap(s)")
sys.exit(1 if gaps else 0)
