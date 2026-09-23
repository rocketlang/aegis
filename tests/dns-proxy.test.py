import sys, json, socket, struct, time, threading
sys.path.insert(0, "/root/aegis/src/kernel")
import importlib.util
spec = importlib.util.spec_from_file_location("dnsproxy", "/root/aegis/src/kernel/dns-proxy.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

def q(name, tid=0x1234):
    out = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    for lab in name.split("."):
        out += bytes([len(lab)]) + lab.encode()
    return out + b"\x00" + struct.pack("!HH", 1, 1)

ok = fail = 0
def check(label, cond):
    global ok, fail
    if cond: ok += 1; print(f"  ok   {label}")
    else:    fail += 1; print(f"  FAIL {label}")

# pure decision
check("exact policy name permitted", m.permitted("github.com", {"github.com"}))
check("a name not in the policy is refused", not m.permitted("evil.attacker.com", {"github.com"}))
check("a SUBDOMAIN of an allowed name is refused (every subdomain is a message)",
      not m.permitted("data-exfil.github.com", {"github.com"}))
check("a parent of an allowed name is refused", not m.permitted("com", {"github.com"}))
check("an unparseable query is refused, never defaulted open", not m.permitted(None, {"github.com"}))
check("qname parses and lowercases", m.parse_qname(q("GitHub.COM")) == "github.com")
check("a truncated packet parses to None", m.parse_qname(b"\x00" * 6) is None)
check("a compression pointer in the question is rejected",
      m.parse_qname(struct.pack("!HHHHHH",1,0x0100,1,0,0,0) + b"\xc0\x0c") is None)

# allowed_names skips IP literals
pol = {"allow":[{"host":"github.com","port":443},{"host":"127.0.0.1","port":0},
                {"host":"::1","port":0},{"host":"API.Anthropic.com","port":443}]}
names = m.allowed_names(pol)
check("IP literals are not in the permitted name set", names == {"github.com","api.anthropic.com"})

# refusal packet shape
r = m.refusal_for(q("evil.com"))
check("refusal echoes the transaction id", r[0:2] == q("evil.com")[0:2])
check("refusal sets QR=1 and RCODE=5", (r[2] & 0x80) and (r[3] & 0x0F) == 5)
check("refusal carries no answer records", struct.unpack_from("!H", r, 6)[0] == 0)

# live end-to-end against a real upstream
up = m.first_upstream()
if up:
    p = m.ResolvingProxy({"github.com"}, up, bind_port=0, session_id="t")
    port = p.start(); time.sleep(0.2)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(6)
    s.sendto(q("github.com"), ("127.0.0.1", port))
    a1, _ = s.recvfrom(65535)
    check("an allowed name is answered NOERROR with records",
          (a1[3] & 0x0F) == 0 and struct.unpack_from("!H", a1, 6)[0] > 0)
    s.sendto(q("exfil-channel.attacker.example"), ("127.0.0.1", port))
    a2, _ = s.recvfrom(65535)
    check("a tunnelling name is REFUSED with no records",
          (a2[3] & 0x0F) == 5 and struct.unpack_from("!H", a2, 6)[0] == 0)
    check("the refusal was counted", p.refused_count == 1 and p.served_count == 1)
    p.stop()
else:
    check("upstream available for the live test", False)

print(f"\n  passed {ok} · failed {fail}")
sys.exit(0 if fail == 0 else 1)
