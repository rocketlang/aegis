#!/usr/bin/env python3
# L2 egress test helper: attempt a TCP connect and report the outcome.
# Prints "OK" on success, or "ERR:<errno-name>" (e.g. ERR:EPERM when the cgroup-BPF
# egress firewall refuses the connection before the socket is established).
import socket, sys, errno

def main() -> None:
    ip, port = sys.argv[1], int(sys.argv[2])
    s = socket.socket()
    s.settimeout(4)
    try:
        s.connect((ip, port))
        s.close()
        print("OK")
    except OSError as e:
        print("ERR:" + errno.errorcode.get(e.errno, str(e.errno)))

main()
