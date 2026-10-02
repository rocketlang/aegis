#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""
Run an AEGIS hook the way the agent harness does: stdin is a SOCKET, not a pipe.

A pipe-fed test passes for a hook that reads "/dev/stdin" and a socket-fed run does not
(the open fails with ENXIO and the hook reads nothing). Pipe-fed tests therefore stay
green while the live hook is blind. This helper is the socket.

usage: run-hook-on-socket.py <aegis-root> <hook-name>      (payload JSON on this process's stdin)
prints one JSON line: {"exit": <code>, "stderr": "<text>"}
Exit: 0 the hook ran (its own code is in the JSON) · 2 bad arguments · 3 the helper broke.
"""
import json
import os
import socket
import subprocess
import sys


def main() -> int:
    if len(sys.argv) != 3:
        sys.stderr.write(__doc__)
        return 2
    root, hook = sys.argv[1], sys.argv[2]
    payload = sys.stdin.buffer.read()
    ours, theirs = socket.socketpair()
    try:
        # AEGIS_TEST_CLI points the run at another build of the same CLI (a bundled file, say).
        cli = os.environ.get("AEGIS_TEST_CLI") or os.path.join(root, "src/cli/index.ts")
        proc = subprocess.Popen(
            ["bun", cli, hook],
            cwd=root, stdin=theirs, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=os.environ.copy(),
        )
        theirs.close()
        ours.sendall(payload)
        ours.shutdown(socket.SHUT_WR)
        _, err = proc.communicate(timeout=60)
        ours.close()
        print(json.dumps({"exit": proc.returncode, "stderr": err.decode("utf-8", "replace")}))
        return 0
    except Exception as e:  # a helper failure must not look like a hook verdict
        sys.stderr.write(f"run-hook-on-socket: helper broke: {type(e).__name__}: {e}\n")
        return 3


if __name__ == "__main__":
    sys.exit(main())
