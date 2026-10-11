# Hardened setup: the separate-account approver and ledger authority

Without this setup aegis runs under one account. The gates still refuse, but the record of what they
refused and the approvals a person gives live in files the agent's own account can write. This page is
the setup that moves both out of the agent's reach. It is a person's work, as root, once per box.
`aegis init` does not do it.

Through 2.17.0 these steps were written down nowhere in the package, and the last one (pinning the key)
was a sentence in the changelog. An install that stopped before it ran with every answer unchecked.

## What you end up with

| Thing | Owner | Who else can touch it |
|---|---|---|
| The store: approvals, the signed refusal ledger, the ledger's private key | the approver account | nobody |
| The consume socket: a gate ASKS here (is this approved; record this refusal) | the approver account | the agent's account, to ask |
| The approve socket: a person APPROVES here; a dated anchor is asked for here | the approver account | members of the approver group only |
| The pinned public key, `/etc/aegis/ledger-signing.pub` | root | everyone reads it |

## Steps

Names and paths are examples. Pick an account number your system does not use.

```sh
# 1. An account for the authority. The agent's account must NOT be in its group.
groupadd --system aegis-approver
useradd  --system --gid aegis-approver --home-dir /var/lib/aegis-approver --shell /usr/sbin/nologin aegis-approver

# 2. Its folders. The store is the authority's alone. The socket folder must let other accounts
#    REACH the sockets (711), or no gate can ask; each socket's own mode decides who may open it.
install -d -o aegis-approver -g aegis-approver -m 700 /var/lib/aegis-approver/store
install -d -o aegis-approver -g aegis-approver -m 711 /var/lib/aegis-approver/sock
install -d -o aegis-approver -g aegis-approver -m 755 /var/lib/aegis-approver/pub

# 3. A copy of the package that the agent's account cannot change (root-owned), and the daemon run from it
#    AS THE APPROVER ACCOUNT, by your service manager:
aegis approver-daemon \
  --store   /var/lib/aegis-approver/store \
  --consume /var/lib/aegis-approver/sock/consume.sock \
  --approve /var/lib/aegis-approver/sock/approve.sock \
  --consume-mode 666 \
  --ledger-pub /var/lib/aegis-approver/pub/ledger-signing.pub
```

`--consume-mode 666` lets any local account ask. Leave it out (660) if the agent's account is root, or if
you would sooner add the agent's account to a group of its own that you give the socket to. The approve
socket is always 660: only the approver account and its group can open it. A person who approves must be
in that group; the agent's account must not be.

```sh
# 4. Tell the gates where to ask. Either in the environment the harness gives them:
export AEGIS_APPROVER_CONSUME_SOCKET=/var/lib/aegis-approver/sock/consume.sock
export AEGIS_APPROVER_APPROVE_SOCKET=/var/lib/aegis-approver/sock/approve.sock
#    or, for the refusal ledger only, one line in the aegis home:
echo /var/lib/aegis-approver/sock/consume.sock > ~/.aegis/ledger-socket

# 5. PIN THE KEY. Until this is done a gate cannot tell the authority's answer from anyone else's,
#    and says "NOT CHECKED" on every refusal.
aegis ledger-pin --from /var/lib/aegis-approver/pub/ledger-signing.pub
```

`ledger-pin` takes the key from the file you name, never from the socket. It asks the authority whether
that is its key and whether it is 2.16.3 or later, and refuses if either answer is no.

## The daily anchor

If the ledger is anchored in a public log with `aegis ledger-anchor --dated`, the account that runs it
must be able to open the **approve** socket: since 2.17.2 the authority gives a dated statement there
only, because the first dated leaf switches the ledger to one leaf a day for good. The command finds
`approve.sock` beside the consume socket by itself; name another with `--anchor-socket`.

## Check it

```sh
aegis ledger-verify /var/lib/aegis-approver/store/refusals.signed.jsonl --local ~/.aegis/refusals.jsonl
./red-team/ledger-unpinned.battery.sh        # from the repository
```

After the next refusal the newest row in `~/.aegis/refusals.jsonl` should say
`"authority_check":"verified"`. The daemon's log says at start whether the pinned key is its own.

## What this does not give

- **An agent that runs as root.** Root reads the private key, opens the approve socket and can rewrite
  the pinned key. The whole setup holds against an agent under an ordinary account, and only that.
- **The socket's location.** The environment and the pointer file say where to ask, and the agent's
  account can change both. That is why the answer is checked against the pinned key: a false authority
  is refused aloud, it is not prevented from being asked.
- **A gate that never asks.** A refusal that does not reach the ledger code leaves no row.
- **What a refusal row says.** Any account that can open the consume socket can ask for a refusal to be
  recorded, true or not. The ledger shows that rows were not removed or reordered, not that each one
  happened.
- **One box.** The approver account is a second account, not a second machine.
