// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// KAVACH — the dev-only database proxy, compiled from the same registry anumati reads.
//
// @rule:ANU-008 compiled from the declarations, never hand-written
// @rule:ANU-010 re-deriving must reproduce it
// @rule:ANU-I-001 schema-touching ops only against dev-class databases
//
// WHY THIS EXISTS
//
// ANU-I-001 could not be enforced against a non-cooperating agent, and the reason was
// not the policy — it was the estate. Dev and production databases share a host and a
// port, so at the only vocabulary the enforcement layer has, the permitted and the
// forbidden database are the same address. No egress rule can separate them.
//
// The fix is to give the permitted set an address of its own. This compiles a pgbouncer
// instance that exposes ONLY dev-class databases, on its own port. Governed agents are
// then allowed that port and denied the shared database ports outright, which is a
// distinction the kernel CAN express.
//
// Nothing moves. Production databases are untouched, keep their address, and keep
// serving every client that is not a governed agent. This is additive (FP-012): a new
// door for agents, not a relocation of the building.

import { readDatabaseEndpoints, readDeclaredPort, type DbEndpoint } from "./plant-state";

export interface DbProxyPlan {
  /** Port the dev-only proxy listens on — from ports.json, never invented here. */
  listenPort: number;
  /** Dev-class databases, the only ones this door opens onto. */
  exposed: DbEndpoint[];
  /** Every distinct database address an agent must therefore be denied. */
  deniedEndpoints: Array<{ host: string; port: number }>;
  /** Databases deliberately NOT exposed, with the class that excluded them. */
  withheld: Array<{ name: string; klass: string }>;
  ini: string;
}

export const DBPROXY_SERVICE = "database-pgbouncer";
export const DBPROXY_INI = "/etc/pgbouncer/anumati-dev.ini";
export const DBPROXY_USERLIST = "/etc/pgbouncer/anumati-dev-userlist.txt";
/** Roles the door knows. trust skips the password check, not the user lookup. */
export const DBPROXY_USERLIST_BODY = '"postgres" ""\n';

/**
 * Compile the plan. Returns null when the registry or the port cannot be read —
 * a proxy built on state we could not read would be a guess. @rule:ANU-004
 */
export function compileDbProxy(): { plan: DbProxyPlan } | { error: string } {
  const port = readDeclaredPort(DBPROXY_SERVICE);
  if (!port.known) return { error: `listen port: ${port.why}` };

  const dbs = readDatabaseEndpoints();
  if (!dbs.known) return { error: `database registry: ${dbs.why}` };

  const exposed = dbs.value.filter(d => d.klass === "dev").sort((a, b) => a.name.localeCompare(b.name));
  const withheld = dbs.value
    .filter(d => d.klass !== "dev")
    .map(d => ({ name: d.name, klass: d.klass ?? "unclassed" }))
    .sort((a, b) => a.name.localeCompare(b.name));

  if (exposed.length === 0) return { error: "no dev-class databases to expose — refusing to open an empty door" };

  // Every address that carries a database, so agents can be denied all of them once the
  // dev set has its own door. Ports the proxy itself must reach are not affected: the
  // proxy is not a governed agent and is not in the agent cgroup.
  const denied = new Map<string, { host: string; port: number }>();
  for (const d of dbs.value) denied.set(`${d.host}:${d.port}`, { host: d.host, port: d.port });

  const lines: string[] = [];
  lines.push("; >>> anumati: generated from databases.json — do not hand-edit");
  lines.push(";");
  lines.push("; Dev-class databases only. This door exists so ANU-I-001 has an address it can");
  lines.push("; express: agents reach dev through here and are denied the shared database ports,");
  lines.push("; which is a distinction the enforcement layer can actually make.");
  lines.push(`; exposed ${exposed.length} dev-class · withheld ${withheld.length} non-dev`);
  lines.push("");
  lines.push("[databases]");
  for (const d of exposed) {
    lines.push(`${d.name} = host=${d.host} port=${d.port} dbname=${d.name}`);
  }
  lines.push("");
  lines.push("[pgbouncer]");
  lines.push("listen_addr = 127.0.0.1");
  lines.push(`listen_port = ${port.value}`);
  // auth_type=trust is correct HERE and the reason must be stated, because it looks
  // wrong at a glance. This cluster stores no password at all — pg_authid.rolpassword
  // is null — so port 5432 already accepts every local connection without one. The door
  // therefore removes no authentication that exists; scram would have nothing to verify
  // against. Its value is narrowing WHAT is reachable, not adding a credential: 25
  // dev-class databases instead of all of them.
  //
  // If this cluster ever sets passwords, this must become scram-sha-256 with a userlist
  // carrying the real verifier — at that point trust WOULD be weaker than the port it
  // replaces, and this generator should be changed with it.
  lines.push("auth_type = trust");
  // pgbouncer's trust still requires the username to be KNOWN — it skips the password
  // check, not the user lookup. The companion file lists the role with an empty secret.
  lines.push(`auth_file = ${DBPROXY_USERLIST}`);
  lines.push("pool_mode = transaction");
  lines.push("max_client_conn = 200");
  lines.push("default_pool_size = 10");
  lines.push("log_connections = 1");
  lines.push("log_disconnections = 1");
  lines.push("log_pooler_errors = 1");
  lines.push("unix_socket_dir =");
  lines.push("pidfile = /run/pgbouncer/anumati-dev.pid");
  lines.push("logfile = /var/log/postgresql/pgbouncer-anumati-dev.log");
  lines.push("admin_users = postgres");
  lines.push("; <<< anumati");

  return {
    plan: {
      listenPort: port.value,
      exposed,
      withheld,
      deniedEndpoints: [...denied.values()].sort((a, b) => a.host.localeCompare(b.host) || a.port - b.port),
      ini: lines.join("\n") + "\n",
    },
  };
}

export function renderDbProxyPlan(p: DbProxyPlan): string {
  const L: string[] = [];
  L.push(`\ndev-only database door — 127.0.0.1:${p.listenPort}`);
  L.push(`  exposes  ${p.exposed.length} dev-class database(s)`);
  L.push(`  withholds ${p.withheld.length} non-dev database(s)`);
  const byClass = new Map<string, number>();
  for (const w of p.withheld) byClass.set(w.klass, (byClass.get(w.klass) ?? 0) + 1);
  L.push(`           ${[...byClass.entries()].map(([k, n]) => `${k}=${n}`).join(" · ")}`);
  L.push(`  lets the compiler deny ${p.deniedEndpoints.length} database address(es) outright:`);
  for (const d of p.deniedEndpoints) L.push(`    ${d.host}:${d.port}`);
  L.push(`\n  Production is untouched: it keeps its address and every non-agent client.`);
  return L.join("\n") + "\n";
}
