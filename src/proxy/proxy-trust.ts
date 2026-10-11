// SPDX-License-Identifier: AGPL-3.0-only
// kavachos proxy — where its certificate lives, and how a governed agent is told to trust it.
//
// Through agent-kernel 2.5.0 the launcher made the agent accept the proxy's self-signed certificate by
// switching certificate checking OFF for the whole agent (NODE_TLS_REJECT_UNAUTHORIZED=0,
// PYTHONHTTPSVERIFY=0). That is not "trust the proxy": it is "trust anyone", to every host the agent
// talks to. And the certificate and its key sat in /tmp under fixed names and were reused if already
// there, so whoever wrote those two files first chose the key.
//
// Now: the pair is made fresh on every proxy start, in a folder only the proxy's account can enter; the
// certificate names localhost and 127.0.0.1; and the agent is handed that ONE certificate as an extra
// trust root. Checking stays on. If the certificate cannot be found the agent's calls to the proxy fail,
// which is the safe direction, and the launcher says so.

import { chmodSync, existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from "fs";
import { spawnSync } from "child_process";
import { join } from "path";
import { getAegisDir } from "../core/config";

export const proxyTlsDir = (): string => join(getAegisDir(), "kernel", "proxy");
export const proxyCertPath = (): string => process.env.KAVACHOS_PROXY_CA?.trim() || join(proxyTlsDir(), "proxy.crt");
const proxyKeyPath = (): string => join(proxyTlsDir(), "proxy.key");

/** Where the operating system keeps its trust roots, first one that exists. */
const SYSTEM_BUNDLES = ["/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/cert.pem"];

/** A fresh key and certificate for this proxy start. The key is never reused and never leaves the folder. */
export function freshProxyCertificate(): { cert: string; key: string; certPath: string } {
  const dir = proxyTlsDir();
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  chmodSync(dir, 0o700);
  const certPath = join(dir, "proxy.crt"), keyPath = proxyKeyPath();
  for (const f of [certPath, keyPath]) { try { unlinkSync(f); } catch { /* not there */ } }
  const result = spawnSync("openssl", [
    "req", "-x509", "-newkey", "rsa:2048", "-keyout", keyPath, "-out", certPath, "-days", "30", "-nodes",
    "-subj", "/CN=kavachos-proxy/O=KavachOS/OU=KERNEL",
    "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1",
  ], { encoding: "utf-8" });
  if (result.status !== 0) throw new Error(`[kavachos:proxy] openssl cert gen failed: ${result.stderr?.slice(0, 200)}`);
  chmodSync(keyPath, 0o600);
  chmodSync(certPath, 0o644);
  return { cert: readFileSync(certPath, "utf-8"), key: readFileSync(keyPath, "utf-8"), certPath };
}

export interface AgentProxyTrust {
  /** Environment for the agent. Never contains a setting that switches certificate checking off. */
  env: Record<string, string>;
  certPath: string;
  certPresent: boolean;
  /** Said on stderr at launch. */
  notes: string[];
}

/**
 * What a governed agent needs in its environment to verify the proxy. `write: false` (a dry run) reports
 * without writing the combined bundle.
 */
export function agentProxyTrust(write = true, env: NodeJS.ProcessEnv = process.env): AgentProxyTrust {
  const certPath = proxyCertPath();
  if (!existsSync(certPath)) {
    return {
      env: {}, certPath, certPresent: false,
      notes: [
        `the proxy's certificate was not found at ${certPath}. The agent cannot verify the proxy, so its calls ` +
        `through it will fail. Certificate checking is NOT switched off. Start the proxy first as this account, ` +
        `or name the certificate with KAVACHOS_PROXY_CA.`,
      ],
    };
  }
  const proxyPem = readFileSync(certPath, "utf-8").trim() + "\n";
  const out: Record<string, string> = {};
  const notes: string[] = [];
  const dir = proxyTlsDir();

  // Node and Bun ADD the certificates in NODE_EXTRA_CA_CERTS to their own roots. Keep what was already there.
  let extra = proxyPem;
  const had = env.NODE_EXTRA_CA_CERTS;
  if (had && had !== certPath && existsSync(had)) extra = readFileSync(had, "utf-8").trim() + "\n" + proxyPem;
  const extraPath = had && had !== certPath && existsSync(had) ? join(dir, "agent-extra-roots.pem") : certPath;

  // Python, curl and anything else built on OpenSSL REPLACE their roots with the file they are given, so
  // they get the system's roots plus this one certificate.
  const system = [env.SSL_CERT_FILE, ...SYSTEM_BUNDLES].find((p): p is string => !!p && existsSync(p));
  const bundlePath = join(dir, "agent-roots.pem");
  if (write) {
    try {
      mkdirSync(dir, { recursive: true, mode: 0o700 });
      if (extraPath !== certPath) writeFileSync(extraPath, extra, { mode: 0o644 });
      if (system) writeFileSync(bundlePath, readFileSync(system, "utf-8").trim() + "\n" + proxyPem, { mode: 0o644 });
    } catch (e) {
      notes.push(`could not write the agent's trust files in ${dir}: ${(e as Error).message}`);
    }
  }
  out.NODE_EXTRA_CA_CERTS = extraPath;
  if (system) {
    out.SSL_CERT_FILE = bundlePath;
    out.REQUESTS_CA_BUNDLE = bundlePath;
    out.CURL_CA_BUNDLE = bundlePath;
  } else {
    notes.push(`no system certificate bundle was found, so only Node and Bun clients are told to trust the proxy; ` +
               `a Python or curl client will fail to verify it. Certificate checking is NOT switched off.`);
  }
  return { env: out, certPath, certPresent: true, notes };
}
