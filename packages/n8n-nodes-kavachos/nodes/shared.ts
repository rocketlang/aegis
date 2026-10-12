// SPDX-License-Identifier: AGPL-3.0-only
// Shared by the Kavach nodes: running a command without stopping n8n, and asking Aegis with a time limit.
import { spawn } from "child_process";
import * as http from "http";
import * as https from "https";

export interface ProcessResult {
  stdout: string;
  stderr: string;
  /** The exit status, or null when the process was killed or never started. */
  code: number | null;
  timedOut: boolean;
  /** Output beyond the cap was dropped (the process was left to finish). */
  truncated: boolean;
  /** Set when the process could not be started at all. */
  error?: string;
}

/**
 * Run a command and wait for it WITHOUT blocking n8n's event loop. Through 1.3.0 the nodes used a blocking
 * call with no time limit: every other workflow, and n8n's own interface, stopped until the command ended.
 */
export function runProcess(command: string, args: string[], timeoutMs: number, maxBytes = 5 * 1024 * 1024): Promise<ProcessResult> {
  return new Promise((resolve) => {
    let stdout = "", stderr = "", size = 0, truncated = false, timedOut = false, done = false;
    const finish = (r: Partial<ProcessResult>) => { if (done) return; done = true; clearTimeout(timer); resolve({ stdout, stderr, code: null, timedOut, truncated, ...r }); };
    let child: ReturnType<typeof spawn>;
    try { child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"] }); }
    catch (e) { resolve({ stdout, stderr, code: null, timedOut, truncated, error: (e as Error).message }); return; }
    const timer = setTimeout(() => {
      timedOut = true;
      try { child.kill("SIGTERM"); } catch { /* already gone */ }
      setTimeout(() => { try { child.kill("SIGKILL"); } catch { /* already gone */ } }, 2000).unref();
    }, timeoutMs);
    const take = (which: "out" | "err") => (d: Buffer) => {
      if (size >= maxBytes) { truncated = true; return; }
      const room = maxBytes - size, piece = d.length > room ? d.subarray(0, room) : d;
      if (piece.length < d.length) truncated = true;
      size += piece.length;
      if (which === "out") stdout += piece.toString("utf8"); else stderr += piece.toString("utf8");
    };
    child.stdout?.on("data", take("out"));
    child.stderr?.on("data", take("err"));
    child.on("error", (e) => finish({ error: e.message }));
    child.on("close", (code) => finish({ code }));
  });
}

export interface JsonReply {
  status: number;
  /** The parsed body, or undefined when it was not JSON. */
  json?: unknown;
  text: string;
}

/**
 * One HTTP request to Aegis with OUR time limit. A redirect is not followed: it comes back as its 3xx status.
 * (The global fetch gives up waiting for an answer after about five minutes whatever the caller wants, which
 * is shorter than the gate's own wait for a level-1 approval.)
 */
export function requestJson(method: "GET" | "POST", url: string, headers: Record<string, string>, body: string | undefined, timeoutMs: number): Promise<JsonReply> {
  return new Promise((resolve, reject) => {
    let u: URL;
    try { u = new URL(url); } catch { reject(new Error(`not a URL: ${url}`)); return; }
    if (u.protocol !== "http:" && u.protocol !== "https:") { reject(new Error(`not an http(s) URL: ${url}`)); return; }
    const lib = u.protocol === "https:" ? https : http;
    const h: Record<string, string> = { ...headers };
    if (body !== undefined) h["Content-Length"] = String(Buffer.byteLength(body));
    const req = lib.request(u, { method, headers: h }, (res) => {
      const chunks: Buffer[] = []; let size = 0;
      res.on("data", (d: Buffer) => { size += d.length; if (size <= 10 * 1024 * 1024) chunks.push(d); });
      res.on("end", () => {
        clearTimeout(timer);
        const text = Buffer.concat(chunks).toString("utf8");
        let json: unknown;
        try { json = JSON.parse(text); } catch { json = undefined; }
        resolve({ status: res.statusCode ?? 0, json, text });
      });
      res.on("error", (e) => { clearTimeout(timer); reject(e); });
    });
    const timer = setTimeout(() => { req.destroy(new Error("TIMEOUT")); }, timeoutMs);
    req.on("error", (e) => { clearTimeout(timer); reject(e); });
    if (body !== undefined) req.write(body);
    req.end();
  });
}

// The Arguments field as a list of words. Through 1.5.1 the field was cut at every space, so an argument that
// holds a space could not be passed. Now quotes group: '...' is taken as it stands, and in "..." a backslash
// before a double quote or another backslash gives that character. Everywhere else every character is itself:
// this is not a shell, so $, *, ~ and a backslash outside double quotes are not read as anything.
// A quote that is never closed is an error and not a guess.
export function splitWords(text: string): { words: string[]; error?: string } {
  const words: string[] = [];
  let word = "", inWord = false, quote: "'" | '"' | null = null;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quote === "'") { if (c === "'") quote = null; else word += c; continue; }
    if (quote === '"') {
      if (c === '"') quote = null;
      else if (c === "\\" && (text[i + 1] === '"' || text[i + 1] === "\\")) word += text[++i];
      else word += c;
      continue;
    }
    if (c === "'" || c === '"') { quote = c; inWord = true; continue; }
    if (/\s/.test(c)) { if (inWord) { words.push(word); word = ""; inWord = false; } continue; }
    word += c; inWord = true;
  }
  if (quote) return { words: [], error: `the arguments have a ${quote === "'" ? "single" : "double"} quote that is never closed` };
  if (inWord) words.push(word);
  return { words };
}
