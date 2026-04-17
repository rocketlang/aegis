#!/usr/bin/env node
// AEGIS CLI entry point
// Requires Bun runtime (https://bun.sh)

import { spawn, execSync } from "child_process";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const cliPath = join(__dirname, "..", "src", "cli", "index.ts");

try {
  execSync("bun --version", { stdio: "ignore" });
} catch {
  console.error(`
AEGIS requires Bun runtime.

Install Bun:
  curl -fsSL https://bun.sh/install | bash

Then re-run: aegis ${process.argv.slice(2).join(" ")}
`);
  process.exit(1);
}

const args = process.argv.slice(2);
const child = spawn("bun", ["run", cliPath, ...args], { stdio: "inherit" });
child.on("exit", (code) => process.exit(code ?? 0));
child.on("error", (err) => {
  console.error(`AEGIS: ${err.message}`);
  process.exit(1);
});
