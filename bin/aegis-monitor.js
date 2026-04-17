#!/usr/bin/env node
import { spawn, execSync } from "child_process";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const target = join(__dirname, "..", "src", "monitor", "index.ts");

try { execSync("bun --version", { stdio: "ignore" }); }
catch {
  console.error("AEGIS requires Bun runtime. Install: curl -fsSL https://bun.sh/install | bash");
  process.exit(1);
}

const child = spawn("bun", ["run", target], { stdio: "inherit" });
child.on("exit", (code) => process.exit(code ?? 0));
