// SPDX-License-Identifier: AGPL-3.0-only
// What npm installs must be what this repository tests.
//
// tsconfig.json maps each @xshieldai/* package to its folder under packages/, so every test and CI run uses the
// repository's own copy, whatever package.json says. On 10 October 2026 package.json still asked for
// aegis-guard ^0.4.0 while the repository ran 0.6.0: the published dashboard could not start from an npm install
// (it imported two functions that 0.4.0 does not have), and every npm install had been running the older guard
// without its later protections. Nothing in the repository could see it.
//
// This test fails when a declared range does not admit the version in packages/. It cannot check that the version
// is actually on the registry: red-team/installed-package.battery.sh installs the packed tarball and starts it.
import { describe, it, expect } from "bun:test";
import { existsSync, readFileSync } from "fs";
import { join } from "path";

const ROOT = new URL("..", import.meta.url).pathname;
const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf-8"));
const paths: Record<string, string[]> = JSON.parse(readFileSync(join(ROOT, "tsconfig.json"), "utf-8").replace(/^\s*\/\/.*$/gm, "")).compilerOptions?.paths ?? {};

/** Does a caret or exact range admit a version? (^0.y.z admits 0.y.* from z; ^x.y.z admits x.*.* from y.z.) */
export function admits(range: string, version: string): boolean {
  const v = version.split(".").map(Number); const r = range.replace(/^\^/, "").split(".").map(Number);
  if (v.length !== 3 || r.length !== 3 || [...v, ...r].some(Number.isNaN)) return false;
  const ge = v[0] > r[0] || (v[0] === r[0] && (v[1] > r[1] || (v[1] === r[1] && v[2] >= r[2])));
  if (!range.startsWith("^")) return v.join(".") === r.join(".");
  if (r[0] > 0) return v[0] === r[0] && ge;
  if (r[1] > 0) return v[0] === 0 && v[1] === r[1] && ge;
  return v.join(".") === r.join(".");
}

describe("declared dependency ranges admit the versions the repository runs", () => {
  it("the range arithmetic is right on the cases that matter", () => {
    expect(admits("^0.4.0", "0.6.0")).toBe(false);   // the fault of 10 October
    expect(admits("^0.6.0", "0.6.0")).toBe(true); expect(admits("^0.6.0", "0.6.3")).toBe(true); expect(admits("^0.6.0", "0.7.0")).toBe(false);
    expect(admits("^1.2.0", "1.4.1")).toBe(true); expect(admits("^1.2.0", "2.0.0")).toBe(false); expect(admits("0.2.0", "0.2.1")).toBe(false);
  });

  const local = Object.keys(paths).filter((name) => (pkg.dependencies ?? {})[name]);
  it("there is something to check", () => { expect(local.length).toBeGreaterThan(0); });
  for (const name of local) {
    it(`${name}: package.json's range admits the version in packages/`, () => {
      const folder = join(ROOT, paths[name][0].split("/src/")[0]); const manifest = join(folder, "package.json");
      expect(existsSync(manifest)).toBe(true);
      const version = JSON.parse(readFileSync(manifest, "utf-8")).version; const range = pkg.dependencies[name];
      if (!admits(range, version)) throw new Error(`${name}: package.json asks for ${range}, the repository runs ${version}. An npm install would get a different version from the one tested here.`);
      expect(admits(range, version)).toBe(true);
    });
  }
});
