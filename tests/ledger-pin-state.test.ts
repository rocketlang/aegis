// SPDX-License-Identifier: AGPL-3.0-only
// What the authority says at start about the key pinned for the gates (2.17.1).
import { describe, it, expect } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { sayPinState } from "../src/kavach/approver-daemon";
import { generateLedgerKeypair } from "../src/core/ledger-sign";
import { keyFingerprint } from "../src/cli/commands/ledger-pin";

describe("the authority says whether its key is the pinned one", () => {
  const dir = mkdtempSync(join(tmpdir(), "aegis-pinstate-")), pin = join(dir, "ledger-signing.pub");
  const mine = generateLedgerKeypair().publicKey, other = generateLedgerKeypair().publicKey;
  const said = (key: string) => { const lines: string[] = []; sayPinState(key, (s) => lines.push(s), pin); return lines.join("\n"); };
  it("PS-1: no pin — says NOT pinned and names the command", () => {
    expect(said(mine)).toMatch(/NOT pinned.*aegis ledger-pin --from/s);
  });
  it("PS-2: another key pinned — says so loudly", () => {
    writeFileSync(pin, other);
    expect(said(mine)).toMatch(/IS NOT THIS AUTHORITY'S KEY/);
  });
  it("PS-3: its own key pinned, whatever the line endings", () => {
    writeFileSync(pin, mine.replace(/\n/g, "\r\n") + "\n");
    expect(said(mine)).toMatch(/is this authority's key/);
    rmSync(dir, { recursive: true, force: true });
  });
  it("PS-4: a fingerprint is 16 hex characters and differs between keys", () => {
    expect(keyFingerprint(mine)).toMatch(/^[0-9a-f]{16}$/);
    expect(keyFingerprint(mine)).not.toBe(keyFingerprint(other));
  });
});
