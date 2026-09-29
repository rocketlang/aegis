// SPDX-License-Identifier: AGPL-3.0-only
//
// merkle-tree — the RFC 6962 maths, and nothing else.
//
// Split out of merkle-ledger on 2026-09-29. These functions are pure, and they were
// sitting beside code that opens a database and reads config — so anything wanting a
// merkle root dragged sqlite in with it. Invisible until the identity register was asked
// whether it could run on an edge board, where every dependency is a cost and a surface.
//
// Nothing here touches the filesystem, a database, config, or the clock. merkle-ledger
// re-exports these, so existing callers are unchanged and the definitions cannot drift.

import { createHash } from "node:crypto";

export interface InclusionProof {
  leaf_hash: string;
  leaf_index: number;
  tree_size: number;
  audit_path: string[];            // sibling hashes bottom-up
  root_hash: string;
}

export function sha256(data: string): string {
  return createHash("sha256").update(data).digest("hex");
}

// Leaf hash: sha256("leaf:" + hash) — domain-separates leaves from interior nodes
function leafHash(receiptHash: string): string {
  return sha256("leaf:" + receiptHash);
}

// Interior node: sha256("node:" + left + right)
function nodeHash(left: string, right: string): string {
  return sha256("node:" + left + right);
}

export function buildMerkleRoot(receiptHashes: string[]): { root: string; tree: string[][] } {
  if (receiptHashes.length === 0) return { root: sha256("empty"), tree: [] };

  let layer: string[] = receiptHashes.map(leafHash);
  const tree: string[][] = [layer];

  while (layer.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < layer.length; i += 2) {
      // RFC 6962: odd leaf duplicates itself
      const right = i + 1 < layer.length ? layer[i + 1] : layer[i];
      next.push(nodeHash(layer[i], right));
    }
    layer = next;
    tree.push(layer);
  }

  return { root: layer[0], tree };
}

export function generateInclusionProof(receiptHashes: string[], leafIndex: number): InclusionProof {
  const { root, tree } = buildMerkleRoot(receiptHashes);
  const auditPath: string[] = [];
  let idx = leafIndex;

  for (let level = 0; level < tree.length - 1; level++) {
    const layer = tree[level];
    const sibling = idx % 2 === 0
      ? (idx + 1 < layer.length ? layer[idx + 1] : layer[idx])
      : layer[idx - 1];
    auditPath.push(sibling);
    idx = Math.floor(idx / 2);
  }

  return {
    leaf_hash: leafHash(receiptHashes[leafIndex]),
    leaf_index: leafIndex,
    tree_size: receiptHashes.length,
    audit_path: auditPath,
    root_hash: root,
  };
}

export function verifyInclusionProof(proof: InclusionProof): boolean {
  let current = proof.leaf_hash;
  let idx = proof.leaf_index;

  for (const sibling of proof.audit_path) {
    current = idx % 2 === 0 ? nodeHash(current, sibling) : nodeHash(sibling, current);
    idx = Math.floor(idx / 2);
  }

  return current === proof.root_hash;
}
