// @rule:AEG-HG-2B-006 — NonceStore.consumeNonce fail-closed semantics:
//   returns true  = first use (allowed)
//   returns false = already consumed (replay — reject)
//   throws        = store unavailable (fails CLOSED, never open)
// Production path: Redis SET NX EX (AEGIS PROOF at port 4850).
// Default: in-memory (single-process only — multi-instance requires Redis).

export interface NonceStore {
  consumeNonce(nonce: string, ttlMs: number): Promise<boolean>;
}

class InMemoryNonceStore implements NonceStore {
  private readonly used = new Map<string, number>(); // nonce → expiry timestamp

  async consumeNonce(nonce: string, ttlMs: number): Promise<boolean> {
    const now = Date.now();
    for (const [k, exp] of this.used) {
      if (now > exp) this.used.delete(k);
    }
    if (this.used.has(nonce)) return false;
    this.used.set(nonce, now + ttlMs);
    return true;
  }
}

export const defaultNonceStore: NonceStore = new InMemoryNonceStore();
