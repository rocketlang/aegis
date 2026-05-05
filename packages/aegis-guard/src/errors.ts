// @rule:AEG-E-016 — no AI agent may perform an irreversible action without a human approval token
// @rule:IRR-NOAPPROVAL — core doctrine: irreversible means human-in-the-loop is mandatory

export class IrrNoApprovalError extends Error {
  readonly code = 'IRR-NOAPPROVAL';
  readonly doctrine = 'AEG-E-016';

  constructor(capability: string, reason?: string) {
    const detail = reason ? ` (${reason})` : '';
    super(
      `IRR-NOAPPROVAL: capability '${capability}' requires a human approval token before execution.` +
      ` No AI agent may perform this irreversible action without one. [AEG-E-016]${detail}`,
    );
    this.name = 'IrrNoApprovalError';
  }
}

export class AegisNonceError extends Error {
  readonly code = 'AEGIS-NONCE-REPLAY';

  constructor(nonce: string) {
    super(`AEGIS-NONCE-REPLAY: nonce '${nonce}' already consumed — approval replay rejected`);
    this.name = 'AegisNonceError';
  }
}
