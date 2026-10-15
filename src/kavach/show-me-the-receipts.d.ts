// show-me-the-receipts ships JavaScript without declarations. Only what flow-close.ts uses.
declare module "show-me-the-receipts" {
  export function grade(transcriptPath: string, opts?: { rerun?: boolean; strict?: boolean; finalText?: string; repo?: string }): {
    results: Array<{ verdict: string; text: string; why?: string; type?: string }>;
    bareDone?: string | null;
    hedged?: string[];
    sessionId?: string;
  };
  export function toHanumanG(report: unknown, opts?: { taskId?: string }): { inputs: Array<Record<string, unknown>>; measured: string[]; note: string };
}
