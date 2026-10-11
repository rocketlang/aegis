// SPDX-License-Identifier: AGPL-3.0-only
// kavachos run — which words on the command line are kavachos's, and which are the agent's.
//
// Through 2.4.0 every word starting with "--" was read as a kavachos option wherever it stood, and
// removed from what the agent received. Two things followed. The agent lost its own options
// (`kavachos run bun agent.ts --port 4900` handed it `4900` without `--port`). And whoever supplied
// the agent's arguments could set kavachos's options: `--dry-run` (nothing runs, exit 0),
// `--allow-unconstrained-egress`, `--needs=`, `--depth=`, `--session-id=`.
//
// From 2.5.0 a bare `--` ends kavachos's options. Everything after it is the agent's command, word
// for word, and none of it is read here:
//
//     kavachos run --trust-mask=0xFF --domain=general -- bun agent.ts --port 4900
//
// Without `--` the old reading still applies, so existing launch lines keep working, and each
// option found after the agent's binary is named in a warning. A caller that passes arguments it
// did not write (a workflow node, a wrapper script) must use `--`.

export interface RunArgs {
  /** Words to read kavachos options from. */
  optionArgs: string[];
  /** The agent's command: the binary, then its arguments. */
  agentArgs: string[];
  /** True when a `--` separated the two. */
  separated: boolean;
  /** Options found after the agent's binary on a line with no `--` (old reading; they were honoured). */
  optionsAfterBinary: string[];
  /** Set when the line cannot be read; the launch must be refused. */
  error?: string;
}

export function splitRunArgs(args: string[]): RunArgs {
  const at = args.indexOf("--");
  if (at !== -1) {
    const before = args.slice(0, at);
    const agentArgs = args.slice(at + 1);
    const stray = before.filter((a) => !a.startsWith("-"));
    if (stray.length) {
      return {
        optionArgs: before, agentArgs, separated: true, optionsAfterBinary: [],
        error: `before "--" only kavachos options may stand; found ${stray.map((s) => JSON.stringify(s)).join(", ")}. ` +
               `Write: kavachos run [options] -- <agent_binary> [its arguments]`,
      };
    }
    if (agentArgs.length === 0) {
      return { optionArgs: before, agentArgs, separated: true, optionsAfterBinary: [], error: `nothing after "--": name the agent's binary` };
    }
    return { optionArgs: before, agentArgs, separated: true, optionsAfterBinary: [] };
  }
  const firstPositional = args.findIndex((a) => !a.startsWith("--"));
  const optionsAfterBinary = firstPositional === -1 ? [] : args.slice(firstPositional + 1).filter((a) => a.startsWith("--"));
  return { optionArgs: args, agentArgs: args.filter((a) => !a.startsWith("--")), separated: false, optionsAfterBinary };
}

/** `a.b.c` at or above `x.y.z`. Used by callers that need the `--` reading. */
export function versionAtLeast(have: string, want: string): boolean {
  const h = have.split(".").map((n) => parseInt(n, 10)), w = want.split(".").map((n) => parseInt(n, 10));
  for (let i = 0; i < 3; i++) {
    const a = h[i] ?? 0, b = w[i] ?? 0;
    if (Number.isNaN(a)) return false;
    if (a !== b) return a > b;
  }
  return true;
}
