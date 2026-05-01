// SPDX-License-Identifier: AGPL-3.0-only
// @rule:KOS-040 egress firewall = cgroup BPF CONNECT4/6, bytes denied before established
// @rule:AEG-012 KavachRun = kernel enforcement surface for n8n
// @rule:INF-KAV-020 phoneback calls are opt-in; Linux enforcement is opt-in by platform
// Defense in depth: KavachGate (policy, always) + KavachRun (kernel, Linux optional)
import type {
  IExecuteFunctions,
  INodeExecutionData,
  INodeType,
  INodeTypeDescription,
} from "n8n-workflow";
import { NodeOperationError } from "n8n-workflow";
import { execSync, spawnSync } from "child_process";

function isLinux(): boolean {
  return process.platform === "linux";
}

function kavachosAvailable(): boolean {
  try {
    execSync("which kavachos", { stdio: "pipe" });
    return true;
  } catch {
    return false;
  }
}

export class KavachRun implements INodeType {
  description: INodeTypeDescription = {
    displayName: "Kavach Run",
    name: "kavachRun",
    icon: "file:kavach-run.svg",
    group: ["transform"],
    version: 1,
    subtitle: "Kernel-enforced subprocess (Linux)",
    description:
      "Wraps a subprocess in kavachos kernel enforcement (seccomp-bpf + cgroup BPF egress). " +
      "Linux only — gracefully degrades on macOS/Windows with a warning. " +
      "Use after KavachGate for defense in depth: policy gate + kernel enforcement.",
    defaults: { name: "Kavach Run" },
    inputs: ["main"],
    outputs: ["main"],
    properties: [
      {
        displayName: "Binary",
        name: "binary",
        type: "string",
        default: "",
        required: true,
        placeholder: "bun",
        description: "The binary to execute under kernel enforcement.",
      },
      {
        displayName: "Arguments",
        name: "args",
        type: "string",
        default: "",
        placeholder: "src/my-agent.ts --port 4900",
        description: "Space-separated arguments to pass to the binary.",
      },
      {
        displayName: "Trust Mask (hex)",
        name: "trustMask",
        type: "string",
        default: "0xFF",
        description:
          "Seccomp-bpf trust mask. Controls which syscall groups the process is allowed to call. " +
          "0xFF = infrastructure bits. See KavachOS trust_mask docs.",
      },
      {
        displayName: "Domain",
        name: "domain",
        type: "options",
        options: [
          { name: "general", value: "general" },
          { name: "maritime", value: "maritime" },
          { name: "logistics", value: "logistics" },
          { name: "ot", value: "ot" },
          { name: "finance", value: "finance" },
        ],
        default: "general",
        description: "Domain profile — controls egress allowlist and Falco rule set.",
      },
      {
        displayName: "Enable Falco",
        name: "falco",
        type: "boolean",
        default: false,
        description: "Enable Falco CRITICAL rule monitoring (requires Falco installed on host).",
      },
      {
        displayName: "On Non-Linux",
        name: "onNonLinux",
        type: "options",
        options: [
          { name: "Warn and run unwrapped", value: "warn" },
          { name: "Skip execution entirely", value: "skip" },
          { name: "Throw error", value: "throw" },
        ],
        default: "warn",
        description:
          "Behavior when running on macOS or Windows where kernel enforcement is unavailable.",
      },
    ],
  };

  async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
    const items = this.getInputData();
    const results: INodeExecutionData[] = [];

    for (let i = 0; i < items.length; i++) {
      const binary = this.getNodeParameter("binary", i) as string;
      const args = (this.getNodeParameter("args", i) as string).trim();
      const trustMask = this.getNodeParameter("trustMask", i) as string;
      const domain = this.getNodeParameter("domain", i) as string;
      const falco = this.getNodeParameter("falco", i) as boolean;
      const onNonLinux = this.getNodeParameter("onNonLinux", i) as string;

      if (!binary?.trim()) {
        throw new NodeOperationError(this.getNode(), "binary must not be empty", { itemIndex: i });
      }

      const linux = isLinux();
      const hasKavachos = linux && kavachosAvailable();

      if (!linux || !hasKavachos) {
        const platform = process.platform;
        const reason = !linux
          ? `KavachRun kernel enforcement not available on ${platform} — requires Linux with seccomp-bpf`
          : "kavachos CLI not found — install with: npm install -g @rocketlang/kavachos";

        if (onNonLinux === "throw") {
          throw new NodeOperationError(this.getNode(), reason, { itemIndex: i });
        }
        if (onNonLinux === "skip") {
          results.push({
            json: { ...items[i].json, kavach_run: { skipped: true, reason } },
            pairedItem: i,
          });
          continue;
        }
        // warn: run unwrapped with a flag in output
        process.stderr.write(`[KavachRun] WARNING: ${reason} — running ${binary} unwrapped\n`);

        const argList = args ? args.split(/\s+/) : [];
        const proc = spawnSync(binary, argList, { encoding: "utf8" });

        results.push({
          json: {
            ...items[i].json,
            kavach_run: {
              enforced: false,
              reason,
              stdout: proc.stdout,
              stderr: proc.stderr,
              exit_code: proc.status,
            },
          },
          pairedItem: i,
        });
        continue;
      }

      // Linux + kavachos available — build command
      const kavachArgs = [
        "run",
        `--trust-mask=${trustMask}`,
        `--domain=${domain}`,
        ...(falco ? ["--falco"] : []),
        binary,
        ...(args ? args.split(/\s+/) : []),
      ];

      const proc = spawnSync("kavachos", kavachArgs, { encoding: "utf8" });

      if (proc.error) {
        throw new NodeOperationError(
          this.getNode(),
          `kavachos run failed: ${proc.error.message}`,
          { itemIndex: i }
        );
      }

      results.push({
        json: {
          ...items[i].json,
          kavach_run: {
            enforced: true,
            trust_mask: trustMask,
            domain,
            falco_enabled: falco,
            stdout: proc.stdout,
            stderr: proc.stderr,
            exit_code: proc.status,
          },
        },
        pairedItem: i,
      });
    }

    return [results];
  }
}
