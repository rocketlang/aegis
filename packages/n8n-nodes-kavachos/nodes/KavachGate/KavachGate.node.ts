// SPDX-License-Identifier: AGPL-3.0-only
// @rule:KAV-001 every dangerous action intercepted before execution
// @rule:KAV-078 HTTP gate returns structured JSON — adapter never infers from status codes
// @rule:AEG-011 framework-agnostic: thin HTTP client, all policy in aegis
// @rule:AEG-012 KavachGate is the n8n deployment surface for aegis governance
// @rule:INF-KAV-021 n8n node → HTTP POST → aegis gate → enforce/notify/audit
// @rule:INF-KAV-022 deny from gate → this node halts workflow with explicit reason
import type {
  IExecuteFunctions,
  INodeExecutionData,
  INodeType,
  INodeTypeDescription,
} from "n8n-workflow";
import { NodeOperationError } from "n8n-workflow";
import { requestJson } from "../shared";

export class KavachGate implements INodeType {
  description: INodeTypeDescription = {
    displayName: "Kavach Gate",
    name: "kavachGate",
    icon: "file:kavach-gate.svg",
    group: ["transform"],
    version: 1,
    subtitle: "Pre-execution DAN gate",
    description:
      "Intercepts AI agent actions before execution. Calls the Aegis KAVACH gate to classify danger level (DAN 1-4), notify approvers, and wait for ALLOW/STOP. Blocks the workflow on STOP or timeout.",
    defaults: { name: "Kavach Gate" },
    inputs: ["main"],
    outputs: ["main"],
    credentials: [
      {
        name: "aegisApi",
        required: true,
      },
    ],
    properties: [
      {
        displayName: "Command",
        name: "command",
        type: "string",
        default: "={{ $json.command }}",
        required: true,
        description:
          "The command or action the agent wants to execute. Accepts an expression referencing upstream node output.",
        placeholder: "prisma migrate reset",
      },
      {
        displayName: "Tool Name",
        name: "toolName",
        type: "string",
        default: "n8n-agent",
        description: "Name of the tool/node calling this gate. Appears in audit records.",
      },
      {
        displayName: "Session ID",
        name: "sessionId",
        type: "string",
        default: "={{ $execution.id }}",
        description: "Workflow execution ID used for audit trail grouping.",
      },
      {
        displayName: "Dry Run",
        name: "dryRun",
        type: "boolean",
        default: false,
        description:
          "Classify danger level only — no notification sent, no polling. Use for testing the gate without blocking.",
      },
      {
        displayName: "Wait For A Decision (seconds)",
        name: "timeoutSeconds",
        type: "number",
        default: 660,
        description:
          "How long to wait for the gate's answer. Aegis itself waits up to 600 s for an approver on the lowest level, " +
          "so the default is a little longer. No answer in this time is treated as a block.",
      },
      {
        displayName: "On STOP / Timeout",
        name: "onBlock",
        type: "options",
        options: [
          { name: "Throw Error (halt workflow)", value: "throw" },
          { name: "Continue with allow=false", value: "continue" },
        ],
        default: "throw",
        description:
          "What to do when the gate blocks the action. Default: throw error to halt the workflow.",
      },
    ],
  };

  async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
    const items = this.getInputData();
    const results: INodeExecutionData[] = [];

    const credentials = await this.getCredentials("aegisApi");
    const baseUrl = (credentials.baseUrl as string).replace(/\/$/, "");
    const token = credentials.token as string | undefined;

    for (let i = 0; i < items.length; i++) {
      const command = this.getNodeParameter("command", i) as string;
      const toolName = this.getNodeParameter("toolName", i) as string;
      const sessionId = this.getNodeParameter("sessionId", i) as string;
      const dryRun = this.getNodeParameter("dryRun", i) as boolean;
      const onBlock = this.getNodeParameter("onBlock", i) as string;
      const limit = Number(this.getNodeParameter("timeoutSeconds", i, 660));
      const timeoutMs = (Number.isFinite(limit) && limit > 0 ? limit : 660) * 1000;

      if (!command?.trim()) {
        throw new NodeOperationError(this.getNode(), "command must not be empty", { itemIndex: i });
      }

      const headers: Record<string, string> = { "Content-Type": "application/json" };
      if (token) headers["Authorization"] = `Bearer ${token}`;

      let gateResult: {
        allow: boolean;
        level?: number;
        reason: string;
        decision?: string;
        approval_id?: string;
        dry_run?: boolean;
        _meta?: { computed_at: string; duration_ms?: number };
      };

      // Three different failures, said as what they are: no answer in time (a block), an answer that is
      // not the gate's (an error), and Aegis not reachable (an error). Through 1.3.0 all three read
      // "Cannot reach Aegis gate".
      let reply;
      try {
        reply = await requestJson(
          "POST",
          `${baseUrl}/api/v1/kavach/gate`,
          headers,
          JSON.stringify({ command, tool_name: toolName, session_id: sessionId, dry_run: dryRun }),
          timeoutMs
        );
      } catch (err: any) {
        if (err?.message === "TIMEOUT") {
          gateResult = { allow: false, reason: `no decision from the Aegis gate within ${timeoutMs / 1000} s`, decision: "TIMEOUT" };
          reply = undefined;
        } else {
          throw new NodeOperationError(this.getNode(), `Cannot reach Aegis gate at ${baseUrl}: ${err?.message ?? err}`, { itemIndex: i });
        }
      }
      if (reply) {
        if (reply.status !== 200) {
          throw new NodeOperationError(
            this.getNode(),
            `Aegis gate answered HTTP ${reply.status}, not a decision: ${reply.text.slice(0, 300)}`,
            { itemIndex: i }
          );
        }
        const j = reply.json as Record<string, unknown> | undefined;
        if (!j || typeof j !== "object" || typeof j.allow !== "boolean") {
          throw new NodeOperationError(
            this.getNode(),
            `what answered at ${baseUrl} is not the Aegis gate: no true/false "allow" in its answer. Treated as a block.`,
            { itemIndex: i }
          );
        }
        gateResult = j as typeof gateResult;
      }
      gateResult = gateResult!;

      // Only the boolean true is an allow. A string, a number or anything else is not.
      if (gateResult.allow !== true) {
        if (onBlock === "throw") {
          throw new NodeOperationError(
            this.getNode(),
            `KAVACH blocked action (DAN ${gateResult.level ?? "?"}): ${gateResult.reason}`,
            { itemIndex: i }
          );
        }
        // continue mode — pass allow=false downstream
      }

      results.push({
        json: {
          ...items[i].json,
          kavach: {
            allow: gateResult.allow === true,
            level: gateResult.level,
            reason: gateResult.reason,
            decision: gateResult.decision,
            approval_id: gateResult.approval_id,
            _meta: gateResult._meta,
          },
        },
        pairedItem: i,
      });
    }

    return [results];
  }
}
