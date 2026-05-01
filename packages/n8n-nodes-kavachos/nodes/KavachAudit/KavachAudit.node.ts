// SPDX-License-Identifier: AGPL-3.0-only
// @rule:KOS-T032 kavachos audit replays PRAMANA receipt chain, flags gaps
// @rule:AEG-012 KavachAudit = audit query surface for n8n workflows
// @rule:CA-001 large payloads → overflow_granthx_ref, never truncate inline
// @rule:INF-KAV-024 audit endpoint filters by session_id, date range, or status
import type {
  IExecuteFunctions,
  INodeExecutionData,
  INodeType,
  INodeTypeDescription,
} from "n8n-workflow";
import { NodeOperationError } from "n8n-workflow";

export class KavachAudit implements INodeType {
  description: INodeTypeDescription = {
    displayName: "Kavach Audit",
    name: "kavachAudit",
    icon: "file:kavach-audit.svg",
    group: ["transform"],
    version: 1,
    subtitle: "Query DAN gate audit log",
    description:
      "Queries the AEGIS audit log (kavach_approvals table). Returns gate decisions filtered by " +
      "session ID, status, DAN level, or date range. Use for compliance reporting or post-incident review.",
    defaults: { name: "Kavach Audit" },
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
        displayName: "Filter by Session ID",
        name: "sessionId",
        type: "string",
        default: "",
        placeholder: "exec_abc123",
        description: "Return only records for this session. Leave empty for all sessions.",
      },
      {
        displayName: "Filter by Status",
        name: "status",
        type: "options",
        options: [
          { name: "All", value: "all" },
          { name: "Pending", value: "pending" },
          { name: "Allowed", value: "allow" },
          { name: "Stopped", value: "stop" },
          { name: "Timed Out", value: "timeout" },
        ],
        default: "all",
        description: "Return only records matching this approval status.",
      },
      {
        displayName: "Filter by DAN Level",
        name: "danLevel",
        type: "options",
        options: [
          { name: "All levels", value: 0 },
          { name: "DAN-1 (safe)", value: 1 },
          { name: "DAN-2 (elevated)", value: 2 },
          { name: "DAN-3 (dangerous)", value: 3 },
          { name: "DAN-4 (catastrophic)", value: 4 },
        ],
        default: 0,
        description: "Return only records at this DAN level. 0 = all levels.",
      },
      {
        displayName: "Limit",
        name: "limit",
        type: "number",
        default: 50,
        description: "Maximum number of records to return.",
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
      const sessionId = (this.getNodeParameter("sessionId", i) as string).trim();
      const status = this.getNodeParameter("status", i) as string;
      const danLevel = this.getNodeParameter("danLevel", i) as number;
      const limit = this.getNodeParameter("limit", i) as number;

      const params = new URLSearchParams();
      if (sessionId) params.set("session_id", sessionId);
      if (status !== "all") params.set("status", status);
      if (danLevel > 0) params.set("level", danLevel.toString());
      params.set("limit", limit.toString());

      const headers: Record<string, string> = {};
      if (token) headers["Authorization"] = `Bearer ${token}`;

      let auditResult: {
        records: Array<{
          id: string;
          created_at: string;
          command: string;
          tool_name: string;
          level: number;
          consequence: string;
          session_id: string;
          status: string;
          decided_at?: string;
          decided_by?: string;
        }>;
        total: number;
        _meta: { computed_at: string; duration_ms?: number };
      };

      try {
        const url = `${baseUrl}/api/v1/kavach/audit?${params.toString()}`;
        const res = await fetch(url, { headers });

        if (!res.ok) {
          const text = await res.text().catch(() => res.status.toString());
          throw new NodeOperationError(
            this.getNode(),
            `Aegis audit returned HTTP ${res.status}: ${text}`,
            { itemIndex: i }
          );
        }

        auditResult = (await res.json()) as typeof auditResult;
      } catch (err: any) {
        throw new NodeOperationError(
          this.getNode(),
          `Cannot reach Aegis audit at ${baseUrl}: ${err.message}`,
          { itemIndex: i }
        );
      }

      results.push({
        json: {
          ...items[i].json,
          kavach_audit: {
            records: auditResult.records,
            total: auditResult.total,
            _meta: auditResult._meta,
          },
        },
        pairedItem: i,
      });
    }

    return [results];
  }
}
