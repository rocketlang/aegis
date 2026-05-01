// SPDX-License-Identifier: AGPL-3.0-only
// @rule:AEG-012 KavachBudget = budget observability surface for n8n workflows
// @rule:CA-004 telemetry minimum — _meta on every response
// @rule:INF-KAV-023 budget state readable without auth — adapters need it for pre-flight checks
import type {
  IExecuteFunctions,
  INodeExecutionData,
  INodeType,
  INodeTypeDescription,
} from "n8n-workflow";
import { NodeOperationError } from "n8n-workflow";

export class KavachBudget implements INodeType {
  description: INodeTypeDescription = {
    displayName: "Kavach Budget",
    name: "kavachBudget",
    icon: "file:kavach-budget.svg",
    group: ["transform"],
    version: 1,
    subtitle: "Budget + valve state",
    description:
      "Reads the current AEGIS budget state (daily spend, limit, remaining, breach flag) and " +
      "gate-valve status. Use to guard expensive workflows or to surface cost data in dashboards.",
    defaults: { name: "Kavach Budget" },
    inputs: ["main"],
    outputs: ["main", "main"],
    outputNames: ["within budget", "breached"],
    credentials: [
      {
        name: "aegisApi",
        required: true,
      },
    ],
    properties: [
      {
        displayName: "Halt on Breach",
        name: "haltOnBreach",
        type: "boolean",
        default: false,
        description:
          "When true and budget is breached, throw an error instead of routing to the 'breached' output.",
      },
    ],
  };

  async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
    const items = this.getInputData();
    const withinBudget: INodeExecutionData[] = [];
    const breachedItems: INodeExecutionData[] = [];

    const credentials = await this.getCredentials("aegisApi");
    const baseUrl = (credentials.baseUrl as string).replace(/\/$/, "");
    const token = credentials.token as string | undefined;

    for (let i = 0; i < items.length; i++) {
      const haltOnBreach = this.getNodeParameter("haltOnBreach", i) as boolean;

      const headers: Record<string, string> = {};
      if (token) headers["Authorization"] = `Bearer ${token}`;

      let state: {
        budget: {
          daily_spent_usd: number;
          daily_limit_usd: number;
          daily_remaining_usd: number;
          breached: boolean;
        };
        kavach_enabled: boolean;
        _meta: { computed_at: string; duration_ms?: number };
      };

      try {
        const res = await fetch(`${baseUrl}/api/v1/kavach/state`, { headers });

        if (!res.ok) {
          const text = await res.text().catch(() => res.status.toString());
          throw new NodeOperationError(
            this.getNode(),
            `Aegis state returned HTTP ${res.status}: ${text}`,
            { itemIndex: i }
          );
        }

        state = (await res.json()) as typeof state;
      } catch (err: any) {
        throw new NodeOperationError(
          this.getNode(),
          `Cannot reach Aegis state at ${baseUrl}: ${err.message}`,
          { itemIndex: i }
        );
      }

      const output: INodeExecutionData = {
        json: {
          ...items[i].json,
          kavach_budget: {
            daily_spent_usd: state.budget.daily_spent_usd,
            daily_limit_usd: state.budget.daily_limit_usd,
            daily_remaining_usd: state.budget.daily_remaining_usd,
            breached: state.budget.breached,
            kavach_enabled: state.kavach_enabled,
            _meta: state._meta,
          },
        },
        pairedItem: i,
      };

      if (state.budget.breached) {
        if (haltOnBreach) {
          throw new NodeOperationError(
            this.getNode(),
            `KAVACH budget breached: $${state.budget.daily_spent_usd.toFixed(4)} of $${state.budget.daily_limit_usd} daily limit used`,
            { itemIndex: i }
          );
        }
        breachedItems.push(output);
      } else {
        withinBudget.push(output);
      }
    }

    return [withinBudget, breachedItems];
  }
}
