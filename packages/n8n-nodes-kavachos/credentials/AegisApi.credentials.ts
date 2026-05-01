// SPDX-License-Identifier: AGPL-3.0-only
// @rule:KAV-078 adapter credentials: base URL + optional token — no keys bundled
import type { ICredentialType, INodeProperties } from "n8n-workflow";

export class AegisApi implements ICredentialType {
  name = "aegisApi";
  displayName = "Aegis API";
  documentationUrl = "https://kavachos.xshieldai.com";

  properties: INodeProperties[] = [
    {
      displayName: "Aegis Base URL",
      name: "baseUrl",
      type: "string",
      default: "http://localhost:4850",
      placeholder: "http://localhost:4850",
      description: "URL of the Aegis dashboard server (runs POST /api/v1/kavach/gate)",
    },
    {
      displayName: "API Token (optional)",
      name: "token",
      type: "string",
      typeOptions: { password: true },
      default: "",
      description: "Bearer token if Aegis dashboard auth is enabled",
    },
  ];
}
