// SPDX-License-Identifier: AGPL-3.0-only
// The dashboard's session guard decides on the matched route, not on the request address (aegis 2.16.3).
// The end-to-end proof against a running dashboard is red-team/dashboard-login-check.battery.sh.
import { describe, expect, test } from "bun:test";
import { isPublicRoute } from "../src/dashboard/public-routes";

describe("dashboard public routes", () => {
  test("a protected route is not public however the address is dressed", () => {
    for (const url of ["/api/status", "/api/status?x=.js", "/api/status;x=.css", "/api/status?.png"]) {
      expect(isPublicRoute("GET", "/api/status", url)).toBe(false);
    }
    expect(isPublicRoute("GET", "/api/v1/tenants/:id", "/api/v1/tenants/a.js")).toBe(false);
    expect(isPublicRoute("POST", "/api/kill", "/api/kill?x=.js")).toBe(false);
  });

  test("an address that matched no route is not public", () => {
    expect(isPublicRoute("GET", undefined, "/demo")).toBe(false);
    expect(isPublicRoute("GET", undefined, "/x.js")).toBe(false);
  });

  test("a public page stays public with a query string after it", () => {
    expect(isPublicRoute("GET", "/demo", "/demo?utm_source=linkedin")).toBe(true);
    expect(isPublicRoute("GET", "/health", "/health?x=1")).toBe(true);
    expect(isPublicRoute("POST", "/api/demo/run", "/api/demo/run")).toBe(true);
  });

  test("on the static route only a plain style sheet, script or image name is public", () => {
    for (const url of ["/aegis.css", "/aegis.js", "/aegis.js?v=2", "/favicon.ico", "/logo.png"]) {
      expect(isPublicRoute("GET", "/*", url)).toBe(true);
    }
    for (const url of ["/", "/index.html", "/index.html?x=.js", "/index.html;.js", "/?x=.js", "/a/b.js", "/..%2fx.js", "/.js"]) {
      expect(isPublicRoute("GET", "/*", url)).toBe(false);
    }
  });

  test("the one method-bound rule: the approvals list is public to GET only", () => {
    expect(isPublicRoute("GET", "/api/approvals", "/api/approvals")).toBe(true);
    expect(isPublicRoute("POST", "/api/approvals/:id/decide", "/api/approvals/1/decide")).toBe(false);
  });

  test("a CORS preflight is answered; the wildcard route is public to nothing else", () => {
    expect(isPublicRoute("OPTIONS", "*", "/api/demo/run")).toBe(true);
    expect(isPublicRoute("GET", "*", "/api/status")).toBe(false);
  });
});
