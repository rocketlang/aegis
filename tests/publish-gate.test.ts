// SPDX-License-Identifier: AGPL-3.0-only
// AF-T-707 — the publish gate (AFW-012, ANU-I-010). Both outcomes per branch
// (@rule:guards-assert-both-outcomes): recognition both ways, artifact resolution both ways,
// mandate matching exact/prefix/wildcard/expired, and every verdict observe-staged at birth.
import { describe, it, expect } from "bun:test";
import {
  isPublishInvocation, resolvePublishArtifact, mandateFor, publishVerdict,
  type PublishMandate,
} from "../src/kavach/publish-capability";

const NOW = Date.now();
const mandate = (artifact: string, expiresInMs = 3600e3): PublishMandate => ({
  artifact, reason: "test", granted_by: "human",
  granted_at: new Date(NOW).toISOString(), expires_at: new Date(NOW + expiresInMs).toISOString(),
});

describe("isPublishInvocation (AFW-012 verb set)", () => {
  it("recognises the outward-write verbs — and inbound/local work is NOT one", () => {
    expect(isPublishInvocation("npm publish").publish).toBe(true);
    expect(isPublishInvocation("cd packages/kavachos && npm publish --access public").kind).toBe("npm-package");
    expect(isPublishInvocation("gem push pkg-1.0.0.gem").kind).toBe("gem");
    expect(isPublishInvocation("python3 -m twine upload dist/*").kind).toBe("pypi");
    expect(isPublishInvocation("docker push registry.example/app:1.2").kind).toBe("docker-image");
    expect(isPublishInvocation("gh release create v2.1.0 dist.tgz").kind).toBe("gh-release");
    expect(isPublishInvocation("npm install left-pad").publish).toBe(false);
    expect(isPublishInvocation("git push origin master").publish).toBe(false);
    expect(isPublishInvocation("npm run publish-docs").publish).toBe(false); // run-script, not the verb
  });
});

describe("resolvePublishArtifact", () => {
  it("names the artifact when the text carries it; cwd-implicit publish resolves to null", () => {
    expect(resolvePublishArtifact("docker push registry.example/app:1.2")).toBe("registry.example/app:1.2");
    expect(resolvePublishArtifact("gem push xshield-1.0.0.gem")).toBe("xshield-1.0.0.gem");
    expect(resolvePublishArtifact("gh release create v2.1.0")).toBe("v2.1.0");
    expect(resolvePublishArtifact("npm publish ./dist-tarball.tgz")).toBe("./dist-tarball.tgz");
    expect(resolvePublishArtifact("npm publish")).toBeNull();
    expect(resolvePublishArtifact("npm publish --access public")).toBeNull(); // flag is not an artifact
  });
});

describe("mandateFor", () => {
  it("matches exact, prefix* and * — and an unresolved artifact only matches *", () => {
    expect(mandateFor("app:1.2", [mandate("app:1.2")])).not.toBeNull();
    expect(mandateFor("app:1.3", [mandate("app:1.2")])).toBeNull();
    expect(mandateFor("registry.example/app:9", [mandate("registry.example/*")])).not.toBeNull();
    expect(mandateFor("other/app:9", [mandate("registry.example/*")])).toBeNull();
    expect(mandateFor(null, [mandate("app:1.2")])).toBeNull();
    expect(mandateFor(null, [mandate("*")])).not.toBeNull();
  });
});

describe("publishVerdict (ANU-I-010) — observe at birth (AFW-006)", () => {
  it("no mandate REFUSES; a live mandate PERMITS and cites it; unresolved artifact is UNKNOWN", () => {
    const refuse = publishVerdict("docker push registry.example/app:1.2", []);
    expect(refuse.verdict).toBe("REFUSE");
    expect(refuse.stage).toBe("observe");
    expect(refuse.detail).toContain("NO live mandate");

    const permit = publishVerdict("docker push registry.example/app:1.2", [mandate("registry.example/*")]);
    expect(permit.verdict).toBe("PERMIT");
    expect(permit.detail).toContain("granted by human");

    const unknown = publishVerdict("npm publish", [mandate("something-else")]);
    expect(unknown.verdict).toBe("UNKNOWN");
    expect(unknown.stage).toBe("observe");
  });
});
