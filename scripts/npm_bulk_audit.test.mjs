import assert from "node:assert/strict";
import test from "node:test";

import { blockingAdvisories, collectPackageVersions } from "./npm_bulk_audit.mjs";

test("collectPackageVersions walks, deduplicates, and excludes only workspace roots", () => {
  const packages = collectPackageVersions([
    {
      name: "private-root",
      version: "1.0.0",
      dependencies: {
        alpha: {
          version: "1.2.3",
          dependencies: { beta: { version: "2.0.0-rc.1" } },
        },
        beta: { version: "2.0.0-rc.1" },
      },
      devDependencies: { alpha: { version: "1.2.3" } },
    },
  ]);

  assert.deepEqual(packages, {
    alpha: ["1.2.3"],
    beta: ["2.0.0-rc.1"],
  });
});

test("collectPackageVersions fails closed on every non-registry dependency source", () => {
  for (const version of [
    "link:../local",
    "file:../local",
    "workspace:*",
    "git+https://example.test/repo.git#0123456789abcdef",
    "https://example.test/package.tgz",
    "npm:actual-package@1.2.3",
    undefined,
  ]) {
    assert.throws(
      () => collectPackageVersions([{
        name: "private-root",
        version: "workspace:.",
        dependencies: { unsupported: { version } },
      }]),
      /non-registry version.*separate pinned-source verifier/,
      `accepted unsupported dependency version ${String(version)}`,
    );
  }
});

test("collectPackageVersions rejects malformed graph nodes instead of skipping them", () => {
  assert.throws(
    () => collectPackageVersions([{ dependencies: { alpha: "1.2.3" } }]),
    /dependency alpha is not an object/,
  );
  assert.throws(
    () => collectPackageVersions([{ dependencies: [] }]),
    /bucket dependencies is not an object/,
  );
  assert.throws(() => collectPackageVersions([null]), /invalid workspace root/);
});

test("blockingAdvisories applies the requested severity floor deterministically", () => {
  const findings = blockingAdvisories({
    beta: [{ id: 3, severity: "moderate", title: "medium" }],
    alpha: [
      { id: 2, severity: "high", title: "high" },
      { id: 1, severity: "critical", title: "critical" },
    ],
  });

  assert.deepEqual(
    findings.map(({ packageName, id }) => [packageName, id]),
    [["alpha", 1], ["alpha", 2]],
  );
});

test("malformed audit responses fail closed", () => {
  assert.throws(() => blockingAdvisories([]), /not an object/);
  assert.throws(() => blockingAdvisories({ alpha: {} }), /not an array/);
  assert.throws(
    () => blockingAdvisories({ alpha: [{ severity: "mystery" }] }),
    /unknown severity/,
  );
});
