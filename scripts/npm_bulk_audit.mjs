#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const AUDIT_ENDPOINT = "https://registry.npmjs.org/-/npm/v1/security/advisories/bulk";
const SEVERITY_RANK = Object.freeze({
  info: 0,
  low: 1,
  moderate: 2,
  high: 3,
  critical: 4,
});

function isRegistryVersion(version) {
  return typeof version === "string"
    && /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(version);
}

export function collectPackageVersions(listOutput) {
  if (!Array.isArray(listOutput)) {
    throw new Error("pnpm list did not return a JSON array");
  }

  const collected = new Map();

  function add(name, version) {
    if (typeof name !== "string" || name.length === 0) {
      throw new Error("pnpm dependency graph contains an unnamed dependency");
    }
    if (!isRegistryVersion(version)) {
      const rendered = version === undefined ? "missing" : JSON.stringify(version);
      throw new Error(
        `dependency ${name} has non-registry version ${rendered}; `
        + "git/file/link/workspace/URL/npm-alias sources require a separate pinned-source verifier",
      );
    }
    const versions = collected.get(name) ?? new Set();
    versions.add(version);
    collected.set(name, versions);
  }

  function walkDependencies(node) {
    if (node === null || typeof node !== "object") {
      return;
    }
    for (const bucket of ["dependencies", "optionalDependencies", "devDependencies"]) {
      const dependencies = node[bucket];
      if (dependencies === undefined) {
        continue;
      }
      if (dependencies === null || typeof dependencies !== "object" || Array.isArray(dependencies)) {
        throw new Error(`pnpm dependency graph bucket ${bucket} is not an object`);
      }
      for (const [name, dependency] of Object.entries(dependencies)) {
        if (dependency === null || typeof dependency !== "object" || Array.isArray(dependency)) {
          throw new Error(`pnpm dependency ${name} is not an object`);
        }
        add(name, dependency.version);
        walkDependencies(dependency);
      }
    }
  }

  for (const root of listOutput) {
    if (root === null || typeof root !== "object" || Array.isArray(root)) {
      throw new Error("pnpm list contains an invalid workspace root");
    }
    walkDependencies(root);
  }

  return Object.fromEntries(
    [...collected.entries()]
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([name, versions]) => [name, [...versions].sort()]),
  );
}

export function blockingAdvisories(response, minimumSeverity = "high") {
  const minimumRank = SEVERITY_RANK[minimumSeverity];
  if (minimumRank === undefined) {
    throw new Error(`unsupported audit severity: ${minimumSeverity}`);
  }
  if (response === null || typeof response !== "object" || Array.isArray(response)) {
    throw new Error("npm bulk advisory response is not an object");
  }

  const findings = [];
  for (const [packageName, advisories] of Object.entries(response)) {
    if (!Array.isArray(advisories)) {
      throw new Error(`npm bulk advisory entry for ${packageName} is not an array`);
    }
    for (const advisory of advisories) {
      const rank = SEVERITY_RANK[advisory?.severity];
      if (rank === undefined) {
        throw new Error(`npm advisory for ${packageName} has an unknown severity`);
      }
      if (rank >= minimumRank) {
        findings.push({ packageName, ...advisory });
      }
    }
  }

  return findings.sort((left, right) =>
    SEVERITY_RANK[right.severity] - SEVERITY_RANK[left.severity]
      || left.packageName.localeCompare(right.packageName)
      || String(left.id).localeCompare(String(right.id)),
  );
}

function parseArguments(argv) {
  let productionOnly = false;
  let minimumSeverity = "high";

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--prod") {
      productionOnly = true;
    } else if (argument === "--audit-level") {
      minimumSeverity = argv[index + 1];
      index += 1;
    } else {
      throw new Error(`unsupported argument: ${argument}`);
    }
  }

  if (SEVERITY_RANK[minimumSeverity] === undefined) {
    throw new Error(`unsupported audit severity: ${minimumSeverity}`);
  }
  return { productionOnly, minimumSeverity };
}

async function run() {
  const { productionOnly, minimumSeverity } = parseArguments(process.argv.slice(2));
  const listArguments = ["list"];
  if (productionOnly) {
    listArguments.push("--prod");
  }
  listArguments.push("--json", "--depth", "Infinity");

  const command = process.platform === "win32" ? (process.env.ComSpec ?? "cmd.exe") : "pnpm";
  const commandArguments = process.platform === "win32"
    ? ["/d", "/s", "/c", `pnpm ${listArguments.join(" ")}`]
    : listArguments;
  const rawList = execFileSync(command, commandArguments, {
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    stdio: ["ignore", "pipe", "inherit"],
  });
  const packages = collectPackageVersions(JSON.parse(rawList));
  const packageNames = Object.keys(packages);
  if (packageNames.length === 0) {
    throw new Error("pnpm dependency graph is empty; refusing to report a clean audit");
  }

  const response = await fetch(AUDIT_ENDPOINT, {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/json",
      "user-agent": "neoth-release-audit/1.0",
    },
    body: JSON.stringify(packages),
    signal: AbortSignal.timeout(30_000),
  });
  if (!response.ok) {
    const detail = (await response.text()).slice(0, 512).replace(/[\r\n]+/g, " ");
    throw new Error(`npm bulk advisory API failed closed (${response.status}): ${detail}`);
  }

  const findings = blockingAdvisories(await response.json(), minimumSeverity);
  const versionCount = Object.values(packages).reduce((total, versions) => total + versions.length, 0);
  console.log(`Audited ${versionCount} package versions across ${packageNames.length} npm packages.`);

  if (findings.length === 0) {
    console.log(`No ${minimumSeverity} or higher npm advisories found.`);
    return;
  }

  for (const finding of findings) {
    const reference = finding.url ?? `npm advisory ${finding.id ?? "unknown"}`;
    console.error(
      `[${String(finding.severity).toUpperCase()}] ${finding.packageName}: ${finding.title ?? "untitled advisory"} (${reference})`,
    );
  }
  throw new Error(`${findings.length} blocking npm advisory finding(s)`);
}

const invokedPath = process.argv[1] ? fileURLToPath(import.meta.url) === process.argv[1] : false;
if (invokedPath) {
  run().catch((error) => {
    console.error(`npm bulk audit failed: ${error.message}`);
    process.exitCode = 1;
  });
}
