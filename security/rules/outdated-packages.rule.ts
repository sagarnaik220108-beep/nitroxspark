import type { RuleContext, RuleMatch, SecurityRule } from "@/types";
import { extractCodeSnippet, offsetToLineColumn } from "@/utils";

interface VulnerablePackageAdvisory {
  readonly minSafeVersion: readonly [number, number, number];
  readonly cve: string;
  readonly reason: string;
}

const VULNERABLE_NPM_PACKAGES: Record<string, VulnerablePackageAdvisory> = {
  lodash: {
    minSafeVersion: [4, 17, 21],
    cve: "CVE-2021-23337 / CVE-2020-8203",
    reason: "Command injection and prototype pollution in lodash < 4.17.21.",
  },
  axios: {
    minSafeVersion: [1, 6, 0],
    cve: "CVE-2023-45857 / CVE-2021-3749",
    reason: "CSRF token leakage and ReDoS in outdated axios < 1.6.0.",
  },
  jsonwebtoken: {
    minSafeVersion: [9, 0, 0],
    cve: "CVE-2022-23529",
    reason: "Remote code execution via malicious secretOrPublicKey in jsonwebtoken < 9.0.0.",
  },
  express: {
    minSafeVersion: [4, 19, 2],
    cve: "CVE-2024-29041",
    reason: "Open redirect vulnerability in Express < 4.19.2.",
  },
  minimist: {
    minSafeVersion: [1, 2, 6],
    cve: "CVE-2021-44906",
    reason: "Prototype pollution vulnerability in minimist < 1.2.6.",
  },
  "node-fetch": {
    minSafeVersion: [2, 6, 7],
    cve: "CVE-2022-0235",
    reason: "Exposure of sensitive headers on cross-origin redirect in node-fetch < 2.6.7.",
  },
  qs: {
    minSafeVersion: [6, 10, 3],
    cve: "CVE-2022-24999",
    reason: "Prototype pollution in qs < 6.10.3.",
  },
  tar: {
    minSafeVersion: [6, 2, 1],
    cve: "CVE-2024-28863",
    reason: "Arbitrary file overwrite / DoS in node-tar < 6.2.1.",
  },
  handlebars: {
    minSafeVersion: [4, 7, 7],
    cve: "CVE-2021-23369",
    reason: "Remote code execution via template compilation in handlebars < 4.7.7.",
  },
  jquery: {
    minSafeVersion: [3, 5, 0],
    cve: "CVE-2020-11022",
    reason: "Cross-site scripting (XSS) in jQuery < 3.5.0.",
  },
  "serialize-javascript": {
    minSafeVersion: [3, 1, 0],
    cve: "CVE-2020-7660",
    reason: "Remote code execution via untrusted RegExp serialization in serialize-javascript < 3.1.0.",
  },
  semver: {
    minSafeVersion: [7, 5, 2],
    cve: "CVE-2022-25883",
    reason: "Regular Expression Denial of Service (ReDoS) in semver < 7.5.2.",
  },
  next: {
    minSafeVersion: [14, 2, 10],
    cve: "CVE-2024-46982",
    reason: "Outdated Next.js version with known cache poisoning / SSRF advisories.",
  },
};

const VULNERABLE_PYTHON_PACKAGES: Record<string, VulnerablePackageAdvisory> = {
  django: {
    minSafeVersion: [4, 2, 0],
    cve: "Multiple CVEs",
    reason: "End-of-life or outdated Django release with known SQLi/XSS vulnerabilities.",
  },
  flask: {
    minSafeVersion: [2, 3, 2],
    cve: "CVE-2023-30861",
    reason: "Session cookie disclosure vulnerability in Flask < 2.3.2.",
  },
  pyyaml: {
    minSafeVersion: [5, 4, 0],
    cve: "CVE-2020-14343",
    reason: "Arbitrary code execution via yaml.load in PyYAML < 5.4.",
  },
  requests: {
    minSafeVersion: [2, 31, 0],
    cve: "CVE-2023-32681",
    reason: "Leak of Proxy-Authorization headers in requests < 2.31.0.",
  },
  urllib3: {
    minSafeVersion: [1, 26, 18],
    cve: "CVE-2023-45803",
    reason: "Request body/header leakage on redirects in urllib3 < 1.26.18.",
  },
  pillow: {
    minSafeVersion: [10, 0, 1],
    cve: "CVE-2023-4863",
    reason: "Heap buffer overflow vulnerability in Pillow < 10.0.1.",
  },
  jinja2: {
    minSafeVersion: [3, 1, 4],
    cve: "CVE-2024-34064",
    reason: "XSS / sandbox escape vulnerabilities in Jinja2 < 3.1.4.",
  },
  cryptography: {
    minSafeVersion: [41, 0, 6],
    cve: "CVE-2023-49083",
    reason: "NULL pointer dereference / memory corruption in cryptography < 41.0.6.",
  },
};

const DEPRECATED_IMPORT_PATTERNS: readonly {
  regex: RegExp;
  pkg: string;
  reason: string;
}[] = [
  {
    regex: /\b(?:require\s*\(\s*["']request["']\s*\)|from\s+["']request["'])/g,
    pkg: "request",
    reason:
      "The `request` npm package is deprecated and unmaintained with known SSRF/prototype issues. Migrate to native `fetch` or `undici`.",
  },
  {
    regex: /\b(?:require\s*\(\s*["']node-uuid["']\s*\)|from\s+["']node-uuid["'])/g,
    pkg: "node-uuid",
    reason:
      "`node-uuid` is deprecated and unmaintained. Use `crypto.randomUUID()` or `uuid`.",
  },
  {
    regex: /\bfrom\s+Crypto\.Cipher\s+import\s+(?:ARC4|DES|Blowfish)\b/g,
    pkg: "pycrypto",
    reason:
      "Deprecated/insecure cipher import from unmaintained PyCrypto. Use `cryptography` with AES-GCM.",
  },
];

function parseSemver(versionStr: string): readonly [number, number, number] | null {
  const match = /(\d+)(?:\.(\d+))?(?:\.(\d+))?/.exec(versionStr);
  if (!match || !match[1]) return null;
  const major = Number.parseInt(match[1], 10);
  const minor = match[2] ? Number.parseInt(match[2], 10) : 0;
  const patch = match[3] ? Number.parseInt(match[3], 10) : 0;
  if (Number.isNaN(major) || Number.isNaN(minor) || Number.isNaN(patch)) {
    return null;
  }
  return [major, minor, patch];
}

function isVersionLessThan(
  actual: readonly [number, number, number],
  minSafe: readonly [number, number, number]
): boolean {
  if (actual[0] !== minSafe[0]) return actual[0] < minSafe[0];
  if (actual[1] !== minSafe[1]) return actual[1] < minSafe[1];
  return actual[2] < minSafe[2];
}

/**
 * Rule 10: Outdated Packages
 * Detects known vulnerable or end-of-life dependency versions in package.json,
 * requirements.txt, wildcard dependency pins, and deprecated insecure package imports.
 */
export const outdatedPackagesRule: SecurityRule = {
  id: "SENTINEL-PKG-001",
  name: "Outdated or Vulnerable Packages",
  description:
    "Detects known vulnerable package versions in package.json or requirements.txt, unpinned wildcard dependencies, and deprecated/unmaintained security-sensitive imports.",
  explanation:
    "Relying on outdated or unmaintained third-party packages exposes the application to publicly disclosed CVEs—including Remote Code Execution, Prototype Pollution, SSRF, and XSS—that attackers actively exploit with automated scanners.",
  severity: "high",
  category: "misconfiguration",
  cweId: "CWE-1104",
  owaspCategory: "A06:2021 - Vulnerable and Outdated Components",
  languages: "*",
  tags: ["dependencies", "supply-chain", "cve", "outdated-packages", "cwe-1104"],
  enabledByDefault: true,
  remediation: {
    summary:
      "Upgrade vulnerable packages to patched releases, replace deprecated libraries, and run automated dependency audits (npm audit / pip-audit) in CI.",
    explanation:
      "Pin dependencies to patched versions above the minimum safe release, avoid wildcard (`*` / `latest`) ranges, and enable automated security updates (Dependabot or Renovate).",
    secureCodeExample: `// package.json (Secure: patched, pinned dependency versions)
{
  "dependencies": {
    "axios": "^1.7.9",
    "express": "^4.21.2",
    "jsonwebtoken": "^9.0.2",
    "lodash": "^4.17.21"
  }
}`,
    references: [
      "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
      "https://cwe.mitre.org/data/definitions/1104.html",
    ],
  },

  evaluate(context: RuleContext): RuleMatch[] {
    const matches: RuleMatch[] = [];
    const seenLineCols = new Set<string>();

    const recordMatch = (
      offset: number,
      length: number,
      matchedText: string,
      explanation: string,
      confidence = 0.91
    ) => {
      const startPos = offsetToLineColumn(context.code, offset);
      const endPos = offsetToLineColumn(context.code, offset + length);
      const key = `${startPos.line}:${startPos.column}`;
      if (seenLineCols.has(key)) return;
      seenLineCols.add(key);

      matches.push({
        line: startPos.line,
        column: startPos.column,
        endLine: endPos.line,
        endColumn: endPos.column,
        matchedText: matchedText.trim().slice(0, 200),
        snippet: extractCodeSnippet(context.lines, startPos.line),
        confidence,
        customExplanation: explanation,
      });
    };

    // 1. Scan package.json style entries: "pkg": "^1.2.3" or "*" / "latest"
    const npmDepRegex =
      /"([a-zA-Z0-9@/_-]+)"\s*:\s*"([~^>=<]*\d+(?:\.\d+){0,2}[^"]*|latest|\*)"/g;
    let match: RegExpExecArray | null;
    while ((match = npmDepRegex.exec(context.code)) !== null) {
      const pkgName = match[1]?.toLowerCase();
      const versionSpec = match[2];
      if (!pkgName || !versionSpec) continue;

      if (versionSpec === "*" || versionSpec === "latest") {
        recordMatch(
          match.index,
          match[0].length,
          match[0],
          `Unpinned wildcard dependency "${pkgName}": "${versionSpec}" can silently pull breaking or compromised releases.`,
          0.86
        );
        continue;
      }

      const advisory = VULNERABLE_NPM_PACKAGES[pkgName];
      if (!advisory) continue;

      const parsed = parseSemver(versionSpec);
      if (parsed && isVersionLessThan(parsed, advisory.minSafeVersion)) {
        const safeStr = advisory.minSafeVersion.join(".");
        recordMatch(
          match.index,
          match[0].length,
          match[0],
          `Outdated npm package "${pkgName}@${versionSpec}" (${advisory.cve}): ${advisory.reason} Upgrade to >= ${safeStr}.`,
          0.94
        );
      }
    }

    // 2. Scan requirements.txt style entries: package==1.2.3 or package<=1.2.3
    const pyDepRegex =
      /^([a-zA-Z0-9_-]+)\s*(?:==|<=|~=)\s*(\d+(?:\.\d+){0,2})/gm;
    while ((match = pyDepRegex.exec(context.code)) !== null) {
      const pkgName = match[1]?.toLowerCase();
      const versionSpec = match[2];
      if (!pkgName || !versionSpec) continue;

      const advisory = VULNERABLE_PYTHON_PACKAGES[pkgName];
      if (!advisory) continue;

      const parsed = parseSemver(versionSpec);
      if (parsed && isVersionLessThan(parsed, advisory.minSafeVersion)) {
        const safeStr = advisory.minSafeVersion.join(".");
        recordMatch(
          match.index,
          match[0].length,
          match[0],
          `Outdated Python package "${pkgName}==${versionSpec}" (${advisory.cve}): ${advisory.reason} Upgrade to >= ${safeStr}.`,
          0.93
        );
      }
    }

    // 3. Scan deprecated / insecure imports in code
    for (const item of DEPRECATED_IMPORT_PATTERNS) {
      const regex = new RegExp(item.regex.source, item.regex.flags);
      while ((match = regex.exec(context.code)) !== null) {
        if (match[0].length === 0) {
          regex.lastIndex += 1;
          continue;
        }
        recordMatch(
          match.index,
          match[0].length,
          match[0],
          `Deprecated package "${item.pkg}" imported: ${item.reason}`,
          0.88
        );
      }
    }

    return matches;
  },
};
