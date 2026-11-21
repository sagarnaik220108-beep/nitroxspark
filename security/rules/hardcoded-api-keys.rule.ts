import type { SecurityRule } from "@/types";
import { createRegexRule } from "./base";

const PLACEHOLDER_INDICATORS = [
  "your-",
  "your_",
  "example",
  "placeholder",
  "changeme",
  "replace_me",
  "replace-me",
  "dummy",
  "fake",
  "sample",
  "xxxx",
  "00000000",
];

/**
 * Rule 1: Hardcoded API Keys
 * Detects embedded cloud, LLM, payment, SCM, and generic service API keys in source code.
 */
export const hardcodedApiKeysRule: SecurityRule = createRegexRule({
  id: "SENTINEL-KEY-001",
  name: "Hardcoded API Keys",
  description:
    "Detects hardcoded cloud provider keys, LLM API keys, payment keys, GitHub tokens, or generic API key literals embedded in source code.",
  explanation:
    "Hardcoded API keys committed to source code are permanently exposed in Git history, client bundles, CI/CD logs, and backups. Attackers continuously scrape repositories and JavaScript bundles to hijack cloud accounts, drain API quotas, and exfiltrate private data.",
  severity: "critical",
  category: "secrets",
  cweId: "CWE-798",
  owaspCategory: "A07:2021 - Identification and Authentication Failures",
  languages: "*",
  tags: ["secrets", "api-key", "credentials", "cwe-798"],
  confidence: 0.95,
  redactMatch: true,
  patterns: [
    /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
    /\bsk-(?:live|test|proj|ant-api\d{2})?-?[a-zA-Z0-9_-]{20,}\b/g,
    /\bgh[pousr]_[a-zA-Z0-9]{20,}\b/g,
    /\bgithub_pat_[a-zA-Z0-9_]{22,}\b/g,
    /\bAIza[0-9A-Za-z_-]{35}\b/g,
    /\bxox[baprs]-[0-9a-zA-Z-]{10,48}\b/g,
    /\bSG\.[a-zA-Z0-9_-]{16,}\.[a-zA-Z0-9_-]{16,}\b/g,
    /\b(?:api[_-]?key|apikey|client[_-]?secret|access[_-]?token|auth[_-]?token|service[_-]?role[_-]?key|stripe[_-]?key|openai[_-]?key|anthropic[_-]?key)\s*[:=]\s*["'][A-Za-z0-9+/=._-]{16,}["']/gi,
  ],
  filterMatch: (match) => {
    const lower = match[0].toLowerCase();
    return !PLACEHOLDER_INDICATORS.some((indicator) =>
      lower.includes(indicator)
    );
  },
  remediation: {
    summary:
      "Remove hardcoded API keys from source code, rotate the exposed credentials immediately, and load them from server-only environment variables or a secret manager.",
    explanation:
      "Store API keys in your deployment platform's encrypted environment variables (e.g., Vercel Environment Variables, AWS Secrets Manager, or HashiCorp Vault) and read them at runtime via `process.env`. Immediately revoke and regenerate any key that was committed.",
    secureCodeExample: `// Secure: Read API keys from server-side environment variables
const apiKey = process.env.OPENAI_API_KEY;
if (!apiKey) {
  throw new Error("OPENAI_API_KEY environment variable is not configured");
}`,
    references: [
      "https://cwe.mitre.org/data/definitions/798.html",
      "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
    ],
  },
});
