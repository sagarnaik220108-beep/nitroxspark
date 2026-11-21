import type { SecurityRule } from "@/types";
import { createRegexRule } from "./base";

const PASSWORD_PLACEHOLDERS = [
  "your-password",
  "your_password",
  "example",
  "placeholder",
  "changeme",
  "change_me",
  "redacted",
  "***",
  "<password>",
  "${",
];

/**
 * Rule 2: Hardcoded Passwords
 * Detects plaintext password literals assigned to variables, config properties,
 * auth headers, or direct authentication comparisons.
 */
export const hardcodedPasswordsRule: SecurityRule = createRegexRule({
  id: "SENTINEL-PWD-001",
  name: "Hardcoded Passwords",
  description:
    "Detects plaintext passwords embedded directly in variable assignments, configuration objects, Basic Auth headers, or authentication comparisons.",
  explanation:
    "Embedding plaintext passwords in source code allows anyone with read access to the repository, build artifacts, or container images to authenticate as privileged accounts or access backend services without authorization.",
  severity: "critical",
  category: "secrets",
  cweId: "CWE-259",
  owaspCategory: "A07:2021 - Identification and Authentication Failures",
  languages: "*",
  tags: ["secrets", "password", "credentials", "cwe-259"],
  confidence: 0.92,
  redactMatch: true,
  patterns: [
    /\b(?:password|passwd|pwd|db[_-]?pass(?:word)?|admin[_-]?pass(?:word)?|root[_-]?pass(?:word)?|user[_-]?pass(?:word)?|smtp[_-]?pass(?:word)?|default[_-]?pass(?:word)?)\s*[:=]\s*["'][^"'\s]{4,}["']/gi,
    /\b(?:password|passwd|pwd)\s*(?:===?|!==?)\s*["'][^"'\s]{4,}["']/gi,
    /\bAuthorization["']?\s*[:=]\s*["']Basic\s+[A-Za-z0-9+/]{12,}={0,2}["']/gi,
  ],
  filterMatch: (match) => {
    const lower = match[0].toLowerCase();
    return !PASSWORD_PLACEHOLDERS.some((placeholder) =>
      lower.includes(placeholder)
    );
  },
  remediation: {
    summary:
      "Remove hardcoded passwords, rotate affected credentials, and load secrets from a secret manager or verify user passwords against salted cryptographic hashes.",
    explanation:
      "Never store plaintext passwords in code. For service credentials, inject them via environment variables or a secret vault. For user authentication, store salted Argon2id, scrypt, or bcrypt hashes in the database and verify using constant-time comparison.",
    secureCodeExample: `import { scryptSync, timingSafeEqual } from "node:crypto";

// Secure: Load service credentials from environment variables
const smtpPassword = process.env.SMTP_PASSWORD;
if (!smtpPassword) {
  throw new Error("SMTP_PASSWORD is not configured");
}

// Secure: Verify user password against a stored salted hash
export function verifyPassword(input: string, storedHash: string): boolean {
  const [salt, keyHex] = storedHash.split(":");
  if (!salt || !keyHex) return false;
  const derived = scryptSync(input, salt, 64);
  const stored = Buffer.from(keyHex, "hex");
  return derived.length === stored.length && timingSafeEqual(derived, stored);
}`,
    references: [
      "https://cwe.mitre.org/data/definitions/259.html",
      "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
    ],
  },
});
