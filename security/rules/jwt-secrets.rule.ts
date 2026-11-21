import type { SecurityRule } from "@/types";
import { createRegexRule } from "./base";

const JWT_PLACEHOLDERS = [
  "your-256-bit-secret",
  "your_jwt_secret",
  "your-jwt-secret",
  "example",
  "placeholder",
];

/**
 * Rule 3: JWT Secrets
 * Detects hardcoded JWT signing secrets, inline secret literals in jwt.sign/verify,
 * and insecure fallback default secrets when environment variables are missing.
 */
export const jwtSecretsRule: SecurityRule = createRegexRule({
  id: "SENTINEL-JWT-001",
  name: "Hardcoded or Weak JWT Secret",
  description:
    "Detects hardcoded JWT signing secrets, inline string literals passed to jwt.sign()/jwt.verify(), or insecure fallback defaults on JWT environment variables.",
  explanation:
    "If a JWT signing secret is hardcoded in source code or falls back to a predictable default string, attackers can forge arbitrary signed tokens with elevated privileges (such as `role: 'admin'`) and bypass authentication across the entire application.",
  severity: "critical",
  category: "secrets",
  cweId: "CWE-798",
  owaspCategory: "A02:2021 - Cryptographic Failures",
  languages: "*",
  tags: ["jwt", "secrets", "token-forgery", "authentication", "cwe-798"],
  confidence: 0.94,
  redactMatch: true,
  patterns: [
    /\b(?:jwt[_-]?secret|jwt[_-]?key|token[_-]?secret|signing[_-]?secret|session[_-]?secret)\s*[:=]\s*["'][^"']{3,}["']/gi,
    /\bjwt\.(?:sign|verify|encode|decode)\s*\([^,\n]+,\s*["'][^"']{3,}["']/g,
    /process\.env\.[A-Z0-9_]*(?:JWT|TOKEN|SESSION|SIGN)[A-Z0-9_]*\s*(?:\|\||\?\?)\s*["'][^"']{2,}["']/g,
  ],
  filterMatch: (match) => {
    const lower = match[0].toLowerCase();
    return !JWT_PLACEHOLDERS.some((placeholder) => lower.includes(placeholder));
  },
  remediation: {
    summary:
      "Store a high-entropy JWT signing key in server-only environment variables (or asymmetric RS256/ES256 keys in a KMS) and fail closed if the variable is missing.",
    explanation:
      "Generate a cryptographically random 256-bit (or stronger) secret or asymmetric keypair, inject it via environment variables, never provide a hardcoded fallback string, and explicitly enforce the allowed signing algorithm.",
    secureCodeExample: `import jwt from "jsonwebtoken";

// Secure: Fail closed if JWT_SECRET is missing — never use a fallback literal
const jwtSecret = process.env.JWT_SECRET;
if (!jwtSecret || jwtSecret.length < 32) {
  throw new Error("JWT_SECRET must be set to a strong 32+ character secret");
}

export function signAccessToken(userId: string): string {
  return jwt.sign({ sub: userId }, jwtSecret, {
    algorithm: "HS256",
    expiresIn: "15m",
    issuer: "sentinel-ai",
  });
}`,
    references: [
      "https://cwe.mitre.org/data/definitions/798.html",
      "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
    ],
  },
});
