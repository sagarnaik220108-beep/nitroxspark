import type { SecurityRule } from "@/types";
import { createRegexRule } from "./base";

/**
 * Rule 8: Weak Authentication
 * Detects unverified JWT decoding, 'none' algorithm allowance, broken password hashes (MD5/SHA-1),
 * plaintext password comparisons, insecure session cookie flags, and authentication bypass toggles.
 */
export const weakAuthenticationRule: SecurityRule = createRegexRule({
  id: "SENTINEL-AUTH-001",
  name: "Weak Authentication",
  description:
    "Detects broken authentication patterns including unverified jwt.decode(), JWT 'none' algorithm, MD5/SHA-1 password hashing, plaintext password comparison, insecure session cookies, or auth-bypass flags.",
  explanation:
    "Weak authentication controls allow attackers to forge session tokens, crack leaked password hashes in seconds, intercept or steal session cookies via XSS/MITM, or bypass login verification completely to take over user and admin accounts.",
  severity: "high",
  category: "authentication",
  cweId: "CWE-287",
  owaspCategory: "A07:2021 - Identification and Authentication Failures",
  languages: [
    "typescript",
    "javascript",
    "python",
    "php",
    "java",
    "go",
    "ruby",
    "csharp",
  ],
  tags: ["authentication", "jwt", "hashing", "cookies", "cwe-287"],
  confidence: 0.9,
  patterns: [
    /\bjwt\.decode\s*\(/g,
    /algorithms\s*:\s*\[[^\]]*["']none["'][^\]]*\]/gi,
    /verify_signature["']?\s*:\s*False/gi,
    /\bcreateHash\s*\(\s*["'](?:md5|sha1)["']\s*\)/gi,
    /\bhashlib\.(?:md5|sha1)\s*\(/gi,
    /\b(?:user|account|dbUser|record)\.password\s*(?:===?|!==?)\s*(?!null\b|undefined\b)[a-zA-Z_$][\w$.]*/g,
    /\b(?:httpOnly|secure)\s*:\s*false\b/g,
    /\b(?:skipAuth|disableAuth|bypassAuth|allowUnauthenticated)\s*[:=]\s*true\b/gi,
  ],
  remediation: {
    summary:
      "Enforce cryptographic JWT signature verification with an explicit algorithm allowlist, hash passwords with Argon2id/scrypt/bcrypt, and set httpOnly, secure, and sameSite on all session cookies.",
    explanation:
      "Always verify tokens with `jwt.verify()` (or `supabase.auth.getUser()`), never compare plaintext passwords or hash them with MD5/SHA-1, and harden all session cookies with `httpOnly: true`, `secure: true`, and `sameSite: 'lax'`.",
    secureCodeExample: `import jwt from "jsonwebtoken";
import { scryptSync, timingSafeEqual } from "node:crypto";

// Secure: Verify JWT signature with explicit algorithm allowlist
const claims = jwt.verify(token, process.env.JWT_PUBLIC_KEY!, {
  algorithms: ["RS256"],
});

// Secure: Hardened session cookie flags
cookieStore.set("session", sessionToken, {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "lax",
  path: "/",
});`,
    references: [
      "https://cwe.mitre.org/data/definitions/287.html",
      "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
    ],
  },
});
