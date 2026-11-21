import type {
  FixVulnerabilityInput,
  SecureFixInput,
  SecureFixResult,
  VulnerabilityFixer,
} from "@/types/fix.types";
import {
  buildFixResult,
  isPythonCode,
  normalizeVulnerabilitySearchText,
} from "./base";

const SUPPORTED_RULE_IDS = [
  "SENTINEL-AUTH-001",
  "SENTINEL-AUTH-002",
  "SENTINEL-AUTH-003",
  "WEAK-AUTH",
  "JWT-DECODE",
  "INSECURE-COOKIE",
  "WEAK-HASH",
] as const;

/**
 * Fixer 4: Weak Authentication, Session Cookies & Broken Password Hashing
 * - Replaces `jwt.decode(...)` with `jwt.verify(...)` using an explicit algorithm allowlist
 * - Replaces `algorithms: ["none"]` with `algorithms: ["RS256"]` and `verify_signature: False` with `True`
 * - Fixes `httpOnly: false` -> `httpOnly: true` and `secure: false` -> `secure: true`
 * - Replaces MD5 / SHA-1 password hashing (`createHash("md5"|"sha1")` / `hashlib.md5|sha1`) with `scryptSync` / `hashlib.scrypt`
 */
export const weakAuthFixer: VulnerabilityFixer = {
  id: "fixer-weak-auth",
  name: "Weak Authentication & Cryptography Fixer",
  description:
    "Upgrades jwt.decode() to jwt.verify() with an algorithm allowlist, hardens cookie flags (httpOnly/secure), and replaces MD5/SHA-1 password hashing with salted scrypt.",
  supportedRuleIds: SUPPORTED_RULE_IDS,
  supportedCategories: ["authentication", "cryptography"],

  canHandle(vulnerability: FixVulnerabilityInput): boolean {
    const text = normalizeVulnerabilitySearchText(vulnerability);
    if (
      SUPPORTED_RULE_IDS.some(
        (id) => id.toLowerCase() === vulnerability.ruleId.trim().toLowerCase()
      )
    ) {
      return true;
    }
    return (
      text.includes("jwt") ||
      text.includes("weak auth") ||
      text.includes("httponly") ||
      text.includes("cookie") ||
      text.includes("md5") ||
      text.includes("sha1") ||
      text.includes("sha-1") ||
      text.includes("weak password hashing") ||
      text.includes("cwe-347") ||
      text.includes("cwe-328") ||
      text.includes("cwe-614")
    );
  },

  apply(input: SecureFixInput): SecureFixResult {
    const { originalCode, vulnerability } = input;
    const python = isPythonCode(originalCode, vulnerability.language);
    let secureCode = originalCode;
    const appliedReasons: string[] = [];
    let needsNodeCryptoScrypt = false;
    let needsPythonOsImport = false;

    // 1. Replace jwt.decode(token) with jwt.verify(token, secret, { algorithms: ["HS256"] })
    const jwtDecodeReplaced = secureCode.replace(
      /\bjwt\.decode\s*\(\s*([^,)]+)(?:\s*,\s*[^)]*)?\)/g,
      (_match, tokenExpr: string) => {
        const cleanToken = tokenExpr.trim();
        appliedReasons.push(
          "Replaced unverified jwt.decode() with jwt.verify() and an explicit algorithm allowlist"
        );
        return `jwt.verify(${cleanToken}, process.env.JWT_SECRET ?? (() => { throw new Error("Missing JWT_SECRET"); })(), { algorithms: ["HS256"] })`;
      }
    );
    secureCode = jwtDecodeReplaced;

    // 2. Replace insecure 'none' JWT algorithm allowlist
    if (/algorithms\s*:\s*\[[^\]]*["']none["'][^\]]*\]/i.test(secureCode)) {
      secureCode = secureCode.replace(
        /algorithms\s*:\s*\[[^\]]*["']none["'][^\]]*\]/gi,
        'algorithms: ["RS256"]'
      );
      appliedReasons.push(
        'Removed insecure "none" algorithm from JWT allowlist and enforced ["RS256"]'
      );
    }

    // 3. Python PyJWT verify_signature: False -> True
    if (/verify_signature["']?\s*:\s*False/i.test(secureCode)) {
      secureCode = secureCode.replace(
        /(verify_signature["']?\s*:\s*)False/gi,
        "$1True"
      );
      appliedReasons.push("Enabled JWT signature verification (verify_signature: True)");
    }

    // 4. Harden insecure cookie flags: httpOnly: false -> true, secure: false -> true
    if (/\bhttpOnly\s*:\s*false\b/.test(secureCode)) {
      secureCode = secureCode.replace(/\bhttpOnly\s*:\s*false\b/g, "httpOnly: true");
      appliedReasons.push("Set httpOnly: true on session cookies");
    }
    if (/\bsecure\s*:\s*false\b/.test(secureCode)) {
      secureCode = secureCode.replace(/\bsecure\s*:\s*false\b/g, "secure: true");
      appliedReasons.push("Set secure: true on session cookies");
    }

    // 5. Replace weak MD5/SHA1 password hashing in JS/TS with scryptSync
    if (!python) {
      // Full chained call: crypto.createHash("md5").update(password).digest("hex")
      const chainedHashRegex =
        /\b(?:crypto\.)?createHash\s*\(\s*["'](?:md5|sha1)["']\s*\)\s*\.update\s*\(\s*([^)]+)\s*\)\s*\.digest\s*\(\s*["'][^"']+["']\s*\)/gi;

      if (chainedHashRegex.test(secureCode)) {
        secureCode = secureCode.replace(
          chainedHashRegex,
          (_match, valueExpr: string) => {
            const usesCryptoPrefix = /\bcrypto\./.test(_match);
            if (!usesCryptoPrefix) {
              needsNodeCryptoScrypt = true;
            }
            const cleanVal = valueExpr.trim();
            appliedReasons.push(
              "Replaced weak MD5/SHA-1 hash with salted scryptSync password derivation"
            );
            return usesCryptoPrefix
              ? `crypto.scryptSync(${cleanVal}, crypto.randomBytes(16).toString("hex"), 64).toString("hex")`
              : `scryptSync(${cleanVal}, randomBytes(16).toString("hex"), 64).toString("hex")`;
          }
        );
      } else if (/\b(?:crypto\.)?createHash\s*\(\s*["'](?:md5|sha1)["']\s*\)/i.test(secureCode)) {
        // Fallback when createHash is split across lines
        secureCode = secureCode.replace(
          /\b(crypto\.)?createHash\s*\(\s*["'](?:md5|sha1)["']\s*\)/gi,
          (_match, prefix?: string) => {
            appliedReasons.push(
              "Upgraded broken MD5/SHA-1 digest algorithm to SHA-256 (use scryptSync for passwords)"
            );
            return `${prefix ?? ""}createHash("sha256")`;
          }
        );
      }

      if (
        needsNodeCryptoScrypt &&
        !/\bscryptSync\b/.test(originalCode)
      ) {
        secureCode = `import { scryptSync, randomBytes } from "node:crypto";\n${secureCode}`;
      }
    } else {
      // Python hashlib.md5(pwd.encode()).hexdigest() -> hashlib.scrypt(...)
      const pyHashRegex =
        /\bhashlib\.(?:md5|sha1)\s*\(\s*([^)]+)\s*\)(?:\.hexdigest\s*\(\s*\))?/gi;
      if (pyHashRegex.test(secureCode)) {
        secureCode = secureCode.replace(pyHashRegex, (_m, argExpr: string) => {
          needsPythonOsImport = true;
          appliedReasons.push(
            "Replaced weak hashlib MD5/SHA-1 with salted hashlib.scrypt()"
          );
          return `hashlib.scrypt(${argExpr.trim()}, salt=os.urandom(16), n=16384, r=8, p=1).hex()`;
        });
      }
      if (needsPythonOsImport && !/^\s*import\s+os\b/m.test(secureCode)) {
        secureCode = `import os\n${secureCode}`;
      }
    }

    const uniqueReasons = Array.from(new Set(appliedReasons));
    const reasonText =
      uniqueReasons.length > 0
        ? uniqueReasons.join("; ") + "."
        : "Hardened authentication, cookie, and password hashing configuration.";

    return buildFixResult({
      fixerId: this.id,
      originalCode,
      secureCode,
      severity: vulnerability.severity,
      reason: reasonText,
      summary: reasonText,
      rationale:
        "Enforces cryptographic JWT signature validation, protects session cookies against XSS/MitM theft, and replaces fast broken hashes with memory-hard salted scrypt.",
    });
  },
};
