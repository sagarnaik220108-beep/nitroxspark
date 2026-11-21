import type {
  FixVulnerabilityInput,
  SecureFixInput,
  SecureFixResult,
  VulnerabilityFixer,
} from "@/types/fix.types";
import {
  buildFixResult,
  getIndentation,
  normalizeVulnerabilitySearchText,
} from "./base";

const SUPPORTED_RULE_IDS = [
  "SENTINEL-JWT-001",
  "JWT-SECRETS",
  "JWT-SECRET",
  "WEAK-JWT",
] as const;

/**
 * Deterministic Non-AI Fixer for JWT Secrets and Unverified Decodes.
 * Relocates hardcoded JWT signing secrets to `process.env.JWT_SECRET`
 * and upgrades unverified `jwt.decode()` calls to cryptographic `jwt.verify()`.
 */
export const jwtSecretsFixer: VulnerabilityFixer = {
  id: "sentinel-jwt-secrets-fixer",
  name: "JWT Secret & Verification Hardener",
  description:
    "Replaces hardcoded JWT signing secrets with process.env.JWT_SECRET and upgrades jwt.decode() to jwt.verify().",
  supportedRuleIds: SUPPORTED_RULE_IDS,
  supportedCategories: ["secrets", "authentication"],

  canHandle(vulnerability: FixVulnerabilityInput): boolean {
    const ruleIdUpper = vulnerability.ruleId.toUpperCase();
    if (SUPPORTED_RULE_IDS.some((id) => ruleIdUpper.includes(id))) {
      return true;
    }
    const title = (vulnerability.title ?? vulnerability.name ?? "").toLowerCase();
    const desc = (vulnerability.description ?? "").toLowerCase();
    return (
      (vulnerability.category === "secrets" || vulnerability.category === "authentication") &&
      (title.includes("jwt") || desc.includes("jwt") || ruleIdUpper.includes("JWT"))
    );
  },

  apply(input: SecureFixInput): SecureFixResult {
    const { originalCode, vulnerability } = input;
    const lines = originalCode.split(/\r?\n/);
    const targetLine = vulnerability.fileLine ?? vulnerability.line ?? 1;
    const targetIdx = Math.max(0, Math.min(lines.length - 1, targetLine - 1));
    const originalLineText = lines[targetIdx] ?? "";

    let updatedLineText = originalLineText;
    let fixSummary = "Secured JWT secret handling via environment configuration.";

    // 1. Check for jwt.decode(token) -> jwt.verify(token, process.env.JWT_SECRET!)
    if (/\bjwt\.decode\s*\(([^)]+)\)/.test(originalLineText)) {
      updatedLineText = originalLineText.replace(
        /\bjwt\.decode\s*\(([^)]+)\)/g,
        'jwt.verify($1, process.env.JWT_SECRET || "")'
      );
      fixSummary = "Upgraded unverified jwt.decode() to cryptographic jwt.verify() using process.env.JWT_SECRET.";
    }
    // 2. Check for hardcoded jwtSecret = '...'
    else if (/const\s+jwtSecret\s*=\s*['"][^'"]+['"];?/.test(originalLineText)) {
      const indent = getIndentation(originalLineText);
      updatedLineText = `${indent}const jwtSecret = process.env.JWT_SECRET || "";`;
      fixSummary = "Relocated hardcoded JWT signing secret to process.env.JWT_SECRET.";
    }
    // 3. Check for inline jwt.sign(..., 'secret_literal')
    else if (/\bjwt\.sign\s*\([^,]+,\s*['"][^'"]+['"]/.test(originalLineText)) {
      updatedLineText = originalLineText.replace(
        /(\bjwt\.sign\s*\([^,]+,\s*)['"][^'"]+['"]/g,
        '$1process.env.JWT_SECRET || ""'
      );
      fixSummary = "Replaced inline JWT signing secret literal with process.env.JWT_SECRET lookup.";
    }
    // 4. Check for inline jwt.verify(..., 'secret_literal')
    else if (/\bjwt\.verify\s*\([^,]+,\s*['"][^'"]+['"]/.test(originalLineText)) {
      updatedLineText = originalLineText.replace(
        /(\bjwt\.verify\s*\([^,]+,\s*)['"][^'"]+['"]/g,
        '$1process.env.JWT_SECRET || ""'
      );
      fixSummary = "Replaced inline JWT verification secret literal with process.env.JWT_SECRET lookup.";
    }
    // 5. Fallback search across nearby lines if line was approximate
    else {
      let matchedLineIdx = -1;
      for (let i = 0; i < lines.length; i++) {
        if (
          /\bjwtSecret\s*=/i.test(lines[i] ?? "") ||
          /\bjwt\.decode\s*\(/i.test(lines[i] ?? "")
        ) {
          matchedLineIdx = i;
          break;
        }
      }

      if (matchedLineIdx !== -1) {
        const line = lines[matchedLineIdx] ?? "";
        if (/\bjwt\.decode\s*\(([^)]+)\)/.test(line)) {
          lines[matchedLineIdx] = line.replace(
            /\bjwt\.decode\s*\(([^)]+)\)/g,
            'jwt.verify($1, process.env.JWT_SECRET || "")'
          );
        } else {
          const indent = getIndentation(line);
          lines[matchedLineIdx] = `${indent}const jwtSecret = process.env.JWT_SECRET || "";`;
        }
        const secureCode = lines.join("\n");
        return buildFixResult(
          originalCode,
          secureCode,
          this.id,
          vulnerability.severity,
          "Relocated JWT secret to environment configuration and enforced cryptographic signature verification."
        );
      }

      // No match found
      return buildFixResult(
        originalCode,
        originalCode,
        this.id,
        vulnerability.severity,
        "JWT pattern was already secured or could not be mapped to a literal line."
      );
    }

    lines[targetIdx] = updatedLineText;
    const secureCode = lines.join("\n");

    return buildFixResult(
      originalCode,
      secureCode,
      this.id,
      vulnerability.severity,
      fixSummary
    );
  },
};
