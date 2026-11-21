import type {
  FixVulnerabilityInput,
  SecureFixInput,
  SecureFixResult,
  VulnerabilityFixer,
} from "@/types/fix.types";
import {
  buildFixResult,
  getIndentation,
} from "./base";

const SUPPORTED_RULE_IDS = [
  "SENTINEL-DB-001",
  "OPEN-DATABASE-CONNECTION",
  "INSECURE-DB-CONFIG",
] as const;

/**
 * Deterministic Non-AI Fixer for Insecure Database Connections.
 * Replaces hardcoded database connection strings with process.env.DATABASE_URL
 * and enforces strict TLS certificate verification (rejectUnauthorized: true, sslmode=require).
 */
export const openDatabaseFixer: VulnerabilityFixer = {
  id: "sentinel-open-database-fixer",
  name: "Database Connection Hardener",
  description:
    "Decouples hardcoded DB URIs into process.env.DATABASE_URL and enforces secure TLS certificate validation.",
  supportedRuleIds: SUPPORTED_RULE_IDS,
  supportedCategories: ["database", "secrets"],

  canHandle(vulnerability: FixVulnerabilityInput): boolean {
    const ruleIdUpper = vulnerability.ruleId.toUpperCase();
    if (SUPPORTED_RULE_IDS.some((id) => ruleIdUpper.includes(id))) {
      return true;
    }
    const title = (vulnerability.title ?? vulnerability.name ?? "").toLowerCase();
    const desc = (vulnerability.description ?? "").toLowerCase();
    return (
      (vulnerability.category === "database" || vulnerability.category === "secrets") &&
      (title.includes("database") || desc.includes("database") || title.includes("db") || ruleIdUpper.includes("DB"))
    );
  },

  apply(input: SecureFixInput): SecureFixResult {
    const { originalCode, vulnerability } = input;
    let secureCode = originalCode;
    let fixSummary = "Hardened database connection configuration.";

    // 1. Replace hardcoded DB URI strings
    const dbUriRegex = /['"](?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|mssql):\/\/[^:\s"'`]+:[^@\s"'`]{3,}@[^\s"'`]+['"]/gi;
    if (dbUriRegex.test(secureCode)) {
      secureCode = secureCode.replace(
        dbUriRegex,
        'process.env.DATABASE_URL || ""'
      );
      fixSummary = "Replaced hardcoded plaintext database URI with process.env.DATABASE_URL.";
    }

    // 2. Fix rejectUnauthorized: false
    if (/rejectUnauthorized\s*:\s*false/i.test(secureCode)) {
      secureCode = secureCode.replace(
        /rejectUnauthorized\s*:\s*false/gi,
        "rejectUnauthorized: true"
      );
      fixSummary += " Enabled TLS certificate verification (rejectUnauthorized: true).";
    }

    // 3. Fix sslmode=disable
    if (/sslmode\s*=\s*disable/i.test(secureCode)) {
      secureCode = secureCode.replace(
        /sslmode\s*=\s*disable/gi,
        "sslmode=require"
      );
      fixSummary += " Enforced encrypted database connection (sslmode=require).";
    }

    return buildFixResult(
      originalCode,
      secureCode,
      this.id,
      vulnerability.severity,
      fixSummary
    );
  },
};
