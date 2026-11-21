import type {
  FixVulnerabilityInput,
  SecureFixInput,
  SecureFixResult,
  VulnerabilityFixer,
} from "@/types/fix.types";
import {
  buildFixResult,
  getIndentation,
  isPythonCode,
  normalizeVulnerabilitySearchText,
  toEnvVarName,
} from "./base";

const SUPPORTED_RULE_IDS = [
  "SENTINEL-SEC-003",
  "SENTINEL-SEC-004",
  "HARDCODED-PASSWORD",
  "PASSWORDS",
] as const;

const PASSWORD_IDENT_REGEX =
  /(?:pass(?:word|wd)?|pwd|db[_-]?pass|admin[_-]?pass|root[_-]?pass|smtp[_-]?pass)/i;

const CONNECTION_STRING_REGEX =
  /["'`](?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^:\s"'`]+:[^@\s"'`]+@[^"'`]+["'`]/i;

/**
 * Fixer 7: Hardcoded Passwords & Database Credentials
 * Replaces hardcoded passwords and credential-bearing connection strings with
 * `process.env.<PASSWORD_VAR>` (or `os.environ` in Python) + a fail-fast secret guard.
 */
export const passwordsFixer: VulnerabilityFixer = {
  id: "fixer-passwords",
  name: "Hardcoded Passwords Fixer",
  description:
    "Replaces hardcoded passwords and embedded database credentials with environment variable lookups and missing-secret guards.",
  supportedRuleIds: SUPPORTED_RULE_IDS,
  supportedCategories: ["secrets", "authentication"],

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
      text.includes("hardcoded password") ||
      text.includes("hard-coded password") ||
      text.includes("password") ||
      text.includes("passwd") ||
      text.includes("connection string") ||
      text.includes("cwe-259")
    );
  },

  apply(input: SecureFixInput): SecureFixResult {
    const { originalCode, vulnerability } = input;
    const python = isPythonCode(originalCode, vulnerability.language);
    const lines = originalCode.split(/\r?\n/);
    const updatedLines: string[] = [];
    const replacedEnvVars: string[] = [];
    let needsOsImport = false;

    for (const line of lines) {
      if (/\b(?:process\.env|os\.environ|os\.getenv)\b/.test(line)) {
        updatedLines.push(line);
        continue;
      }

      const indent = getIndentation(line);

      if (python) {
        const pyMatch =
          /^(\s*)([a-zA-Z_]\w*)\s*=\s*(["'][^"']{4,}["'])(.*)$/.exec(line);
        if (pyMatch) {
          const varName = pyMatch[2] ?? "password";
          const literal = pyMatch[3] ?? "";
          const trailing = pyMatch[4] ?? "";
          const isConnStr = CONNECTION_STRING_REGEX.test(literal);

          if (PASSWORD_IDENT_REGEX.test(varName) || isConnStr) {
            const envName = isConnStr
              ? "DATABASE_URL"
              : toEnvVarName(varName, "APP_PASSWORD");
            replacedEnvVars.push(envName);
            needsOsImport = true;
            updatedLines.push(
              `${indent}${varName} = os.environ.get("${envName}")${trailing}`
            );
            updatedLines.push(`${indent}if not ${varName}:`);
            updatedLines.push(
              `${indent}    raise RuntimeError("Missing required secret environment variable: ${envName}")`
            );
            continue;
          }
        }
        updatedLines.push(line);
        continue;
      }

      // Pattern 1: JS/TS variable declaration: const dbPassword = "secret123" or const dbUrl = "postgres://user:pass@..."
      const varDeclMatch =
        /^(\s*)(export\s+)?(const|let|var)\s+([a-zA-Z_$][\w$]*)\s*(?::\s*[^=]+)?=\s*(["'`][^"'`]{4,}["'`])\s*(;?)(.*)$/.exec(
          line
        );

      if (varDeclMatch) {
        const exportKw = varDeclMatch[2] ?? "";
        const declKw = varDeclMatch[3] ?? "const";
        const varName = varDeclMatch[4] ?? "password";
        const literal = varDeclMatch[5] ?? "";
        const semi = varDeclMatch[6] ?? ";";
        const isConnStr = CONNECTION_STRING_REGEX.test(literal);

        if (PASSWORD_IDENT_REGEX.test(varName) || isConnStr) {
          const envName = isConnStr
            ? "DATABASE_URL"
            : toEnvVarName(varName, "APP_PASSWORD");
          replacedEnvVars.push(envName);
          updatedLines.push(
            `${indent}${exportKw}${declKw} ${varName} = process.env.${envName}${semi}`
          );
          updatedLines.push(`${indent}if (!${varName}) {`);
          updatedLines.push(
            `${indent}  throw new Error("Missing required secret environment variable: ${envName}");`
          );
          updatedLines.push(`${indent}}`);
          continue;
        }
      }

      // Pattern 2: Object property: password: "secret123" or connectionString: "postgres://..."
      const propMatch =
        /^(\s*)(["']?[a-zA-Z_$][\w$-]*["']?)\s*:\s*(["'`][^"'`]{4,}["'`])(\s*,?)(.*)$/.exec(
          line
        );
      if (propMatch) {
        const rawProp = propMatch[2] ?? "password";
        const cleanProp = rawProp.replace(/^["']|["']$/g, "");
        const literal = propMatch[3] ?? "";
        const comma = propMatch[4] ?? "";
        const isConnStr = CONNECTION_STRING_REGEX.test(literal);

        if (PASSWORD_IDENT_REGEX.test(cleanProp) || isConnStr) {
          const envName = isConnStr
            ? "DATABASE_URL"
            : toEnvVarName(cleanProp, "APP_PASSWORD");
          replacedEnvVars.push(envName);
          updatedLines.push(
            `${indent}${rawProp}: process.env.${envName} ?? (() => { throw new Error("Missing required secret environment variable: ${envName}"); })()${comma}`
          );
          continue;
        }
      }

      // Pattern 3: Direct hardcoded password comparison: password === "admin123"
      const compareMatch =
        /\b([a-zA-Z_$][\w$.]*pass(?:word|wd)?)\s*(===|==)\s*(["'`][^"'`]{4,}["'`])/i.exec(
          line
        );
      if (compareMatch) {
        const envName = "APP_PASSWORD";
        replacedEnvVars.push(envName);
        const replaced = line.replace(
          /(\b[a-zA-Z_$][\w$.]*pass(?:word|wd)?\s*(?:===|==)\s*)(["'`][^"'`]{4,}["'`])/i,
          `$1(process.env.${envName} ?? (() => { throw new Error("Missing required secret environment variable: ${envName}"); })())`
        );
        updatedLines.push(replaced);
        continue;
      }

      updatedLines.push(line);
    }

    if (python && needsOsImport && !/^\s*import\s+os\b/m.test(originalCode)) {
      updatedLines.unshift("import os");
    }

    const secureCode = updatedLines.join("\n");
    const uniqueEnvVars = Array.from(new Set(replacedEnvVars));
    const envList =
      uniqueEnvVars.length > 0 ? uniqueEnvVars.join(", ") : "APP_PASSWORD";

    return buildFixResult({
      fixerId: this.id,
      originalCode,
      secureCode,
      severity: vulnerability.severity,
      reason: `Replaced hardcoded password/credential with secure environment variable lookup (${envList}) and fail-fast guard.`,
      summary: `Removed hardcoded password(s) and replaced them with guarded environment variable loading (${envList}).`,
      rationale:
        "Eliminates plaintext credentials from source code and Git history, preventing unauthorized account or database takeover.",
      notes: [
        `Inject ${envList} via a secret manager or deployment environment variables and rotate the previously hardcoded credential.`,
      ],
    });
  },
};
