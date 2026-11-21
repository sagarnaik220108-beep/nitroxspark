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
  "SENTINEL-SEC-001",
  "SENTINEL-API-KEY",
  "HARDCODED-API-KEY",
  "API-KEYS",
] as const;

const KNOWN_KEY_LITERAL_REGEX =
  /["'`](?:AKIA[0-9A-Z]{16}|sk-(?:live|test|proj)?-?[a-zA-Z0-9_-]{16,}|gh[pousr]_[a-zA-Z0-9]{16,}|AIza[0-9A-Za-z_-]{30,})["'`]/;

const SECRET_IDENT_REGEX =
  /(?:api[_-]?key|secret[_-]?key|jwt[_-]?secret|client[_-]?secret|access[_-]?token|auth[_-]?token|bearer[_-]?token|openai[_-]?key|stripe[_-]?key|anthropic[_-]?key|gemini[_-]?key|token)/i;

function inferEnvNameFromToken(literal: string): string {
  const cleaned = literal.replace(/^["'`]|["'`]$/g, "");
  if (cleaned.startsWith("AKIA")) return "AWS_ACCESS_KEY_ID";
  if (cleaned.startsWith("sk-proj-") || cleaned.startsWith("sk-")) {
    return cleaned.startsWith("sk-live") || cleaned.startsWith("sk-test")
      ? "STRIPE_SECRET_KEY"
      : "OPENAI_API_KEY";
  }
  if (/^gh[pousr]_/.test(cleaned)) return "GITHUB_TOKEN";
  if (cleaned.startsWith("AIza")) return "GOOGLE_API_KEY";
  return "API_KEY";
}

function isPasswordIdentifier(ident: string): boolean {
  return /(?:pass(?:word|wd)?|pwd)/i.test(ident);
}

/**
 * Fixer 1: Hardcoded API Keys & Secret Tokens
 * Replaces hardcoded API keys with `process.env.<KEY_NAME>` (or `os.environ` in Python)
 * and injects a runtime guard that throws when the environment variable is missing.
 */
export const apiKeysFixer: VulnerabilityFixer = {
  id: "fixer-api-keys",
  name: "Hardcoded API Keys Fixer",
  description:
    "Replaces hardcoded API keys and secret tokens with environment variable lookups and missing-env runtime guards.",
  supportedRuleIds: SUPPORTED_RULE_IDS,
  supportedCategories: ["secrets"],

  canHandle(vulnerability: FixVulnerabilityInput): boolean {
    const text = normalizeVulnerabilitySearchText(vulnerability);

    // Defer password-specific or NEXT_PUBLIC_ env exposure findings to their dedicated fixers
    if (
      /\b(?:password|passwd|db_pass|connection string)\b/.test(text) &&
      !text.includes("api key") &&
      !text.includes("api_key")
    ) {
      return false;
    }
    if (text.includes("next_public_") || text.includes("console.log(process.env")) {
      return false;
    }

    if (
      SUPPORTED_RULE_IDS.some(
        (id) => id.toLowerCase() === vulnerability.ruleId.trim().toLowerCase()
      )
    ) {
      return true;
    }

    return (
      text.includes("api key") ||
      text.includes("api_key") ||
      text.includes("apikey") ||
      text.includes("secret token") ||
      text.includes("secret_key") ||
      text.includes("access_token") ||
      text.includes("client_secret") ||
      KNOWN_KEY_LITERAL_REGEX.test(vulnerability.matchedText ?? "")
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
      // Skip lines already reading from process.env / os.environ / os.getenv
      if (/\b(?:process\.env|os\.environ|os\.getenv)\b/.test(line)) {
        updatedLines.push(line);
        continue;
      }

      const indent = getIndentation(line);

      if (python) {
        const pyAssign =
          /^(\s*)([a-zA-Z_]\w*)\s*=\s*(["'][^"']{8,}["'])(.*)$/.exec(line);
        if (pyAssign) {
          const varName = pyAssign[2] ?? "api_key";
          const literal = pyAssign[3] ?? "";
          const trailing = pyAssign[4] ?? "";
          const isTarget =
            !isPasswordIdentifier(varName) &&
            (SECRET_IDENT_REGEX.test(varName) ||
              KNOWN_KEY_LITERAL_REGEX.test(literal));

          if (isTarget) {
            const envName = toEnvVarName(
              varName,
              inferEnvNameFromToken(literal)
            );
            replacedEnvVars.push(envName);
            needsOsImport = true;
            updatedLines.push(
              `${indent}${varName} = os.environ.get("${envName}")${trailing}`
            );
            updatedLines.push(`${indent}if not ${varName}:`);
            updatedLines.push(
              `${indent}    raise RuntimeError("Missing required environment variable: ${envName}")`
            );
            continue;
          }
        }
        updatedLines.push(line);
        continue;
      }

      // Pattern 1: JS/TS variable declaration: const/let/var apiKey = "sk-..."
      const varDeclMatch =
        /^(\s*)(export\s+)?(const|let|var)\s+([a-zA-Z_$][\w$]*)\s*(?::\s*[^=]+)?=\s*(["'`][^"'`]{8,}["'`])\s*(;?)(.*)$/.exec(
          line
        );

      if (varDeclMatch) {
        const exportKw = varDeclMatch[2] ?? "";
        const declKw = varDeclMatch[3] ?? "const";
        const varName = varDeclMatch[4] ?? "apiKey";
        const literal = varDeclMatch[5] ?? "";
        const semi = varDeclMatch[6] ?? ";";

        const isTarget =
          !isPasswordIdentifier(varName) &&
          (SECRET_IDENT_REGEX.test(varName) ||
            KNOWN_KEY_LITERAL_REGEX.test(literal));

        if (isTarget) {
          const envName = toEnvVarName(varName, inferEnvNameFromToken(literal));
          replacedEnvVars.push(envName);
          updatedLines.push(
            `${indent}${exportKw}${declKw} ${varName} = process.env.${envName}${semi}`
          );
          updatedLines.push(`${indent}if (!${varName}) {`);
          updatedLines.push(
            `${indent}  throw new Error("Missing required environment variable: ${envName}");`
          );
          updatedLines.push(`${indent}}`);
          continue;
        }
      }

      // Pattern 2: Object property or header assignment: apiKey: "sk-..." or Authorization: "Bearer sk-..."
      const propMatch =
        /^(\s*)(["']?[a-zA-Z_$][\w$-]*["']?)\s*:\s*(["'`][^"'`]{8,}["'`])(\s*,?)(.*)$/.exec(
          line
        );

      if (propMatch) {
        const rawProp = propMatch[2] ?? "apiKey";
        const cleanProp = rawProp.replace(/^["']|["']$/g, "");
        const literal = propMatch[3] ?? "";
        const comma = propMatch[4] ?? "";

        const isTarget =
          !isPasswordIdentifier(cleanProp) &&
          (SECRET_IDENT_REGEX.test(cleanProp) ||
            KNOWN_KEY_LITERAL_REGEX.test(literal));

        if (isTarget) {
          const envName = toEnvVarName(
            cleanProp,
            inferEnvNameFromToken(literal)
          );
          replacedEnvVars.push(envName);
          const unquotedLiteral = literal.replace(/^["'`]|["'`]$/g, "");
          const isBearer = /^Bearer\s+/i.test(unquotedLiteral);
          const replacementValue = isBearer
            ? `\`Bearer \${process.env.${envName} ?? (() => { throw new Error("Missing required environment variable: ${envName}"); })()}\``
            : `process.env.${envName} ?? (() => { throw new Error("Missing required environment variable: ${envName}"); })()`;

          updatedLines.push(
            `${indent}${rawProp}: ${replacementValue}${comma}`
          );
          continue;
        }
      }

      // Pattern 3: Standalone known provider key literal anywhere in the line
      if (KNOWN_KEY_LITERAL_REGEX.test(line)) {
        const replaced = line.replace(
          new RegExp(KNOWN_KEY_LITERAL_REGEX.source, "g"),
          (matchedLiteral) => {
            const envName = inferEnvNameFromToken(matchedLiteral);
            replacedEnvVars.push(envName);
            return `process.env.${envName} ?? (() => { throw new Error("Missing required environment variable: ${envName}"); })()`;
          }
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
      uniqueEnvVars.length > 0 ? uniqueEnvVars.join(", ") : "API_KEY";

    return buildFixResult({
      fixerId: this.id,
      originalCode,
      secureCode,
      severity: vulnerability.severity,
      reason: `Replaced hardcoded API key with environment variable (${envList}) and added a missing-env runtime guard.`,
      summary: `Moved hardcoded API key(s) to environment variable(s) (${envList}) with fail-fast missing-env guards.`,
      rationale:
        "Eliminates hardcoded credentials from source control and build artifacts, preventing credential leakage and unauthorized API billing.",
      notes: [
        `Configure ${envList} in your server environment (e.g. .env.local or deployment secret manager) and immediately rotate the exposed key.`,
      ],
    });
  },
};
