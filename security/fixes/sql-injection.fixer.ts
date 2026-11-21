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
} from "./base";

const SUPPORTED_RULE_IDS = [
  "SENTINEL-INJ-001",
  "SQL-INJECTION",
  "SQLI",
] as const;

const SQL_KEYWORD_REGEX =
  /\b(?:SELECT|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b/i;

/**
 * Converts a JS/TS template literal containing SQL and `${expr}` placeholders
 * into a parameterized SQL string (`$1`, `$2`, ...) and an array of parameter expressions.
 */
function parameterizeTemplateLiteral(templateBody: string): {
  sql: string;
  params: string[];
} {
  const params: string[] = [];
  // Replace quoted `'${expr}'` or bare `${expr}` with positional `$N`
  const sql = templateBody.replace(
    /'\$\{([^}]+)\}'|"\$\{([^}]+)\}"|\$\{([^}]+)\}/g,
    (_match, singleQuoted?: string, doubleQuoted?: string, bare?: string) => {
      const expr = (singleQuoted ?? doubleQuoted ?? bare ?? "").trim();
      params.push(expr);
      return `$${params.length}`;
    }
  );
  return { sql, params };
}

/**
 * Converts a JS/TS string concatenation SQL expression (e.g. `"SELECT * FROM users WHERE id = " + userId`)
 * into a parameterized SQL string (`$1`, `$2`, ...) and parameter list.
 */
function parameterizeConcatenation(expr: string): {
  sql: string;
  params: string[];
} | null {
  const parts: string[] = [];
  let current = "";
  let inQuote: string | null = null;
  let escaped = false;

  for (let i = 0; i < expr.length; i++) {
    const ch = expr[i] ?? "";
    if (escaped) {
      current += ch;
      escaped = false;
      continue;
    }
    if (ch === "\\" && inQuote) {
      current += ch;
      escaped = true;
      continue;
    }
    if ((ch === '"' || ch === "'") && !inQuote) {
      inQuote = ch;
      current += ch;
      continue;
    }
    if (ch === inQuote) {
      inQuote = null;
      current += ch;
      continue;
    }
    if (ch === "+" && !inQuote) {
      parts.push(current.trim());
      current = "";
      continue;
    }
    current += ch;
  }
  if (current.trim().length > 0) {
    parts.push(current.trim());
  }

  if (parts.length < 2) return null;

  let sql = "";
  const params: string[] = [];

  for (let i = 0; i < parts.length; i++) {
    const part = parts[i] ?? "";
    const isStringLiteral =
      (part.startsWith('"') && part.endsWith('"')) ||
      (part.startsWith("'") && part.endsWith("'"));

    if (isStringLiteral) {
      let inner = part.slice(1, -1);
      // If previous part was a param and this literal starts with a closing SQL single-quote, strip it
      if (params.length > 0 && sql.endsWith(`$${params.length}`) && inner.startsWith("'")) {
        inner = inner.slice(1);
      }
      sql += inner;
    } else {
      // Strip trailing SQL single-quote right before the interpolated param (e.g. `WHERE email = '` + email + `'`)
      if (sql.endsWith("'")) {
        sql = sql.slice(0, -1);
      }
      params.push(part);
      sql += `$${params.length}`;
    }
  }

  if (params.length === 0 || !SQL_KEYWORD_REGEX.test(sql)) {
    return null;
  }

  return { sql, params };
}

/**
 * Fixer 2: SQL Injection
 * Converts interpolated template literals, string concatenations, and Python f-strings
 * in SQL queries into parameterized queries (`$1`, `$2`, ... or `%s`).
 */
export const sqlInjectionFixer: VulnerabilityFixer = {
  id: "fixer-sql-injection",
  name: "SQL Injection Parameterizer",
  description:
    "Converts interpolated or concatenated SQL queries into parameterized queries using positional placeholders ($1, $2, ...).",
  supportedRuleIds: SUPPORTED_RULE_IDS,
  supportedCategories: ["injection"],

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
      text.includes("sql injection") ||
      text.includes("sqli") ||
      text.includes("cwe-89") ||
      (text.includes("sql") && text.includes("injection"))
    );
  },

  apply(input: SecureFixInput): SecureFixResult {
    const { originalCode, vulnerability } = input;
    const python = isPythonCode(originalCode, vulnerability.language);
    const lines = originalCode.split(/\r?\n/);
    const updatedLines: string[] = [];

    for (const line of lines) {
      // Python f-string SQL: cursor.execute(f"SELECT ... {var}")
      if (python) {
        const pyFStringMatch =
          /^(\s*)(.*?\.(?:execute|executemany|raw)\s*\()\s*f(["'])(.+?)\3(\s*\).*)$/.exec(
            line
          );
        if (pyFStringMatch) {
          const indent = pyFStringMatch[1] ?? "";
          const callPrefix = pyFStringMatch[2] ?? "";
          const quote = pyFStringMatch[3] ?? '"';
          const body = pyFStringMatch[4] ?? "";
          const callSuffix = pyFStringMatch[5] ?? ")";

          if (SQL_KEYWORD_REGEX.test(body) && /\{[^}]+\}/.test(body)) {
            const params: string[] = [];
            const parameterizedSql = body.replace(
              /'\{([^}]+)\}'|"\{([^}]+)\}"|\{([^}]+)\}/g,
              (_m, s?: string, d?: string, b?: string) => {
                params.push((s ?? d ?? b ?? "").trim());
                return "%s";
              }
            );
            const tupleStr =
              params.length === 1
                ? `(${params[0]},)`
                : `(${params.join(", ")})`;
            updatedLines.push(
              `${indent}${callPrefix}${quote}${parameterizedSql}${quote}, ${tupleStr}${callSuffix}`
            );
            continue;
          }
        }
        updatedLines.push(line);
        continue;
      }

      // Pattern 1: Method call with template literal: db.query(`SELECT ... ${id}`)
      const callTemplateMatch =
        /^(\s*)(.*?\.(?:query|execute|raw|all|get|run)\s*\()\s*`([^`]*\$\{[^}]+\}[^`]*)`\s*(\).*)$/.exec(
          line
        );
      if (callTemplateMatch) {
        const indent = callTemplateMatch[1] ?? "";
        const prefix = callTemplateMatch[2] ?? "";
        const body = callTemplateMatch[3] ?? "";
        const suffix = callTemplateMatch[4] ?? ")";

        if (SQL_KEYWORD_REGEX.test(body)) {
          const { sql, params } = parameterizeTemplateLiteral(body);
          if (params.length > 0) {
            const escapedSql = sql.replace(/"/g, '\\"');
            updatedLines.push(
              `${indent}${prefix}"${escapedSql}", [${params.join(", ")}]${suffix}`
            );
            continue;
          }
        }
      }

      // Pattern 2: Method call with string concatenation: db.query("SELECT ... " + userId)
      const callConcatMatch =
        /^(\s*)(.*?\.(?:query|execute|raw|all|get|run)\s*\()\s*(.+?)\s*(\)\s*;?\s*)$/.exec(
          line
        );
      if (
        callConcatMatch &&
        line.includes("+") &&
        SQL_KEYWORD_REGEX.test(line)
      ) {
        const indent = callConcatMatch[1] ?? "";
        const prefix = callConcatMatch[2] ?? "";
        const argExpr = callConcatMatch[3] ?? "";
        const suffix = callConcatMatch[4] ?? ")";

        const result = parameterizeConcatenation(argExpr);
        if (result) {
          const escapedSql = result.sql.replace(/"/g, '\\"');
          updatedLines.push(
            `${indent}${prefix}"${escapedSql}", [${result.params.join(", ")}]${suffix}`
          );
          continue;
        }
      }

      // Pattern 3: Standalone SQL variable using template literal: const sql = `SELECT ... ${id}`;
      const varTemplateMatch =
        /^(\s*)(const|let|var)\s+([a-zA-Z_$][\w$]*)\s*=\s*`([^`]*\$\{[^}]+\}[^`]*)`\s*(;?)$/.exec(
          line
        );
      if (varTemplateMatch) {
        const indent = getIndentation(line);
        const kw = varTemplateMatch[2] ?? "const";
        const varName = varTemplateMatch[3] ?? "query";
        const body = varTemplateMatch[4] ?? "";
        const semi = varTemplateMatch[5] ?? ";";

        if (SQL_KEYWORD_REGEX.test(body)) {
          const { sql, params } = parameterizeTemplateLiteral(body);
          if (params.length > 0) {
            const escapedSql = sql.replace(/"/g, '\\"');
            updatedLines.push(
              `${indent}${kw} ${varName} = "${escapedSql}"${semi}`
            );
            updatedLines.push(
              `${indent}const ${varName}Params = [${params.join(", ")}]${semi}`
            );
            continue;
          }
        }
      }

      // Pattern 4: Standalone SQL variable using string concatenation
      const varConcatMatch =
        /^(\s*)(const|let|var)\s+([a-zA-Z_$][\w$]*)\s*=\s*(.+?)\s*(;?)$/.exec(
          line
        );
      if (
        varConcatMatch &&
        line.includes("+") &&
        SQL_KEYWORD_REGEX.test(line)
      ) {
        const indent = getIndentation(line);
        const kw = varConcatMatch[2] ?? "const";
        const varName = varConcatMatch[3] ?? "query";
        const expr = varConcatMatch[4] ?? "";
        const semi = varConcatMatch[5] ?? ";";

        const result = parameterizeConcatenation(expr);
        if (result) {
          const escapedSql = result.sql.replace(/"/g, '\\"');
          updatedLines.push(
            `${indent}${kw} ${varName} = "${escapedSql}"${semi}`
          );
          updatedLines.push(
            `${indent}const ${varName}Params = [${result.params.join(", ")}]${semi}`
          );
          continue;
        }
      }

      updatedLines.push(line);
    }

    const secureCode = updatedLines.join("\n");

    return buildFixResult({
      fixerId: this.id,
      originalCode,
      secureCode,
      severity: vulnerability.severity,
      reason:
        "Converted dynamically constructed SQL query into a parameterized query with positional placeholders.",
      summary:
        "Replaced interpolated/concatenated SQL strings with parameterized queries ($1, $2, ...) so user input is bound strictly as data.",
      rationale:
        "Parameterized queries completely separate SQL command syntax from untrusted parameter values, neutralizing SQL injection attacks.",
    });
  },
};
