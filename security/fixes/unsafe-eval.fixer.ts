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
  "SENTINEL-INJ-003",
  "UNSAFE-EVAL",
  "EVAL",
  "DYNAMIC-CODE",
] as const;

/**
 * Fixer 5: Unsafe Dynamic Code Execution (`eval` / `new Function` / string timers)
 * - Replaces `eval(...)` with `JSON.parse(...)` (or `ast.literal_eval(...)` in Python)
 * - Replaces `new Function(...)` with `JSON.parse(...)` or a safe explicit dispatch guard
 * - Converts string-based `setTimeout("fn()", ms)` / `setInterval("fn()", ms)` into callback arrows
 */
export const unsafeEvalFixer: VulnerabilityFixer = {
  id: "fixer-unsafe-eval",
  name: "Unsafe Eval & Dynamic Code Fixer",
  description:
    "Replaces eval(), new Function(), and string-based timers with JSON.parse() or safe explicit dispatch.",
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
      text.includes("eval") ||
      text.includes("new function") ||
      text.includes("dynamic code execution") ||
      text.includes("cwe-95")
    );
  },

  apply(input: SecureFixInput): SecureFixResult {
    const { originalCode, vulnerability } = input;
    const python = isPythonCode(originalCode, vulnerability.language);
    let secureCode = originalCode;
    let needsAstImport = false;

    if (python) {
      if (/\beval\s*\(/.test(secureCode)) {
        secureCode = secureCode.replace(/\beval\s*\(/g, "ast.literal_eval(");
        needsAstImport = true;
      }
      if (needsAstImport && !/^\s*import\s+ast\b/m.test(secureCode)) {
        secureCode = `import ast\n${secureCode}`;
      }
    } else {
      // 1. Replace eval("(" + expr + ")") -> JSON.parse(expr)
      secureCode = secureCode.replace(
        /\beval\s*\(\s*["']\(\s*["']\s*\+\s*([^+)]+?)\s*\+\s*["']\s*\)["']\s*\)/g,
        (_m, expr: string) => `JSON.parse(${expr.trim()})`
      );

      // 2. Replace eval(expr) -> JSON.parse(expr)
      secureCode = secureCode.replace(
        /\beval\s*\(\s*([^)]+?)\s*\)/g,
        (_m, expr: string) => `JSON.parse(${expr.trim()})`
      );

      // 3. Replace immediately invoked new Function("return " + expr)() -> JSON.parse(expr)
      secureCode = secureCode.replace(
        /\bnew\s+Function\s*\(\s*["']return\s+["']\s*\+\s*([^)]+?)\s*\)\s*\(\s*\)/g,
        (_m, expr: string) => `JSON.parse(${expr.trim()})`
      );

      // 4. Replace remaining new Function(...) with safe explicit dispatch placeholder
      secureCode = secureCode.replace(
        /\bnew\s+Function\s*\([^)]*\)/g,
        `((op: string, ...args: unknown[]) => { const allowedOps: Record<string, (...a: unknown[]) => unknown> = {}; const handler = allowedOps[op]; if (!handler) { throw new Error(\`Unsupported operation: \${op}\`); } return handler(...args); })`
      );

      // 5. Replace string-based setTimeout("foo()", 1000) / setInterval("foo()", 1000)
      secureCode = secureCode.replace(
        /\b(setTimeout|setInterval)\s*\(\s*["'`]([a-zA-Z_$][\w$.]*\s*\([^)]*\))["'`]/g,
        "$1(() => { $2; }"
      );
      secureCode = secureCode.replace(
        /\b(setTimeout|setInterval)\s*\(\s*["'`]([^"'`]+)["'`]/g,
        "$1(() => { /* Replace dynamic code string with an explicit function call */ }"
      );
    }

    return buildFixResult({
      fixerId: this.id,
      originalCode,
      secureCode,
      severity: vulnerability.severity,
      reason:
        "Replaced dynamic code execution (eval / new Function / string timer) with JSON.parse() or an explicit allowlisted dispatch handler.",
      summary:
        "Eliminated arbitrary code execution by replacing eval() / new Function() with JSON.parse() or safe explicit dispatch.",
      rationale:
        "Prevents Remote Code Execution (RCE) and XSS by ensuring untrusted strings are parsed strictly as data or routed through an allowlisted operation map rather than compiled as executable code.",
    });
  },
};
