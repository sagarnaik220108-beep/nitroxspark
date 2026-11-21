import type { SecurityRule } from "@/types";
import { createRegexRule } from "./base";

/**
 * Rule 7: Unsafe eval()
 * Detects dynamic code execution via eval(), new Function(), string-based timers,
 * Node vm evaluation, or Python exec().
 */
export const unsafeEvalRule: SecurityRule = createRegexRule({
  id: "SENTINEL-EVAL-001",
  name: "Unsafe eval() and Dynamic Code Execution",
  description:
    "Detects dynamic evaluation of strings as code via eval(), new Function(), string-based setTimeout/setInterval, Node vm execution, or Python exec().",
  explanation:
    "Evaluating dynamic strings as executable code exposes the application to Remote Code Execution (RCE) on servers and arbitrary script execution (XSS) in browsers whenever any portion of the evaluated string can be influenced by untrusted input.",
  severity: "high",
  category: "injection",
  cweId: "CWE-95",
  owaspCategory: "A03:2021 - Injection",
  languages: ["typescript", "javascript", "python", "php", "ruby"],
  tags: ["eval", "code-injection", "rce", "dynamic-code", "cwe-95"],
  confidence: 0.91,
  patterns: [
    /\beval\s*\(/g,
    /\bnew\s+Function\s*\(/g,
    /\b(?:setTimeout|setInterval)\s*\(\s*["'`][^"'`]+["'`]/g,
    /\bvm\.(?:runInNewContext|runInThisContext|runInContext|compileFunction)\s*\(/g,
    /(?<![.\w])exec\s*\(/g,
  ],
  filterMatch: (match, context) => {
    // Only flag bare `exec(` for Python dynamic code execution; JS child_process.exec is handled by Command Injection.
    if (/^exec\s*\(/.test(match[0])) {
      return context.language === "python";
    }
    return true;
  },
  remediation: {
    summary:
      "Replace eval() and dynamic code execution with JSON.parse(), explicit lookup tables, or a safe non-executing parser.",
    explanation:
      "Use `JSON.parse()` for structured payloads, static function dispatch maps for dynamic operations, or dedicated expression evaluators that do not expose the host runtime.",
    secureCodeExample: `// Secure: Use JSON.parse() for structured data instead of eval()
const payload = JSON.parse(rawInput);

// Secure: Use an explicit allowlisted operation map
const operations: Record<string, (a: number, b: number) => number> = {
  add: (a, b) => a + b,
  subtract: (a, b) => a - b,
};

const handler = operations[action];
if (!handler) {
  throw new Error("Unsupported operation");
}`,
    references: [
      "https://cwe.mitre.org/data/definitions/95.html",
      "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_direct_eval!",
    ],
  },
});
