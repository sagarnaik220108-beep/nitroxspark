import type {
  FixVulnerabilityInput,
  SecureFixInput,
  SecureFixResult,
  VulnerabilityFixer,
} from "@/types/fix.types";
import { buildFixResult, normalizeVulnerabilitySearchText } from "./base";

const SUPPORTED_RULE_IDS = [
  "SENTINEL-XSS-001",
  "SENTINEL-XSS-002",
  "XSS",
  "DOM-XSS",
] as const;

/**
 * Fixer 3: Cross-Site Scripting (XSS)
 * - Replaces `.innerHTML =` / `.outerHTML =` with `.textContent =`
 * - Replaces `.insertAdjacentHTML(...)` and `document.write(...)` with safe text node APIs
 * - Wraps React `dangerouslySetInnerHTML={{ __html: expr }}` with `DOMPurify.sanitize(expr)`
 *   and injects `import DOMPurify from "isomorphic-dompurify";` when missing.
 */
export const xssFixer: VulnerabilityFixer = {
  id: "fixer-xss",
  name: "XSS Sanitization & Safe DOM Fixer",
  description:
    "Replaces unsafe DOM HTML sinks (innerHTML/outerHTML) with textContent and wraps dangerouslySetInnerHTML payloads with DOMPurify.sanitize().",
  supportedRuleIds: SUPPORTED_RULE_IDS,
  supportedCategories: ["xss"],

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
      text.includes("xss") ||
      text.includes("cross-site scripting") ||
      text.includes("innerhtml") ||
      text.includes("outerhtml") ||
      text.includes("dangerouslysetinnerhtml") ||
      text.includes("document.write") ||
      text.includes("cwe-79")
    );
  },

  apply(input: SecureFixInput): SecureFixResult {
    const { originalCode, vulnerability } = input;
    let secureCode = originalCode;
    let addedDomPurifyUsage = false;

    // 1. Replace element.innerHTML = ... and element.outerHTML = ... with element.textContent = ...
    secureCode = secureCode.replace(
      /\.(innerHTML|outerHTML)(\s*=\s*)(?!["']\s*["'])/g,
      ".textContent$2"
    );

    // 2. Replace element.insertAdjacentHTML(position, html) with safe text node insertion
    secureCode = secureCode.replace(
      /([a-zA-Z_$][\w$.]*)\.insertAdjacentHTML\s*\(\s*["'][^"']+["']\s*,\s*([^)]+)\)/g,
      "$1.appendChild(document.createTextNode(String($2)))"
    );

    // 3. Replace document.write(expr) / document.writeln(expr) with safe text node append
    secureCode = secureCode.replace(
      /\bdocument\.write(?:ln)?\s*\(\s*([^)]+)\)/g,
      "document.body.appendChild(document.createTextNode(String($1)))"
    );

    // 4. Wrap dangerouslySetInnerHTML={{ __html: expr }} with DOMPurify.sanitize(expr)
    secureCode = secureCode.replace(
      /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*([^}]+?)\s*\}\s*\}/g,
      (fullMatch, rawExpr: string) => {
        const trimmed = rawExpr.trim();
        if (/DOMPurify\.sanitize\s*\(/i.test(trimmed)) {
          return fullMatch;
        }
        addedDomPurifyUsage = true;
        return `dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(${trimmed}) }}`;
      }
    );

    // Add DOMPurify import if we introduced DOMPurify.sanitize and it's not already imported
    if (
      addedDomPurifyUsage &&
      !/\bimport\s+DOMPurify\b/.test(secureCode) &&
      !/\brequire\s*\(\s*["'](?:isomorphic-)?dompurify["']\s*\)/.test(secureCode)
    ) {
      secureCode = `import DOMPurify from "isomorphic-dompurify";\n${secureCode}`;
    }

    return buildFixResult({
      fixerId: this.id,
      originalCode,
      secureCode,
      severity: vulnerability.severity,
      reason:
        "Replaced unsafe HTML sinks with textContent / safe DOM APIs and sanitized dangerouslySetInnerHTML with DOMPurify.sanitize().",
      summary:
        "Neutralized XSS sinks by switching raw HTML DOM assignments to textContent and wrapping dangerouslySetInnerHTML with DOMPurify.sanitize().",
      rationale:
        "Prevents untrusted input from being parsed as executable HTML or script tags in the browser DOM, eliminating script injection and session hijacking.",
    });
  },
};
