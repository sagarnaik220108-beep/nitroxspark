import type { SecurityRule } from "@/types";
import { createRegexRule } from "./base";

/**
 * Rule 5: Cross-Site Scripting (XSS)
 * Detects unsanitized HTML rendering sinks in React, browser DOM APIs,
 * server HTML responses, and javascript: URI bindings.
 */
export const xssRule: SecurityRule = createRegexRule({
  id: "SENTINEL-XSS-001",
  name: "Cross-Site Scripting (XSS)",
  description:
    "Detects unsanitized data flowing into dangerous HTML/script sinks such as dangerouslySetInnerHTML, innerHTML, document.write, insertAdjacentHTML, raw HTML responses, or javascript: URIs.",
  explanation:
    "Injecting untrusted input into raw HTML or script sinks bypasses framework auto-escaping and allows attackers to execute arbitrary JavaScript in victims' browsers—enabling session hijacking, credential theft, CSRF bypass, and account takeover.",
  severity: "high",
  category: "xss",
  cweId: "CWE-79",
  owaspCategory: "A03:2021 - Injection",
  languages: ["typescript", "javascript", "php"],
  tags: ["xss", "dom-xss", "react", "html-injection", "cwe-79"],
  confidence: 0.89,
  patterns: [
    /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:/g,
    /\.(?:innerHTML|outerHTML)\s*\+?=\s*(?!["']\s*["'])/g,
    /\bdocument\.write(?:ln)?\s*\(/g,
    /\.insertAdjacentHTML\s*\(/g,
    /\bres\.send\s*\(\s*`[^`]*<[a-zA-Z][^`]*\$\{[^}]+\}[^`]*`/g,
    /\bhref\s*=\s*\{?\s*["'`]?javascript:/gi,
  ],
  filterMatch: (match, context) => {
    const surrounding = context.code.slice(
      Math.max(0, match.index - 60),
      Math.min(context.code.length, match.index + match[0].length + 140)
    );
    return !/DOMPurify\.sanitize|sanitizeHtml|xss\s*\(/i.test(surrounding);
  },
  remediation: {
    summary:
      "Render untrusted values as escaped text (JSX children or textContent), or strictly sanitize unavoidable HTML with DOMPurify.",
    explanation:
      "Use safe text rendering (`textContent` or standard JSX interpolation) by default. When rendering rich HTML is strictly necessary, sanitize it with `DOMPurify.sanitize()` using a minimal tag/attribute allowlist and enforce a strict Content-Security-Policy (CSP).",
    secureCodeExample: `import DOMPurify from "isomorphic-dompurify";

// Secure: Prefer plain JSX text or sanitize unavoidable HTML
const cleanHtml = DOMPurify.sanitize(untrustedHtml, {
  ALLOWED_TAGS: ["b", "i", "em", "strong", "p", "br"],
  ALLOWED_ATTR: [],
});

export function SafeContent({ html }: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: cleanHtml }} />;
}`,
    references: [
      "https://owasp.org/www-community/attacks/xss/",
      "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html",
      "https://cwe.mitre.org/data/definitions/79.html",
    ],
  },
});
