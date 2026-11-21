import type { SecurityRule } from "@/types";
import { createRegexRule } from "./base";

/**
 * Rule 4: SQL Injection Patterns
 * Detects SQL statements constructed dynamically via template literals, string concatenation,
 * Python f-strings/formatting, or unsafe raw query helpers.
 */
export const sqlInjectionRule: SecurityRule = createRegexRule({
  id: "SENTINEL-SQLI-001",
  name: "SQL Injection Patterns",
  description:
    "Detects SQL queries built dynamically through string interpolation, concatenation, or unsafe raw query execution with untrusted variables.",
  explanation:
    "Interpolating or concatenating untrusted input directly into SQL statements allows attackers to break out of data literals and inject arbitrary SQL commands—enabling authentication bypass, full database exfiltration, data tampering, or destructive table drops.",
  severity: "critical",
  category: "injection",
  cweId: "CWE-89",
  owaspCategory: "A03:2021 - Injection",
  languages: [
    "typescript",
    "javascript",
    "python",
    "sql",
    "php",
    "java",
    "go",
    "ruby",
    "csharp",
  ],
  tags: ["sql", "sqli", "injection", "database", "cwe-89"],
  confidence: 0.93,
  patterns: [
    /`[^`]*\b(?:SELECT|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b[^`]*\$\{[^}]+\}[^`]*`/gi,
    /["'][^"']*\b(?:SELECT|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b[^"']*["']\s*\+\s*[a-zA-Z_$][\w$.]*/gi,
    /\b(?:execute|executemany|query|raw)\s*\(\s*f["'][^"']*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*\{[^}]+\}/gi,
    /\b(?:execute|executemany|query|raw)\s*\(\s*["'][^"']*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*["']\s*(?:%|\.format\s*\()/gi,
    /\$(?:queryRawUnsafe|executeRawUnsafe)\s*\(/g,
    /\bWHERE\s+[\w.]+\s*=\s*['"]?\s*["']\s*\+\s*[a-zA-Z_$][\w$.]*/gi,
  ],
  remediation: {
    summary:
      "Replace dynamic SQL string building with parameterized queries, prepared statements, or a typed query builder/ORM.",
    explanation:
      "Bind all user-supplied values as query parameters (`$1`, `?`, or named parameters) so the database engine strictly separates executable SQL syntax from untrusted data.",
    secureCodeExample: `// Secure: Parameterized query with node-postgres
const result = await pool.query(
  "SELECT id, email FROM users WHERE email = $1",
  [userEmail]
);

// Or with Supabase typed query builder:
const { data, error } = await supabase
  .from("users")
  .select("id, email")
  .eq("email", userEmail)
  .single();`,
    references: [
      "https://owasp.org/www-community/attacks/SQL_Injection",
      "https://cwe.mitre.org/data/definitions/89.html",
    ],
  },
});
