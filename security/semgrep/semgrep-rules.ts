import type { StructuredVulnerability } from "@/security/analyzer";
import type {
  Severity,
  SupportedLanguage,
  VulnerabilityCategory,
} from "@/types/security.types";
import type { SemgrepRuleset } from "@/types/semgrep.types";
import {
  extractCodeSnippet,
  offsetToLineColumn,
  redactSecretValue,
} from "@/utils/code.utils";

export const SEMGREP_SUPPORTED_RULESETS: readonly SemgrepRuleset[] = [
  "auto",
  "p/security-audit",
  "p/owasp-top-ten",
  "p/javascript",
  "p/typescript",
  "p/python",
  "p/secrets",
] as const;

export interface SemgrepBuiltinRule {
  readonly id: string;
  readonly name: string;
  readonly severity: Severity;
  readonly category: VulnerabilityCategory;
  readonly cweId: string;
  readonly owaspCategory: string;
  readonly description: string;
  readonly risk: string;
  readonly suggestedFix: string;
  readonly secureCodeExample: string;
  readonly confidenceScore: number;
  readonly languages: readonly SupportedLanguage[] | "*";
  readonly rulesets: readonly SemgrepRuleset[];
  readonly patterns: readonly RegExp[];
  readonly redactMatch?: boolean;
}

export const SEMGREP_BUILTIN_RULES: readonly SemgrepBuiltinRule[] = [
  {
    id: "javascript.lang.security.audit.sqli.node-postgres-sqli",
    name: "SQL Injection via Unparameterized Query",
    severity: "critical",
    category: "injection",
    cweId: "CWE-89",
    owaspCategory: "A03:2021 - Injection",
    description:
      "Detected a database query constructed with template interpolation or string concatenation instead of parameterized placeholders.",
    risk: "Untrusted input interpolated into SQL statements allows attackers to bypass authentication, exfiltrate sensitive records, or modify database state.",
    suggestedFix:
      "Use parameterized queries ($1, $2 or ?) or a typed query builder/ORM so user input is always bound as data rather than SQL syntax.",
    secureCodeExample:
      'const result = await pool.query("SELECT id, email FROM users WHERE id = $1", [userId]);',
    confidenceScore: 0.93,
    languages: ["javascript", "typescript", "sql"],
    rulesets: [
      "auto",
      "p/security-audit",
      "p/owasp-top-ten",
      "p/javascript",
      "p/typescript",
    ],
    patterns: [
      /\.(?:query|execute)\s*\(\s*`[^`]*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|UNION)\b[^`]*\$\{[^}]+\}[^`]*`/gi,
      /\.(?:query|execute)\s*\(\s*["'][^"']*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b[^"']*["']\s*\+/gi,
    ],
  },
  {
    id: "typescript.react.security.audit.react-dangerouslysetinnerhtml",
    name: "React dangerouslySetInnerHTML XSS Risk",
    severity: "high",
    category: "xss",
    cweId: "CWE-79",
    owaspCategory: "A03:2021 - Injection",
    description:
      "Detected use of React's dangerouslySetInnerHTML prop, which bypasses React's built-in DOM escaping.",
    risk: "Rendering unescaped or unsanitized HTML enables Cross-Site Scripting (XSS), allowing attackers to steal session tokens or perform actions on behalf of users.",
    suggestedFix:
      "Render plain text through JSX expressions whenever possible, or sanitize HTML with a strict allowlist library such as DOMPurify before rendering.",
    secureCodeExample:
      "import DOMPurify from 'dompurify';\nconst cleanHtml = DOMPurify.sanitize(untrustedHtml);\nreturn <div dangerouslySetInnerHTML={{ __html: cleanHtml }} />;",
    confidenceScore: 0.89,
    languages: ["javascript", "typescript"],
    rulesets: [
      "auto",
      "p/security-audit",
      "p/owasp-top-ten",
      "p/javascript",
      "p/typescript",
    ],
    patterns: [/dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:/g],
  },
  {
    id: "javascript.lang.security.detect-child-process",
    name: "OS Command Injection via child_process",
    severity: "critical",
    category: "injection",
    cweId: "CWE-78",
    owaspCategory: "A03:2021 - Injection",
    description:
      "Detected child_process execution with dynamic arguments or shell interpretation enabled.",
    risk: "Passing untrusted input to a shell command allows arbitrary OS command execution with the privileges of the Node.js process.",
    suggestedFix:
      "Use execFile or spawn with shell: false and pass arguments as a validated array instead of concatenating shell command strings.",
    secureCodeExample:
      'import { execFile } from "node:child_process";\nexecFile("git", ["status", "--short"], { shell: false }, callback);',
    confidenceScore: 0.92,
    languages: ["javascript", "typescript"],
    rulesets: [
      "auto",
      "p/security-audit",
      "p/owasp-top-ten",
      "p/javascript",
      "p/typescript",
    ],
    patterns: [
      /\b(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{[^}]+\}[^`]*`|[^)"'`\n]+\s*\+\s*[^)\n]+|(?:req|input|cmd|command|userInput)\b)/g,
      /\b(?:spawn|spawnSync)\s*\([^)]*shell\s*:\s*true/g,
    ],
  },
  {
    id: "javascript.lang.security.detect-eval-with-expression",
    name: "Dynamic Code Execution via eval / Function",
    severity: "critical",
    category: "injection",
    cweId: "CWE-95",
    owaspCategory: "A03:2021 - Injection",
    description:
      "Detected dynamic JavaScript code evaluation using eval(), new Function(), or string-based timers.",
    risk: "Evaluating dynamically constructed code strings leads to Remote Code Execution (RCE) on servers and XSS in browsers.",
    suggestedFix:
      "Replace eval/Function with safe data parsers such as JSON.parse, explicit lookup maps, or a sandboxed expression evaluator.",
    secureCodeExample:
      "const parsed = JSON.parse(rawPayload);\nconst handler = ALLOWED_HANDLERS[parsed.action];",
    confidenceScore: 0.94,
    languages: ["javascript", "typescript"],
    rulesets: [
      "auto",
      "p/security-audit",
      "p/owasp-top-ten",
      "p/javascript",
      "p/typescript",
    ],
    patterns: [
      /\beval\s*\(\s*(?!["'][^"']*["']\s*\))[^)]+\)/g,
      /\bnew\s+Function\s*\(/g,
      /\b(?:setTimeout|setInterval)\s*\(\s*(?:`[^`]*\$\{[^}]+\}[^`]*`|["'][^"']+["']\s*\+)/g,
    ],
  },
  {
    id: "javascript.jsonwebtoken.security.jwt-hardcode",
    name: "Hardcoded JWT Secret or Unverified Token Handling",
    severity: "high",
    category: "authentication",
    cweId: "CWE-798",
    owaspCategory: "A07:2021 - Identification and Authentication Failures",
    description:
      "Detected a hardcoded secret passed to jsonwebtoken sign/verify or insecure JWT algorithm configuration.",
    risk: "Hardcoded JWT secrets or accepting algorithm 'none' allow attackers to forge arbitrary authentication tokens and escalate privileges.",
    suggestedFix:
      "Load high-entropy signing keys from a secret manager or environment variables and enforce an explicit allowlist of strong algorithms (e.g., HS256 or RS256).",
    secureCodeExample:
      'const secret = process.env.JWT_SECRET;\nif (!secret) throw new Error("JWT_SECRET is required");\nconst payload = jwt.verify(token, secret, { algorithms: ["HS256"] });',
    confidenceScore: 0.9,
    languages: ["javascript", "typescript"],
    rulesets: [
      "auto",
      "p/security-audit",
      "p/owasp-top-ten",
      "p/javascript",
      "p/typescript",
      "p/secrets",
    ],
    patterns: [
      /\bjwt\.(?:sign|verify)\s*\([^,]+,\s*["'`][^"'`]{4,}["'`]/g,
      /algorithms?\s*:\s*\[?\s*["']none["']\s*\]?/gi,
    ],
  },
  {
    id: "javascript.express.security.audit.xss.direct-response-write",
    name: "Reflected XSS via Direct HTTP Response Write",
    severity: "high",
    category: "xss",
    cweId: "CWE-79",
    owaspCategory: "A03:2021 - Injection",
    description:
      "Detected user-controlled request data written directly into an Express HTTP response without encoding.",
    risk: "Directly echoing request parameters into HTML responses allows attackers to inject executable scripts into victim browsers.",
    suggestedFix:
      "Return structured JSON with res.json() or escape untrusted values before interpolating them into HTML templates.",
    secureCodeExample:
      "res.status(200).json({ message: `Hello ${String(req.query.name ?? '')}` });",
    confidenceScore: 0.87,
    languages: ["javascript", "typescript"],
    rulesets: [
      "auto",
      "p/security-audit",
      "p/owasp-top-ten",
      "p/javascript",
      "p/typescript",
    ],
    patterns: [
      /\bres\.(?:send|write|end)\s*\([^)]*\breq\.(?:query|params|body|headers)\b[^)]*\)/g,
    ],
  },
  {
    id: "javascript.lang.security.audit.prototype-pollution",
    name: "Prototype Pollution via Unsafe Property Assignment",
    severity: "high",
    category: "injection",
    cweId: "CWE-1321",
    owaspCategory: "A08:2021 - Software and Data Integrity Failures",
    description:
      "Detected direct reference to __proto__ or constructor.prototype, or recursive property assignment without prototype key guards.",
    risk: "Attackers can inject properties onto Object.prototype, corrupting application logic, bypassing authorization checks, or causing denial of service.",
    suggestedFix:
      "Reject '__proto__', 'constructor', and 'prototype' keys when merging untrusted objects, or use Object.create(null) / Map for dynamic key-value storage.",
    secureCodeExample:
      'const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);\nif (!FORBIDDEN_KEYS.has(key)) {\n  safeMap.set(key, value);\n}',
    confidenceScore: 0.86,
    languages: ["javascript", "typescript"],
    rulesets: [
      "auto",
      "p/security-audit",
      "p/owasp-top-ten",
      "p/javascript",
      "p/typescript",
    ],
    patterns: [
      /(?:\.__proto__|\[["']__proto__["']\]|constructor\.prototype)\s*=/g,
      /Object\.assign\s*\(\s*\{\s*\}\s*,\s*req\.(?:body|query)\b/g,
    ],
  },
  {
    id: "javascript.lang.security.audit.detect-non-literal-regexp",
    name: "Non-Literal RegExp Construction (ReDoS Risk)",
    severity: "medium",
    category: "other",
    cweId: "CWE-1333",
    owaspCategory: "A05:2021 - Security Misconfiguration",
    description:
      "Detected RegExp constructed from a dynamic variable or expression instead of a static literal.",
    risk: "Attacker-controlled regular expression patterns can trigger catastrophic backtracking (ReDoS), blocking the single-threaded event loop.",
    suggestedFix:
      "Use static regex literals, escape user input before constructing a RegExp, or use plain string methods such as String.prototype.includes.",
    secureCodeExample:
      'const escaped = userInput.replace(/[.*+?^${}()|[\\]\\\\]/g, "\\\\$&");\nconst matcher = new RegExp(escaped, "i");',
    confidenceScore: 0.8,
    languages: ["javascript", "typescript"],
    rulesets: [
      "auto",
      "p/security-audit",
      "p/javascript",
      "p/typescript",
    ],
    patterns: [
      /\bnew\s+RegExp\s*\(\s*(?!["'`][^"'`$]*["'`]\s*(?:,|\)))[^,)]+/g,
    ],
  },
  {
    id: "python.lang.security.audit.subprocess-shell-true",
    name: "Python Command Injection via subprocess shell=True",
    severity: "critical",
    category: "injection",
    cweId: "CWE-78",
    owaspCategory: "A03:2021 - Injection",
    description:
      "Detected Python subprocess invocation with shell=True or direct os.system execution.",
    risk: "Invoking a system shell with untrusted input allows command chaining and full Remote Code Execution.",
    suggestedFix:
      "Use subprocess.run([...], shell=False, check=True) with a static executable path and explicit argument list.",
    secureCodeExample:
      'import subprocess\nsubprocess.run(["ls", "-la", safe_dir], shell=False, check=True)',
    confidenceScore: 0.94,
    languages: ["python"],
    rulesets: ["auto", "p/security-audit", "p/owasp-top-ten", "p/python"],
    patterns: [
      /\bsubprocess\.(?:run|Popen|call|check_call|check_output)\s*\([^)]*shell\s*=\s*True/g,
      /\bos\.(?:system|popen)\s*\(/g,
    ],
  },
  {
    id: "python.lang.security.deserialization.pickle.avoid-pickle",
    name: "Unsafe Deserialization via Python pickle / yaml.load",
    severity: "critical",
    category: "deserialization",
    cweId: "CWE-502",
    owaspCategory: "A08:2021 - Software and Data Integrity Failures",
    description:
      "Detected use of Python pickle.load(s) or unsafe yaml.load(), which can execute arbitrary code during deserialization.",
    risk: "Deserializing untrusted byte streams with pickle or yaml.load allows attackers to trigger arbitrary Python code execution.",
    suggestedFix:
      "Use safe, data-only formats like JSON (json.loads) or yaml.safe_load() for untrusted inputs.",
    secureCodeExample:
      "import json\ndata = json.loads(raw_payload)",
    confidenceScore: 0.95,
    languages: ["python"],
    rulesets: ["auto", "p/security-audit", "p/owasp-top-ten", "p/python"],
    patterns: [
      /\b(?:cPickle|pickle)\.(?:loads|load)\s*\(/g,
      /\byaml\.load\s*\((?![^)]*Loader\s*=\s*(?:yaml\.)?SafeLoader)[^)]*\)/g,
    ],
  },
  {
    id: "generic.secrets.security.detected-generic-api-key",
    name: "Hardcoded API Key or Secret Token",
    severity: "critical",
    category: "secrets",
    cweId: "CWE-798",
    owaspCategory: "A07:2021 - Identification and Authentication Failures",
    description:
      "Detected a hardcoded API key, cloud access key, or bearer secret embedded directly in source code.",
    risk: "Secrets committed to source control can be harvested by attackers to compromise cloud infrastructure, third-party APIs, and customer data.",
    suggestedFix:
      "Revoke and rotate the exposed credential immediately, then load secrets from environment variables or a managed vault.",
    secureCodeExample:
      'const apiKey = process.env.SERVICE_API_KEY;\nif (!apiKey) throw new Error("Missing SERVICE_API_KEY");',
    confidenceScore: 0.93,
    languages: "*",
    rulesets: [
      "auto",
      "p/security-audit",
      "p/owasp-top-ten",
      "p/secrets",
      "p/javascript",
      "p/typescript",
      "p/python",
    ],
    patterns: [
      /\b(?:AKIA[0-9A-Z]{16}|sk_live_[0-9a-zA-Z]{16,}|ghp_[0-9a-zA-Z]{30,}|sk-[a-zA-Z0-9]{24,})\b/g,
      /\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?token)\s*[:=]\s*["'][A-Za-z0-9_\-/.+=]{16,}["']/gi,
    ],
    redactMatch: true,
  },
  {
    id: "generic.secrets.security.detected-private-key",
    name: "Hardcoded Cryptographic Private Key",
    severity: "critical",
    category: "secrets",
    cweId: "CWE-321",
    owaspCategory: "A02:2021 - Cryptographic Failures",
    description:
      "Detected an inline PEM-encoded cryptographic private key inside source code.",
    risk: "Exposed private keys compromise TLS termination, SSH access, JWT signing, and code-signing integrity.",
    suggestedFix:
      "Remove the private key from source control, revoke/reissue the key pair, and inject keys at runtime via KMS or secret mounts.",
    secureCodeExample:
      'const privateKey = await secretsManager.getSecret("APP_SIGNING_PRIVATE_KEY");',
    confidenceScore: 0.98,
    languages: "*",
    rulesets: [
      "auto",
      "p/security-audit",
      "p/owasp-top-ten",
      "p/secrets",
      "p/javascript",
      "p/typescript",
      "p/python",
    ],
    patterns: [
      /-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+|PGP\s+)?PRIVATE\s+KEY-----/g,
    ],
    redactMatch: true,
  },
  {
    id: "javascript.lang.security.audit.path-traversal.path-join-resolve-traversal",
    name: "Path Traversal via Unvalidated File Path",
    severity: "high",
    category: "path-traversal",
    cweId: "CWE-22",
    owaspCategory: "A01:2021 - Broken Access Control",
    description:
      "Detected filesystem path construction or file read using untrusted request parameters without canonical boundary verification.",
    risk: "Attackers can supply '../' sequences to read arbitrary files outside the intended directory (e.g., /etc/passwd or .env).",
    suggestedFix:
      "Resolve the canonical path with path.resolve() and verify it starts with the intended base directory before reading or writing.",
    secureCodeExample:
      'const resolved = path.resolve(BASE_DIR, path.basename(userFile));\nif (!resolved.startsWith(BASE_DIR + path.sep)) throw new Error("Invalid path");',
    confidenceScore: 0.87,
    languages: ["javascript", "typescript"],
    rulesets: [
      "auto",
      "p/security-audit",
      "p/owasp-top-ten",
      "p/javascript",
      "p/typescript",
    ],
    patterns: [
      /\bpath\.(?:join|resolve)\s*\([^)]*\breq\.(?:query|params|body)\b[^)]*\)/g,
      /\bfs\.(?:readFile|readFileSync|createReadStream)\s*\([^)]*\breq\.(?:query|params|body)\b[^)]*\)/g,
    ],
  },
  {
    id: "javascript.lang.security.audit.ssrf.node-fetch-ssrf",
    name: "Server-Side Request Forgery (SSRF) via User-Controlled URL",
    severity: "high",
    category: "ssrf",
    cweId: "CWE-918",
    owaspCategory: "A10:2021 - Server-Side Request Forgery (SSRF)",
    description:
      "Detected an outbound HTTP request whose target URL is derived directly from request parameters.",
    risk: "Attackers can force the server to access internal metadata endpoints (169.254.169.254), private networks, or localhost services.",
    suggestedFix:
      "Validate outbound URLs against an explicit allowlist of trusted hostnames and block private/loopback IP ranges.",
    secureCodeExample:
      'const parsed = new URL(targetUrl);\nif (!ALLOWED_HOSTS.has(parsed.hostname)) throw new Error("Disallowed host");\nconst res = await fetch(parsed.toString());',
    confidenceScore: 0.86,
    languages: ["javascript", "typescript"],
    rulesets: [
      "auto",
      "p/security-audit",
      "p/owasp-top-ten",
      "p/javascript",
      "p/typescript",
    ],
    patterns: [
      /\b(?:fetch|axios(?:\.(?:get|post|put|delete|request))?)\s*\(\s*(?:req\.(?:query|params|body)\b|`[^`]*\$\{\s*req\.(?:query|params|body)\b)/g,
    ],
  },
];

export function getApplicableBuiltinRules(
  language: SupportedLanguage,
  ruleset: SemgrepRuleset
): readonly SemgrepBuiltinRule[] {
  return SEMGREP_BUILTIN_RULES.filter((rule) => {
    const matchesRuleset =
      ruleset === "auto" || rule.rulesets.includes(ruleset);
    if (!matchesRuleset) {
      return false;
    }

    if (rule.languages === "*" || language === "unknown") {
      return true;
    }

    return rule.languages.includes(language);
  });
}

export interface BuiltinSemgrepExecutionResult {
  findings: StructuredVulnerability[];
  rawMatchCount: number;
  executedRulesCount: number;
}

/**
 * Executes the built-in Semgrep-compatible static rule pack against source code.
 */
export function runBuiltinSemgrepRules(
  code: string,
  language: SupportedLanguage,
  ruleset: SemgrepRuleset
): BuiltinSemgrepExecutionResult {
  const applicableRules = getApplicableBuiltinRules(language, ruleset);
  const lines = code.split(/\r?\n/);
  const findings: StructuredVulnerability[] = [];
  let rawMatchCount = 0;

  for (const rule of applicableRules) {
    const seenLinesForRule = new Set<number>();

    for (const pattern of rule.patterns) {
      const flags = pattern.flags.includes("g")
        ? pattern.flags
        : `${pattern.flags}g`;
      const regex = new RegExp(pattern.source, flags);

      let match: RegExpExecArray | null = regex.exec(code);
      while (match !== null) {
        rawMatchCount += 1;
        const matchedText = match[0] ?? "";
        const { line, column } = offsetToLineColumn(code, match.index);

        if (!seenLinesForRule.has(line)) {
          seenLinesForRule.add(line);
          let snippet = extractCodeSnippet(lines, line, 2);
          if (rule.redactMatch && matchedText.length > 0) {
            snippet = snippet.replace(
              matchedText,
              redactSecretValue(matchedText)
            );
          }

          findings.push({
            ruleId: rule.id,
            name: rule.name,
            severity: rule.severity,
            category: rule.category,
            cweId: rule.cweId,
            owaspCategory: rule.owaspCategory,
            description: rule.description,
            risk: rule.risk,
            fileLine: line,
            column,
            snippet,
            suggestedFix: rule.suggestedFix,
            secureCodeExample: rule.secureCodeExample,
            confidenceScore: rule.confidenceScore,
          });
        }

        if (matchedText.length === 0) {
          regex.lastIndex += 1;
        }
        match = regex.exec(code);
      }
    }
  }

  return {
    findings,
    rawMatchCount,
    executedRulesCount: applicableRules.length,
  };
}
