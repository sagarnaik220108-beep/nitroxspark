import type { ExplanationTemplate } from "@/types/explanation.types";

/**
 * Curated, beginner-friendly explanation templates for Sentinel AI's 12 core
 * vulnerability types. Each template is written in plain English so junior
 * developers, vibe-coders, and students can immediately understand the risk
 * and fix their code safely.
 */
export const CORE_EXPLANATION_TEMPLATES: readonly ExplanationTemplate[] = [
  // 1. Hardcoded API Keys
  {
    id: "hardcoded-api-keys",
    name: "Hardcoded API Keys",
    ruleIds: [
      "SENTINEL-SEC-001",
      "SENTINEL-SEC-002",
      "SEC-001",
      "HARDCODED-API-KEY",
    ],
    keywords: [
      "hardcoded api key",
      "api key",
      "api_key",
      "secret token",
      "secret key",
      "stripe key",
      "aws key",
      "github token",
      "private cryptographic key",
      "private key",
      "cwe-798",
      "cwe-321",
    ],
    category: "secrets",
    defaultSeverity: "critical",
    defaultCweId: "CWE-798",
    defaultOwaspCategory: "A07:2021 - Identification and Authentication Failures",
    whatItIs:
      "A hardcoded API key means you pasted a secret service key (like an OpenAI, Stripe, AWS, or GitHub key) directly inside your source code instead of loading it safely from environment variables.",
    whyItHappens:
      "Developers and AI code generators often paste keys directly into code to get a prototype working quickly. Later, that file gets committed to Git, shared with teammates, or bundled into frontend JavaScript where anyone can read it.",
    howHackersExploitIt:
      "1. Automated bots continuously scan public GitHub repositories, npm packages, and browser JavaScript bundles for key patterns like 'sk-' or 'AKIA'. 2. Within minutes of a key being pushed, a bot grabs it. 3. The attacker uses your key to run expensive AI/cloud workloads on your billing account or steal data from your connected services.",
    realWorldAnalogy:
      "It is like writing your credit card number and PIN on a sticky note and taping it to the outside of your front door so you don't forget it.",
    impact:
      "Runaway cloud or AI bills (often thousands of dollars overnight), unauthorized access to customer data, service suspension, and forced emergency key rotation.",
    bestPractice:
      "Store all API keys in server-side environment variables (such as `.env.local` locally and Vercel/cloud secret managers in production). Add `.env*` files to `.gitignore`, never expose private keys to browser code, and immediately revoke any key that was ever committed to Git.",
    secureVersion: `// Secure: Load the API key from server-side environment variables
const apiKey = process.env.OPENAI_API_KEY;

if (!apiKey) {
  throw new Error("Missing OPENAI_API_KEY in server environment variables");
}

// Use the key only on the server (API routes, Server Actions, backend services)
const response = await fetch("https://api.openai.com/v1/models", {
  headers: { Authorization: \`Bearer \${apiKey}\` },
});`,
    secureVersionsByLanguage: {
      python: `# Secure: Read API keys from environment variables instead of hardcoding them
import os
import requests

api_key = os.environ.get("OPENAI_API_KEY")
if not api_key:
    raise RuntimeError("Missing OPENAI_API_KEY environment variable")

response = requests.get(
    "https://api.openai.com/v1/models",
    headers={"Authorization": f"Bearer {api_key}"},
    timeout=10,
)`,
    },
  },

  // 2. Hardcoded Passwords
  {
    id: "hardcoded-passwords",
    name: "Hardcoded Passwords",
    ruleIds: [
      "SENTINEL-SEC-004",
      "SENTINEL-PWD-001",
      "SEC-004",
      "HARDCODED-PASSWORD",
    ],
    keywords: [
      "hardcoded password",
      "password literal",
      "default password",
      "embedded password",
      "admin password",
      "plaintext password in code",
      "cwe-259",
    ],
    category: "secrets",
    defaultSeverity: "critical",
    defaultCweId: "CWE-259",
    defaultOwaspCategory: "A07:2021 - Identification and Authentication Failures",
    whatItIs:
      "A hardcoded password is a real login password, admin passphrase, or service credential typed directly into your source code as plain text.",
    whyItHappens:
      "During early development or tutorials, developers and AI assistants often write quick shortcuts like `if (password === 'admin123')` to test login flows and forget to replace them before deploying.",
    howHackersExploitIt:
      "1. An attacker reads your repository, leaked backup, or decompiled app bundle. 2. They spot the plain-text password right in the code. 3. They log straight into your admin panel, database, or internal service with full privileges—no guessing required.",
    realWorldAnalogy:
      "It is like hiding the spare key to a bank vault inside the public instruction manual handed out to every visitor.",
    impact:
      "Instant account takeover, complete compromise of admin dashboards or databases, and inability to change the password without redeploying the entire application.",
    bestPractice:
      "Never store real passwords in source code. Load service credentials from environment variables or a secret manager, and store user passwords only as salted cryptographic hashes (Argon2id, scrypt, or bcrypt) in your database.",
    secureVersion: `// Secure: Never hardcode admin passwords; verify against a salted hash
import { scryptSync, timingSafeEqual } from "node:crypto";

export function verifyPassword(inputPassword: string, storedHash: string): boolean {
  const [salt, originalHex] = storedHash.split(":");
  if (!salt || !originalHex) return false;

  const derived = scryptSync(inputPassword, salt, 64);
  const original = Buffer.from(originalHex, "hex");
  return (
    derived.length === original.length &&
    timingSafeEqual(derived, original)
  );
}`,
    secureVersionsByLanguage: {
      python: `# Secure: Load service credentials from environment variables or verify hashes
import os
import hmac

expected_secret = os.environ.get("ADMIN_SERVICE_SECRET")
if not expected_secret:
    raise RuntimeError("ADMIN_SERVICE_SECRET is not configured")

def verify_service_secret(provided: str) -> bool:
    return hmac.compare_digest(provided, expected_secret)`,
    },
  },

  // 3. JWT Secrets
  {
    id: "jwt-secrets",
    name: "JWT Secrets & Insecure Token Handling",
    ruleIds: [
      "SENTINEL-JWT-001",
      "SENTINEL-AUTH-001",
      "JWT-001",
      "HARDCODED-JWT-SECRET",
    ],
    keywords: [
      "jwt secret",
      "jwt_secret",
      "jwt.decode",
      "jwt.sign",
      "json web token",
      "insecure jwt",
      "unverified token",
      "none algorithm",
      "token forgery",
      "cwe-347",
    ],
    category: "authentication",
    defaultSeverity: "critical",
    defaultCweId: "CWE-347",
    defaultOwaspCategory: "A07:2021 - Identification and Authentication Failures",
    whatItIs:
      "A JWT (JSON Web Token) acts like a digital ID badge for logged-in users. If its signing secret is hardcoded, too weak, or if your code decodes tokens without verifying their signature, anyone can forge their own ID badge.",
    whyItHappens:
      "AI-generated auth snippets frequently use placeholder secrets like `'my-secret-key'` or call `jwt.decode()` instead of `jwt.verify()` because `decode()` looks simpler and still returns the user object during happy-path testing.",
    howHackersExploitIt:
      "1. The attacker grabs a normal user's JWT from browser cookies or headers. 2. Using the leaked/weak secret (or exploiting unverified `jwt.decode()`), they edit the token payload to say `{\"role\": \"admin\", \"userId\": \"1\"}`. 3. They send the forged token back to your API, and your server trusts them as an administrator.",
    realWorldAnalogy:
      "It is like a nightclub using a cheap rubber stamp anyone can buy online—or a bouncer who checks if you have a wristband without checking whether it is actually from tonight's event.",
    impact:
      "Full authentication bypass, impersonation of any user or administrator, and unauthorized access to every protected endpoint in your app.",
    bestPractice:
      "Generate a high-entropy random secret (at least 32 bytes / 256 bits) stored only in environment variables, always verify tokens with `jwt.verify()` (never trust `jwt.decode()` alone), and pin the exact allowed signing algorithm (e.g., `HS256` or `RS256`).",
    secureVersion: `// Secure: Load a strong JWT secret from env and always verify with an explicit algorithm
import jwt from "jsonwebtoken";

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  throw new Error("JWT_SECRET must be configured with at least 32 characters");
}

export function verifySessionToken(token: string) {
  return jwt.verify(token, JWT_SECRET, {
    algorithms: ["HS256"],
    issuer: "sentinel-ai",
  });
}`,
    secureVersionsByLanguage: {
      python: `# Secure: Verify JWT signature and enforce an explicit algorithm allowlist
import os
import jwt

JWT_SECRET = os.environ["JWT_SECRET"]

def verify_session_token(token: str) -> dict:
    return jwt.decode(
        token,
        JWT_SECRET,
        algorithms=["HS256"],
        issuer="sentinel-ai",
    )`,
    },
  },

  // 4. SQL Injection
  {
    id: "sql-injection",
    name: "SQL Injection",
    ruleIds: ["SENTINEL-INJ-001", "INJ-001", "SQL-INJECTION", "SQLI"],
    keywords: [
      "sql injection",
      "sqli",
      "sql query",
      "string interpolation",
      "nosql injection",
      "SENTINEL-INJ-004",
      "cwe-89",
      "cwe-943",
    ],
    category: "injection",
    defaultSeverity: "critical",
    defaultCweId: "CWE-89",
    defaultOwaspCategory: "A03:2021 - Injection",
    whatItIs:
      "SQL Injection happens when user input is glued directly into a database query string. Because the database cannot tell where your command ends and the user's text begins, clever input can rewrite the query itself.",
    whyItHappens:
      "Building queries with template literals like `` `SELECT * FROM users WHERE email = '${email}'` `` feels fast and natural, and AI code generators often produce it when asked for quick database examples.",
    howHackersExploitIt:
      "1. An attacker finds an input field (like a login email or search box) that goes into a SQL query. 2. Instead of a normal value, they enter text containing SQL syntax such as `' OR '1'='1' --`. 3. The database executes the altered query, logging them in without a password or dumping the entire users table.",
    realWorldAnalogy:
      "It is like filling out a form where you write 'John Smith; also give me the keys to every locker' in the Name box, and the clerk obeys the extra instruction as if their boss wrote it.",
    impact:
      "Complete theft of customer databases (emails, passwords, billing data), silent tampering with records, authentication bypass, or total deletion of tables.",
    bestPractice:
      "Always use parameterized queries (prepared statements) or a typed ORM/query builder (like Supabase, Prisma, Drizzle, or `pg` with `$1` placeholders). Never concatenate or interpolate user input into SQL strings.",
    secureVersion: `// Secure: Use parameterized queries so input is treated strictly as data, never SQL code
const result = await db.query(
  "SELECT id, email, role FROM users WHERE email = $1",
  [userEmail]
);

// Or with a typed query builder (e.g., Supabase):
const { data, error } = await supabase
  .from("users")
  .select("id, email, role")
  .eq("email", userEmail)
  .single();`,
    secureVersionsByLanguage: {
      python: `# Secure: Pass user input as query parameters, never via f-strings or '+'
cursor.execute(
    "SELECT id, email, role FROM users WHERE email = %s",
    (user_email,),
)
user = cursor.fetchone()`,
    },
  },

  // 5. Cross-Site Scripting (XSS)
  {
    id: "cross-site-scripting",
    name: "Cross-Site Scripting (XSS)",
    ruleIds: [
      "SENTINEL-XSS-001",
      "SENTINEL-XSS-002",
      "XSS-001",
      "XSS-002",
      "XSS",
    ],
    keywords: [
      "cross-site scripting",
      "xss",
      "dangerouslysetinnerhtml",
      "innerhtml",
      "outerhtml",
      "document.write",
      "insertadjacenthtml",
      "html injection",
      "cwe-79",
    ],
    category: "xss",
    defaultSeverity: "high",
    defaultCweId: "CWE-79",
    defaultOwaspCategory: "A03:2021 - Injection",
    whatItIs:
      "Cross-Site Scripting (XSS) occurs when your web page displays untrusted user input as raw HTML, allowing an attacker to sneak malicious JavaScript into other people's browsers.",
    whyItHappens:
      "Developers use `dangerouslySetInnerHTML`, `innerHTML`, or `document.write()` to render formatted text, comments, or AI-generated markdown without sanitizing it first.",
    howHackersExploitIt:
      "1. An attacker submits a comment, profile bio, or URL containing hidden HTML/JavaScript (for example, an image tag with an `onerror` script). 2. Your app renders that raw HTML to another visitor. 3. The attacker's script runs inside the victim's browser as if it were your website, stealing session data or performing actions on their behalf.",
    realWorldAnalogy:
      "It is like a community bulletin board where someone posts a flyer that secretly rewrites the store's rules whenever a customer reads it.",
    impact:
      "Session hijacking, stolen user accounts, defaced web pages, fake login popups (phishing) inside your own domain, and unauthorized actions performed as admin users.",
    bestPractice:
      "Render untrusted text using safe defaults (React JSX `{userInput}` or `element.textContent`) which automatically escape HTML. If you truly need rich HTML, sanitize it first with a battle-tested library like DOMPurify and enforce a Content Security Policy (CSP).",
    secureVersion: `import DOMPurify from "isomorphic-dompurify";

// Best: Render plain text directly in React (automatically escaped)
export function SafeComment({ text }: { text: string }) {
  return <p>{text}</p>;
}

// If rich HTML is required, sanitize it with a strict allowlist first
export function SafeRichContent({ rawHtml }: { rawHtml: string }) {
  const cleanHtml = DOMPurify.sanitize(rawHtml, {
    ALLOWED_TAGS: ["b", "i", "em", "strong", "p", "br", "ul", "li"],
    ALLOWED_ATTR: [],
  });

  return <div dangerouslySetInnerHTML={{ __html: cleanHtml }} />;
}`,
  },

  // 6. Command Injection
  {
    id: "command-injection",
    name: "Command Injection",
    ruleIds: ["SENTINEL-INJ-002", "INJ-002", "CMD-INJECTION", "COMMAND-INJECTION"],
    keywords: [
      "command injection",
      "os command",
      "shell injection",
      "execsync",
      "child_process",
      "os.system",
      "subprocess",
      "shell=true",
      "cwe-78",
    ],
    category: "injection",
    defaultSeverity: "critical",
    defaultCweId: "CWE-78",
    defaultOwaspCategory: "A03:2021 - Injection",
    whatItIs:
      "Command Injection happens when your code passes user input directly into a system terminal/shell command (like `exec()`, `os.system()`, or `subprocess` with `shell=True`), letting attackers run their own operating system commands on your server.",
    whyItHappens:
      "When converting files, pinging hosts, or running CLI tools, developers often build a shell command string with template literals because it feels just like typing in a terminal.",
    howHackersExploitIt:
      "1. An attacker spots a feature that passes input (like a filename or hostname) to a shell command. 2. They append shell separators like `;`, `&&`, or `|` followed by another command (for example, `report.pdf; cat /etc/passwd`). 3. The server's shell runs both your command and the attacker's command, giving them direct control of the machine.",
    realWorldAnalogy:
      "It is like handing an automated warehouse robot a voice note from a stranger: you meant for it to fetch a box, but the stranger added 'and unlock all the doors' at the end.",
    impact:
      "Full Remote Code Execution (RCE)—attackers can read server secrets, install ransomware or crypto-miners, pivot into internal networks, or wipe the server.",
    bestPractice:
      "Avoid calling shell commands whenever a native library exists. If you must run an external program, use `execFile()` or `spawn()` with `shell: false`, pass arguments as a separate array, and validate inputs against a strict allowlist.",
    secureVersion: `// Secure: Use execFile with shell disabled and strict input validation
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export async function inspectReportFile(fileName: string): Promise<string> {
  // Allow only safe, predictable filenames
  if (!/^[a-zA-Z0-9._-]{1,100}$/.test(fileName)) {
    throw new Error("Invalid file name");
  }

  // Arguments are passed as an array with shell: false, preventing command chaining
  const { stdout } = await execFileAsync("ls", ["-la", fileName], {
    shell: false,
  });
  return stdout;
}`,
    secureVersionsByLanguage: {
      python: `# Secure: Pass an argument list and keep shell=False
import re
import subprocess

def inspect_report_file(file_name: str) -> str:
    if not re.fullmatch(r"[a-zA-Z0-9._-]{1,100}", file_name):
        raise ValueError("Invalid file name")

    result = subprocess.run(
        ["ls", "-la", file_name],
        shell=False,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout`,
    },
  },

  // 7. Unsafe eval()
  {
    id: "unsafe-eval",
    name: "Unsafe eval() / Dynamic Code Execution",
    ruleIds: ["SENTINEL-INJ-003", "INJ-003", "UNSAFE-EVAL", "EVAL-001"],
    keywords: [
      "unsafe eval",
      "eval(",
      "eval()",
      "new function",
      "dynamic code execution",
      "code injection",
      "settimeout string",
      "cwe-95",
      "cwe-94",
    ],
    category: "injection",
    defaultSeverity: "high",
    defaultCweId: "CWE-95",
    defaultOwaspCategory: "A03:2021 - Injection",
    whatItIs:
      "Calling `eval()` or `new Function()` tells your programming language to treat a plain text string as live executable code. If any part of that string comes from a user or external source, they can run whatever code they want.",
    whyItHappens:
      "Developers and AI tools sometimes reach for `eval()` as a shortcut to parse JSON, evaluate math formulas, or dynamically call functions by name.",
    howHackersExploitIt:
      "1. An attacker finds an input that eventually flows into `eval()` (like a calculator expression, filter string, or JSON payload). 2. Instead of a harmless value, they send executable code such as `process.env` exfiltration or browser script calls. 3. The runtime executes the attacker's code with the exact same permissions as your application.",
    realWorldAnalogy:
      "It is like signing a blank check and letting anyone on the street write both the dollar amount and the recipient.",
    impact:
      "In backend code (Node.js/Python), it leads to full server takeover (Remote Code Execution). In browser code, it causes Cross-Site Scripting (XSS) and account hijacking.",
    bestPractice:
      "Remove `eval()` and `new Function()` completely. Use `JSON.parse()` for data, an explicit object/Map of allowed functions for dynamic dispatch, or a sandboxed expression parser library for math formulas.",
    secureVersion: `// Secure: Parse data with JSON.parse() and use an explicit lookup table instead of eval()
export function parseConfig(rawJson: string): unknown {
  return JSON.parse(rawJson);
}

const OPERATIONS: Record<string, (a: number, b: number) => number> = {
  add: (a, b) => a + b,
  subtract: (a, b) => a - b,
  multiply: (a, b) => a * b,
};

export function runOperation(op: string, a: number, b: number): number {
  const fn = OPERATIONS[op];
  if (!fn) {
    throw new Error(\`Unsupported operation: \${op}\`);
  }
  return fn(a, b);
}`,
    secureVersionsByLanguage: {
      python: `# Secure: Use json.loads() or ast.literal_eval() instead of eval()
import json

def parse_config(raw_json: str) -> dict:
    return json.loads(raw_json)`,
    },
  },

  // 8. Weak Authentication
  {
    id: "weak-authentication",
    name: "Weak Authentication",
    ruleIds: [
      "SENTINEL-AUTH-002",
      "SENTINEL-AUTH-003",
      "SENTINEL-CRYPTO-001",
      "AUTH-002",
      "WEAK-AUTH",
    ],
    keywords: [
      "weak authentication",
      "weak auth",
      "weak password",
      "md5",
      "sha1",
      "sha-1",
      "insecure session",
      "insecure cookie",
      "httponly",
      "math.random",
      "predictable randomness",
      "broken authentication",
      "cwe-287",
      "cwe-328",
      "cwe-614",
      "cwe-338",
    ],
    category: "authentication",
    defaultSeverity: "high",
    defaultCweId: "CWE-287",
    defaultOwaspCategory: "A07:2021 - Identification and Authentication Failures",
    whatItIs:
      "Weak Authentication means your app's login or session system uses outdated or easily guessed protections—such as hashing passwords with MD5/SHA-1, generating tokens with `Math.random()`, or leaving session cookies unprotected.",
    whyItHappens:
      "Fast hashes like MD5 and built-in helpers like `Math.random()` are easy to remember and frequently appear in older tutorials and AI-generated code, even though modern attackers can crack them in seconds.",
    howHackersExploitIt:
      "1. If passwords use MD5/SHA-1, attackers with consumer GPUs can crack millions of leaked hashes per second using precomputed rainbow tables. 2. If session tokens use `Math.random()` or cookies lack `httpOnly`/`secure`, attackers predict or steal active sessions and take over accounts without knowing the password.",
    realWorldAnalogy:
      "It is like protecting a house with a luggage padlock that opens with a paperclip, or using consecutive ticket numbers (101, 102, 103) for coat check so anyone can guess the next ticket.",
    impact:
      "Mass account takeovers, leaked user credentials (often reused across other sites), session hijacking, and loss of customer trust.",
    bestPractice:
      "Hash passwords with slow, salted, memory-hard algorithms (Argon2id, scrypt, or bcrypt). Generate tokens with `crypto.randomBytes()`, configure cookies with `httpOnly: true`, `secure: true`, and `sameSite: 'lax'`, and add rate limiting on login endpoints.",
    secureVersion: `// Secure: Strong password hashing + cryptographically random tokens + hardened cookies
import { randomBytes, scryptSync } from "node:crypto";

export function hashPassword(password: string): string {
  const salt = randomBytes(16).toString("hex");
  const hash = scryptSync(password, salt, 64).toString("hex");
  return \`\${salt}:\${hash}\`;
}

export function generateSessionToken(): string {
  // 256 bits of cryptographic randomness (never use Math.random())
  return randomBytes(32).toString("base64url");
}

// Always harden session cookies in production:
// { httpOnly: true, secure: true, sameSite: "lax", path: "/" }`,
    secureVersionsByLanguage: {
      python: `# Secure: Use secrets for tokens and scrypt/argon2 for password hashing
import hashlib
import secrets

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    derived = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)
    return f"{salt.hex()}:{derived.hex()}"

def generate_session_token() -> str:
    return secrets.token_urlsafe(32)`,
    },
  },

  // 9. Missing Authorization
  {
    id: "missing-authorization",
    name: "Missing Authorization",
    ruleIds: [
      "SENTINEL-AUTHZ-001",
      "SENTINEL-REDIR-001",
      "SENTINEL-PATH-001",
      "AUTHZ-001",
      "MISSING-AUTHZ",
      "IDOR",
    ],
    keywords: [
      "missing authorization",
      "broken access control",
      "idor",
      "insecure direct object",
      "missing permission",
      "role check",
      "admin check",
      "access control",
      "unauthenticated route",
      "unauthorized access",
      "cwe-862",
      "cwe-639",
    ],
    category: "authorization",
    defaultSeverity: "high",
    defaultCweId: "CWE-862",
    defaultOwaspCategory: "A01:2021 - Broken Access Control",
    whatItIs:
      "Missing Authorization means an API endpoint or action forgets to verify *who* the user is and whether they are actually allowed to view, edit, or delete the requested resource.",
    whyItHappens:
      "Developers often hide buttons in the frontend UI (like an 'Admin' or 'Delete' button) and assume nobody will call the backend URL directly. AI-generated API routes also frequently skip ownership checks to keep examples concise.",
    howHackersExploitIt:
      "1. An attacker logs in as a normal user and sees a request like `GET /api/invoices/1042` or `DELETE /api/users/55`. 2. Using browser DevTools or `curl`, they simply change the ID to `1043` or call an admin endpoint directly. 3. Because the server never checked ownership or role, it happily returns or deletes someone else's data.",
    realWorldAnalogy:
      "It is like a hotel that checks your ID at the front lobby (authentication), but then lets your room key open every single room on the floor (missing authorization).",
    impact:
      "Data breaches exposing other customers' private records, unauthorized account modifications, privilege escalation to admin, and regulatory fines (GDPR/HIPAA/SOC 2).",
    bestPractice:
      "Enforce authentication and ownership/role checks on the server for *every* API route and Server Action. Scope database queries to the authenticated user's ID (e.g., `WHERE id = $1 AND user_id = $2`) and enable Row Level Security (RLS) when using Postgres/Supabase.",
    secureVersion: `// Secure: Always verify both authentication AND resource ownership on the server
import { NextResponse } from "next/server";

export async function DELETE(
  _request: Request,
  context: { params: Promise<{ id: string }> }
) {
  const session = await getAuthenticatedUser();
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { id } = await context.params;

  // Enforce ownership in the query itself so users can only delete their own records
  const deleted = await db.project.deleteMany({
    where: {
      id,
      ownerId: session.userId,
    },
  });

  if (deleted.count === 0) {
    return NextResponse.json({ error: "Forbidden or not found" }, { status: 403 });
  }

  return NextResponse.json({ success: true });
}`,
  },

  // 10. Outdated Packages
  {
    id: "outdated-packages",
    name: "Outdated or Vulnerable Packages",
    ruleIds: [
      "SENTINEL-DEP-001",
      "SENTINEL-PKG-001",
      "DEP-001",
      "OUTDATED-PACKAGES",
    ],
    keywords: [
      "outdated package",
      "outdated packages",
      "outdated dependency",
      "vulnerable dependency",
      "vulnerable package",
      "deprecated package",
      "known cve",
      "supply chain",
      "npm audit",
      "package.json",
      "cwe-1104",
    ],
    category: "misconfiguration",
    defaultSeverity: "medium",
    defaultCweId: "CWE-1104",
    defaultOwaspCategory: "A06:2021 - Vulnerable and Outdated Components",
    whatItIs:
      "Your project depends on an old version of a third-party library or framework that has publicly known security bugs (CVEs) already fixed in newer releases.",
    whyItHappens:
      "AI assistants often suggest older package versions from their training data, and teams rarely revisit `package.json` or `requirements.txt` once a feature works.",
    howHackersExploitIt:
      "1. Public vulnerability databases publish exact details and ready-made exploit scripts for bugs in old library versions. 2. Attackers run automated scanners across the internet looking for apps running those vulnerable versions. 3. When they find a match, they fire the known exploit to steal data, crash the app, or take over the server.",
    realWorldAnalogy:
      "It is like driving a car after the manufacturer issued a free safety recall for faulty brakes, but never taking it to the shop for the fix.",
    impact:
      "Exposure to automated mass-exploitation, data theft, denial of service, or full server compromise through no mistake in your own custom code.",
    bestPractice:
      "Run `npm audit` (or `pip-audit` / `pnpm audit`) regularly, enable automated dependency updates (Dependabot or Renovate), lock dependency versions with a lockfile, and prioritize patching critical/high security advisories.",
    secureVersion: `// Secure: Keep dependencies patched and audit them automatically in CI
// 1. Check for known vulnerabilities locally:
//    npm audit
//
// 2. Apply non-breaking security patches:
//    npm audit fix
//
// 3. Pin safe, up-to-date versions in package.json:
{
  "scripts": {
    "security:audit": "npm audit --audit-level=high"
  },
  "dependencies": {
    "next": "^15.2.0",
    "zod": "^3.24.2"
  }
}`,
  },

  // 11. Open Database Connection
  {
    id: "open-database-connection",
    name: "Open or Insecure Database Connection",
    ruleIds: [
      "SENTINEL-SEC-003",
      "SENTINEL-DB-001",
      "SENTINEL-CFG-001",
      "DB-001",
      "OPEN-DATABASE",
    ],
    keywords: [
      "open database",
      "database connection",
      "connection string",
      "sslmode=disable",
      "unencrypted database",
      "public database",
      "0.0.0.0",
      "mongodb://",
      "postgres://",
      "disabled tls",
      "rejectunauthorized",
      "cwe-319",
      "cwe-295",
    ],
    category: "misconfiguration",
    defaultSeverity: "critical",
    defaultCweId: "CWE-319",
    defaultOwaspCategory: "A05:2021 - Security Misconfiguration",
    whatItIs:
      "An Open Database Connection occurs when your database is exposed without proper encryption (TLS/SSL disabled), uses embedded credentials in code, or accepts connections from anywhere on the public internet without strict firewall or auth rules.",
    whyItHappens:
      "When troubleshooting connection errors, developers and AI tools often add `sslmode=disable`, `rejectUnauthorized: false`, or allow `0.0.0.0/0` IP access to make the error disappear—and accidentally leave it enabled in production.",
    howHackersExploitIt:
      "1. Attackers scan the internet (using tools like Shodan) for open database ports (5432, 27017, 3306, 6379) or sniff unencrypted network traffic. 2. Using exposed connection strings or unauthenticated endpoints, they connect directly to the database. 3. They copy all tables, drop the database, or leave a ransom note.",
    realWorldAnalogy:
      "It is like moving your company's filing cabinets onto the sidewalk with the locks removed because carrying keys was slowing everyone down.",
    impact:
      "Complete exposure or destruction of your entire production database, ransomware attacks, severe downtime, and mandatory breach notifications.",
    bestPractice:
      "Load `DATABASE_URL` from server-only environment variables, always require TLS/SSL (`sslmode=require` with certificate verification enabled), restrict database access to private networks/allowlisted IPs, and use least-privilege database roles.",
    secureVersion: `// Secure: Load DATABASE_URL from env and enforce verified TLS encryption
import { Pool } from "pg";

const connectionString = process.env.DATABASE_URL;
if (!connectionString) {
  throw new Error("DATABASE_URL environment variable is required");
}

export const dbPool = new Pool({
  connectionString,
  ssl: {
    rejectUnauthorized: true, // Always verify the database TLS certificate
  },
  max: 10,
  idleTimeoutMillis: 30_000,
});`,
    secureVersionsByLanguage: {
      python: `# Secure: Read DATABASE_URL from env and enforce TLS (sslmode=require)
import os
import psycopg

database_url = os.environ["DATABASE_URL"]

with psycopg.connect(database_url, sslmode="require") as conn:
    with conn.cursor() as cur:
        cur.execute("SELECT 1")`,
    },
  },

  // 12. Exposed Environment Variables
  {
    id: "exposed-environment-variables",
    name: "Exposed Environment Variables",
    ruleIds: [
      "SENTINEL-ENV-001",
      "SENTINEL-CFG-002",
      "ENV-001",
      "EXPOSED-ENV",
    ],
    keywords: [
      "exposed environment",
      "exposed env",
      "environment variable",
      "next_public_",
      "vite_",
      "react_app_",
      ".env",
      "dotenv",
      "process.env",
      "client bundle",
      "leaked env",
      "cwe-200",
      "cwe-489",
    ],
    category: "secrets",
    defaultSeverity: "high",
    defaultCweId: "CWE-200",
    defaultOwaspCategory: "A05:2021 - Security Misconfiguration",
    whatItIs:
      "Exposed Environment Variables happen when sensitive server secrets are accidentally sent to the browser (for example, prefixing a secret with `NEXT_PUBLIC_` or `VITE_`), logged to the console, or committed in a `.env` file.",
    whyItHappens:
      "Frontend frameworks like Next.js and Vite only expose variables with special prefixes (`NEXT_PUBLIC_`, `VITE_`) to browser code. Beginners often add that prefix to fix an `undefined` error without realizing it embeds the secret into every visitor's browser.",
    howHackersExploitIt:
      "1. An attacker opens your website in Chrome and inspects the downloaded JavaScript bundle in DevTools—or checks a publicly committed `.env` file. 2. They search for keys, tokens, or database URLs baked into the bundle. 3. They extract the secret and use it directly against your backend or third-party APIs.",
    realWorldAnalogy:
      "It is like printing the restaurant's safe combination on the back of every customer menu because the manager wanted it easy to reference.",
    impact:
      "Silent leakage of admin keys, database credentials, or paid API tokens to every single visitor of your website, leading to account abuse and data breaches.",
    bestPractice:
      "Never prefix private secrets with `NEXT_PUBLIC_`, `VITE_`, or `REACT_APP_`. Keep secrets strictly inside server-side routes/Server Actions, add `.env*` (except `.env.example`) to `.gitignore`, and never dump `process.env` into logs or API responses.",
    secureVersion: `// Secure: Keep secrets server-only (NO NEXT_PUBLIC_ prefix)
// File: app/api/ai/route.ts (runs strictly on the server)
import { NextResponse } from "next/server";

export async function POST() {
  // Safe: Only accessible on the server, never shipped to the browser bundle
  const secretKey = process.env.SERVICE_API_KEY;
  if (!secretKey) {
    return NextResponse.json(
      { error: "Server configuration missing" },
      { status: 500 }
    );
  }

  // Only return safe, non-sensitive data to the browser
  return NextResponse.json({ status: "ok" });
}`,
  },
];

/**
 * Category-based fallback templates so any future or custom Sentinel AI rule
 * automatically receives a helpful, beginner-friendly explanation even before
 * a dedicated template is authored.
 */
export const CATEGORY_FALLBACK_TEMPLATES: Record<string, ExplanationTemplate> = {
  injection: {
    id: "fallback-injection",
    name: "Injection Vulnerability",
    ruleIds: [],
    keywords: ["injection"],
    category: "injection",
    defaultSeverity: "high",
    defaultCweId: "CWE-74",
    defaultOwaspCategory: "A03:2021 - Injection",
    isFallback: true,
    whatItIs:
      "An injection vulnerability happens when untrusted user input is mixed directly into a command, query, or expression so the computer mistakes user data for executable instructions.",
    whyItHappens:
      "Concatenating strings with user input is the quickest way to write a prototype, and AI code generators often skip input validation or parameterized APIs unless explicitly asked.",
    howHackersExploitIt:
      "1. The attacker finds an input field that reaches a backend query or interpreter. 2. They enter special syntax characters that break out of the data context. 3. The backend executes their injected instructions, exposing data or running unauthorized actions.",
    realWorldAnalogy:
      "It is like a chef blindly following any extra cooking instructions a customer scribbles onto the back of their order slip.",
    impact:
      "Unauthorized data exposure, tampered records, authentication bypass, or full server compromise depending on the targeted interpreter.",
    bestPractice:
      "Keep code and data strictly separated using parameterized APIs, validate and sanitize all inputs with a schema library like Zod, and reject unexpected characters or types.",
    secureVersion: `// Secure: Validate input strictly and use parameterized APIs
import { z } from "zod";

const inputSchema = z.object({
  identifier: z.string().trim().regex(/^[a-zA-Z0-9_-]{1,64}$/),
});

export function handleRequest(rawBody: unknown) {
  const { identifier } = inputSchema.parse(rawBody);
  // Pass \`identifier\` as a bound parameter, never concatenated into a command
  return identifier;
}`,
  },

  ssrf: {
    id: "fallback-ssrf",
    name: "Server-Side Request Forgery (SSRF)",
    ruleIds: ["SENTINEL-SSRF-001"],
    keywords: ["ssrf", "server-side request forgery", "cwe-918"],
    category: "ssrf",
    defaultSeverity: "high",
    defaultCweId: "CWE-918",
    defaultOwaspCategory: "A10:2021 - Server-Side Request Forgery",
    isFallback: true,
    whatItIs:
      "Server-Side Request Forgery (SSRF) happens when your server makes an HTTP request to a URL supplied by a user without checking whether that destination is safe.",
    whyItHappens:
      "Features like webhook testers, URL previews, or image fetchers pass user-provided URLs straight into `fetch()` or `axios.get()` without validating the host.",
    howHackersExploitIt:
      "1. An attacker submits an internal address like `http://169.254.169.254/latest/meta-data/` or `http://localhost:8080/admin`. 2. Because the request comes from *your* server inside your private network, firewalls let it through. 3. The server fetches internal secrets or cloud credentials and returns them to the attacker.",
    realWorldAnalogy:
      "It is like tricking a bank employee inside the secure vault into walking over to a restricted desk and reading confidential files aloud over the phone.",
    impact:
      "Theft of cloud IAM credentials, unauthorized access to internal microservices and databases, and internal network scanning.",
    bestPractice:
      "Validate user-supplied URLs with the `URL` parser, allow only `https:`, enforce a strict allowlist of trusted hostnames, and block loopback and private IP ranges.",
    secureVersion: `// Secure: Restrict outbound server requests to an explicit HTTPS allowlist
const ALLOWED_HOSTS = new Set(["api.github.com", "hooks.slack.com"]);

export async function safeServerFetch(rawUrl: string) {
  const parsed = new URL(rawUrl);
  if (parsed.protocol !== "https:" || !ALLOWED_HOSTS.has(parsed.hostname)) {
    throw new Error("Blocked: destination host is not on the allowlist");
  }
  return fetch(parsed.toString());
}`,
  },

  "path-traversal": {
    id: "fallback-path-traversal",
    name: "Path Traversal",
    ruleIds: [],
    keywords: ["path traversal", "directory traversal", "../", "lfi", "cwe-22"],
    category: "path-traversal",
    defaultSeverity: "high",
    defaultCweId: "CWE-22",
    defaultOwaspCategory: "A01:2021 - Broken Access Control",
    isFallback: true,
    whatItIs:
      "Path Traversal happens when user input is used to build a file path on your server, allowing someone to sneak `../` sequences to escape the intended folder and read or overwrite private files.",
    whyItHappens:
      "Joining a base folder with a filename from a query parameter (`path.join('./uploads', req.query.file)`) looks safe at a glance, but `../` climbs right out of the `uploads` directory.",
    howHackersExploitIt:
      "1. An attacker changes a download parameter from `invoice.pdf` to `../../.env` or `../../../../etc/passwd`. 2. The server resolves the path outside the uploads folder. 3. Your app reads and sends back sensitive server configuration files.",
    realWorldAnalogy:
      "It is like asking a librarian for 'the book two hallways back inside the locked staff office' and having them hand it over without checking.",
    impact:
      "Leakage of `.env` secrets, source code, SSH keys, or overwriting critical system files on the server.",
    bestPractice:
      "Strip directory paths with `path.basename()`, resolve the canonical full path with `path.resolve()`, and verify it still starts with your safe base directory.",
    secureVersion: `// Secure: Strip directory segments and verify the resolved path stays inside BASE_DIR
import fs from "node:fs/promises";
import path from "node:path";

const BASE_DIR = path.resolve(process.cwd(), "uploads");

export async function readSafeFile(userFileName: string): Promise<string> {
  const safeName = path.basename(userFileName);
  const fullPath = path.resolve(BASE_DIR, safeName);

  if (!fullPath.startsWith(\`\${BASE_DIR}\${path.sep}\`)) {
    throw new Error("Invalid file path");
  }

  return fs.readFile(fullPath, "utf8");
}`,
  },

  cryptography: {
    id: "fallback-cryptography",
    name: "Weak Cryptography",
    ruleIds: [],
    keywords: ["cryptography", "weak cipher", "weak hash", "encryption"],
    category: "cryptography",
    defaultSeverity: "high",
    defaultCweId: "CWE-327",
    defaultOwaspCategory: "A02:2021 - Cryptographic Failures",
    isFallback: true,
    whatItIs:
      "Weak Cryptography means your code uses an outdated, broken, or predictable encryption or hashing method that modern computers can break easily.",
    whyItHappens:
      "Older algorithms like MD5, SHA-1, DES, or `Math.random()` still appear in legacy docs and AI completions even though security standards retired them years ago.",
    howHackersExploitIt:
      "1. Attackers intercept encrypted data or obtain hashed values. 2. Using modern GPUs or known mathematical weaknesses in the outdated algorithm, they reverse or forge the protected values. 3. Sensitive data or tokens are exposed.",
    realWorldAnalogy:
      "It is like writing secret messages using a simple A=1, B=2 kids' decoder ring instead of a real lockbox.",
    impact:
      "Decrypted customer data, cracked passwords, forged tokens, and compliance failures.",
    bestPractice:
      "Use modern, standard cryptographic primitives: AES-256-GCM for encryption, SHA-256/SHA-3 for digests, Argon2id/scrypt for passwords, and `crypto.randomBytes()` for random tokens.",
    secureVersion: `// Secure: Use Node's built-in crypto module with modern primitives
import { createHash, randomBytes } from "node:crypto";

export function createSecureToken(): string {
  return randomBytes(32).toString("base64url");
}

export function sha256Digest(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}`,
  },

  deserialization: {
    id: "fallback-deserialization",
    name: "Insecure Deserialization",
    ruleIds: [],
    keywords: ["deserialization", "pickle", "unserialize", "yaml.load", "cwe-502"],
    category: "deserialization",
    defaultSeverity: "high",
    defaultCweId: "CWE-502",
    defaultOwaspCategory: "A08:2021 - Software and Data Integrity Failures",
    isFallback: true,
    whatItIs:
      "Insecure Deserialization happens when your app converts untrusted raw bytes or serialized objects (like Python `pickle` or unsafe YAML) back into live code objects, which can accidentally trigger hidden code execution.",
    whyItHappens:
      "Serialization libraries make saving and restoring complex objects effortless, so developers sometimes use them on cookies, cache entries, or API inputs from untrusted users.",
    howHackersExploitIt:
      "1. An attacker crafts a malicious serialized payload that includes instructions to run a system command when unpacked. 2. They send it to your server in a cookie or request body. 3. The moment your app deserializes it, the attacker's code executes.",
    realWorldAnalogy:
      "It is like opening a flat-pack box from a stranger that automatically assembles itself into a lock-picking robot the second you cut the tape.",
    impact:
      "Remote Code Execution (RCE), privilege escalation, or denial of service.",
    bestPractice:
      "Never deserialize untrusted data with `pickle`, `yaml.load()`, or native object serializers. Use plain JSON (`JSON.parse` / `json.loads`) and validate the parsed shape with a strict schema.",
    secureVersion: `// Secure: Use JSON.parse() paired with strict schema validation
import { z } from "zod";

const payloadSchema = z.object({
  userId: z.string().uuid(),
  theme: z.enum(["light", "dark"]),
});

export function parseUserPreferences(rawJson: string) {
  const parsed: unknown = JSON.parse(rawJson);
  return payloadSchema.parse(parsed);
}`,
  },

  misconfiguration: {
    id: "fallback-misconfiguration",
    name: "Security Misconfiguration",
    ruleIds: [],
    keywords: ["misconfiguration", "cors", "debug mode", "default config"],
    category: "misconfiguration",
    defaultSeverity: "medium",
    defaultCweId: "CWE-16",
    defaultOwaspCategory: "A05:2021 - Security Misconfiguration",
    isFallback: true,
    whatItIs:
      "A Security Misconfiguration means a setting in your server, framework, headers, or cloud service is left too permissive—like allowing any website via wildcard CORS or leaving debug mode turned on in production.",
    whyItHappens:
      "Loose settings (like `Access-Control-Allow-Origin: *`) make local development easier and silence errors quickly, so they often slip into production deployments.",
    howHackersExploitIt:
      "1. Attackers probe your headers, error pages, and endpoints for permissive settings. 2. They abuse overly broad CORS rules, exposed stack traces, or default accounts to gather internals or make unauthorized cross-origin requests.",
    realWorldAnalogy:
      "It is like installing a high-tech alarm system in your store but leaving it switched to 'Demo Mode' with the default factory passcode.",
    impact:
      "Information leakage, cross-origin data theft, and easier exploitation of other flaws in your application.",
    bestPractice:
      "Follow least-privilege defaults: restrict CORS to explicit trusted origins, disable verbose stack traces in production, keep TLS verification enabled, and review configuration checklists before deploying.",
    secureVersion: `// Secure: Allow only explicitly trusted frontend origins in CORS
const ALLOWED_ORIGINS = new Set(["https://app.example.com"]);

export function applyCorsHeaders(requestOrigin: string | null, headers: Headers) {
  if (requestOrigin && ALLOWED_ORIGINS.has(requestOrigin)) {
    headers.set("Access-Control-Allow-Origin", requestOrigin);
    headers.set("Vary", "Origin");
  }
}`,
  },
};

/**
 * Generic fallback template used when a vulnerability does not match any
 * specific rule, keyword, or category template.
 */
export const GENERIC_FALLBACK_TEMPLATE: ExplanationTemplate = {
  id: "generic-security-vulnerability",
  name: "Security Vulnerability",
  ruleIds: [],
  keywords: [],
  category: "other",
  defaultSeverity: "medium",
  defaultOwaspCategory: "OWASP Top 10 Security Risk",
  isFallback: true,
  whatItIs:
    "Sentinel AI flagged a coding pattern that can weaken your application's defenses or allow untrusted input to behave in unexpected, unsafe ways.",
  whyItHappens:
    "When moving fast or accepting AI-generated code, it is easy to overlook edge cases like untrusted user input, missing permission checks, or unsafe default settings.",
  howHackersExploitIt:
    "1. Attackers probe your application with unexpected inputs or direct API calls that bypass normal UI flows. 2. They exploit the weak spot to read private data, alter behavior, or escalate privileges.",
  realWorldAnalogy:
    "It is like leaving a side window unlocked on an otherwise secure building—most visitors use the front door, but a burglar specifically checks every side window.",
  impact:
    "Depending on where this code runs, exploiting it could lead to data exposure, broken access controls, service disruption, or compromised user accounts.",
  bestPractice:
    "Validate all external inputs with a strict schema (like Zod), enforce authentication and authorization on the server, keep secrets in environment variables, and follow the principle of least privilege.",
  secureVersion: `// Secure pattern: Validate untrusted input at the boundary before using it
import { z } from "zod";

const requestSchema = z.object({
  action: z.enum(["read", "list"]),
  targetId: z.string().uuid(),
});

export function processSafeRequest(rawInput: unknown) {
  // Reject malformed or unexpected payloads immediately
  const validated = requestSchema.parse(rawInput);
  return validated;
}`,
};
