import type {
  AttackSimulationResult,
  AttackStep,
  DetectedVulnerability,
  VulnerabilityCategory,
} from "@/types";

const EDUCATIONAL_DISCLAIMER =
  "DEFENSIVE SIMULATION ONLY: This attack scenario is generated strictly for authorized security assessment, threat modeling, and defensive validation of your own code.";

interface SimulationTemplate {
  attackName: string;
  mitreAttackTechnique: string;
  likelihood: "low" | "medium" | "high";
  simulatedPayload: string;
  entryPoint: string;
  blastRadius: "isolated" | "service" | "data-tier" | "organization";
  potentialImpact: string[];
  detectionSignatures: string[];
  defensiveControls: string[];
  buildKillChain: (vuln: DetectedVulnerability) => AttackStep[];
}

const CATEGORY_TEMPLATES: Record<VulnerabilityCategory, SimulationTemplate> = {
  injection: {
    attackName: "Structured Query / Command Injection Exploit Chain",
    mitreAttackTechnique: "T1190 - Exploit Public-Facing Application",
    likelihood: "high",
    simulatedPayload: "' OR '1'='1' -- /* defensive test marker */",
    entryPoint: "Untrusted HTTP parameter / request body flowing into interpreter sink",
    blastRadius: "data-tier",
    potentialImpact: [
      "Unauthorized read/write access to sensitive database records",
      "Authentication bypass and privilege escalation",
      "Potential Remote Code Execution (RCE) on host runtime",
    ],
    detectionSignatures: [
      "WAF anomaly alert for SQL/shell metacharacters (`'`, `;`, `&&`, `UNION SELECT`)",
      "Database query error spike (syntax errors or unexpected row counts)",
      "Unexpected child shell processes spawned by Node/Python worker",
    ],
    defensiveControls: [
      "Parameterized queries / prepared statements",
      "Strict Zod input schema validation at API boundaries",
      "Least-privilege database roles and Supabase Row-Level Security (RLS)",
    ],
    buildKillChain: (vuln) => [
      {
        stepNumber: 1,
        phase: "reconnaissance",
        title: "Identify Dynamic Sink",
        description: `Attacker probes endpoint invoking vulnerable pattern at line ${vuln.location.line}.`,
        technicalDetail: `Rule ${vuln.ruleId} (${vuln.cweId}) indicates unparameterized data interpolation.`,
      },
      {
        stepNumber: 2,
        phase: "weaponization",
        title: "Craft Syntax-Breaking Payload",
        description:
          "Attacker crafts input containing delimiter characters to break out of the data context into executable syntax.",
        technicalDetail:
          "Payload escapes literal quotes or shell token boundaries to append attacker-controlled logic.",
      },
      {
        stepNumber: 3,
        phase: "delivery",
        title: "Submit Malicious Request",
        description:
          "Payload is sent via query string, JSON body, or HTTP header to the exposed route.",
        technicalDetail:
          "Input bypasses missing schema validation and reaches the backend execution layer.",
      },
      {
        stepNumber: 4,
        phase: "exploitation",
        title: "Interpreter Evaluates Injected Logic",
        description:
          "The database or OS shell interprets the injected tokens as trusted instructions.",
        technicalDetail: `Observed vulnerable expression: ${vuln.matchedText.slice(0, 120)}`,
      },
      {
        stepNumber: 5,
        phase: "impact",
        title: "Data Exfiltration or Host Compromise",
        description:
          "Attacker extracts sensitive records, bypasses auth checks, or executes arbitrary commands.",
        technicalDetail: "Blast radius extends across the data tier or application host.",
      },
    ],
  },

  xss: {
    attackName: "Client-Side Script Injection & Session Hijacking",
    mitreAttackTechnique: "T1189 / T1059.007 - JavaScript Execution in Victim Browser",
    likelihood: "high",
    simulatedPayload: "<img src=x onerror=\"console.warn('XSS_SIMULATION_MARKER')\">",
    entryPoint: "Unsanitized user content rendered into raw HTML sink",
    blastRadius: "service",
    potentialImpact: [
      "Arbitrary JavaScript execution in authenticated users' browsers",
      "Theft of non-HttpOnly tokens, CSRF bypass, and account takeover",
      "UI redressing and credential harvesting overlays",
    ],
    detectionSignatures: [
      "Content-Security-Policy (CSP) violation reports (`script-src` blocked)",
      "Unexpected DOM mutations or outbound beacons to unknown origins",
    ],
    defensiveControls: [
      "Render untrusted values as escaped text (JSX / textContent)",
      "Sanitize unavoidable HTML with DOMPurify",
      "Enforce strict CSP with nonces and `HttpOnly` session cookies",
    ],
    buildKillChain: (vuln) => [
      {
        stepNumber: 1,
        phase: "reconnaissance",
        title: "Locate Raw HTML Sink",
        description: `Attacker discovers user-controlled data reaching HTML sink at line ${vuln.location.line}.`,
        technicalDetail: `Triggered rule ${vuln.ruleId} (${vuln.cweId}).`,
      },
      {
        stepNumber: 2,
        phase: "weaponization",
        title: "Build Event-Handler Payload",
        description: "Attacker crafts an HTML fragment with an inline event handler.",
        technicalDetail: "Bypasses naive `<script>` tag filters using `onerror` or `onload` attributes.",
      },
      {
        stepNumber: 3,
        phase: "delivery",
        title: "Store or Reflect Payload",
        description: "Payload is persisted in a database field or embedded in a crafted link.",
        technicalDetail: "Victim browser loads the affected page containing the unsanitized markup.",
      },
      {
        stepNumber: 4,
        phase: "exploitation",
        title: "Browser Executes Injected Script",
        description: "DOM parser executes attacker JavaScript within the trusted application origin.",
        technicalDetail: `Sink expression: ${vuln.matchedText.slice(0, 120)}`,
      },
      {
        stepNumber: 5,
        phase: "impact",
        title: "Authenticated Action Abuse",
        description: "Script invokes privileged API routes using the victim's active session.",
        technicalDetail: "Leads to unauthorized data access or account compromise.",
      },
    ],
  },

  secrets: {
    attackName: "Credential Harvesting & Cloud/API Account Takeover",
    mitreAttackTechnique: "T1552.001 - Unsecured Credentials: Credentials In Files",
    likelihood: "high",
    simulatedPayload: "git log -p | grep -E '(AKIA|sk-|PRIVATE KEY)'",
    entryPoint: "Source code repository, client bundle, or CI/CD build artifact",
    blastRadius: "organization",
    potentialImpact: [
      "Unauthorized access to cloud infrastructure, databases, or third-party APIs",
      "Financial abuse (crypto mining, runaway LLM/cloud billing)",
      "Lateral movement into production environments",
    ],
    detectionSignatures: [
      "Secret-scanning alerts in Git pre-commit hooks or GitHub Push Protection",
      "Anomalous API usage from unrecognized IP ranges or geolocations",
    ],
    defensiveControls: [
      "Store secrets exclusively in Vercel Environment Variables / secret manager",
      "Rotate exposed credentials immediately and audit access logs",
      "Enable automated secret scanning in CI/CD",
    ],
    buildKillChain: (vuln) => [
      {
        stepNumber: 1,
        phase: "reconnaissance",
        title: "Automated Secret Scanning",
        description: `Automated bots scan repositories or JS bundles and detect credential pattern at line ${vuln.location.line}.`,
        technicalDetail: `Rule ${vuln.ruleId} (${vuln.cweId}) matched high-entropy secret literal.`,
      },
      {
        stepNumber: 2,
        phase: "delivery",
        title: "Credential Extraction",
        description: "Attacker extracts the hardcoded credential from source or compiled assets.",
        technicalDetail: "Even if later deleted in a new commit, the secret remains in Git history.",
      },
      {
        stepNumber: 3,
        phase: "exploitation",
        title: "Direct API / Infrastructure Authentication",
        description: "Attacker authenticates directly against the target provider using the stolen key.",
        technicalDetail: "Bypasses application-level authentication and rate limits completely.",
      },
      {
        stepNumber: 4,
        phase: "impact",
        title: "Account Compromise & Data Exfiltration",
        description: "Attacker reads production data, provisions resources, or pivots laterally.",
        technicalDetail: "Requires immediate key revocation and forensic log review.",
      },
    ],
  },

  authentication: {
    attackName: "Authentication Bypass & Token Forgery",
    mitreAttackTechnique: "T1550 - Use Alternate Authentication Material",
    likelihood: "high",
    simulatedPayload: "{\"alg\":\"none\",\"typ\":\"JWT\"}.{\"sub\":\"admin\",\"role\":\"admin\"}.",
    entryPoint: "Authorization header / session cookie verification handler",
    blastRadius: "service",
    potentialImpact: [
      "Forging arbitrary user or administrator identities",
      "Session hijacking across tenant boundaries",
      "Full bypass of application access controls",
    ],
    detectionSignatures: [
      "JWT verification failure spikes or unexpected `alg: none` tokens in gateway logs",
      "Privilege escalation anomalies in audit logs",
    ],
    defensiveControls: [
      "Use Supabase `auth.getUser()` or `jwt.verify()` with explicit algorithm allowlists",
      "Enforce `HttpOnly`, `Secure`, and `SameSite` cookie attributes",
      "Enforce PostgreSQL Row-Level Security (RLS) as defense-in-depth",
    ],
    buildKillChain: (vuln) => [
      {
        stepNumber: 1,
        phase: "reconnaissance",
        title: "Inspect Token / Session Handling",
        description: `Attacker observes weak token or cookie validation at line ${vuln.location.line}.`,
        technicalDetail: `Rule ${vuln.ruleId} (${vuln.cweId}).`,
      },
      {
        stepNumber: 2,
        phase: "weaponization",
        title: "Forge Modified Claims",
        description: "Attacker modifies token payload claims (e.g., `role: admin`) without knowing the signing key.",
        technicalDetail: "Unverified decode or weak algorithm accepts unsigned or tampered claims.",
      },
      {
        stepNumber: 3,
        phase: "exploitation",
        title: "Impersonate Privileged User",
        description: "Attacker sends forged token to protected endpoints.",
        technicalDetail: "Backend trusts unverified claims and grants unauthorized access.",
      },
      {
        stepNumber: 4,
        phase: "impact",
        title: "Account Takeover",
        description: "Attacker accesses or modifies protected resources belonging to other users.",
        technicalDetail: "Compromises confidentiality and integrity across user accounts.",
      },
    ],
  },

  authorization: {
    attackName: "Access Control & Open Redirect Abuse",
    mitreAttackTechnique: "T1566.002 - Phishing / Authorization Bypass",
    likelihood: "medium",
    simulatedPayload: "?next=https://attacker-phishing.example/login",
    entryPoint: "Redirect or resource identifier parameter",
    blastRadius: "service",
    potentialImpact: [
      "Credential phishing leveraging trusted application domain",
      "Unauthorized access to restricted resources",
    ],
    detectionSignatures: [
      "3xx redirects pointing to external non-allowlisted hostnames",
      "403/404 probing patterns against sequential resource IDs",
    ],
    defensiveControls: [
      "Restrict redirects to relative same-origin paths",
      "Enforce server-side ownership checks and RLS on every query",
    ],
    buildKillChain: (vuln) => [
      {
        stepNumber: 1,
        phase: "weaponization",
        title: "Craft Trusted-Domain Redirect Link",
        description: `Attacker supplies an external URL to the redirect sink at line ${vuln.location.line}.`,
        technicalDetail: `Rule ${vuln.ruleId} (${vuln.cweId}).`,
      },
      {
        stepNumber: 2,
        phase: "delivery",
        title: "Distribute Link to Victim",
        description: "Victim clicks link appearing to originate from the trusted domain.",
        technicalDetail: "Application issues a 302 redirect directly to the attacker site.",
      },
      {
        stepNumber: 3,
        phase: "impact",
        title: "Credential Harvesting",
        description: "Victim enters credentials on spoofed login page.",
        technicalDetail: "Leads to user account compromise.",
      },
    ],
  },

  ssrf: {
    attackName: "Internal Network Pivoting & Cloud Metadata Exfiltration",
    mitreAttackTechnique: "T1552.005 - Cloud Instance Metadata API",
    likelihood: "high",
    simulatedPayload: "http://169.254.169.254/latest/meta-data/ (blocked defensive test URI)",
    entryPoint: "Server-side fetch/HTTP client accepting user-supplied URL",
    blastRadius: "organization",
    potentialImpact: [
      "Access to cloud instance metadata credentials (IAM roles)",
      "Port scanning and exploitation of internal microservices",
      "Bypassing firewall/VPC perimeter controls",
    ],
    detectionSignatures: [
      "Outbound egress requests to link-local (169.254.0.0/16) or RFC1918 addresses",
      "Unexpected DNS lookups for internal service hostnames",
    ],
    defensiveControls: [
      "Enforce strict HTTPS hostname allowlist",
      "Resolve DNS and block private/loopback/link-local IP ranges before connecting",
      "Disable HTTP redirects on untrusted outbound fetches",
    ],
    buildKillChain: (vuln) => [
      {
        stepNumber: 1,
        phase: "reconnaissance",
        title: "Identify URL Fetch Endpoint",
        description: `Attacker finds server-side HTTP request driven by user input at line ${vuln.location.line}.`,
        technicalDetail: `Rule ${vuln.ruleId} (${vuln.cweId}).`,
      },
      {
        stepNumber: 2,
        phase: "delivery",
        title: "Supply Internal Target URI",
        description: "Attacker submits internal IP or cloud metadata endpoint.",
        technicalDetail: "Server initiates request from inside the trusted network perimeter.",
      },
      {
        stepNumber: 3,
        phase: "exploitation",
        title: "Retrieve Internal Response",
        description: "Server returns or leaks internal service data to the attacker.",
        technicalDetail: "Exposes internal APIs or temporary cloud credentials.",
      },
      {
        stepNumber: 4,
        phase: "impact",
        title: "Cloud Environment Pivot",
        description: "Attacker uses leaked internal credentials to escalate cloud privileges.",
        technicalDetail: "Potential organization-wide blast radius.",
      },
    ],
  },

  "path-traversal": {
    attackName: "Arbitrary File Read / Write via Directory Traversal",
    mitreAttackTechnique: "T1083 - File and Directory Discovery",
    likelihood: "high",
    simulatedPayload: "../../../../etc/passwd",
    entryPoint: "File name or path parameter passed to filesystem API",
    blastRadius: "service",
    potentialImpact: [
      "Disclosure of `.env` secrets, SSH keys, and application source code",
      "Arbitrary file overwrite leading to Remote Code Execution",
    ],
    detectionSignatures: [
      "HTTP requests containing `../`, `..\\`, or URL-encoded `%2e%2e%2f` sequences",
      "Filesystem access errors outside designated upload/storage directories",
    ],
    defensiveControls: [
      "Use `path.basename()` and verify canonical `path.resolve()` starts with `baseDir`",
      "Store user files in object storage (Supabase Storage / S3) keyed by UUID instead of local disk",
    ],
    buildKillChain: (vuln) => [
      {
        stepNumber: 1,
        phase: "reconnaissance",
        title: "Detect File Parameter",
        description: `Attacker identifies filesystem operation using untrusted path at line ${vuln.location.line}.`,
        technicalDetail: `Rule ${vuln.ruleId} (${vuln.cweId}).`,
      },
      {
        stepNumber: 2,
        phase: "delivery",
        title: "Inject Parent Directory Segments",
        description: "Attacker supplies `../` traversal sequences to escape the intended folder.",
        technicalDetail: "Unvalidated `path.join` resolves outside the storage root.",
      },
      {
        stepNumber: 3,
        phase: "impact",
        title: "Sensitive File Disclosure",
        description: "Application returns contents of configuration or system files.",
        technicalDetail: "Exposes secrets and server internals.",
      },
    ],
  },

  cryptography: {
    attackName: "Cryptographic Weakness Exploitation",
    mitreAttackTechnique: "T1110.002 - Password Cracking / Token Prediction",
    likelihood: "medium",
    simulatedPayload: "Offline GPU hash cracking / PRNG state recovery",
    entryPoint: "Weak hash function or predictable PRNG token generator",
    blastRadius: "data-tier",
    potentialImpact: [
      "Rapid offline cracking of leaked password hashes",
      "Prediction of password reset tokens or session identifiers",
    ],
    detectionSignatures: [
      "High-volume password reset or token brute-force attempts",
      "Static analysis flags for MD5, SHA-1, or Math.random() in security flows",
    ],
    defensiveControls: [
      "Migrate password hashes to Argon2id or scrypt",
      "Use `crypto.randomBytes()` / `crypto.randomUUID()` for all security tokens",
    ],
    buildKillChain: (vuln) => [
      {
        stepNumber: 1,
        phase: "reconnaissance",
        title: "Identify Weak Primitive",
        description: `Weak cryptographic primitive detected at line ${vuln.location.line}.`,
        technicalDetail: `Rule ${vuln.ruleId} (${vuln.cweId}).`,
      },
      {
        stepNumber: 2,
        phase: "exploitation",
        title: "Crack or Predict Secret Material",
        description: "Attacker recovers plaintext passwords or predicts future token values.",
        technicalDetail: "Modern hardware trivially breaks MD5/SHA-1 and non-CSPRNG outputs.",
      },
      {
        stepNumber: 3,
        phase: "impact",
        title: "Unauthorized Account Access",
        description: "Attacker logs into victim accounts or resets passwords.",
        technicalDetail: "Impacts all users protected by the weak primitive.",
      },
    ],
  },

  misconfiguration: {
    attackName: "Security Misconfiguration Exploitation (MitM / Cross-Origin Abuse)",
    mitreAttackTechnique: "T1557 - Adversary-in-the-Middle",
    likelihood: "medium",
    simulatedPayload: "Cross-origin credentialed fetch or MitM TLS interception",
    entryPoint: "Insecure TLS client option or permissive CORS policy",
    blastRadius: "service",
    potentialImpact: [
      "Interception and tampering of sensitive data in transit",
      "Cross-origin data exfiltration from authenticated user sessions",
    ],
    detectionSignatures: [
      "TLS certificate mismatch alerts",
      "Unexpected cross-origin API calls from untrusted Referer/Origin headers",
    ],
    defensiveControls: [
      "Keep TLS certificate verification enabled in all environments",
      "Restrict CORS origins to an explicit allowlist",
    ],
    buildKillChain: (vuln) => [
      {
        stepNumber: 1,
        phase: "reconnaissance",
        title: "Detect Weak Transport or Origin Policy",
        description: `Security misconfiguration found at line ${vuln.location.line}.`,
        technicalDetail: `Rule ${vuln.ruleId} (${vuln.cweId}).`,
      },
      {
        stepNumber: 2,
        phase: "exploitation",
        title: "Intercept Traffic or Issue Cross-Origin Request",
        description: "Attacker exploits disabled TLS validation or wildcard CORS.",
        technicalDetail: "Application accepts untrusted certificates or cross-origin credentialed calls.",
      },
      {
        stepNumber: 3,
        phase: "impact",
        title: "Data Interception / Leakage",
        description: "Sensitive payloads or session responses are exposed to the attacker.",
        technicalDetail: "Undermines confidentiality of API communication.",
      },
    ],
  },

  deserialization: {
    attackName: "Unsafe Deserialization Gadget Chain",
    mitreAttackTechnique: "T1190 - Exploit Public-Facing Application",
    likelihood: "medium",
    simulatedPayload: "Serialized object graph triggering side-effect constructor",
    entryPoint: "Untrusted serialized payload parser",
    blastRadius: "service",
    potentialImpact: ["Remote Code Execution or Denial of Service"],
    detectionSignatures: ["Unexpected runtime exceptions during payload deserialization"],
    defensiveControls: ["Use strict JSON parsing with Zod schema validation"],
    buildKillChain: (vuln) => [
      {
        stepNumber: 1,
        phase: "delivery",
        title: "Submit Crafted Serialized Payload",
        description: `Attacker sends crafted payload to parser at line ${vuln.location.line}.`,
        technicalDetail: `Rule ${vuln.ruleId} (${vuln.cweId}).`,
      },
      {
        stepNumber: 2,
        phase: "impact",
        title: "Arbitrary Behavior Execution",
        description: "Deserializer instantiates unintended objects or executes side effects.",
        technicalDetail: "Replace unsafe deserializers with schema-validated JSON.",
      },
    ],
  },

  other: {
    attackName: "Custom Security Rule Violation Scenario",
    mitreAttackTechnique: "T1190 - Exploit Public-Facing Application",
    likelihood: "medium",
    simulatedPayload: "Boundary-violating input targeting matched pattern",
    entryPoint: "Code path matching custom security policy",
    blastRadius: "isolated",
    potentialImpact: ["Violation of organizational security baseline"],
    detectionSignatures: ["Sentinel AI custom rule violation telemetry"],
    defensiveControls: ["Apply the remediation guidance defined for this rule"],
    buildKillChain: (vuln) => [
      {
        stepNumber: 1,
        phase: "reconnaissance",
        title: "Locate Policy Violation",
        description: `Matched pattern at line ${vuln.location.line}.`,
        technicalDetail: `Rule ${vuln.ruleId} (${vuln.cweId}).`,
      },
      {
        stepNumber: 2,
        phase: "impact",
        title: "Security Control Bypass",
        description: vuln.explanation,
        technicalDetail: "Follow the rule's remediation advice to close this gap.",
      },
    ],
  },
};

/**
 * Generates a safe, educational, defensive attack simulation for a detected vulnerability.
 */
export function simulateAttackForVulnerability(
  vulnerability: DetectedVulnerability,
  vulnerabilityId?: string
): AttackSimulationResult {
  const template =
    CATEGORY_TEMPLATES[vulnerability.category] ?? CATEGORY_TEMPLATES.other;

  return {
    ...(vulnerabilityId ? { vulnerabilityId } : {}),
    ruleId: vulnerability.ruleId,
    attackName: template.attackName,
    mitreAttackTechnique: template.mitreAttackTechnique,
    severity: vulnerability.severity,
    likelihood: template.likelihood,
    simulatedPayload: template.simulatedPayload,
    entryPoint: `${template.entryPoint} (Line ${vulnerability.location.line})`,
    killChain: template.buildKillChain(vulnerability),
    potentialImpact: template.potentialImpact,
    blastRadius: template.blastRadius,
    detectionSignatures: template.detectionSignatures,
    defensiveControls: template.defensiveControls,
    disclaimer: EDUCATIONAL_DISCLAIMER,
  };
}
