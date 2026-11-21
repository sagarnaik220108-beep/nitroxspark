import {
  SIMULATION_DISCLAIMER,
  type AttackScenario,
  type BeforeAfterSimulationResult,
  type SimulationCodeContext,
} from "@/types/simulation.types";

const DEFAULT_ENDPOINT = "/api/account/profile";

/**
 * Simulated Before-vs-After Broken Authentication scenario.
 * Demonstrates unverified JWT decoding (`jwt.decode` / `alg: none` / weak secret)
 * vs. cryptographic signature verification with explicit algorithm allowlists and server-side session checks.
 */
export const brokenAuthenticationScenario: AttackScenario = {
  attackType: "broken-authentication",
  attackName: "Broken Authentication (JWT Signature Bypass & Token Forgery)",
  description:
    "Simulates forging an unsigned or tampered JWT token against an endpoint that decodes claims without cryptographic verification, compared against strict signature verification and server-validated sessions.",
  severity: "critical",
  cweId: "CWE-287",
  owaspCategory: "A07:2021 - Identification and Authentication Failures",
  mitreAttackTechnique: "T1550.001 - Use Alternate Authentication Material: Application Access Token",
  tags: ["authentication", "jwt", "session", "token-forgery", "owasp-a07"],

  simulate(codeContext?: SimulationCodeContext): BeforeAfterSimulationResult {
    const targetEndpoint =
      codeContext?.endpoint?.trim() || DEFAULT_ENDPOINT;
    const contextNote = codeContext?.fileName
      ? ` (${codeContext.fileName})`
      : "";

    const attackPayload =
      "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1c3JfYWRtaW4iLCJlbWFpbCI6ImFkbWluQGRlbW8uaW52YWxpZCIsInNpbXVsYXRlZCI6dHJ1ZX0.";

    return {
      attackType: this.attackType,
      attackName: this.attackName,
      description: this.description,
      severity: this.severity,
      cweId: this.cweId,
      owaspCategory: this.owaspCategory,
      mitreAttackTechnique: this.mitreAttackTechnique,
      attackPayload,
      beforeResult: {
        status: "compromised",
        httpStatus: 200,
        responsePreview: JSON.stringify(
          {
            endpoint: targetEndpoint,
            tokenVerification: "SKIPPED (jwt.decode used without signature check)",
            acceptedClaims: {
              sub: "usr_admin",
              email: "admin@demo.invalid",
              alg: "none",
            },
            accountAccess: "GRANTED — Full impersonation of target account",
          },
          null,
          2
        ),
        impactSummary: `The authentication middleware decoded JWT claims without verifying the cryptographic signature or enforcing an algorithm allowlist${contextNote}. The attacker forged an arbitrary identity and hijacked the victim's account.`,
        compromisedAssets: [
          "Target user account and private profile data",
          "Authentication boundary integrity across all user accounts",
          "Audit attribution (actions logged under forged identity)",
        ],
      },
      afterResult: {
        status: "blocked",
        httpStatus: 401,
        responsePreview: JSON.stringify(
          {
            success: false,
            error: {
              code: "UNAUTHORIZED",
              message:
                "Invalid or unverified authentication token (alg 'none' rejected).",
            },
            verificationPolicy: "RS256/HS256 allowlist + server-side session lookup",
          },
          null,
          2
        ),
        defenseMechanism:
          "Cryptographic Signature Verification (jwt.verify / auth.getUser) + Explicit Algorithm Allowlist + Short-Lived HttpOnly Sessions",
        mitigationSummary:
          "Enforcing strict cryptographic verification with an explicit algorithm allowlist and server-side session validation immediately rejected the unsigned token with HTTP 401 Unauthorized.",
      },
      success: true,
      blocked: true,
      animationData: {
        durationMs: 4200,
        nodes: [
          { id: "attacker", label: "Simulated Attacker", type: "attacker" },
          { id: "auth", label: "Auth Middleware", type: "auth" },
          { id: "app", label: "Protected Account API", type: "app" },
          { id: "database", label: "User Account Store", type: "database" },
        ],
        beforeFrames: [
          {
            step: 1,
            timestampMs: 0,
            from: "attacker",
            to: "auth",
            label: `Send forged alg:none JWT to ${targetEndpoint}`,
            status: "info",
          },
          {
            step: 2,
            timestampMs: 1100,
            from: "auth",
            to: "app",
            label: "jwt.decode() parses payload without verifying signature",
            status: "warning",
          },
          {
            step: 3,
            timestampMs: 2400,
            from: "app",
            to: "database",
            label: "Fetch private records for forged subject usr_admin",
            status: "breach",
          },
          {
            step: 4,
            timestampMs: 3600,
            from: "app",
            to: "attacker",
            label: "HTTP 200 OK — Full account takeover via forged token",
            status: "breach",
          },
        ],
        afterFrames: [
          {
            step: 1,
            timestampMs: 0,
            from: "attacker",
            to: "auth",
            label: `Send forged alg:none JWT to ${targetEndpoint}`,
            status: "info",
          },
          {
            step: 2,
            timestampMs: 1100,
            from: "auth",
            to: "auth",
            label: "Signature verifier rejects disallowed alg:none and missing MAC",
            status: "blocked",
          },
          {
            step: 3,
            timestampMs: 2400,
            from: "auth",
            to: "attacker",
            label: "HTTP 401 Unauthorized — Request terminated before reaching API",
            status: "blocked",
          },
          {
            step: 4,
            timestampMs: 3600,
            from: "database",
            to: "app",
            label: "User account store untouched; invalid token alert recorded",
            status: "safe",
          },
        ],
      },
      disclaimer: SIMULATION_DISCLAIMER,
    };
  },
};
