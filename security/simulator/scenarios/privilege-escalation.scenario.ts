import {
  SIMULATION_DISCLAIMER,
  type AttackScenario,
  type BeforeAfterSimulationResult,
  type SimulationCodeContext,
} from "@/types/simulation.types";

const DEFAULT_ENDPOINT = "/api/admin/users/usr_target/role";

/**
 * Simulated Before-vs-After Privilege Escalation scenario.
 * Demonstrates missing server-side RBAC / ownership enforcement and mass-assignment
 * of privileged fields (`role: "admin"`) vs. strict server-side RBAC + Zod field allowlists + RLS.
 */
export const privilegeEscalationScenario: AttackScenario = {
  attackType: "privilege-escalation",
  attackName: "Privilege Escalation (Broken Access Control / RBAC Bypass)",
  description:
    "Simulates a standard authenticated user tampering with a request payload or admin endpoint to elevate their role to administrator due to missing server-side authorization checks, compared against enforced RBAC, field allowlists, and Row-Level Security.",
  severity: "critical",
  cweId: "CWE-269",
  owaspCategory: "A01:2021 - Broken Access Control",
  mitreAttackTechnique: "T1068 - Exploitation for Privilege Escalation",
  tags: ["authorization", "rbac", "privilege-escalation", "idor", "owasp-a01"],

  simulate(codeContext?: SimulationCodeContext): BeforeAfterSimulationResult {
    const targetEndpoint =
      codeContext?.endpoint?.trim() || DEFAULT_ENDPOINT;
    const contextNote = codeContext?.fileName
      ? ` in ${codeContext.fileName}`
      : "";

    const attackPayload = JSON.stringify({
      actorRole: "viewer",
      method: "PATCH",
      endpoint: targetEndpoint,
      body: {
        role: "admin",
        permissions: ["billing:write", "users:delete"],
        simulatedMarker: "PRIV_ESC_DEMO",
      },
    });

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
            authenticatedAs: "usr_standard_42 (role: viewer)",
            authorizationCheck: "MISSING (authenticated session treated as admin)",
            updatedRecord: {
              id: "usr_standard_42",
              previousRole: "viewer",
              newRole: "admin",
              permissions: ["billing:write", "users:delete"],
            },
          },
          null,
          2
        ),
        impactSummary: `The route verified only that the caller was logged in without checking server-side role permissions or stripping privileged fields${contextNote}. A low-privilege viewer self-promoted to full administrator.`,
        compromisedAssets: [
          "Administrative control plane and tenant configuration",
          "User management and billing permissions",
          "Cross-tenant data isolation boundaries",
        ],
      },
      afterResult: {
        status: "blocked",
        httpStatus: 403,
        responsePreview: JSON.stringify(
          {
            success: false,
            error: {
              code: "FORBIDDEN",
              message:
                "Insufficient permissions: 'admin' role required for this operation.",
            },
            enforcedControls: [
              "Server-side RBAC policy check",
              "Strict Zod DTO allowlist (drops immutable role field)",
              "PostgreSQL Row-Level Security (RLS)",
            ],
          },
          null,
          2
        ),
        defenseMechanism:
          "Server-Side RBAC Enforcement + Explicit Field Allowlists (No Mass Assignment) + Database Row-Level Security (RLS)",
        mitigationSummary:
          "Explicit server-side role verification rejected the viewer's request with HTTP 403 Forbidden, while strict Zod field allowlists and database RLS prevent unauthorized privilege mutations even at the data layer.",
      },
      success: true,
      blocked: true,
      animationData: {
        durationMs: 4200,
        nodes: [
          { id: "attacker", label: "Standard User (Viewer)", type: "attacker" },
          { id: "auth", label: "RBAC Policy Guard", type: "auth" },
          { id: "app", label: "Admin Role Controller", type: "app" },
          { id: "database", label: "Permissions Database", type: "database" },
        ],
        beforeFrames: [
          {
            step: 1,
            timestampMs: 0,
            from: "attacker",
            to: "auth",
            label: `Send PATCH ${targetEndpoint} with {"role":"admin"}`,
            status: "info",
          },
          {
            step: 2,
            timestampMs: 1100,
            from: "auth",
            to: "app",
            label: "Session valid, but server skips RBAC role check",
            status: "warning",
          },
          {
            step: 3,
            timestampMs: 2400,
            from: "app",
            to: "database",
            label: "Mass-assignment updates user role from viewer -> admin",
            status: "breach",
          },
          {
            step: 4,
            timestampMs: 3600,
            from: "app",
            to: "attacker",
            label: "HTTP 200 OK — Vertical privilege escalation succeeded",
            status: "breach",
          },
        ],
        afterFrames: [
          {
            step: 1,
            timestampMs: 0,
            from: "attacker",
            to: "auth",
            label: `Send PATCH ${targetEndpoint} with {"role":"admin"}`,
            status: "info",
          },
          {
            step: 2,
            timestampMs: 1100,
            from: "auth",
            to: "auth",
            label: "RBAC guard verifies caller role 'viewer' lacks 'admin' permission",
            status: "blocked",
          },
          {
            step: 3,
            timestampMs: 2400,
            from: "auth",
            to: "attacker",
            label: "HTTP 403 Forbidden — Privilege escalation attempt denied",
            status: "blocked",
          },
          {
            step: 4,
            timestampMs: 3600,
            from: "database",
            to: "app",
            label: "Role unchanged in database; RLS & audit log preserved",
            status: "safe",
          },
        ],
      },
      disclaimer: SIMULATION_DISCLAIMER,
    };
  },
};
