import {
  SIMULATION_DISCLAIMER,
  type AttackScenario,
  type BeforeAfterSimulationResult,
  type SimulationCodeContext,
} from "@/types/simulation.types";

const DEFAULT_TARGET = "client-bundle.js / public Git repository";

/**
 * Simulated Before-vs-After API Key Theft scenario.
 * Demonstrates hardcoded secret extraction from client bundles or source code
 * vs. server-side environment variables, secret rotation, and scoped proxy routes.
 */
export const apiKeyTheftScenario: AttackScenario = {
  attackType: "api-key-theft",
  attackName: "API Key Theft (Hardcoded Credential Exposure)",
  description:
    "Simulates an automated scanner discovering a hardcoded third-party API key in frontend code or source history and abusing it directly against cloud billing APIs, compared against server-side secret isolation.",
  severity: "critical",
  cweId: "CWE-798",
  owaspCategory: "A07:2021 - Identification and Authentication Failures",
  mitreAttackTechnique: "T1552.001 - Unsecured Credentials: Credentials In Files",
  tags: ["secrets", "api-key", "credentials", "cloud", "billing-abuse"],

  simulate(codeContext?: SimulationCodeContext): BeforeAfterSimulationResult {
    const targetSurface =
      codeContext?.fileName?.trim() ||
      codeContext?.endpoint?.trim() ||
      DEFAULT_TARGET;

    const attackPayload =
      "SCAN_PATTERN: /(sk_live_|AIza|AKIA)[A-Za-z0-9_\\-]{16,}/ -> DEMO_FAKE_KEY_sk_live_0000000000000000";

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
            sourceArtifact: targetSurface,
            extractedCredential: "sk_live_SIMULATED_REDACTED_DEMO_KEY",
            providerCall: "POST https://api.cloud-provider.invalid/v1/completions",
            providerStatus: "200 OK (Authenticated as Production Org)",
            simulatedAbuseImpact:
              "Unauthorized high-volume API calls & read access to organization storage",
          },
          null,
          2
        ),
        impactSummary: `Automated secret scraper extracted a hardcoded production API key from ${targetSurface}. The attacker authenticated directly to the third-party cloud provider, bypassing all application rate limits and authentication.`,
        compromisedAssets: [
          "Production third-party API key (revocation required)",
          "Organization cloud billing quota and usage limits",
          "Private provider-hosted project data accessible to the key scope",
        ],
      },
      afterResult: {
        status: "blocked",
        httpStatus: 401,
        responsePreview: JSON.stringify(
          {
            sourceArtifact: targetSurface,
            extractedCredential: null,
            providerCall: "POST https://api.cloud-provider.invalid/v1/completions",
            providerStatus: "401 Unauthorized (Revoked / No key in bundle)",
            serverProxy: "process.env.PROVIDER_API_KEY (server-only, rate-limited)",
          },
          null,
          2
        ),
        defenseMechanism:
          "Server-Only Environment Variables + Secret Rotation + Pre-Commit Secret Scanning + Authenticated Backend Proxy",
        mitigationSummary:
          "All credentials were removed from client bundles and source files, moved into server-only environment variables, rotated, and gated behind an authenticated, rate-limited backend route.",
      },
      success: true,
      blocked: true,
      animationData: {
        durationMs: 4200,
        nodes: [
          { id: "attacker", label: "Automated Secret Bot", type: "attacker" },
          { id: "browser", label: "Public Repo / JS Bundle", type: "browser" },
          { id: "app", label: "Backend API Proxy", type: "app" },
          { id: "cloud", label: "Third-Party Cloud API", type: "cloud" },
        ],
        beforeFrames: [
          {
            step: 1,
            timestampMs: 0,
            from: "attacker",
            to: "browser",
            label: `Scan ${targetSurface} for high-entropy API key patterns`,
            status: "info",
          },
          {
            step: 2,
            timestampMs: 1100,
            from: "browser",
            to: "attacker",
            label: "Hardcoded secret literal extracted from bundled source",
            status: "warning",
          },
          {
            step: 3,
            timestampMs: 2400,
            from: "attacker",
            to: "cloud",
            label: "Replay stolen key directly against production cloud API",
            status: "breach",
          },
          {
            step: 4,
            timestampMs: 3600,
            from: "cloud",
            to: "attacker",
            label: "HTTP 200 OK — Direct unauthorized cloud access & billing abuse",
            status: "breach",
          },
        ],
        afterFrames: [
          {
            step: 1,
            timestampMs: 0,
            from: "attacker",
            to: "browser",
            label: `Scan ${targetSurface} for hardcoded API keys`,
            status: "info",
          },
          {
            step: 2,
            timestampMs: 1100,
            from: "browser",
            to: "attacker",
            label: "Zero secrets present in client bundle or source repository",
            status: "blocked",
          },
          {
            step: 3,
            timestampMs: 2400,
            from: "attacker",
            to: "app",
            label: "Unauthenticated probe to backend proxy rejected (HTTP 401)",
            status: "blocked",
          },
          {
            step: 4,
            timestampMs: 3600,
            from: "app",
            to: "cloud",
            label: "Rotated server-only secret remains isolated inside backend runtime",
            status: "safe",
          },
        ],
      },
      disclaimer: SIMULATION_DISCLAIMER,
    };
  },
};
