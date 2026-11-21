import {
  SIMULATION_DISCLAIMER,
  type AttackScenario,
  type BeforeAfterSimulationResult,
  type SimulationCodeContext,
} from "@/types/simulation.types";

const DEFAULT_ENDPOINT = "/comments/render";

/**
 * Simulated Before-vs-After Cross-Site Scripting (XSS) scenario.
 * Demonstrates unsanitized HTML sink execution (e.g., dangerouslySetInnerHTML / innerHTML)
 * vs. contextual output encoding, DOMPurify sanitization, and strict CSP + HttpOnly cookies.
 */
export const xssScenario: AttackScenario = {
  attackType: "xss",
  attackName: "Cross-Site Scripting (Stored / Reflected XSS)",
  description:
    "Simulates injecting an HTML event-handler payload into an unsanitized DOM sink so JavaScript executes inside a victim's browser origin, compared against safe text rendering, HTML sanitization, and a strict Content-Security-Policy.",
  severity: "high",
  cweId: "CWE-79",
  owaspCategory: "A03:2021 - Injection",
  mitreAttackTechnique: "T1059.007 - Command and Scripting Interpreter: JavaScript",
  tags: ["xss", "browser", "dom", "session-hijacking", "csp"],

  simulate(codeContext?: SimulationCodeContext): BeforeAfterSimulationResult {
    const targetEndpoint =
      codeContext?.endpoint?.trim() || DEFAULT_ENDPOINT;
    const contextNote = codeContext?.fileName
      ? ` in ${codeContext.fileName}`
      : "";

    const attackPayload =
      "<img src=\"x\" onerror=\"/* SIMULATED_XSS_MARKER */ window.__sentinelSimulatedAlert = true\">";

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
            renderedMarkup: `<div class="comment-body">${attackPayload}</div>`,
            browserExecution:
              "Inline onerror handler executed inside trusted app origin",
            accessibleClientState: [
              "Non-HttpOnly session token / localStorage JWT",
              "Authenticated fetch() calls on behalf of victim",
            ],
          },
          null,
          2
        ),
        impactSummary: `Unsanitized user markup was injected directly into an HTML sink${contextNote}. The victim's browser parsed and executed the inline JavaScript event handler within the application's trusted origin.`,
        compromisedAssets: [
          "Victim browser session and DOM integrity",
          "Client-accessible auth tokens stored outside HttpOnly cookies",
          "Authenticated user actions via same-origin API calls",
        ],
      },
      afterResult: {
        status: "blocked",
        httpStatus: 200,
        responsePreview: JSON.stringify(
          {
            renderedMarkup:
              "&lt;img src=&quot;x&quot; onerror=&quot;/* SIMULATED_XSS_MARKER */ ...&quot;&gt;",
            contentSecurityPolicy:
              "default-src 'self'; script-src 'self' 'nonce-SIMULATED'; object-src 'none'",
            browserExecution: "Blocked — rendered strictly as inert text nodes",
          },
          null,
          2
        ),
        defenseMechanism:
          "Contextual JSX/Text Escaping + DOMPurify Sanitization + Strict Nonce-Based CSP + HttpOnly Cookies",
        mitigationSummary:
          "Replacing raw HTML injection with escaped text rendering neutralized all executable markup, while a strict Content-Security-Policy and HttpOnly cookies provide layered browser defense-in-depth.",
      },
      success: true,
      blocked: true,
      animationData: {
        durationMs: 4200,
        nodes: [
          { id: "attacker", label: "Simulated Attacker", type: "attacker" },
          { id: "app", label: "Web Application Server", type: "app" },
          { id: "browser", label: "Victim Browser DOM", type: "browser" },
        ],
        beforeFrames: [
          {
            step: 1,
            timestampMs: 0,
            from: "attacker",
            to: "app",
            label: `Submit HTML event-handler payload via ${targetEndpoint}`,
            status: "info",
          },
          {
            step: 2,
            timestampMs: 1100,
            from: "app",
            to: "browser",
            label: "Render unescaped HTML directly into innerHTML / dangerouslySetInnerHTML",
            status: "warning",
          },
          {
            step: 3,
            timestampMs: 2400,
            from: "browser",
            to: "browser",
            label: "DOM parser fires onerror JavaScript inside trusted app origin",
            status: "breach",
          },
          {
            step: 4,
            timestampMs: 3600,
            from: "browser",
            to: "attacker",
            label: "Simulated session token & DOM data exfiltrated from victim browser",
            status: "breach",
          },
        ],
        afterFrames: [
          {
            step: 1,
            timestampMs: 0,
            from: "attacker",
            to: "app",
            label: `Submit HTML event-handler payload via ${targetEndpoint}`,
            status: "info",
          },
          {
            step: 2,
            timestampMs: 1100,
            from: "app",
            to: "browser",
            label: "Encode output as safe text / strip event handlers with DOMPurify",
            status: "blocked",
          },
          {
            step: 3,
            timestampMs: 2400,
            from: "browser",
            to: "browser",
            label: "CSP blocks inline script execution; payload displays as plain text",
            status: "blocked",
          },
          {
            step: 4,
            timestampMs: 3600,
            from: "browser",
            to: "app",
            label: "Victim session and HttpOnly cookies remain fully protected",
            status: "safe",
          },
        ],
      },
      disclaimer: SIMULATION_DISCLAIMER,
    };
  },
};
