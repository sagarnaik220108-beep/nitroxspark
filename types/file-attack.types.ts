/**
 * Types for the File-Targeted Attack Simulation Engine.
 *
 * Unlike the generic scenario library, these simulations are driven by the
 * vulnerabilities detected in the user's OWN uploaded/pasted code: each attack
 * targets a real file line, the real tainted identifier, the real automated fix,
 * and a real re-scan verification of the hardened code.
 *
 * Everything is simulated: payloads are only rendered as strings — nothing is
 * ever executed, sent over the network, or evaluated.
 */

import type { Severity, SupportedLanguage } from "./security.types";

export type FileAttackType =
  | "sql-injection"
  | "command-injection"
  | "code-injection"
  | "xss"
  | "api-key-theft"
  | "broken-authentication"
  | "privilege-escalation"
  | "ssrf"
  | "path-traversal"
  | "data-exposure"
  | "supply-chain";

/**
 * Outcome of re-attacking the hardened code:
 * - `blocked`: automated fix applied AND re-scan confirms the rule no longer fires.
 * - `partially-mitigated`: fix applied but the rule still fires somewhere in the file.
 * - `manual-fix-required`: no automated fixer exists; the attack still succeeds until fixed manually.
 */
export type FileAttackVerdict =
  | "blocked"
  | "partially-mitigated"
  | "manual-fix-required";

export type FileAttackNodeType =
  | "attacker"
  | "entry"
  | "code"
  | "sink"
  | "asset"
  | "defense";

export type FileAttackFrameStatus =
  | "info"
  | "warning"
  | "breach"
  | "blocked"
  | "safe";

export interface FileAttackNode {
  id: string;
  label: string;
  detail: string;
  type: FileAttackNodeType;
}

export interface FileAttackFrame {
  step: number;
  timestampMs: number;
  from: string;
  to: string;
  label: string;
  status: FileAttackFrameStatus;
}

export interface FileCodeLine {
  lineNumber: number;
  text: string;
  highlighted: boolean;
}

export interface FileAttackSimulation {
  id: string;
  attackType: FileAttackType;
  attackName: string;
  ruleId: string;
  vulnerabilityName: string;
  severity: Severity;
  cweId: string;
  owaspCategory: string;
  mitreTechnique: string;

  /** Location of the targeted vulnerable line inside the provided code. */
  target: {
    fileName: string;
    line: number;
    lineText: string;
    contextLines: FileCodeLine[];
    taintedInput: string | null;
    entryPoint: string;
    sink: string;
  };

  /** Safe, simulated payload (string only, never executed). */
  attackPayload: string;
  attackSteps: string[];

  before: {
    success: true;
    exploitedLine: string;
    resultingExecution: string;
    impactSummary: string;
    compromisedAssets: string[];
  };

  after: {
    verdict: FileAttackVerdict;
    blocked: boolean;
    fixApplied: boolean;
    fixSummary: string;
    fixedLines: Array<{
      lineNumber: number;
      originalLine: string;
      updatedLine: string;
    }>;
    reattackResult: string;
    defenseMechanism: string;
    verification: string;
    recommendedSecureCode: string;
  };

  animation: {
    durationMs: number;
    nodes: FileAttackNode[];
    beforeFrames: FileAttackFrame[];
    afterFrames: FileAttackFrame[];
  };
}

export interface FileAttackRunResponse {
  fileName: string;
  language: SupportedLanguage;
  totalFindings: number;
  simulations: FileAttackSimulation[];
  summary: {
    attacksLaunched: number;
    succeededBeforeFix: number;
    blockedAfterFix: number;
    partiallyMitigated: number;
    manualFixRequired: number;
    riskScoreBefore: number;
    riskGradeBefore: string;
    riskScoreAfter: number;
    riskGradeAfter: string;
    findingsBefore: number;
    findingsAfter: number;
  };
  /** Full file with every automated fix applied (useful for "Apply hardened file"). */
  hardenedCode: string;
  disclaimer: string;
}
