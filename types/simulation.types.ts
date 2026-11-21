/**
 * Core domain types for the Sentinel AI Before-vs-After Attack Simulation Engine.
 * All simulations are 100% synthetic and defensive — no real attacks, network calls,
 * or shell commands are ever executed.
 */

import type { Severity, SupportedLanguage } from "@/types/security.types";

export const BUILTIN_SIMULATION_ATTACK_TYPES = [
  "sql-injection",
  "api-key-theft",
  "xss",
  "broken-authentication",
  "privilege-escalation",
] as const;

export type BuiltinSimulationAttackType =
  (typeof BUILTIN_SIMULATION_ATTACK_TYPES)[number];

/**
 * Extensible attack type identifier. Built-in scenarios use the five canonical
 * identifiers above, while custom pluggable scenarios may register additional keys.
 */
export type SimulationAttackType =
  | BuiltinSimulationAttackType
  | (string & Record<never, never>);

export type SimulationNodeType =
  | "attacker"
  | "app"
  | "auth"
  | "database"
  | "browser"
  | "cloud";

export type SimulationBeforeFrameStatus = "info" | "warning" | "breach";
export type SimulationAfterFrameStatus = "info" | "blocked" | "safe";

export interface SimulationNode {
  id: string;
  label: string;
  type: SimulationNodeType;
}

export interface SimulationBeforeFrame {
  step: number;
  timestampMs: number;
  from: string;
  to: string;
  label: string;
  status: SimulationBeforeFrameStatus;
}

export interface SimulationAfterFrame {
  step: number;
  timestampMs: number;
  from: string;
  to: string;
  label: string;
  status: SimulationAfterFrameStatus;
}

export interface SimulationAnimationData {
  durationMs: number;
  nodes: SimulationNode[];
  beforeFrames: SimulationBeforeFrame[];
  afterFrames: SimulationAfterFrame[];
}

export interface SimulationBeforeResult {
  status: "compromised";
  httpStatus: number;
  responsePreview: string;
  impactSummary: string;
  compromisedAssets: string[];
}

export interface SimulationAfterResult {
  status: "blocked";
  httpStatus: number;
  responsePreview: string;
  defenseMechanism: string;
  mitigationSummary: string;
}

/**
 * Optional caller-provided context used purely as read-only metadata to tailor
 * educational simulation output (never executed or evaluated).
 */
export interface SimulationCodeContext {
  endpoint?: string;
  fileName?: string;
  language?: SupportedLanguage;
  snippet?: string;
  vulnerablePattern?: string;
  fixedPattern?: string;
}

export interface BeforeAfterSimulationResult {
  attackType: SimulationAttackType;
  attackName: string;
  description: string;
  severity: Severity;
  cweId: string;
  owaspCategory: string;
  mitreAttackTechnique: string;
  attackPayload: string;
  beforeResult: SimulationBeforeResult;
  afterResult: SimulationAfterResult;
  /**
   * True in the vulnerable "before" state, indicating the simulated attack succeeds
   * prior to applying the security fix.
   */
  success: boolean;
  /**
   * True in the hardened "after" state, indicating the simulated attack is blocked
   * once the security fix is in place.
   */
  blocked: boolean;
  animationData: SimulationAnimationData;
  disclaimer: string;
}

export interface AttackScenarioMetadata {
  attackType: SimulationAttackType;
  attackName: string;
  description: string;
  severity: Severity;
  cweId: string;
  owaspCategory: string;
  mitreAttackTechnique: string;
  tags: readonly string[];
}

/**
 * Pluggable contract for Before-vs-After Attack Simulation scenarios.
 * Implement this interface and register it with `AttackScenarioRegistry` to
 * add new simulated attack demonstrations without modifying existing code.
 */
export interface AttackScenario {
  readonly attackType: SimulationAttackType;
  readonly attackName: string;
  readonly description: string;
  readonly severity: Severity;
  readonly cweId: string;
  readonly owaspCategory: string;
  readonly mitreAttackTechnique: string;
  readonly tags: readonly string[];
  simulate(codeContext?: SimulationCodeContext): BeforeAfterSimulationResult;
}

export interface SimulationBatchSummary {
  totalSimulations: number;
  vulnerableBeforeCount: number;
  blockedAfterCount: number;
  simulatedOnly: true;
  disclaimer: string;
}

export interface SimulationRunResponse {
  mode: "single" | "multiple" | "all";
  simulations: BeforeAfterSimulationResult[];
  summary: SimulationBatchSummary;
}

export interface SimulationScenarioListResponse {
  scenarios: AttackScenarioMetadata[];
  total: number;
  simulatedOnly: true;
  disclaimer: string;
}

export const SIMULATION_DISCLAIMER =
  "100% SIMULATED DEFENSIVE DEMONSTRATION: This before-vs-after attack simulation is completely synthetic. No real exploits, network requests, database queries, or shell commands are executed. Results are generated solely for educational security awareness and defensive verification.";
