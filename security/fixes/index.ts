import type {
  AppliedFixSummary,
  BatchSecureFixResult,
  FixerMetadata,
  FixVulnerabilityInput,
  SecureFixInput,
  SecureFixResult,
  VulnerabilityFixer,
} from "@/types/fix.types";
import { apiKeysFixer } from "./api-keys.fixer";
import {
  buildFixResult,
  calculateBatchRiskReduction,
  calculateRiskReduction,
  computeLineChanges,
} from "./base";
import { commandInjectionFixer } from "./command-injection.fixer";
import { envVarsFixer } from "./env-vars.fixer";
import { passwordsFixer } from "./passwords.fixer";
import { FixerRegistry } from "./registry";
import { sqlInjectionFixer } from "./sql-injection.fixer";
import { unsafeEvalFixer } from "./unsafe-eval.fixer";
import { weakAuthFixer } from "./weak-auth.fixer";
import { xssFixer } from "./xss.fixer";

export {
  apiKeysFixer,
  sqlInjectionFixer,
  xssFixer,
  weakAuthFixer,
  unsafeEvalFixer,
  commandInjectionFixer,
  passwordsFixer,
  envVarsFixer,
  FixerRegistry,
  computeLineChanges,
  calculateRiskReduction,
  calculateBatchRiskReduction,
  buildFixResult,
};

export type { VulnerabilityFixer };

/**
 * All 8 built-in modular Sentinel AI vulnerability fixers.
 * Order ensures specific fixers (e.g. env-vars, passwords) are evaluated cleanly
 * alongside general secret/injection fixers.
 */
export const BUILT_IN_FIXERS: readonly VulnerabilityFixer[] = [
  envVarsFixer,
  passwordsFixer,
  apiKeysFixer,
  sqlInjectionFixer,
  xssFixer,
  weakAuthFixer,
  unsafeEvalFixer,
  commandInjectionFixer,
] as const;

/**
 * Default pluggable fixer registry pre-loaded with all built-in fixers.
 * Call `defaultFixerRegistry.register(customFixer)` to plug in new fixers at runtime.
 */
export const defaultFixerRegistry = new FixerRegistry();
defaultFixerRegistry.registerMany(BUILT_IN_FIXERS);

/**
 * Sentinel AI Secure Fix Engine.
 * Transforms vulnerable code into hardened code and quantifies risk reduction.
 */
export class SecureFixEngine {
  constructor(
    private readonly registry: FixerRegistry = defaultFixerRegistry
  ) {}

  /**
   * Generates a secure fix for a single detected vulnerability.
   */
  public generateFix(input: SecureFixInput): SecureFixResult {
    const fixer = this.registry.findForVulnerability(input.vulnerability);

    if (!fixer) {
      return {
        originalCode: input.originalCode,
        secureCode: input.originalCode,
        linesChanged: [],
        changedLineNumbers: [],
        summary: `No automated fixer is registered for rule '${input.vulnerability.ruleId}' (category: ${input.vulnerability.category}). Manual remediation is required.`,
        riskReduction: calculateRiskReduction(
          input.vulnerability.severity,
          false,
          `No automated fixer matched rule '${input.vulnerability.ruleId}'.`
        ),
        fixerId: "unmatched",
        applied: false,
      };
    }

    return fixer.apply(input);
  }

  /**
   * Sequentially applies fixes for multiple detected vulnerabilities in a single source file,
   * aggregating line changes and quantifying combined risk reduction.
   */
  public generateBatchFix(
    originalCode: string,
    vulnerabilities: readonly FixVulnerabilityInput[]
  ): BatchSecureFixResult {
    let workingCode = originalCode;
    const appliedFixes: AppliedFixSummary[] = [];
    const appliedFlags: boolean[] = [];

    for (const vulnerability of vulnerabilities) {
      const result = this.generateFix({
        originalCode: workingCode,
        vulnerability,
      });

      if (result.applied) {
        workingCode = result.secureCode;
      }

      appliedFlags.push(result.applied);
      appliedFixes.push({
        ruleId: vulnerability.ruleId,
        fixerId: result.fixerId,
        applied: result.applied,
        summary: result.summary,
        changedLineNumbers: result.changedLineNumbers,
      });
    }

    const appliedCount = appliedFlags.filter(Boolean).length;
    const appliedSummaries = appliedFixes
      .filter((f) => f.applied)
      .map((f) => f.summary);

    const aggregateReason =
      appliedSummaries.length > 0
        ? appliedSummaries.join(" ")
        : "No automated fixes applied.";

    const { linesChanged, changedLineNumbers } = computeLineChanges(
      originalCode,
      workingCode,
      aggregateReason
    );

    const riskReduction = calculateBatchRiskReduction(
      vulnerabilities,
      appliedFlags
    );

    const summary =
      appliedCount > 0
        ? `Applied ${appliedCount} of ${vulnerabilities.length} automated security fix(es) across ${changedLineNumbers.length} line(s).`
        : `No automated fixes were applied for the ${vulnerabilities.length} provided vulnerability item(s).`;

    return {
      originalCode,
      secureCode: workingCode,
      linesChanged,
      changedLineNumbers,
      summary,
      riskReduction,
      appliedFixes,
    };
  }

  /**
   * Lists all fixers currently registered in this engine's registry.
   */
  public listFixers(): FixerMetadata[] {
    return this.registry.listRegisteredFixers();
  }
}

export const defaultSecureFixEngine = new SecureFixEngine(defaultFixerRegistry);
