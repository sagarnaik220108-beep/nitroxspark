import type {
  AttackSimulationRow,
  DetectedVulnerability,
  VulnerabilityRow,
} from "@/types";
import {
  AuditRepository,
  ScanRepository,
  SimulationRepository,
  VulnerabilityRepository,
} from "@/database/repositories";
import { simulateAttackForVulnerability } from "@/security";
import { parseOrThrow, simulateAttackSchema, uuidParamSchema } from "@/utils";
import { authService } from "./auth.service";

function toDetectedVulnerability(row: VulnerabilityRow): DetectedVulnerability {
  return {
    ruleId: row.rule_id,
    title: row.title,
    description: row.description,
    explanation: row.explanation,
    severity: row.severity,
    category: row.category,
    cweId: row.cwe_id,
    owaspCategory: row.owasp_category,
    confidence: Number(row.confidence),
    location: {
      line: row.line_start,
      column: row.column_start,
      endLine: row.line_end,
      endColumn: row.column_end,
      snippet: row.code_snippet,
    },
    matchedText: row.matched_text,
    remediation: row.remediation,
  };
}

/**
 * AttackSimulationService runs safe, educational, defensive attack simulations
 * against detected vulnerabilities and persists the results in Supabase.
 */
export class AttackSimulationService {
  public async simulateForScan(
    rawInput: unknown
  ): Promise<AttackSimulationRow[]> {
    const input = parseOrThrow(simulateAttackSchema, rawInput);
    const { user, supabase } = await authService.requireAuthenticatedUser();

    const scanRepo = new ScanRepository(supabase);
    const vulnRepo = new VulnerabilityRepository(supabase);
    const simRepo = new SimulationRepository(supabase);
    const auditRepo = new AuditRepository(supabase);

    // Ensure scan belongs to the authenticated user
    await scanRepo.findById(input.scanId, user.id);

    const targets: VulnerabilityRow[] = input.vulnerabilityId
      ? [await vulnRepo.findById(input.vulnerabilityId, user.id)]
      : await vulnRepo.findByScanId(input.scanId, user.id);

    if (targets.length === 0) {
      return [];
    }

    const simulationRows = targets.map((vulnRow) => {
      const result = simulateAttackForVulnerability(
        toDetectedVulnerability(vulnRow),
        vulnRow.id
      );

      return {
        scan_id: input.scanId,
        vulnerability_id: vulnRow.id,
        user_id: user.id,
        rule_id: result.ruleId,
        attack_name: result.attackName,
        mitre_attack_technique: result.mitreAttackTechnique,
        severity: result.severity,
        likelihood: result.likelihood,
        simulation_payload: result,
      };
    });

    const persisted = await simRepo.createMany(simulationRows);

    await auditRepo.record({
      userId: user.id,
      action: "attack_simulation.executed",
      resourceType: "scan",
      resourceId: input.scanId,
      metadata: {
        simulatedCount: persisted.length,
        vulnerabilityId: input.vulnerabilityId ?? null,
      },
    });

    return persisted;
  }

  public async listByScanId(scanId: string): Promise<AttackSimulationRow[]> {
    const validId = parseOrThrow(uuidParamSchema, scanId);
    const { user, supabase } = await authService.requireAuthenticatedUser();

    const scanRepo = new ScanRepository(supabase);
    const simRepo = new SimulationRepository(supabase);

    await scanRepo.findById(validId, user.id);
    return simRepo.findByScanId(validId, user.id);
  }
}

export const attackSimulationService = new AttackSimulationService();
