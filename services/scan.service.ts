import type {
  PaginationMeta,
  ScanRow,
  SecurityRule,
  VulnerabilityRow,
} from "@/types";
import {
  AuditRepository,
  CustomRuleRepository,
  ScanRepository,
  VulnerabilityRepository,
} from "@/database/repositories";
import { getEnv } from "@/lib/env";
import { logger } from "@/lib/logger";
import { enforceRateLimit } from "@/lib/rate-limit";
import { compileCustomRule, defaultSecurityEngine } from "@/security";
import {
  createScanSchema,
  paginationQuerySchema,
  parseOrThrow,
  uuidParamSchema,
} from "@/utils";
import { authService } from "./auth.service";

export interface ScanWithVulnerabilities {
  scan: ScanRow;
  vulnerabilities: VulnerabilityRow[];
}

/**
 * ScanService orchestrates code analysis:
 * validation -> rate limiting -> custom rule loading -> SecurityEngine execution
 * -> persistence (scans + vulnerabilities) -> audit logging.
 */
export class ScanService {
  public async createAndRunScan(
    rawInput: unknown
  ): Promise<ScanWithVulnerabilities> {
    const input = parseOrThrow(createScanSchema, rawInput);
    const { user, supabase } = await authService.requireAuthenticatedUser();

    const env = getEnv();
    enforceRateLimit(`scan:${user.id}`, {
      maxRequests: env.SCAN_RATE_LIMIT_MAX,
      windowMs: env.SCAN_RATE_LIMIT_WINDOW_MS,
    });

    const scanRepo = new ScanRepository(supabase);
    const vulnRepo = new VulnerabilityRepository(supabase);
    const customRuleRepo = new CustomRuleRepository(supabase);
    const auditRepo = new AuditRepository(supabase);

    let extraRules: SecurityRule[] = [];
    if (input.includeCustomRules) {
      const userRules = await customRuleRepo.listEnabledByUser(user.id);
      extraRules = userRules.map(compileCustomRule);
    }

    const analysis = defaultSecurityEngine.analyze({
      code: input.code,
      fileName: input.fileName,
      language: input.language,
      enabledRuleIds: input.enabledRuleIds,
      disabledRuleIds: input.disabledRuleIds,
      extraRules,
    });

    const scan = await scanRepo.create({
      user_id: user.id,
      project_name: input.projectName,
      file_name: input.fileName,
      language: analysis.language,
      source_code: input.code,
      code_hash: analysis.codeHash,
      ai_model_source: input.aiModelSource ?? null,
      status: "completed",
      risk_score: analysis.riskScore,
      risk_grade: analysis.riskGrade,
      summary: analysis.summary,
      severity_breakdown: analysis.severityBreakdown,
      executed_rules_count: analysis.executedRulesCount,
      duration_ms: analysis.durationMs,
    });

    const vulnerabilities = await vulnRepo.createMany(
      analysis.vulnerabilities.map((vuln) => ({
        scan_id: scan.id,
        user_id: user.id,
        rule_id: vuln.ruleId,
        title: vuln.title,
        description: vuln.description,
        explanation: vuln.explanation,
        severity: vuln.severity,
        category: vuln.category,
        cwe_id: vuln.cweId,
        owasp_category: vuln.owaspCategory,
        confidence: vuln.confidence,
        line_start: vuln.location.line,
        column_start: vuln.location.column,
        line_end: vuln.location.endLine,
        column_end: vuln.location.endColumn,
        code_snippet: vuln.location.snippet,
        matched_text: vuln.matchedText,
        remediation: vuln.remediation,
        status: "open",
      }))
    );

    await auditRepo.record({
      userId: user.id,
      action: "scan.created",
      resourceType: "scan",
      resourceId: scan.id,
      metadata: {
        language: analysis.language,
        riskScore: analysis.riskScore,
        vulnerabilitiesCount: vulnerabilities.length,
        durationMs: analysis.durationMs,
      },
    });

    logger.info("Code scan completed", {
      scanId: scan.id,
      userId: user.id,
      findings: vulnerabilities.length,
      riskScore: analysis.riskScore,
    });

    return { scan, vulnerabilities };
  }

  public async getScanById(scanId: string): Promise<ScanWithVulnerabilities> {
    const validId = parseOrThrow(uuidParamSchema, scanId);
    const { user, supabase } = await authService.requireAuthenticatedUser();

    const scanRepo = new ScanRepository(supabase);
    const vulnRepo = new VulnerabilityRepository(supabase);

    const scan = await scanRepo.findById(validId, user.id);
    const vulnerabilities = await vulnRepo.findByScanId(scan.id, user.id);

    return { scan, vulnerabilities };
  }

  public async listUserScans(rawQuery: unknown): Promise<{
    scans: ScanRow[];
    pagination: PaginationMeta;
  }> {
    const { page, pageSize } = parseOrThrow(paginationQuerySchema, rawQuery);
    const { user, supabase } = await authService.requireAuthenticatedUser();

    const scanRepo = new ScanRepository(supabase);
    const { items, total } = await scanRepo.listByUser(user.id, page, pageSize);

    return {
      scans: items,
      pagination: {
        page,
        pageSize,
        total,
        totalPages: Math.max(1, Math.ceil(total / pageSize)),
      },
    };
  }

  public async deleteScan(scanId: string): Promise<{ deletedId: string }> {
    const validId = parseOrThrow(uuidParamSchema, scanId);
    const { user, supabase } = await authService.requireAuthenticatedUser();

    const scanRepo = new ScanRepository(supabase);
    const auditRepo = new AuditRepository(supabase);

    await scanRepo.delete(validId, user.id);
    await auditRepo.record({
      userId: user.id,
      action: "scan.deleted",
      resourceType: "scan",
      resourceId: validId,
    });

    return { deletedId: validId };
  }
}

export const scanService = new ScanService();
