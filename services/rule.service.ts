import type { CustomRuleRow, RuleMetadata } from "@/types";
import { AuditRepository, CustomRuleRepository } from "@/database/repositories";
import { defaultRuleRegistry } from "@/security";
import {
  createCustomRuleSchema,
  parseOrThrow,
  uuidParamSchema,
} from "@/utils";
import { authService } from "./auth.service";

/**
 * RuleService exposes built-in security rules and manages user-defined
 * custom security rules persisted in Supabase.
 */
export class RuleService {
  public async listAvailableRules(): Promise<{
    builtin: RuleMetadata[];
    custom: CustomRuleRow[];
  }> {
    const { user, supabase } = await authService.requireAuthenticatedUser();
    const customRuleRepo = new CustomRuleRepository(supabase);

    const builtin = defaultRuleRegistry.listMetadata();
    const custom = await customRuleRepo.listAllByUser(user.id);

    return { builtin, custom };
  }

  public async createCustomRule(rawInput: unknown): Promise<CustomRuleRow> {
    const input = parseOrThrow(createCustomRuleSchema, rawInput);
    const { user, supabase } = await authService.requireAuthenticatedUser();

    const customRuleRepo = new CustomRuleRepository(supabase);
    const auditRepo = new AuditRepository(supabase);

    const created = await customRuleRepo.create({
      user_id: user.id,
      rule_key: input.ruleKey,
      name: input.name,
      description: input.description,
      explanation: input.explanation,
      severity: input.severity,
      category: input.category,
      cwe_id: input.cweId,
      owasp_category: input.owaspCategory,
      languages: input.languages,
      pattern: input.pattern,
      pattern_flags: input.patternFlags,
      remediation: input.remediation,
      enabled: input.enabled,
    });

    await auditRepo.record({
      userId: user.id,
      action: "custom_rule.created",
      resourceType: "custom_rule",
      resourceId: created.id,
      metadata: { ruleKey: created.rule_key, severity: created.severity },
    });

    return created;
  }

  public async deleteCustomRule(ruleId: string): Promise<{ deletedId: string }> {
    const validId = parseOrThrow(uuidParamSchema, ruleId);
    const { user, supabase } = await authService.requireAuthenticatedUser();

    const customRuleRepo = new CustomRuleRepository(supabase);
    const auditRepo = new AuditRepository(supabase);

    await customRuleRepo.delete(validId, user.id);
    await auditRepo.record({
      userId: user.id,
      action: "custom_rule.deleted",
      resourceType: "custom_rule",
      resourceId: validId,
    });

    return { deletedId: validId };
  }
}

export const ruleService = new RuleService();
