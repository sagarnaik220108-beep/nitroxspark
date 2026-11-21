import type {
  RuleMetadata,
  SecurityRule,
  SupportedLanguage,
  VulnerabilityCategory,
} from "@/types";
import { BUILT_IN_RULES } from "./rules";

export interface RuleFilterOptions {
  language?: SupportedLanguage;
  category?: VulnerabilityCategory;
  enabledRuleIds?: string[];
  disabledRuleIds?: string[];
  extraRules?: SecurityRule[];
}

/**
 * Modular, extensible RuleRegistry for Sentinel AI.
 * Supports built-in rules, runtime registration of plugin rules, and
 * per-scan composition with user-defined custom rules from Supabase.
 */
export class RuleRegistry {
  private readonly rules = new Map<string, SecurityRule>();

  constructor(initialRules: readonly SecurityRule[] = BUILT_IN_RULES) {
    for (const rule of initialRules) {
      this.register(rule);
    }
  }

  /**
   * Registers a new security rule (or replaces an existing one with the same id).
   */
  public register(rule: SecurityRule): void {
    this.rules.set(rule.id, rule);
  }

  /**
   * Registers multiple security rules in one call.
   */
  public registerMany(rules: readonly SecurityRule[]): void {
    for (const rule of rules) {
      this.register(rule);
    }
  }

  public unregister(ruleId: string): boolean {
    return this.rules.delete(ruleId);
  }

  public get(ruleId: string): SecurityRule | undefined {
    return this.rules.get(ruleId);
  }

  public listAll(): SecurityRule[] {
    return Array.from(this.rules.values());
  }

  public listMetadata(): RuleMetadata[] {
    return this.listAll().map((rule) => ({
      id: rule.id,
      name: rule.name,
      description: rule.description,
      severity: rule.severity,
      category: rule.category,
      cweId: rule.cweId,
      owaspCategory: rule.owaspCategory,
      languages: rule.languages,
      tags: rule.tags,
      enabled: rule.enabledByDefault,
      source: "builtin",
    }));
  }

  /**
   * Resolves the active set of rules for a specific scan, applying language
   * applicability, explicit allow/deny overrides, and optional user custom rules.
   */
  public resolveForScan(options: RuleFilterOptions = {}): SecurityRule[] {
    const combined = new Map<string, SecurityRule>(this.rules);

    if (options.extraRules) {
      for (const customRule of options.extraRules) {
        combined.set(customRule.id, customRule);
      }
    }

    const enabledSet = options.enabledRuleIds
      ? new Set(options.enabledRuleIds)
      : null;
    const disabledSet = new Set(options.disabledRuleIds ?? []);

    return Array.from(combined.values()).filter((rule) => {
      if (disabledSet.has(rule.id)) return false;

      if (enabledSet) {
        if (!enabledSet.has(rule.id)) return false;
      } else if (!rule.enabledByDefault) {
        return false;
      }

      if (options.category && rule.category !== options.category) {
        return false;
      }

      if (
        options.language &&
        options.language !== "unknown" &&
        rule.languages !== "*" &&
        !rule.languages.includes(options.language)
      ) {
        return false;
      }

      return true;
    });
  }
}

/**
 * Default shared registry pre-loaded with all built-in Sentinel AI rules.
 */
export const defaultRuleRegistry = new RuleRegistry(BUILT_IN_RULES);
