import type {
  FixerMetadata,
  FixVulnerabilityInput,
  VulnerabilityFixer,
} from "@/types/fix.types";

/**
 * Pluggable registry for Sentinel AI vulnerability fixers.
 * Third-party or custom fixers can be plugged in at runtime via `register()`.
 */
export class FixerRegistry {
  private readonly fixers = new Map<string, VulnerabilityFixer>();

  /**
   * Registers a single vulnerability fixer. Re-registering an existing ID replaces it.
   */
  public register(fixer: VulnerabilityFixer): void {
    this.fixers.set(fixer.id, fixer);
  }

  /**
   * Registers multiple fixers in order.
   */
  public registerMany(fixers: readonly VulnerabilityFixer[]): void {
    for (const fixer of fixers) {
      this.register(fixer);
    }
  }

  /**
   * Removes a registered fixer by ID.
   */
  public unregister(fixerId: string): boolean {
    return this.fixers.delete(fixerId);
  }

  /**
   * Looks up a registered fixer by its unique ID.
   */
  public getById(fixerId: string): VulnerabilityFixer | undefined {
    return this.fixers.get(fixerId);
  }

  /**
   * Finds the best matching fixer for a detected vulnerability.
   * Priority:
   *   1. Fixer whose `supportedRuleIds` explicitly contains `vulnerability.ruleId`
   *      AND whose `canHandle()` returns true.
   *   2. First fixer whose `canHandle(vulnerability)` returns true.
   */
  public findForVulnerability(
    vulnerability: FixVulnerabilityInput
  ): VulnerabilityFixer | undefined {
    const normalizedRuleId = vulnerability.ruleId.trim().toUpperCase();

    for (const fixer of this.fixers.values()) {
      const matchesRuleId = fixer.supportedRuleIds.some(
        (id) => id.toUpperCase() === normalizedRuleId
      );
      if (matchesRuleId && fixer.canHandle(vulnerability)) {
        return fixer;
      }
    }

    for (const fixer of this.fixers.values()) {
      if (fixer.canHandle(vulnerability)) {
        return fixer;
      }
    }

    return undefined;
  }

  /**
   * Lists metadata for all registered fixers.
   */
  public listRegisteredFixers(): FixerMetadata[] {
    return Array.from(this.fixers.values()).map((fixer) => ({
      id: fixer.id,
      name: fixer.name,
      description: fixer.description,
      supportedRuleIds: [...fixer.supportedRuleIds],
      supportedCategories: [...fixer.supportedCategories],
    }));
  }
}
