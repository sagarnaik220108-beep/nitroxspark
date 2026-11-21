import type {
  AttackScenario,
  AttackScenarioMetadata,
  BeforeAfterSimulationResult,
  SimulationAttackType,
  SimulationCodeContext,
} from "@/types/simulation.types";
import { NotFoundError } from "@/utils/errors";
import { apiKeyTheftScenario } from "./api-key-theft.scenario";
import { brokenAuthenticationScenario } from "./broken-authentication.scenario";
import { privilegeEscalationScenario } from "./privilege-escalation.scenario";
import { sqlInjectionScenario } from "./sql-injection.scenario";
import { xssScenario } from "./xss.scenario";

export {
  sqlInjectionScenario,
  apiKeyTheftScenario,
  xssScenario,
  brokenAuthenticationScenario,
  privilegeEscalationScenario,
};

export const BUILTIN_ATTACK_SCENARIOS: readonly AttackScenario[] = [
  sqlInjectionScenario,
  apiKeyTheftScenario,
  xssScenario,
  brokenAuthenticationScenario,
  privilegeEscalationScenario,
] as const;

/**
 * Pluggable registry for Before-vs-After Attack Simulation scenarios.
 * New scenarios can be added dynamically via `register()` without modifying
 * existing scenarios, services, or API routes.
 */
export class AttackScenarioRegistry {
  private readonly scenarios = new Map<string, AttackScenario>();

  constructor(initialScenarios: readonly AttackScenario[] = []) {
    this.registerMany(initialScenarios);
  }

  public register(scenario: AttackScenario): this {
    this.scenarios.set(scenario.attackType, scenario);
    return this;
  }

  public registerMany(scenarios: readonly AttackScenario[]): this {
    for (const scenario of scenarios) {
      this.register(scenario);
    }
    return this;
  }

  public unregister(attackType: SimulationAttackType): boolean {
    return this.scenarios.delete(attackType);
  }

  public get(attackType: SimulationAttackType): AttackScenario | undefined {
    return this.scenarios.get(attackType);
  }

  public has(attackType: SimulationAttackType): boolean {
    return this.scenarios.has(attackType);
  }

  public list(): AttackScenario[] {
    return Array.from(this.scenarios.values());
  }

  public listMetadata(): AttackScenarioMetadata[] {
    return this.list().map((scenario) => ({
      attackType: scenario.attackType,
      attackName: scenario.attackName,
      description: scenario.description,
      severity: scenario.severity,
      cweId: scenario.cweId,
      owaspCategory: scenario.owaspCategory,
      mitreAttackTechnique: scenario.mitreAttackTechnique,
      tags: [...scenario.tags],
    }));
  }

  public get size(): number {
    return this.scenarios.size;
  }
}

export const defaultAttackScenarioRegistry = new AttackScenarioRegistry(
  BUILTIN_ATTACK_SCENARIOS
);

/**
 * Orchestrator for running 100% simulated Before-vs-After attack demonstrations.
 * Never executes real network requests, database queries, or shell commands.
 */
export class BeforeAfterAttackSimulator {
  constructor(
    private readonly registry: AttackScenarioRegistry = defaultAttackScenarioRegistry
  ) {}

  public simulate(
    attackType: SimulationAttackType,
    codeContext?: SimulationCodeContext
  ): BeforeAfterSimulationResult {
    const scenario = this.registry.get(attackType);
    if (!scenario) {
      throw new NotFoundError("Attack simulation scenario", attackType);
    }
    return scenario.simulate(codeContext);
  }

  public simulateMany(
    attackTypes: readonly SimulationAttackType[],
    codeContext?: SimulationCodeContext
  ): BeforeAfterSimulationResult[] {
    const seen = new Set<string>();
    const results: BeforeAfterSimulationResult[] = [];

    for (const attackType of attackTypes) {
      if (seen.has(attackType)) {
        continue;
      }
      seen.add(attackType);
      results.push(this.simulate(attackType, codeContext));
    }

    return results;
  }

  public simulateAll(
    codeContext?: SimulationCodeContext
  ): BeforeAfterSimulationResult[] {
    return this.registry
      .list()
      .map((scenario) => scenario.simulate(codeContext));
  }

  public listScenarios(): AttackScenarioMetadata[] {
    return this.registry.listMetadata();
  }

  public hasScenario(attackType: SimulationAttackType): boolean {
    return this.registry.has(attackType);
  }
}

export const defaultBeforeAfterAttackSimulator =
  new BeforeAfterAttackSimulator(defaultAttackScenarioRegistry);
