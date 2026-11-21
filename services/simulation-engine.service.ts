import { z } from "zod";
import {
  BeforeAfterAttackSimulator,
  defaultBeforeAfterAttackSimulator,
} from "@/security/simulator/scenarios";
import {
  SIMULATION_DISCLAIMER,
  type BeforeAfterSimulationResult,
  type SimulationBatchSummary,
  type SimulationCodeContext,
  type SimulationRunResponse,
  type SimulationScenarioListResponse,
} from "@/types/simulation.types";
import { parseOrThrow, supportedLanguageSchema } from "@/utils/validators";

const simulationCodeContextObjectSchema = z.object({
  endpoint: z.string().trim().max(256).optional(),
  fileName: z.string().trim().max(255).optional(),
  language: supportedLanguageSchema.optional(),
  snippet: z.string().max(8192).optional(),
  vulnerablePattern: z.string().max(1024).optional(),
  fixedPattern: z.string().max(1024).optional(),
});

/**
 * Accepts either a plain code snippet string or a structured SimulationCodeContext object.
 */
export const simulationCodeContextSchema = z.union([
  z.string().trim().max(8192),
  simulationCodeContextObjectSchema,
]);

function normalizeCodeContext(
  codeContext?: string | SimulationCodeContext
): SimulationCodeContext | undefined {
  if (codeContext === undefined) {
    return undefined;
  }
  if (typeof codeContext === "string") {
    return codeContext.length > 0 ? { snippet: codeContext } : undefined;
  }
  return codeContext;
}

export const runSingleSimulationSchema = z.object({
  attackType: z.string().trim().min(1, "attackType is required").max(64),
  codeContext: simulationCodeContextSchema.optional(),
});

export const runAllSimulationsSchema = z.object({
  codeContext: simulationCodeContextSchema.optional(),
});

export const simulationRequestSchema = z
  .object({
    attackType: z.string().trim().min(1).max(64).optional(),
    attackTypes: z
      .array(z.string().trim().min(1).max(64))
      .min(1, "attackTypes must contain at least one attack type")
      .max(25, "At most 25 attackTypes may be requested at once")
      .optional(),
    codeContext: simulationCodeContextSchema.optional(),
  })
  .refine(
    (data) => !(data.attackType && data.attackTypes),
    {
      message: "Specify either 'attackType' or 'attackTypes', not both",
      path: ["attackTypes"],
    }
  );

export type RunSingleSimulationInput = z.infer<typeof runSingleSimulationSchema>;
export type SimulationRequestInput = z.infer<typeof simulationRequestSchema>;

function buildSummary(
  simulations: readonly BeforeAfterSimulationResult[]
): SimulationBatchSummary {
  return {
    totalSimulations: simulations.length,
    vulnerableBeforeCount: simulations.filter(
      (sim) => sim.success && sim.beforeResult.status === "compromised"
    ).length,
    blockedAfterCount: simulations.filter(
      (sim) => sim.blocked && sim.afterResult.status === "blocked"
    ).length,
    simulatedOnly: true,
    disclaimer: SIMULATION_DISCLAIMER,
  };
}

/**
 * Application service for Sentinel AI's Before-vs-After Attack Simulation Engine.
 * Validates incoming requests with Zod and executes 100% synthetic simulations.
 */
export class SimulationEngineService {
  constructor(
    private readonly simulator: BeforeAfterAttackSimulator = defaultBeforeAfterAttackSimulator
  ) {}

  /**
   * Lists metadata for all registered simulated attack scenarios.
   */
  public listScenarios(): SimulationScenarioListResponse {
    const scenarios = this.simulator.listScenarios();
    return {
      scenarios,
      total: scenarios.length,
      simulatedOnly: true,
      disclaimer: SIMULATION_DISCLAIMER,
    };
  }

  /**
   * Validates input and runs a single Before-vs-After attack simulation.
   */
  public runSimulation(rawInput: unknown): BeforeAfterSimulationResult {
    const validated = parseOrThrow(runSingleSimulationSchema, rawInput);
    return this.simulator.simulate(
      validated.attackType,
      normalizeCodeContext(validated.codeContext)
    );
  }

  /**
   * Validates optional context and runs all registered Before-vs-After attack simulations.
   */
  public runAllSimulations(rawInput: unknown = {}): SimulationRunResponse {
    const validated = parseOrThrow(runAllSimulationsSchema, rawInput ?? {});
    const simulations = this.simulator.simulateAll(
      normalizeCodeContext(validated.codeContext)
    );
    return {
      mode: "all",
      simulations,
      summary: buildSummary(simulations),
    };
  }

  /**
   * Unified request handler supporting `{ attackType?, attackTypes?, codeContext? }`:
   * - `attackType` provided -> runs that single scenario (`mode: "single"`)
   * - `attackTypes` provided -> runs those scenarios (`mode: "multiple"`)
   * - neither provided -> runs all registered scenarios (`mode: "all"`)
   */
  public executeSimulationRequest(rawInput: unknown = {}): SimulationRunResponse {
    const validated = parseOrThrow(simulationRequestSchema, rawInput ?? {});
    const codeContext = normalizeCodeContext(validated.codeContext);

    if (validated.attackType) {
      const simulation = this.simulator.simulate(
        validated.attackType,
        codeContext
      );
      return {
        mode: "single",
        simulations: [simulation],
        summary: buildSummary([simulation]),
      };
    }

    if (validated.attackTypes) {
      const simulations = this.simulator.simulateMany(
        validated.attackTypes,
        codeContext
      );
      return {
        mode: "multiple",
        simulations,
        summary: buildSummary(simulations),
      };
    }

    const simulations = this.simulator.simulateAll(codeContext);
    return {
      mode: "all",
      simulations,
      summary: buildSummary(simulations),
    };
  }
}

export const simulationEngineService = new SimulationEngineService(
  defaultBeforeAfterAttackSimulator
);
