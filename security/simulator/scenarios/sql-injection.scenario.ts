import {
  SIMULATION_DISCLAIMER,
  type AttackScenario,
  type BeforeAfterSimulationResult,
  type SimulationCodeContext,
} from "@/types/simulation.types";

const DEFAULT_ENDPOINT = "/api/users/search?email=";

/**
 * Simulated Before-vs-After SQL Injection scenario.
 * Demonstrates string-interpolated SQL query exploitation before remediation
 * vs. parameterized query + Zod schema validation after remediation.
 */
export const sqlInjectionScenario: AttackScenario = {
  attackType: "sql-injection",
  attackName: "SQL Injection (Query Logic Bypass)",
  description:
    "Simulates an attacker supplying SQL boolean tautology syntax in an untrusted input field to manipulate a dynamically concatenated database query, compared against a parameterized prepared statement.",
  severity: "critical",
  cweId: "CWE-89",
  owaspCategory: "A03:2021 - Injection",
  mitreAttackTechnique: "T1190 - Exploit Public-Facing Application",
  tags: ["injection", "sql", "database", "data-exfiltration", "owasp-a03"],

  simulate(codeContext?: SimulationCodeContext): BeforeAfterSimulationResult {
    const targetEndpoint =
      codeContext?.endpoint?.trim() || DEFAULT_ENDPOINT;
    const contextNote = codeContext?.fileName
      ? ` (target: ${codeContext.fileName})`
      : "";

    const attackPayload =
      "' OR '1'='1' -- /* SIMULATED_EDUCATIONAL_SQLI_MARKER */";

    return {
      attackType: this.attackType,
      attackName: this.attackName,
      description: this.description,
      severity: this.severity,
      cweId: this.cweId,
      owaspCategory: this.owaspCategory,
      mitreAttackTechnique: this.mitreAttackTechnique,
      attackPayload,
      beforeResult: {
        status: "compromised",
        httpStatus: 200,
        responsePreview: JSON.stringify(
          {
            endpoint: targetEndpoint,
            executedQuery:
              "SELECT id, email, role, api_quota FROM users WHERE email = '' OR '1'='1' -- /* SIMULATED_EDUCATIONAL_SQLI_MARKER */'",
            returnedRowCount: 1482,
            sampleRows: [
              { id: "usr_001", email: "admin@demo.invalid", role: "admin" },
              { id: "usr_002", email: "finance@demo.invalid", role: "owner" },
            ],
          },
          null,
          2
        ),
        impactSummary: `String concatenation merged attacker-controlled syntax directly into the SQL WHERE clause${contextNote}. The tautology ('1'='1') bypassed row filtering and exposed all 1,482 simulated user records.`,
        compromisedAssets: [
          "users table (1,482 simulated account records)",
          "Administrator email addresses and role assignments",
          "Database query execution integrity",
        ],
      },
      afterResult: {
        status: "blocked",
        httpStatus: 400,
        responsePreview: JSON.stringify(
          {
            success: false,
            error: {
              code: "VALIDATION_ERROR",
              message: "Invalid email format. Query rejected before execution.",
            },
            preparedStatement:
              "SELECT id, email, role FROM users WHERE email = $1",
            boundParameters: [attackPayload],
            returnedRowCount: 0,
          },
          null,
          2
        ),
        defenseMechanism:
          "Parameterized Prepared Statements ($1 placeholder) + Strict Zod Email Schema Validation + Least-Privilege RLS",
        mitigationSummary:
          "Input validation rejected malformed SQL syntax at the API boundary, and parameterized binding ensures any untrusted string is treated strictly as inert data rather than executable SQL syntax.",
      },
      success: true,
      blocked: true,
      animationData: {
        durationMs: 4200,
        nodes: [
          { id: "attacker", label: "Simulated Attacker", type: "attacker" },
          { id: "app", label: "API Route Handler", type: "app" },
          { id: "database", label: "PostgreSQL Database", type: "database" },
        ],
        beforeFrames: [
          {
            step: 1,
            timestampMs: 0,
            from: "attacker",
            to: "app",
            label: `Send crafted SQL tautology payload to ${targetEndpoint}`,
            status: "info",
          },
          {
            step: 2,
            timestampMs: 1100,
            from: "app",
            to: "database",
            label: "Concatenate raw input into SQL string and execute query",
            status: "warning",
          },
          {
            step: 3,
            timestampMs: 2400,
            from: "database",
            to: "app",
            label: "WHERE clause evaluates TRUE for all rows (1,482 records returned)",
            status: "breach",
          },
          {
            step: 4,
            timestampMs: 3600,
            from: "app",
            to: "attacker",
            label: "HTTP 200 OK — Full user table dump leaked in response",
            status: "breach",
          },
        ],
        afterFrames: [
          {
            step: 1,
            timestampMs: 0,
            from: "attacker",
            to: "app",
            label: `Send crafted SQL tautology payload to ${targetEndpoint}`,
            status: "info",
          },
          {
            step: 2,
            timestampMs: 1100,
            from: "app",
            to: "app",
            label: "Zod schema rejects non-email characters; prepared statement binds $1 as literal",
            status: "blocked",
          },
          {
            step: 3,
            timestampMs: 2400,
            from: "app",
            to: "attacker",
            label: "HTTP 400 Bad Request — Attack blocked with zero database rows accessed",
            status: "blocked",
          },
          {
            step: 4,
            timestampMs: 3600,
            from: "database",
            to: "app",
            label: "Database integrity preserved; security telemetry event logged",
            status: "safe",
          },
        ],
      },
      disclaimer: SIMULATION_DISCLAIMER,
    };
  },
};
