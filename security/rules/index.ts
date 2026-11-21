import type { SecurityRule } from "@/types";
import { commandInjectionRule } from "./command-injection.rule";
import { exposedEnvVarsRule } from "./exposed-env-vars.rule";
import { hardcodedApiKeysRule } from "./hardcoded-api-keys.rule";
import { hardcodedPasswordsRule } from "./hardcoded-passwords.rule";
import { jwtSecretsRule } from "./jwt-secrets.rule";
import { missingAuthorizationRule } from "./missing-authorization.rule";
import { openDatabaseConnectionRule } from "./open-database-connection.rule";
import { outdatedPackagesRule } from "./outdated-packages.rule";
import { sqlInjectionRule } from "./sql-injection.rule";
import { unsafeEvalRule } from "./unsafe-eval.rule";
import { weakAuthenticationRule } from "./weak-authentication.rule";
import { xssRule } from "./xss.rule";

/**
 * Central registry list of all 12 modular built-in Sentinel AI security rules.
 *
 * HOW TO ADD A NEW RULE:
 * 1. Create a dedicated rule module under `security/rules/<name>.rule.ts`
 *    implementing `SecurityRule` (or using `createRegexRule(...)`).
 * 2. Export it individually below and append it to `BUILT_IN_RULES`.
 *    It will automatically be loaded by `RuleRegistry`, `SecurityEngine`,
 *    `SecurityAnalysisEngine`, and `/api/analyze`.
 */
export const BUILT_IN_RULES: readonly SecurityRule[] = [
  hardcodedApiKeysRule,
  hardcodedPasswordsRule,
  jwtSecretsRule,
  sqlInjectionRule,
  xssRule,
  commandInjectionRule,
  unsafeEvalRule,
  weakAuthenticationRule,
  missingAuthorizationRule,
  outdatedPackagesRule,
  openDatabaseConnectionRule,
  exposedEnvVarsRule,
];

export {
  commandInjectionRule,
  exposedEnvVarsRule,
  hardcodedApiKeysRule,
  hardcodedPasswordsRule,
  jwtSecretsRule,
  missingAuthorizationRule,
  openDatabaseConnectionRule,
  outdatedPackagesRule,
  sqlInjectionRule,
  unsafeEvalRule,
  weakAuthenticationRule,
  xssRule,
};

export { compileCustomRule, createRegexRule } from "./base";
