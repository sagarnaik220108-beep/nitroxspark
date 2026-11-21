import type {
  FixVulnerabilityInput,
  SecureFixInput,
  SecureFixResult,
  VulnerabilityFixer,
} from "@/types/fix.types";
import {
  buildFixResult,
  isPythonCode,
  normalizeVulnerabilitySearchText,
} from "./base";

const SUPPORTED_RULE_IDS = [
  "SENTINEL-INJ-002",
  "COMMAND-INJECTION",
  "OS-COMMAND",
  "RCE",
] as const;

/**
 * Splits a shell template literal like `ls -la ${dir}` into an executable name
 * and a JS/TS array of string/expression arguments.
 */
function parseTemplateCommand(templateBody: string): {
  cmd: string;
  args: string[];
} | null {
  const tokens = templateBody
    .trim()
    .split(/\s+/)
    .filter((token) => token.length > 0);
  const firstToken = tokens[0];
  if (!firstToken || firstToken.includes("${")) {
    return null;
  }

  const cmd = firstToken.replace(/^["']|["']$/g, "");
  const args = tokens.slice(1).map((token) => {
    const exactInterp = /^\$\{([^}]+)\}$/.exec(token);
    if (exactInterp?.[1]) {
      return `String(${exactInterp[1].trim()})`;
    }
    if (token.includes("${")) {
      return `\`${token}\``;
    }
    const clean = token.replace(/^["']|["']$/g, "");
    return `"${clean.replace(/"/g, '\\"')}"`;
  });

  return { cmd, args };
}

/**
 * Splits a Python f-string or command literal into an argv list string.
 */
function parsePythonCommand(commandBody: string): string | null {
  const tokens = commandBody
    .trim()
    .split(/\s+/)
    .filter((token) => token.length > 0);
  if (tokens.length === 0) return null;

  const pyTokens = tokens.map((token) => {
    const exactInterp = /^\{([^}]+)\}$/.exec(token);
    if (exactInterp?.[1]) {
      return `str(${exactInterp[1].trim()})`;
    }
    if (token.includes("{") && token.includes("}")) {
      return `f"${token.replace(/"/g, '\\"')}"`;
    }
    const clean = token.replace(/^["']|["']$/g, "");
    return `"${clean.replace(/"/g, '\\"')}"`;
  });

  return `[${pyTokens.join(", ")}]`;
}

/**
 * Fixer 6: OS Command Injection
 * - Replaces Node.js `exec(\`cmd \${arg}\`)` / `execSync(...)` with `execFile(cmd, [args], { shell: false })` / `execFileSync(...)`
 * - Updates `child_process` imports to include `execFile` / `execFileSync`
 * - Replaces Python `subprocess.run(..., shell=True)` with `shell=False` and list-form argv
 * - Replaces Python `os.system(...)` with `subprocess.run([...], shell=False, check=True)`
 */
export const commandInjectionFixer: VulnerabilityFixer = {
  id: "fixer-command-injection",
  name: "OS Command Injection Fixer",
  description:
    "Replaces shell-invoking exec()/execSync() calls with execFile()/execFileSync(..., { shell: false }) and disables shell=True in Python subprocess calls.",
  supportedRuleIds: SUPPORTED_RULE_IDS,
  supportedCategories: ["injection"],

  canHandle(vulnerability: FixVulnerabilityInput): boolean {
    const text = normalizeVulnerabilitySearchText(vulnerability);
    if (
      SUPPORTED_RULE_IDS.some(
        (id) => id.toLowerCase() === vulnerability.ruleId.trim().toLowerCase()
      )
    ) {
      return true;
    }
    return (
      text.includes("command injection") ||
      text.includes("os command") ||
      text.includes("shell=true") ||
      text.includes("execsync") ||
      text.includes("os.system") ||
      text.includes("cwe-78")
    );
  },

  apply(input: SecureFixInput): SecureFixResult {
    const { originalCode, vulnerability } = input;
    const python = isPythonCode(originalCode, vulnerability.language);
    let secureCode = originalCode;
    let introducedExecFile = false;
    let introducedExecFileSync = false;
    let needsSubprocessImport = false;

    if (python) {
      // 1. subprocess.run(f"cmd {arg}", shell=True) -> subprocess.run(["cmd", str(arg)], shell=False)
      secureCode = secureCode.replace(
        /\bsubprocess\.(run|Popen|call)\s*\(\s*f(["'])(.+?)\2([^)]*?)shell\s*=\s*True/g,
        (_m, fnName: string, _q: string, cmdBody: string, rest: string) => {
          const argvList = parsePythonCommand(cmdBody);
          if (argvList) {
            return `subprocess.${fnName}(${argvList}${rest}shell=False`;
          }
          return `subprocess.${fnName}(f"${cmdBody}"${rest}shell=False`;
        }
      );

      // 2. Any remaining subprocess.*(..., shell=True) -> shell=False
      secureCode = secureCode.replace(
        /\b(subprocess\.(?:run|Popen|call)\s*\([^)]*?)shell\s*=\s*True/g,
        "$1shell=False"
      );

      // 3. os.system(f"cmd {arg}") -> subprocess.run(["cmd", str(arg)], shell=False, check=True)
      secureCode = secureCode.replace(
        /\bos\.system\s*\(\s*f(["'])(.+?)\1\s*\)/g,
        (_m, _q: string, cmdBody: string) => {
          needsSubprocessImport = true;
          const argvList = parsePythonCommand(cmdBody) ?? `[${cmdBody}]`;
          return `subprocess.run(${argvList}, shell=False, check=True)`;
        }
      );

      // 4. os.system("cmd " + arg) -> subprocess.run(["cmd", str(arg)], shell=False, check=True)
      secureCode = secureCode.replace(
        /\bos\.system\s*\(\s*(["'])([^"']+)\1\s*\+\s*([^)]+)\)/g,
        (_m, _q: string, prefix: string, argExpr: string) => {
          needsSubprocessImport = true;
          const prefixTokens = prefix
            .trim()
            .split(/\s+/)
            .filter(Boolean)
            .map((t) => `"${t}"`);
          prefixTokens.push(`str(${argExpr.trim()})`);
          return `subprocess.run([${prefixTokens.join(", ")}], shell=False, check=True)`;
        }
      );

      if (
        needsSubprocessImport &&
        !/^\s*import\s+subprocess\b/m.test(secureCode)
      ) {
        secureCode = `import subprocess\n${secureCode}`;
      }
    } else {
      // 1. exec(`cmd arg ${var}`, cb?) or execSync(`cmd arg ${var}`)
      secureCode = secureCode.replace(
        /\b(exec|execSync)\s*\(\s*`([^`]*\$\{[^}]+\}[^`]*)`(\s*,\s*([^)]+))?\s*\)/g,
        (
          fullMatch,
          fnName: string,
          templateBody: string,
          _commaGroup?: string,
          trailingArg?: string
        ) => {
          const parsed = parseTemplateCommand(templateBody);
          if (!parsed) return fullMatch;

          const safeFn = fnName === "execSync" ? "execFileSync" : "execFile";
          if (safeFn === "execFile") introducedExecFile = true;
          if (safeFn === "execFileSync") introducedExecFileSync = true;

          const argsArray = `[${parsed.args.join(", ")}]`;
          const trailing = trailingArg?.trim()
            ? `, ${trailingArg.trim()}`
            : "";

          return `${safeFn}("${parsed.cmd}", ${argsArray}, { shell: false }${trailing})`;
        }
      );

      // 2. exec("cmd arg " + userInput, cb?) or execSync("cmd arg " + userInput)
      secureCode = secureCode.replace(
        /\b(exec|execSync)\s*\(\s*["']([^"']+)["']\s*\+\s*([^,)]+)(\s*,\s*([^)]+))?\s*\)/g,
        (
          fullMatch,
          fnName: string,
          prefixCmd: string,
          varExpr: string,
          _commaGroup?: string,
          trailingArg?: string
        ) => {
          const tokens = prefixCmd
            .trim()
            .split(/\s+/)
            .filter((t) => t.length > 0);
          const cmd = tokens[0];
          if (!cmd) return fullMatch;

          const safeFn = fnName === "execSync" ? "execFileSync" : "execFile";
          if (safeFn === "execFile") introducedExecFile = true;
          if (safeFn === "execFileSync") introducedExecFileSync = true;

          const argItems = [
            ...tokens.slice(1).map((t) => `"${t.replace(/"/g, '\\"')}"`),
            `String(${varExpr.trim()})`,
          ];
          const trailing = trailingArg?.trim()
            ? `, ${trailingArg.trim()}`
            : "";

          return `${safeFn}("${cmd}", [${argItems.join(", ")}], { shell: false }${trailing})`;
        }
      );

      // 3. Update child_process import if we switched exec -> execFile / execSync -> execFileSync
      if (introducedExecFile) {
        secureCode = secureCode.replace(
          /import\s*\{([^}]*)\bexec\b([^}]*)\}\s*from\s*["'](?:node:)?child_process["']/g,
          (match, before: string, after: string) => {
            if (match.includes("execFile")) return match;
            return `import {${before}execFile${after}} from "node:child_process"`;
          }
        );
      }
      if (introducedExecFileSync) {
        secureCode = secureCode.replace(
          /import\s*\{([^}]*)\bexecSync\b([^}]*)\}\s*from\s*["'](?:node:)?child_process["']/g,
          (match, before: string, after: string) => {
            if (match.includes("execFileSync")) return match;
            return `import {${before}execFileSync${after}} from "node:child_process"`;
          }
        );
      }
    }

    return buildFixResult({
      fixerId: this.id,
      originalCode,
      secureCode,
      severity: vulnerability.severity,
      reason:
        "Replaced shell command interpolation with non-shell argument-array execution (execFile / shell: false / shell=False).",
      summary:
        "Eliminated OS command injection by passing arguments as an explicit array with shell execution disabled.",
      rationale:
        "Invoking executables directly with shell disabled prevents shell metacharacters (;, &&, |, $()) from being interpreted as additional OS commands.",
    });
  },
};
