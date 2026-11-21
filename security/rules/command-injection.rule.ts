import type { SecurityRule } from "@/types";
import { createRegexRule } from "./base";

/**
 * Rule 6: Command Injection
 * Detects OS shell invocation functions executed with interpolated/concatenated input
 * or explicit shell=true execution modes.
 */
export const commandInjectionRule: SecurityRule = createRegexRule({
  id: "SENTINEL-CMDI-001",
  name: "Command Injection",
  description:
    "Detects OS command execution sinks (exec, execSync, spawn with shell: true, os.system, subprocess with shell=True, PHP shell_exec) invoked with untrusted or dynamic input.",
  explanation:
    "Passing unvalidated input into a shell interpreter allows attackers to append shell metacharacters (`;`, `&&`, `|`, `$()`) and execute arbitrary operating system commands on the server, resulting in full Remote Code Execution (RCE).",
  severity: "critical",
  category: "injection",
  cweId: "CWE-78",
  owaspCategory: "A03:2021 - Injection",
  languages: [
    "typescript",
    "javascript",
    "python",
    "php",
    "ruby",
    "go",
    "java",
  ],
  tags: ["command-injection", "rce", "shell", "os-command", "cwe-78"],
  confidence: 0.93,
  patterns: [
    /\b(?:exec|execSync)\s*\(\s*`[^`]*\$\{[^}]+\}[^`]*`/g,
    /\b(?:exec|execSync)\s*\(\s*["'][^"']*["']\s*\+/g,
    /\b(?:spawn|spawnSync|execFile|execFileSync)\s*\([\s\S]{0,200}\bshell\s*:\s*true\b/g,
    /\bos\.(?:system|popen)\s*\([^)]*(?:\+|f["']|%|\.format)/g,
    /\bsubprocess\.(?:run|Popen|call|check_output|check_call)\s*\([^)]*\bshell\s*=\s*True\b/g,
    /\b(?:shell_exec|system|passthru|proc_open)\s*\([^)]*\$/g,
  ],
  remediation: {
    summary:
      "Avoid shell interpreters; invoke binaries directly via execFile/spawn with shell: false, an argument array, and strict allowlist input validation.",
    explanation:
      "Use `execFile` or `spawn` with `shell: false` (or `subprocess.run([...], shell=False)` in Python) so arguments are passed directly to `execve` without shell parsing, and validate every dynamic argument against a strict allowlist.",
    secureCodeExample: `import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export async function listSafeFile(fileName: string): Promise<string> {
  if (!/^[a-zA-Z0-9._-]+$/.test(fileName)) {
    throw new Error("Invalid file name");
  }
  const { stdout } = await execFileAsync("ls", ["-la", fileName], {
    shell: false,
  });
  return stdout;
}`,
    references: [
      "https://owasp.org/www-community/attacks/Command_Injection",
      "https://cwe.mitre.org/data/definitions/78.html",
    ],
  },
});
