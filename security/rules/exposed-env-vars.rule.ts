import type { RuleContext, RuleMatch, SecurityRule } from "@/types";
import { extractCodeSnippet, offsetToLineColumn } from "@/utils";

const CLIENT_PUBLIC_SECRET_ENV_REGEX =
  /\b(?:NEXT_PUBLIC|VITE|REACT_APP|NUXT_PUBLIC)_[A-Z0-9_]*(?:SECRET|PRIVATE|SERVICE_ROLE|API_KEY|ACCESS_KEY|TOKEN|PASSWORD|PASSWD|DB_URL|DATABASE_URL|JWT|STRIPE_SK|OPENAI_KEY|ANTHROPIC_KEY)\b/g;

const LOG_ENV_PATTERNS: readonly RegExp[] = [
  /\bconsole\.(?:log|info|debug|warn|error|dir)\s*\([^)]*\bprocess\.env\b/g,
  /\bprint\s*\([^)]*\bos\.environ\b/g,
  /\blogger\.(?:info|debug|warn|error)\s*\([^)]*\bprocess\.env\b/g,
];

const RESPONSE_ENV_PATTERNS: readonly RegExp[] = [
  /\b(?:NextResponse\.json|Response\.json|res\.json|res\.send)\s*\([^)]*\bprocess\.env\b/g,
  /\breturn\s+\{[^}]*\.\.\.process\.env[^}]*\}/g,
  /\bJSON\.stringify\s*\(\s*process\.env\b/g,
];

const CLIENT_BUNDLE_SECRET_REGEX =
  /\bprocess\.env\.(?!NODE_ENV\b|NEXT_PUBLIC_|VITE_|REACT_APP_)[A-Z0-9_]*(?:SECRET|PRIVATE|SERVICE_ROLE|PASSWORD|DATABASE_URL|JWT|API_KEY|TOKEN)[A-Z0-9_]*\b/g;

/**
 * Rule 12: Exposed Environment Variables
 * Detects NEXT_PUBLIC_/VITE_/REACT_APP_ secrets, logging process.env,
 * returning process.env in API responses, or referencing server secrets in client components.
 */
export const exposedEnvVarsRule: SecurityRule = {
  id: "SENTINEL-ENV-001",
  name: "Exposed Environment Variables",
  description:
    "Detects server secrets exposed via client-public prefixes (NEXT_PUBLIC_*, VITE_*), logging process.env/os.environ, returning environment objects in API responses, or referencing server secrets inside client components.",
  explanation:
    "Environment variables prefixed with `NEXT_PUBLIC_`, logged to stdout, or serialized into HTTP responses are exposed directly to end users, browsers, and log aggregators—leaking database credentials, signing secrets, and third-party API keys.",
  severity: "critical",
  category: "secrets",
  cweId: "CWE-200",
  owaspCategory: "A05:2021 - Security Misconfiguration",
  languages: ["typescript", "javascript", "python", "unknown"],
  tags: ["env-vars", "secrets", "next-public", "data-leak", "cwe-200"],
  enabledByDefault: true,
  remediation: {
    summary:
      "Keep secrets in server-only environment variables (without NEXT_PUBLIC_ prefix), never log or serialize process.env, and access secrets strictly inside server-side routes or Server Actions.",
    explanation:
      "Rename any secret prefixed with `NEXT_PUBLIC_` to a server-only name, rotate the exposed value, remove all `process.env` logging/responses, and proxy third-party API calls through a server Route Handler.",
    secureCodeExample: `// Secure: Server-only Route Handler (never use NEXT_PUBLIC_ for secrets)
import { NextResponse } from "next/server";

export async function GET() {
  const apiKey = process.env.INTERNAL_API_KEY;
  if (!apiKey) {
    return NextResponse.json(
      { error: "Server configuration missing" },
      { status: 500 }
    );
  }
  // Use apiKey strictly on the server; return only non-sensitive data
  return NextResponse.json({ status: "ok" });
}`,
    references: [
      "https://nextjs.org/docs/app/building-your-application/configuring/environment-variables#bundling-environment-variables-for-the-browser",
      "https://cwe.mitre.org/data/definitions/200.html",
    ],
  },

  evaluate(context: RuleContext): RuleMatch[] {
    const matches: RuleMatch[] = [];
    const seenLineCols = new Set<string>();

    const record = (
      offset: number,
      matchedText: string,
      explanation: string,
      confidence: number
    ) => {
      const startPos = offsetToLineColumn(context.code, offset);
      const endPos = offsetToLineColumn(
        context.code,
        offset + matchedText.length
      );
      const key = `${startPos.line}:${startPos.column}`;
      if (seenLineCols.has(key)) return;
      seenLineCols.add(key);

      matches.push({
        line: startPos.line,
        column: startPos.column,
        endLine: endPos.line,
        endColumn: endPos.column,
        matchedText: matchedText.trim().slice(0, 220),
        snippet: extractCodeSnippet(context.lines, startPos.line),
        confidence,
        customExplanation: explanation,
      });
    };

    let match: RegExpExecArray | null;

    // 1. NEXT_PUBLIC_* / VITE_* / REACT_APP_* secret variables
    const publicSecretRegex = new RegExp(
      CLIENT_PUBLIC_SECRET_ENV_REGEX.source,
      CLIENT_PUBLIC_SECRET_ENV_REGEX.flags
    );
    while ((match = publicSecretRegex.exec(context.code)) !== null) {
      record(
        match.index,
        match[0],
        `Sensitive variable "${match[0]}" uses a public client-bundle prefix and will be embedded into browser JavaScript.`,
        0.95
      );
    }

    // 2. Logging process.env / os.environ
    for (const pattern of LOG_ENV_PATTERNS) {
      const regex = new RegExp(pattern.source, pattern.flags);
      while ((match = regex.exec(context.code)) !== null) {
        record(
          match.index,
          match[0],
          "Logging environment variables writes server secrets into application logs and observability pipelines.",
          0.92
        );
      }
    }

    // 3. Returning process.env in HTTP responses or JSON serialization
    for (const pattern of RESPONSE_ENV_PATTERNS) {
      const regex = new RegExp(pattern.source, pattern.flags);
      while ((match = regex.exec(context.code)) !== null) {
        record(
          match.index,
          match[0],
          "Serializing or returning `process.env` in an API response leaks all runtime secrets to external callers.",
          0.96
        );
      }
    }

    // 4. Referencing server-only secrets inside a "use client" module
    const isClientComponent = /^\s*["']use client["'];?/m.test(context.code);
    if (isClientComponent) {
      const clientSecretRegex = new RegExp(
        CLIENT_BUNDLE_SECRET_REGEX.source,
        CLIENT_BUNDLE_SECRET_REGEX.flags
      );
      while ((match = clientSecretRegex.exec(context.code)) !== null) {
        record(
          match.index,
          match[0],
          `Server secret "${match[0]}" is referenced inside a "use client" component, risking accidental client bundle exposure or misconfiguration.`,
          0.9
        );
      }
    }

    return matches;
  },
};
