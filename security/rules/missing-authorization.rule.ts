import type { RuleContext, RuleMatch, SecurityRule } from "@/types";
import { extractCodeSnippet, offsetToLineColumn } from "@/utils";

const AUTHZ_GUARD_PATTERN =
  /\b(?:getUser|getSession|requireAuth|requireAdmin|requireRole|verifyToken|verifySession|jwt\.verify|auth\(|checkPermission|authorize|hasRole|isAdmin|currentUser|req\.user|session\.user|x-api-key|authorization)\b/i;

const SENSITIVE_OPERATION_PATTERN =
  /\b(?:delete|destroy|remove|drop|update|insert|create|upsert|admin|role|permission|billing|invoice|payout|prisma\.\w+\.(?:delete|update|create)|supabase\.from\([^)]+\)\.(?:delete|update|insert))\b/i;

const ROUTE_HANDLER_PATTERNS: readonly RegExp[] = [
  /export\s+(?:async\s+)?function\s+(?:POST|PUT|PATCH|DELETE)\s*\([^)]*\)\s*\{/g,
  /\b(?:app|router)\.(?:post|put|patch|delete)\s*\(\s*["'`][^"'`]+["'`]\s*,\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{/gi,
  /@(?:app|router)\.(?:post|put|patch|delete)\s*\([^)]*\)\s*\r?\n\s*(?:async\s+)?def\s+\w+\s*\([^)]*\)\s*:/gi,
];

const OPEN_ACCESS_PATTERNS: readonly { regex: RegExp; reason: string }[] = [
  {
    regex: /\b(?:allowAll|publicAdmin|skipAuthorization|disableRbac)\s*[:=]\s*true\b/gi,
    reason:
      "Explicit authorization bypass flag enables unrestricted access to protected resources.",
  },
  {
    regex:
      /Access-Control-Allow-Origin["']?\s*[:=]\s*["']\*["'][\s\S]{0,160}Access-Control-Allow-Credentials["']?\s*[:=]\s*["']?true["']?/gi,
    reason:
      "Combining wildcard CORS origin ('*') with credentials allows cross-origin authenticated requests from untrusted sites.",
  },
];

function extractHandlerWindow(code: string, startIndex: number): string {
  return code.slice(startIndex, Math.min(code.length, startIndex + 900));
}

/**
 * Rule 9: Missing Authorization
 * Detects mutating API routes performing sensitive operations without authentication/authorization checks,
 * explicit RBAC bypass flags, or overly permissive authenticated CORS configurations.
 */
export const missingAuthorizationRule: SecurityRule = {
  id: "SENTINEL-AUTHZ-001",
  name: "Missing Authorization",
  description:
    "Detects mutating API endpoints performing sensitive database or admin operations without visible authentication or role-based access control checks, as well as explicit access-control bypasses.",
  explanation:
    "Missing server-side authorization checks (Broken Access Control) allow unauthenticated or low-privilege attackers to invoke mutating endpoints directly, modify or delete other users' data (IDOR), or perform unauthorized administrative actions.",
  severity: "high",
  category: "authorization",
  cweId: "CWE-862",
  owaspCategory: "A01:2021 - Broken Access Control",
  languages: ["typescript", "javascript", "python", "go", "php", "java"],
  tags: ["authorization", "access-control", "idor", "rbac", "cwe-862"],
  enabledByDefault: true,
  remediation: {
    summary:
      "Verify the caller's identity and role/ownership on the server before executing any mutating or sensitive operation.",
    explanation:
      "Always authenticate the session server-side (e.g., `supabase.auth.getUser()` or verified JWT middleware) and enforce explicit ownership or role checks (`record.userId === user.id` or `user.role === 'admin'`) before mutating records.",
    secureCodeExample: `import { NextResponse } from "next/server";
import { createServerSupabaseClient } from "@/lib/supabase/server";

export async function DELETE(
  _req: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const supabase = await createServerSupabaseClient();
  const { data: { user }, error } = await supabase.auth.getUser();
  if (error || !user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { id } = await params;
  // Enforce resource ownership in the query (and via RLS)
  await supabase.from("projects").delete().eq("id", id).eq("user_id", user.id);
  return NextResponse.json({ deleted: true });
}`,
    references: [
      "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
      "https://cwe.mitre.org/data/definitions/862.html",
    ],
  },

  evaluate(context: RuleContext): RuleMatch[] {
    const matches: RuleMatch[] = [];
    const seenLines = new Set<number>();

    // 1. Check mutating route handlers lacking auth/authz guards
    for (const sourcePattern of ROUTE_HANDLER_PATTERNS) {
      const regex = new RegExp(sourcePattern.source, sourcePattern.flags);
      let match: RegExpExecArray | null;
      while ((match = regex.exec(context.code)) !== null) {
        if (match[0].length === 0) {
          regex.lastIndex += 1;
          continue;
        }

        const handlerBody = extractHandlerWindow(context.code, match.index);
        const performsSensitiveOp = SENSITIVE_OPERATION_PATTERN.test(handlerBody);
        const hasAuthzCheck = AUTHZ_GUARD_PATTERN.test(handlerBody);

        if (performsSensitiveOp && !hasAuthzCheck) {
          const startPos = offsetToLineColumn(context.code, match.index);
          const endPos = offsetToLineColumn(
            context.code,
            match.index + match[0].length
          );
          if (!seenLines.has(startPos.line)) {
            seenLines.add(startPos.line);
            matches.push({
              line: startPos.line,
              column: startPos.column,
              endLine: endPos.line,
              endColumn: endPos.column,
              matchedText: match[0].trim().slice(0, 200),
              snippet: extractCodeSnippet(context.lines, startPos.line),
              confidence: 0.82,
              customExplanation:
                "Mutating route handler executes sensitive database or state-changing operations without a visible server-side authentication or authorization check.",
            });
          }
        }
      }
    }

    // 2. Check explicit access-control bypass patterns
    for (const item of OPEN_ACCESS_PATTERNS) {
      const regex = new RegExp(item.regex.source, item.regex.flags);
      let match: RegExpExecArray | null;
      while ((match = regex.exec(context.code)) !== null) {
        if (match[0].length === 0) {
          regex.lastIndex += 1;
          continue;
        }
        const startPos = offsetToLineColumn(context.code, match.index);
        const endPos = offsetToLineColumn(
          context.code,
          match.index + match[0].length
        );
        if (!seenLines.has(startPos.line)) {
          seenLines.add(startPos.line);
          matches.push({
            line: startPos.line,
            column: startPos.column,
            endLine: endPos.line,
            endColumn: endPos.column,
            matchedText: match[0].trim().slice(0, 200),
            snippet: extractCodeSnippet(context.lines, startPos.line),
            confidence: 0.9,
            customExplanation: item.reason,
          });
        }
      }
    }

    return matches;
  },
};
