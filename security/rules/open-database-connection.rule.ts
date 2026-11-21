import type { RuleContext, RuleMatch, SecurityRule } from "@/types";
import {
  extractCodeSnippet,
  offsetToLineColumn,
  redactSecretValue,
} from "@/utils";

const HARDCODED_DB_URI_REGEX =
  /(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|mssql):\/\/[^:\s"'`]+:[^@\s"'`]{3,}@[^\s"'`]+/gi;

const SSL_DISABLED_PATTERNS: readonly { regex: RegExp; reason: string }[] = [
  {
    regex: /\bsslmode\s*=\s*disable\b/gi,
    reason:
      "Database connection explicitly disables TLS (`sslmode=disable`), exposing credentials and query data to network eavesdropping and MITM attacks.",
  },
  {
    regex: /\b(?:useSSL|tls|ssl)\s*[:=]\s*false\b/gi,
    reason:
      "Database TLS/SSL encryption is explicitly disabled, allowing plaintext interception of database traffic.",
  },
  {
    regex: /\brejectUnauthorized\s*:\s*false\b/g,
    reason:
      "TLS certificate verification is disabled (`rejectUnauthorized: false`), enabling Man-in-the-Middle attacks against the database connection.",
  },
];

const PUBLIC_DB_BIND_PATTERNS: readonly { regex: RegExp; reason: string }[] = [
  {
    regex: /\b(?:bind_address|bind-address|bindIp|listen_addresses)\s*[:=]\s*["']?(?:0\.0\.0\.0|\*)["']?/gi,
    reason:
      "Database server is bound to all network interfaces (`0.0.0.0` or `*`), exposing the database port to untrusted networks.",
  },
  {
    regex: /\bhost\s*[:=]\s*["']0\.0\.0\.0["']/g,
    reason:
      "Connection or service binds to public wildcard host `0.0.0.0`, increasing exposure to unauthorized network access.",
  },
];

const DIRECT_CONNECTION_PATTERNS: readonly {
  regex: RegExp;
  cleanupCheck: RegExp;
  reason: string;
}[] = [
  {
    regex: /\bnew\s+(?:pg\.)?Client\s*\(/g,
    cleanupCheck: /\.end\s*\(|\.release\s*\(|finally\s*\{/,
    reason:
      "Direct PostgreSQL `new Client()` created without connection pooling or a visible `.end()` cleanup call, risking connection exhaustion and dangling open sockets.",
  },
  {
    regex: /\bmysql2?\.createConnection\s*\(/g,
    cleanupCheck: /\.end\s*\(|\.destroy\s*\(|finally\s*\{/,
    reason:
      "Unpooled MySQL `createConnection()` opened without a visible `.end()`/`.destroy()` cleanup handler, risking leaked database connections.",
  },
  {
    regex: /\b(?:psycopg2|sqlite3|pymysql)\.connect\s*\(/g,
    cleanupCheck: /\bwith\s+.*connect\s*\(|\.close\s*\(/,
    reason:
      "Direct Python database connection opened without a `with` context manager or `.close()` call, risking leaked open database connections.",
  },
];

/**
 * Rule 11: Open Database Connection
 * Detects hardcoded credentials in database URIs, disabled SSL/TLS, public 0.0.0.0 DB binds,
 * and unpooled/unclosed direct database connections.
 */
export const openDatabaseConnectionRule: SecurityRule = {
  id: "SENTINEL-DB-001",
  name: "Open or Insecure Database Connection",
  description:
    "Detects insecure database connections including hardcoded credentials in connection strings, disabled SSL/TLS (sslmode=disable), public 0.0.0.0 binds, and unclosed or unpooled direct connections.",
  explanation:
    "Insecurely configured or unclosed database connections can expose sensitive credentials in source code, transmit database traffic in plaintext over untrusted networks, accept unauthorized external connections on `0.0.0.0`, or exhaust database connection limits causing Denial of Service.",
  severity: "high",
  category: "misconfiguration",
  cweId: "CWE-200",
  owaspCategory: "A05:2021 - Security Misconfiguration",
  languages: "*",
  tags: ["database", "tls", "connection-pool", "credentials", "cwe-200"],
  enabledByDefault: true,
  remediation: {
    summary:
      "Load DATABASE_URL from environment variables, enforce TLS (`sslmode=require`), restrict binds to private interfaces, and use managed connection pooling with guaranteed cleanup.",
    explanation:
      "Never embed database credentials in code or disable SSL verification. Use a shared `Pool` (or serverless pooler like Supabase Supavisor/PgBouncer) and ensure any dedicated client is closed inside a `try/finally` block.",
    secureCodeExample: `import { Pool } from "pg";

// Secure: Pooled connection using environment variable and enforced TLS
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: true },
  max: 10,
  idleTimeoutMillis: 30_000,
});

export async function queryUsers() {
  const client = await pool.connect();
  try {
    return await client.query("SELECT id, email FROM users LIMIT 50");
  } finally {
    client.release();
  }
}`,
    references: [
      "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
      "https://cwe.mitre.org/data/definitions/200.html",
    ],
  },

  evaluate(context: RuleContext): RuleMatch[] {
    const matches: RuleMatch[] = [];
    const seenLineCols = new Set<string>();

    const addMatch = (
      offset: number,
      rawText: string,
      reason: string,
      confidence: number,
      redact = false
    ) => {
      const startPos = offsetToLineColumn(context.code, offset);
      const endPos = offsetToLineColumn(context.code, offset + rawText.length);
      const key = `${startPos.line}:${startPos.column}`;
      if (seenLineCols.has(key)) return;
      seenLineCols.add(key);

      const trimmed = rawText.trim();
      const matchedText = redact
        ? redactSecretValue(trimmed)
        : trimmed.slice(0, 220);
      let snippet = extractCodeSnippet(context.lines, startPos.line);
      if (redact && trimmed.length > 0) {
        snippet = snippet.replaceAll(trimmed, matchedText);
      }

      matches.push({
        line: startPos.line,
        column: startPos.column,
        endLine: endPos.line,
        endColumn: endPos.column,
        matchedText,
        snippet,
        confidence,
        customExplanation: reason,
      });
    };

    // 1. Hardcoded credentials in DB connection strings
    const uriRegex = new RegExp(
      HARDCODED_DB_URI_REGEX.source,
      HARDCODED_DB_URI_REGEX.flags
    );
    let match: RegExpExecArray | null;
    while ((match = uriRegex.exec(context.code)) !== null) {
      const raw = match[0];
      if (/example|placeholder|user:pass@/i.test(raw)) continue;
      addMatch(
        match.index,
        raw,
        "Database connection string contains hardcoded username and password credentials.",
        0.95,
        true
      );
    }

    // 2. SSL/TLS disabled
    for (const item of SSL_DISABLED_PATTERNS) {
      const regex = new RegExp(item.regex.source, item.regex.flags);
      while ((match = regex.exec(context.code)) !== null) {
        addMatch(match.index, match[0], item.reason, 0.91);
      }
    }

    // 3. Public 0.0.0.0 DB binds
    for (const item of PUBLIC_DB_BIND_PATTERNS) {
      const regex = new RegExp(item.regex.source, item.regex.flags);
      while ((match = regex.exec(context.code)) !== null) {
        addMatch(match.index, match[0], item.reason, 0.87);
      }
    }

    // 4. Unclosed / unpooled direct DB connections
    for (const item of DIRECT_CONNECTION_PATTERNS) {
      const regex = new RegExp(item.regex.source, item.regex.flags);
      while ((match = regex.exec(context.code)) !== null) {
        if (!item.cleanupCheck.test(context.code)) {
          addMatch(match.index, match[0], item.reason, 0.83);
        }
      }
    }

    return matches;
  },
};
