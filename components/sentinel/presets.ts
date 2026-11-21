import type { SupportedLanguage } from "@/types";

export interface CodePreset {
  id: string;
  label: string;
  fileName: string;
  language: SupportedLanguage;
  description: string;
  code: string;
}

export const CODE_PRESETS: readonly CodePreset[] = [
  {
    id: "nextjs-auth-sql",
    label: "Next.js Auth & SQL Route (TS)",
    fileName: "app/api/auth/login/route.ts",
    language: "typescript",
    description:
      "AI-generated Next.js login & admin route containing SQL injection, hardcoded JWT secret, weak password comparison, and missing authorization.",
    code: `import { NextResponse } from "next/server";
import jwt from "jsonwebtoken";
import { db } from "@/lib/db";

const JWT_SECRET = "super-secret-jwt-signing-key-2025";

export async function POST(request: Request) {
  const { email, password } = await request.json();

  // Vulnerable: direct string interpolation into SQL query
  const query = \`SELECT id, email, role, password FROM users WHERE email = '\${email}'\`;
  const result = await db.query(query);
  const user = result.rows[0];

  // Vulnerable: plaintext password check without constant-time hashing
  if (!user || user.password != password) {
    return NextResponse.json({ error: "Invalid credentials" }, { status: 401 });
  }

  const token = jwt.sign(
    { userId: user.id, role: user.role },
    JWT_SECRET,
    { algorithm: "HS256" }
  );

  return NextResponse.json({ token, user });
}

export async function DELETE(request: Request) {
  const { searchParams } = new URL(request.url);
  const userId = searchParams.get("id");

  // Vulnerable: admin delete endpoint with no auth or role verification
  await db.query(\`DELETE FROM users WHERE id = '\${userId}'\`);
  return NextResponse.json({ deleted: true });
}
`,
  },
  {
    id: "stripe-secrets-service",
    label: "Stripe & Secrets Service (TS)",
    fileName: "lib/billing-service.ts",
    language: "typescript",
    description:
      "Payment and database helper with hardcoded Stripe API key, plaintext DB credentials, open 0.0.0.0 connection string, and client-exposed secret env var.",
    code: `import Stripe from "stripe";
import { Pool } from "pg";

// Vulnerable: hardcoded live-format API key and admin password
const STRIPE_API_KEY = "stripe_mock_secret_key_prod_sample_987654";
const DB_PASSWORD = "ProdAdminPassword!2025";

// Vulnerable: unencrypted database connection bound to public host
const databaseUrl = "postgres://admin:ProdAdminPassword!2025@0.0.0.0:5432/billing_prod?sslmode=disable";

export const stripe = new Stripe(STRIPE_API_KEY);
export const pool = new Pool({ connectionString: databaseUrl });

// Vulnerable: secret exposed via NEXT_PUBLIC_ prefix and logged
export const PUBLIC_WEBHOOK_SECRET = process.env.NEXT_PUBLIC_STRIPE_WEBHOOK_SECRET;

export async function createInvoice(customerId: string, amountCents: number) {
  console.log("Initializing billing with env:", process.env);

  const invoice = await stripe.invoiceItems.create({
    customer: customerId,
    amount: amountCents,
    currency: "usd",
  });

  await pool.query(
    \`INSERT INTO invoices (customer_id, amount) VALUES ('\${customerId}', \${amountCents})\`
  );

  return invoice;
}
`,
  },
  {
    id: "react-xss-eval",
    label: "React XSS & Eval Widget (TSX)",
    fileName: "components/AnalyticsWidget.tsx",
    language: "typescript",
    description:
      "Client-side React component using dangerouslySetInnerHTML with unsanitized markup, dynamic eval() formula execution, and leaked NEXT_PUBLIC secret.",
    code: `"use client";

import { useEffect, useState } from "react";

interface WidgetProps {
  userBioHtml: string;
  metricFormula: string;
}

export function AnalyticsWidget({ userBioHtml, metricFormula }: WidgetProps) {
  const [computedValue, setComputedValue] = useState<string>("0");

  useEffect(() => {
    // Vulnerable: executing untrusted formula string via eval()
    const result = eval(metricFormula);
    setComputedValue(String(result));

    // Vulnerable: leaking secret key in client bundle
    const internalToken = process.env.NEXT_PUBLIC_ANALYTICS_API_SECRET;
    if (internalToken) {
      document.getElementById("debug-banner")!.innerHTML = userBioHtml;
    }
  }, [metricFormula, userBioHtml]);

  return (
    <section className="rounded-xl p-4">
      <h3>Live Metric: {computedValue}</h3>
      {/* Vulnerable: unescaped HTML injection sink */}
      <div dangerouslySetInnerHTML={{ __html: userBioHtml }} />
      <div id="debug-banner" />
    </section>
  );
}
`,
  },
  {
    id: "python-subprocess-env",
    label: "Python Subprocess & Env (PY)",
    fileName: "scripts/deploy_worker.py",
    language: "python",
    description:
      "Python automation worker vulnerable to OS command injection via shell=True, hardcoded AWS credentials, SQL string interpolation, and unsafe eval().",
    code: `import os
import sqlite3
import subprocess

# Vulnerable: hardcoded cloud credentials and admin password
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
ADMIN_PASSWORD = "SuperSecretDeployPassword123!"

def archive_tenant_logs(tenant_id: str, filter_expr: str):
    # Vulnerable: OS command injection via shell=True with user input
    cmd = f"tar -czf /tmp/{tenant_id}_logs.tar.gz /var/log/tenants/{tenant_id}"
    subprocess.run(cmd, shell=True, check=True)

    # Vulnerable: SQL injection via f-string query
    conn = sqlite3.connect("deploy_audit.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM deployments WHERE tenant = '{tenant_id}'")

    # Vulnerable: arbitrary Python execution via eval()
    should_notify = eval(filter_expr)
    if should_notify:
        os.system(f"echo 'Archived {tenant_id}' >> /var/log/audit.log")

    return cursor.fetchall()
`,
  },
];
