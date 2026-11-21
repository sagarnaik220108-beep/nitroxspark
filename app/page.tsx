"use client";

import Link from "next/link";
import { useState } from "react";
import { ScoreRing } from "@/components/sentinel/ScoreRing";
import { SeverityBadge } from "@/components/sentinel/SeverityBadge";

const VULNERABLE_SNIPPET = `const query = \`SELECT id, email, role FROM users WHERE email = '\${email}'\`;
const result = await db.query(query);`;

const SECURE_SNIPPET = `const query = "SELECT id, email, role FROM users WHERE email = $1";
const result = await db.query(query, [email]);`;

export default function LandingPage() {
  const [previewFixed, setPreviewFixed] = useState(false);

  return (
    <div
      className="min-h-screen w-full text-on-surface font-body"
      style={{
        backgroundColor: "#0D1322",
        backgroundImage: [
          "radial-gradient(ellipse 65% 45% at 15% 0%, rgba(34, 211, 238, 0.14), transparent 70%)",
          "radial-gradient(ellipse 55% 40% at 85% 15%, rgba(5, 102, 217, 0.18), transparent 70%)",
          "linear-gradient(to right, rgba(60, 73, 76, 0.12) 1px, transparent 1px)",
          "linear-gradient(to bottom, rgba(60, 73, 76, 0.12) 1px, transparent 1px)",
        ].join(", "),
        backgroundSize: "100% 100%, 100% 100%, 40px 40px, 40px 40px",
      }}
    >
      <div className="max-w-[1380px] mx-auto px-4 sm:px-6 lg:px-8 py-5 flex flex-col gap-10">
        {/* Slim Glass Header */}
        <header className="glass-panel rounded-2xl px-5 py-3 flex flex-wrap items-center justify-between gap-4 shadow-[0_12px_36px_-12px_rgba(0,0,0,0.65)]">
          <Link href="/" className="flex items-center gap-3 group">
            <div className="w-9 h-9 rounded-xl bg-surface-container-lowest border border-primary/40 flex items-center justify-center cyan-glow group-hover:border-primary transition-colors">
              <span
                className="material-symbols-outlined text-[20px] text-primary"
                aria-hidden="true"
              >
                shield_lock
              </span>
            </div>
            <div className="flex flex-col">
              <span className="font-display text-base font-semibold text-on-surface tracking-tight leading-tight">
                Sentinel AI
              </span>
              <span className="font-code text-[10px] text-on-surface-variant tracking-wider uppercase">
                AppSec Co-Pilot
              </span>
            </div>
          </Link>

          <nav
            aria-label="Primary navigation"
            className="hidden md:flex items-center gap-7"
          >
            <a
              href="#live-preview"
              className="font-label text-sm font-medium text-on-surface-variant hover:text-primary transition-colors"
            >
              Live Preview
            </a>
            <a
              href="#capabilities"
              className="font-label text-sm font-medium text-on-surface-variant hover:text-primary transition-colors"
            >
              Capabilities
            </a>
            <Link
              href="/dashboard"
              className="font-label text-sm font-medium text-on-surface-variant hover:text-primary transition-colors"
            >
              Command Center
            </Link>
          </nav>

          <Link
            href="/dashboard"
            className="inline-flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-primary-container text-on-primary-container font-label text-sm font-semibold cyan-glow hover:bg-primary hover:text-on-primary active:scale-[0.98] transition-all duration-150"
          >
            <span
              className="material-symbols-outlined text-[18px]"
              aria-hidden="true"
            >
              terminal
            </span>
            <span>Launch Command Center</span>
          </Link>
        </header>

        {/* Glowing Hero Section */}
        <main className="flex flex-col gap-12">
          <section
            aria-label="Hero"
            className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center pt-2"
          >
            <div className="lg:col-span-7 flex flex-col gap-6">
              <div className="inline-flex items-center gap-2 self-start px-3 py-1 rounded-full bg-surface-container-low/85 border border-primary/30">
                <span
                  aria-hidden="true"
                  className="w-2 h-2 rounded-full bg-primary-container shadow-[0_0_8px_rgba(34,211,238,0.95)]"
                />
                <span className="font-code text-[11px] text-primary tracking-wide">
                  12-Rule Static Engine · Zero-Trust Sandbox
                </span>
              </div>

              <h1 className="font-display text-4xl sm:text-5xl font-bold text-on-surface tracking-tight leading-[1.08] text-balance">
                Autonomous code security for{" "}
                <span className="text-primary">AI-generated</span> apps.
              </h1>

              <p className="font-body text-base text-on-surface-variant max-w-xl leading-relaxed">
                Sentinel AI scans TypeScript, JavaScript, and Python in
                milliseconds, translates complex CVEs into plain English,
                replays synthetic before-vs-after exploits, and ships verified
                one-click patches.
              </p>

              <div className="flex flex-wrap items-center gap-3.5">
                <Link
                  href="/dashboard"
                  className="inline-flex items-center justify-center gap-2 px-5 py-3 rounded-lg bg-primary-container text-on-primary-container font-label text-sm font-semibold shadow-[0_0_28px_-4px_rgba(34,211,238,0.55)] hover:bg-primary hover:text-on-primary active:scale-[0.98] transition-all duration-150"
                >
                  <span
                    className="material-symbols-outlined text-[18px]"
                    aria-hidden="true"
                  >
                    rocket_launch
                  </span>
                  <span>Launch Command Center</span>
                </Link>

                <a
                  href="#live-preview"
                  className="inline-flex items-center justify-center gap-2 px-5 py-3 rounded-lg bg-surface-container-high/80 backdrop-blur-md border border-outline-variant/50 text-on-surface font-label text-sm font-medium hover:bg-surface-container-highest hover:border-primary/50 active:scale-[0.98] transition-all duration-150"
                >
                  <span
                    className="material-symbols-outlined text-[18px] text-primary"
                    aria-hidden="true"
                  >
                    play_circle
                  </span>
                  <span>Try Live Fix Preview</span>
                </a>
              </div>

              {/* Hero Telemetry Strip */}
              <div className="grid grid-cols-3 gap-4 pt-5 border-t border-outline-variant/30 max-w-lg">
                <div className="flex flex-col gap-0.5">
                  <span className="font-display text-2xl font-semibold text-primary tabular-nums">
                    12 Rules
                  </span>
                  <span className="font-label text-xs text-on-surface-variant">
                    OWASP &amp; CWE Coverage
                  </span>
                </div>
                <div className="flex flex-col gap-0.5">
                  <span className="font-display text-2xl font-semibold text-on-surface tabular-nums">
                    &lt; 40ms
                  </span>
                  <span className="font-label text-xs text-on-surface-variant">
                    Static Scan Latency
                  </span>
                </div>
                <div className="flex flex-col gap-0.5">
                  <span className="font-display text-2xl font-semibold text-success tabular-nums">
                    100%
                  </span>
                  <span className="font-label text-xs text-on-surface-variant">
                    Synthetic Safe Replay
                  </span>
                </div>
              </div>
            </div>

            {/* Interactive Preview Metric Cards Showcase */}
            <div className="lg:col-span-5">
              <div className="glass-panel-elevated rounded-2xl p-6 flex flex-col gap-5 relative overflow-hidden">
                <div className="flex items-center justify-between gap-3">
                  <div className="flex items-center gap-2">
                    <span
                      className="material-symbols-outlined text-[18px] text-primary"
                      aria-hidden="true"
                    >
                      monitoring
                    </span>
                    <span className="font-display text-sm font-semibold text-on-surface">
                      Live Posture Telemetry
                    </span>
                  </div>
                  <SeverityBadge
                    variant={previewFixed ? "fixed" : "critical"}
                    label={previewFixed ? "Hardened" : "3 Open Threats"}
                    pulse={!previewFixed}
                  />
                </div>

                <div className="flex flex-col sm:flex-row items-center justify-between gap-6 py-2">
                  <ScoreRing
                    score={previewFixed ? 96 : 34}
                    letterGrade={previewFixed ? "A+" : "F"}
                    riskCategory={previewFixed ? "Minimal Risk" : "Critical Risk"}
                    size={156}
                  />

                  <div className="flex-1 w-full grid grid-cols-1 gap-3">
                    <div className="rounded-xl bg-surface-container-lowest/90 border border-outline-variant/40 px-4 py-3 flex items-center justify-between">
                      <div className="flex flex-col">
                        <span className="font-label text-[11px] text-on-surface-variant uppercase tracking-wider">
                          SQL Injection
                        </span>
                        <span className="font-code text-xs text-on-surface mt-0.5">
                          CWE-89 · Line 12
                        </span>
                      </div>
                      <SeverityBadge
                        variant={previewFixed ? "blocked" : "compromised"}
                      />
                    </div>

                    <div className="rounded-xl bg-surface-container-lowest/90 border border-outline-variant/40 px-4 py-3 flex items-center justify-between">
                      <div className="flex flex-col">
                        <span className="font-label text-[11px] text-on-surface-variant uppercase tracking-wider">
                          Hardcoded Secret
                        </span>
                        <span className="font-code text-xs text-on-surface mt-0.5">
                          CWE-798 · Line 5
                        </span>
                      </div>
                      <SeverityBadge
                        variant={previewFixed ? "fixed" : "high"}
                      />
                    </div>

                    <div className="rounded-xl bg-surface-container-lowest/90 border border-outline-variant/40 px-4 py-3 flex items-center justify-between">
                      <div className="flex flex-col">
                        <span className="font-label text-[11px] text-on-surface-variant uppercase tracking-wider">
                          Est. Time Saved
                        </span>
                        <span className="font-code text-xs text-primary tabular-nums mt-0.5">
                          {previewFixed ? "1h 45m saved" : "Ready to patch"}
                        </span>
                      </div>
                      <span
                        className="material-symbols-outlined text-[18px] text-primary"
                        aria-hidden="true"
                      >
                        bolt
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </section>

          {/* Interactive One-Click Remediation Preview Band */}
          <section
            id="live-preview"
            aria-label="Interactive Remediation Preview"
            className="glass-panel rounded-2xl p-6 shadow-[0_20px_50px_-14px_rgba(0,0,0,0.7)] flex flex-col gap-5"
          >
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div className="flex flex-col gap-1">
                <h2 className="font-display text-xl font-semibold text-on-surface">
                  One-Click Verified Remediation
                </h2>
                <p className="font-body text-sm text-on-surface-variant">
                  Preview how Sentinel AI neutralizes a CWE-89 SQL Injection
                  sink and re-verifies against the exploit payload.
                </p>
              </div>

              <div className="flex items-center gap-3">
                <SeverityBadge
                  variant={previewFixed ? "blocked" : "compromised"}
                  label={previewFixed ? "403 Blocked" : "200 Exploited"}
                  size="md"
                />
                <button
                  type="button"
                  onClick={() => setPreviewFixed((prev) => !prev)}
                  className="inline-flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-primary-container text-on-primary-container font-label text-sm font-semibold cyan-glow hover:bg-primary hover:text-on-primary active:scale-[0.98] transition-all duration-150"
                >
                  <span
                    className="material-symbols-outlined text-[18px]"
                    aria-hidden="true"
                  >
                    {previewFixed ? "restart_alt" : "auto_fix_high"}
                  </span>
                  <span>
                    {previewFixed ? "Reset Preview" : "Apply Secure Fix"}
                  </span>
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <div className="p-4 rounded-xl bg-surface-container-lowest/95 border border-outline-variant/40 flex flex-col gap-2.5">
                <div className="flex items-center justify-between">
                  <span className="font-code text-xs text-on-surface-variant">
                    app/api/auth/login/route.ts
                  </span>
                  <span className="font-code text-[11px] text-primary">
                    {previewFixed ? "Parameterized ($1)" : "Interpolated String"}
                  </span>
                </div>
                <pre className="font-code text-[13px] text-on-surface overflow-x-auto leading-relaxed">
                  <code>{previewFixed ? SECURE_SNIPPET : VULNERABLE_SNIPPET}</code>
                </pre>
              </div>

              <div className="p-4 rounded-xl bg-surface-container-lowest/95 border border-outline-variant/40 flex flex-col justify-between gap-3">
                <div className="flex flex-col gap-1.5">
                  <span className="font-label text-xs font-medium text-primary">
                    Synthetic Attack Replay Vector
                  </span>
                  <code className="font-code text-xs text-on-surface-variant break-all">
                    POST /api/auth/login · &#123; &quot;email&quot;: &quot;admin&apos;
                    OR 1=1 --&quot; &#125;
                  </code>
                </div>

                <div
                  className={`px-3.5 py-2.5 rounded-lg border font-code text-xs transition-colors duration-200 ${
                    previewFixed
                      ? "bg-success-container/25 border-success/40 text-success"
                      : "bg-error-container/25 border-error/40 text-error"
                  }`}
                >
                  {previewFixed
                    ? "Guard enforced: Parameterized $1 binding treated payload as literal string — login bypass blocked."
                    : "Sink reached: SQL predicate tautology bypassed authentication and exposed user records."}
                </div>
              </div>
            </div>
          </section>

          {/* 3-Column Bento Feature Grid */}
          <section
            id="capabilities"
            aria-label="Core Capabilities"
            className="grid grid-cols-1 md:grid-cols-3 gap-5"
          >
            {/* Card 1: 12-Rule Static Engine */}
            <article className="glass-panel rounded-2xl p-6 flex flex-col justify-between gap-5 hover:border-primary/40 transition-colors duration-200">
              <div className="flex flex-col gap-3">
                <div className="w-10 h-10 rounded-xl bg-surface-container-lowest border border-primary/35 flex items-center justify-center">
                  <span
                    className="material-symbols-outlined text-[20px] text-primary"
                    aria-hidden="true"
                  >
                    radar
                  </span>
                </div>
                <span className="font-code text-[11px] text-primary uppercase tracking-wider">
                  Static Analysis
                </span>
                <h3 className="font-display text-lg font-semibold text-on-surface">
                  12-Rule Static Engine
                </h3>
                <p className="font-body text-sm text-on-surface-variant leading-relaxed">
                  Detects SQL injection, XSS, command injection, unsafe{" "}
                  <code className="font-code text-xs text-on-surface">eval()</code>
                  , hardcoded API keys, JWT secrets, weak auth, and exposed env
                  variables with exact line precision.
                </p>
              </div>
              <div className="flex flex-wrap gap-1.5 pt-2 border-t border-outline-variant/30">
                <SeverityBadge variant="critical" label="SQLi" />
                <SeverityBadge variant="high" label="Secrets" />
                <SeverityBadge variant="medium" label="XSS" />
              </div>
            </article>

            {/* Card 2: Beginner-Friendly AI Explainer */}
            <article className="glass-panel rounded-2xl p-6 flex flex-col justify-between gap-5 hover:border-secondary/40 transition-colors duration-200">
              <div className="flex flex-col gap-3">
                <div className="w-10 h-10 rounded-xl bg-surface-container-lowest border border-secondary/35 flex items-center justify-center">
                  <span
                    className="material-symbols-outlined text-[20px] text-secondary"
                    aria-hidden="true"
                  >
                    psychology
                  </span>
                </div>
                <span className="font-code text-[11px] text-secondary uppercase tracking-wider">
                  Guided Security Intel
                </span>
                <h3 className="font-display text-lg font-semibold text-on-surface">
                  Beginner-Friendly AI Explainer
                </h3>
                <p className="font-body text-sm text-on-surface-variant leading-relaxed">
                  Breaks down every finding into plain English: what it is, why
                  AI tools generate it, how attackers exploit it, a real-world
                  analogy, and the clean secure pattern.
                </p>
              </div>
              <div className="flex items-center justify-between pt-2 border-t border-outline-variant/30 text-xs text-on-surface-variant font-code">
                <span>CWE + OWASP Mapped</span>
                <span className="text-secondary">Plain English</span>
              </div>
            </article>

            {/* Card 3: One-Click Auto-Fix & Before/After Attack Simulator */}
            <article className="glass-panel rounded-2xl p-6 flex flex-col justify-between gap-5 hover:border-success/40 transition-colors duration-200">
              <div className="flex flex-col gap-3">
                <div className="w-10 h-10 rounded-xl bg-surface-container-lowest border border-success/35 flex items-center justify-center">
                  <span
                    className="material-symbols-outlined text-[20px] text-success"
                    aria-hidden="true"
                  >
                    verified_user
                  </span>
                </div>
                <span className="font-code text-[11px] text-success uppercase tracking-wider">
                  Remediation &amp; Proof
                </span>
                <h3 className="font-display text-lg font-semibold text-on-surface">
                  One-Click Auto-Fix &amp; Attack Simulator
                </h3>
                <p className="font-body text-sm text-on-surface-variant leading-relaxed">
                  Apply deterministic single or batch patches, watch your
                  security score jump in real time, and replay synthetic
                  before-vs-after exploits to prove the fix holds.
                </p>
              </div>
              <Link
                href="/dashboard"
                className="inline-flex items-center gap-1.5 pt-2 border-t border-outline-variant/30 font-label text-sm font-medium text-primary hover:underline"
              >
                <span>Open Command Center</span>
                <span
                  className="material-symbols-outlined text-[16px]"
                  aria-hidden="true"
                >
                  arrow_forward
                </span>
              </Link>
            </article>
          </section>
        </main>

        {/* Minimal Glass Footer */}
        <footer className="glass-panel rounded-2xl px-5 py-4 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-2.5">
            <span
              className="material-symbols-outlined text-[18px] text-primary"
              aria-hidden="true"
            >
              shield_lock
            </span>
            <span className="font-body text-xs text-on-surface-variant">
              Sentinel AI · Autonomous Application Security Co-Pilot
            </span>
          </div>
          <div className="flex items-center gap-5">
            <a
              href="#live-preview"
              className="font-label text-xs text-on-surface-variant hover:text-primary transition-colors"
            >
              Live Preview
            </a>
            <a
              href="#capabilities"
              className="font-label text-xs text-on-surface-variant hover:text-primary transition-colors"
            >
              Capabilities
            </a>
            <Link
              href="/dashboard"
              className="font-label text-xs font-medium text-primary hover:underline"
            >
              Launch Command Center
            </Link>
          </div>
        </footer>
      </div>
    </div>
  );
}
