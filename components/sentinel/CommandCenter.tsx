"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { StructuredSecurityReport } from "@/security/analyzer";
import type { SecureFixResult } from "@/types/fix.types";
import type { SecurityScoreReport } from "@/types/score.types";
import type { SemgrepStatusResponse } from "@/types/semgrep.types";
import type { UploadScanResult } from "@/services/upload-scan.service";
import {
  analyzeCodeApi,
  calculateScoreApi,
  getSemgrepStatusApi,
  getSessionApi,
  initiateGoogleLoginApi,
  logoutApi,
  scanWithSemgrepApi,
  type AuthUserRecord,
} from "./api-client";
import { AttackSimulatorPanel } from "./AttackSimulatorPanel";
import { CodeAnalysisWorkspace } from "./CodeAnalysisWorkspace";
import { CODE_PRESETS } from "./presets";
import { ScoreRing } from "./ScoreRing";
import {
  SecurityReportPanel,
  type AppliedFixSummary,
  type TimelineEventItem,
} from "./SecurityReportPanel";
import { SeverityBadge } from "./SeverityBadge";
import { UploadScanPanel } from "./UploadScanPanel";

type WorkspaceTab = "overview" | "analysis" | "simulator" | "report";

const WORKSPACE_TABS: readonly {
  id: WorkspaceTab;
  label: string;
  shortLabel: string;
  icon: string;
}[] = [
  { id: "overview", label: "Overview", shortLabel: "Overview", icon: "space_dashboard" },
  {
    id: "analysis",
    label: "Code Analysis & Auto-Fix",
    shortLabel: "Code & Fix",
    icon: "code_blocks",
  },
  {
    id: "simulator",
    label: "Attack Simulator",
    shortLabel: "Simulator",
    icon: "security",
  },
  {
    id: "report",
    label: "Security Report",
    shortLabel: "Report",
    icon: "description",
  },
] as const;

function getScorePillClass(score: number): string {
  if (score >= 85) {
    return "border-success/40 bg-success-container/40 text-success";
  }
  if (score >= 65) {
    return "border-primary/40 bg-primary-container/15 text-primary";
  }
  if (score >= 45) {
    return "border-warning/40 bg-warning-container/40 text-warning";
  }
  return "border-error/40 bg-error-container/45 text-error";
}

function formatTimelineTime(iso: string): string {
  try {
    return new Date(iso).toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return iso;
  }
}

export function CommandCenter() {
  const initialPreset = CODE_PRESETS[0];

  const [activeTab, setActiveTab] = useState<WorkspaceTab>("overview");
  const [code, setCode] = useState<string>(initialPreset?.code ?? "");
  const [fileName, setFileName] = useState<string>(
    initialPreset?.fileName ?? "app/api/auth/login/route.ts"
  );
  const [projectName] = useState<string>("Sentinel AI Core Workspace");

  const [analysisReport, setAnalysisReport] =
    useState<StructuredSecurityReport | null>(null);
  const [scoreReport, setScoreReport] = useState<SecurityScoreReport | null>(
    null
  );
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanError, setScanError] = useState<string | null>(null);

  const [scansRunCount, setScansRunCount] = useState<number>(0);
  const [distinctFilesCount, setDistinctFilesCount] = useState<number>(1);
  const [appliedFixes, setAppliedFixes] = useState<AppliedFixSummary[]>([]);
  const [timelineEvents, setTimelineEvents] = useState<TimelineEventItem[]>([]);

  // Semgrep multi-engine integration state
  const [useSemgrep, setUseSemgrep] = useState<boolean>(true);
  const [semgrepStatus, setSemgrepStatus] =
    useState<SemgrepStatusResponse | null>(null);
  const [lastEngineLabel, setLastEngineLabel] = useState<string>(
    "Sentinel AI + Semgrep"
  );

  // Auth state with graceful fallback when Supabase env is not configured
  const [authUser, setAuthUser] = useState<AuthUserRecord | null>(null);
  const [authLoading, setAuthLoading] = useState<boolean>(false);
  const [authNotice, setAuthNotice] = useState<string | null>(null);

  const hasBootstrappedRef = useRef<boolean>(false);
  const scansRunRef = useRef<number>(0);
  const scannedFilesRef = useRef<Set<string>>(new Set());
  const baselineVulnMapRef = useRef<Map<string, number>>(new Map());
  const threatsFixedRef = useRef<number>(0);

  const logTimelineEvent = useCallback(
    (
      action: string,
      label: string,
      severity: "critical" | "high" | "medium" | "low" | "info",
      status: string
    ) => {
      const event: TimelineEventItem = {
        timestamp: new Date().toISOString(),
        action,
        label,
        severity,
        status,
      };
      setTimelineEvents((prev) => [event, ...prev].slice(0, 40));
    },
    []
  );

  const runLiveScan = useCallback(
    async (
      targetCode: string,
      targetFileName: string,
      options?: { silent?: boolean; threatsFixedOverride?: number }
    ) => {
      setIsScanning(true);
      setScanError(null);

      try {
        let report: StructuredSecurityReport;
        if (useSemgrep) {
          const semgrepRes = await scanWithSemgrepApi({
            code: targetCode,
            fileName: targetFileName,
            combineWithSentinel: true,
          });
          report = {
            ...semgrepRes.combinedReport,
          };
          setLastEngineLabel(
            semgrepRes.semgrep.engineMode === "cli"
              ? "Sentinel AI + Semgrep CLI"
              : "Sentinel AI + Semgrep Engine"
          );
        } else {
          report = await analyzeCodeApi({
            code: targetCode,
            fileName: targetFileName,
          });
          setLastEngineLabel("Sentinel AI Core");
        }
        setAnalysisReport(report);

        scansRunRef.current += 1;
        setScansRunCount(scansRunRef.current);

        scannedFilesRef.current.add(targetFileName);
        const currentFilesCount = scannedFilesRef.current.size;
        setDistinctFilesCount(currentFilesCount);

        // Record initial vulnerability baseline for this file on its first scan
        if (!baselineVulnMapRef.current.has(targetFileName)) {
          baselineVulnMapRef.current.set(targetFileName, report.vulnerabilities.length);
        }
        const baselineCount =
          baselineVulnMapRef.current.get(targetFileName) ??
          report.vulnerabilities.length;
        const currentVulnsCount = report.vulnerabilities.length;
        const calculatedThreatsFixed = Math.max(
          0,
          baselineCount - currentVulnsCount
        );

        const totalThreatsFixed =
          options?.threatsFixedOverride !== undefined
            ? options.threatsFixedOverride
            : calculatedThreatsFixed;
        threatsFixedRef.current = totalThreatsFixed;

        const score = await calculateScoreApi({
          criticalIssues: report.severityBreakdown.critical,
          highIssues: report.severityBreakdown.high,
          mediumIssues: report.severityBreakdown.medium,
          lowIssues: report.severityBreakdown.low,
          filesScanned: currentFilesCount,
          threatsFixed: totalThreatsFixed,
        });
        setScoreReport(score);

        if (!options?.silent) {
          const totalVulns = report.vulnerabilities.length;
          const topSeverity: "critical" | "high" | "medium" | "low" | "info" =
            report.severityBreakdown.critical > 0
              ? "critical"
              : report.severityBreakdown.high > 0
                ? "high"
                : report.severityBreakdown.medium > 0
                  ? "medium"
                  : report.severityBreakdown.low > 0
                    ? "low"
                    : "info";

          logTimelineEvent(
            "code_scanned",
            `Scanned ${targetFileName} — ${totalVulns} issue${
              totalVulns === 1 ? "" : "s"
            } detected (Score ${score.score}/100, Grade ${score.letterGrade})`,
            topSeverity,
            totalVulns === 0 ? "completed" : "info"
          );
        }
      } catch (err) {
        const message =
          err instanceof Error ? err.message : "Failed to run security scan.";
        setScanError(message);
      } finally {
        setIsScanning(false);
      }
    },
    [logTimelineEvent, useSemgrep]
  );

  const handleUploadScanComplete = useCallback(
    (result: UploadScanResult) => {
      setCode(result.code);
      setFileName(result.fileName);
      setAnalysisReport(result.report);
      setActiveTab("analysis");

      scansRunRef.current += 1;
      setScansRunCount(scansRunRef.current);
      scannedFilesRef.current.add(result.fileName);

      const isZipArchive =
        result.source === "file" && Boolean(result.archiveSummary);
      const archiveFiles =
        isZipArchive && result.archiveSummary
          ? result.archiveSummary.scannedFiles
          : scannedFilesRef.current.size;
      setDistinctFilesCount(archiveFiles);

      baselineVulnMapRef.current.set(
        result.fileName,
        result.report.vulnerabilities.length
      );
      threatsFixedRef.current = 0;

      void (async () => {
        try {
          if (useSemgrep && !isZipArchive) {
            await runLiveScan(result.code, result.fileName, { silent: true });
          } else {
            const score = await calculateScoreApi({
              criticalIssues: result.report.severityBreakdown.critical,
              highIssues: result.report.severityBreakdown.high,
              mediumIssues: result.report.severityBreakdown.medium,
              lowIssues: result.report.severityBreakdown.low,
              filesScanned: archiveFiles,
              threatsFixed: 0,
            });
            setScoreReport(score);
          }
        } catch {
          // Keep uploaded scan report visible even if score refresh fails
        }
      })();

      const sourceLabel =
        result.source === "url"
          ? `URL (${result.fetchedUrl})`
          : `file (${result.fileName})`;
      const count = result.report.vulnerabilities.length;
      const topSeverity: "critical" | "high" | "medium" | "low" | "info" =
        result.report.severityBreakdown.critical > 0
          ? "critical"
          : result.report.severityBreakdown.high > 0
            ? "high"
            : result.report.severityBreakdown.medium > 0
              ? "medium"
              : result.report.severityBreakdown.low > 0
                ? "low"
                : "info";

      logTimelineEvent(
        "ANALYSIS_STARTED",
        `Uploaded & scanned ${sourceLabel} — ${count} issue${count === 1 ? "" : "s"} found`,
        topSeverity,
        count === 0 ? "completed" : "warning"
      );
    },
    [logTimelineEvent, runLiveScan, useSemgrep]
  );

  // Bootstrap initial preset scan, Semgrep status & auth session on mount
  useEffect(() => {
    if (hasBootstrappedRef.current) return;
    hasBootstrappedRef.current = true;

    if (initialPreset) {
      void runLiveScan(initialPreset.code, initialPreset.fileName);
    }

    void (async () => {
      try {
        const status = await getSemgrepStatusApi();
        setSemgrepStatus(status);
      } catch {
        // Non-blocking Semgrep status lookup
      }
    })();

    void (async () => {
      try {
        const session = await getSessionApi();
        if (session.authenticated && session.user) {
          setAuthUser(session.user);
        }
      } catch {
        // Graceful local demo mode if Supabase env is not configured
      }
    })();
  }, [initialPreset, runLiveScan]);

  const handleCodeChange = useCallback(
    (nextCode: string, nextFileName?: string) => {
      setCode(nextCode);
      if (nextFileName) {
        setFileName(nextFileName);
      }
    },
    []
  );

  const handleRunScan = useCallback(
    async (overrideCode?: string, overrideFileName?: string) => {
      const targetCode = overrideCode ?? code;
      const targetFileName = overrideFileName ?? fileName;
      await runLiveScan(targetCode, targetFileName);
    },
    [code, fileName, runLiveScan]
  );

  const handleFixApplied = useCallback(
    (fixResult: SecureFixResult, updatedCode: string) => {
      const summary = fixResult.summary;
      const riskReductionPercent = Math.round(
        fixResult.riskReduction.reductionPercent
      );
      const linesChangedCount =
        fixResult.changedLineNumbers.length || fixResult.linesChanged.length;

      setCode(updatedCode);

      setAppliedFixes((prev) => [
        { summary, riskReductionPercent, linesChangedCount },
        ...prev,
      ]);

      logTimelineEvent(
        "fix_applied",
        `Applied secure fix: ${summary} (-${riskReductionPercent}% risk)`,
        "info",
        "completed"
      );

      void runLiveScan(updatedCode, fileName, {
        silent: true,
      });
    },
    [fileName, logTimelineEvent, runLiveScan]
  );

  const handleGoogleSignIn = useCallback(async () => {
    setAuthLoading(true);
    setAuthNotice(null);
    try {
      const { url } = await initiateGoogleLoginApi("/dashboard");
      window.location.href = url;
    } catch {
      setAuthNotice(
        "Google OAuth requires Supabase credentials in .env.local — running in Local Demo Mode."
      );
      window.setTimeout(() => setAuthNotice(null), 5000);
    } finally {
      setAuthLoading(false);
    }
  }, []);

  const handleLogout = useCallback(async () => {
    setAuthLoading(true);
    try {
      await logoutApi();
      setAuthUser(null);
      logTimelineEvent(
        "user_logout",
        "Signed out of Sentinel AI session",
        "info",
        "completed"
      );
    } catch {
      setAuthUser(null);
    } finally {
      setAuthLoading(false);
    }
  }, [logTimelineEvent]);

  const severityCounts = useMemo(() => {
    return (
      analysisReport?.severityBreakdown ?? {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
      }
    );
  }, [analysisReport]);

  const liveScore = scoreReport?.score ?? 0;
  const liveGrade = scoreReport?.letterGrade ?? "—";

  return (
    <div className="min-h-screen bg-background text-on-background">
      {/* Subtle Ambient Background Gradient */}
      <div
        aria-hidden="true"
        className="pointer-events-none fixed inset-0 -z-10 overflow-hidden"
      >
        <div className="absolute -top-40 left-1/4 h-[420px] w-[420px] rounded-full bg-primary-container/10 blur-[120px]" />
        <div className="absolute bottom-0 right-1/5 h-[360px] w-[360px] rounded-full bg-secondary-container/10 blur-[120px]" />
      </div>

      {/* Top Glass Command Bar */}
      <header className="glass-panel sticky top-0 z-40 border-x-0 border-t-0">
        <div className="mx-auto flex max-w-[1440px] flex-wrap items-center justify-between gap-3 px-4 py-3 sm:px-6">
          {/* Brand Logo */}
          <Link
            href="/"
            className="group flex items-center gap-2.5 focus:outline-none"
          >
            <span className="cyan-glow flex h-9 w-9 items-center justify-center rounded-xl border border-primary/40 bg-primary-container/15 text-primary transition group-hover:bg-primary-container/25">
              <span className="material-symbols-outlined text-[20px]">
                shield_lock
              </span>
            </span>
            <div>
              <div className="font-display text-sm font-bold tracking-tight text-on-surface">
                Sentinel AI
              </div>
              <div className="font-code text-[10px] uppercase tracking-wider text-primary/80">
                Command Center
              </div>
            </div>
          </Link>

          {/* 4 Workspace Navigation Tabs */}
          <nav
            aria-label="Workspace navigation"
            className="flex items-center gap-1 rounded-xl border border-outline-variant/40 bg-surface-container-lowest/80 p-1"
          >
            {WORKSPACE_TABS.map((tab) => {
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setActiveTab(tab.id)}
                  className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition-all duration-150 ${
                    isActive
                      ? "bg-primary-container/20 text-primary shadow-[inset_0_0_0_1px_rgba(138,235,255,0.35)]"
                      : "text-on-surface-variant hover:bg-surface-container-low hover:text-on-surface"
                  }`}
                >
                  <span className="material-symbols-outlined text-[16px]">
                    {tab.icon}
                  </span>
                  <span className="hidden md:inline">{tab.label}</span>
                  <span className="md:hidden">{tab.shortLabel}</span>
                </button>
              );
            })}
          </nav>

          {/* Right Controls: Live Score Pill + Google Auth */}
          <div className="flex items-center gap-2.5">
            <button
              type="button"
              onClick={() => setActiveTab("overview")}
              className={`inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-semibold tabular-nums transition hover:brightness-110 ${
                scoreReport
                  ? getScorePillClass(liveScore)
                  : "border-outline-variant/40 bg-surface-container-low text-on-surface-variant"
              }`}
              title="View Security Posture Overview"
            >
              <span className="material-symbols-outlined text-[15px]">
                {isScanning ? "progress_activity" : "verified_user"}
              </span>
              <span>
                {scoreReport
                  ? `Score ${liveScore} • ${liveGrade}`
                  : isScanning
                    ? "Scanning..."
                    : "Ready"}
              </span>
            </button>

            {authUser ? (
              <div className="flex items-center gap-2 rounded-full border border-outline-variant/40 bg-surface-container-low px-3 py-1">
                <span className="h-2 w-2 rounded-full bg-success" />
                <span className="max-w-[140px] truncate text-xs text-on-surface">
                  {authUser.email}
                </span>
                <button
                  type="button"
                  disabled={authLoading}
                  onClick={() => void handleLogout()}
                  className="ml-1 text-[11px] font-medium text-on-surface-variant transition hover:text-error"
                >
                  Sign out
                </button>
              </div>
            ) : (
              <button
                type="button"
                disabled={authLoading}
                onClick={() => void handleGoogleSignIn()}
                className="inline-flex items-center gap-1.5 rounded-lg border border-outline-variant/50 bg-surface-container-high px-3 py-1.5 text-xs font-medium text-on-surface transition hover:border-primary/50 hover:text-primary disabled:opacity-50"
              >
                <span className="material-symbols-outlined text-[16px]">
                  login
                </span>
                <span className="hidden sm:inline">Sign in with Google</span>
                <span className="sm:hidden">Sign in</span>
              </button>
            )}
          </div>
        </div>
      </header>

      {/* Non-blocking Auth / Scan Notices */}
      {authNotice ? (
        <div className="mx-auto max-w-[1440px] px-4 pt-3 sm:px-6">
          <div className="glass-panel flex items-center justify-between gap-3 rounded-xl border-secondary/35 bg-secondary-container/15 px-4 py-2.5 text-xs text-secondary">
            <div className="flex items-center gap-2">
              <span className="material-symbols-outlined text-[16px]">
                info
              </span>
              <span>{authNotice}</span>
            </div>
            <button
              type="button"
              onClick={() => setAuthNotice(null)}
              className="text-on-surface-variant hover:text-on-surface"
            >
              Dismiss
            </button>
          </div>
        </div>
      ) : null}

      {scanError ? (
        <div className="mx-auto max-w-[1440px] px-4 pt-3 sm:px-6">
          <div className="glass-panel flex items-center justify-between gap-3 rounded-xl border-error/40 bg-error-container/20 px-4 py-2.5 text-xs text-error">
            <div className="flex items-center gap-2">
              <span className="material-symbols-outlined text-[16px]">
                error
              </span>
              <span>{scanError}</span>
            </div>
            <button
              type="button"
              onClick={() => void handleRunScan()}
              className="rounded-md border border-error/40 px-2.5 py-1 text-[11px] font-medium text-on-error-container hover:bg-error-container/40"
            >
              Retry Scan
            </button>
          </div>
        </div>
      ) : null}

      {/* Main Workspace Viewport */}
      <main className="mx-auto max-w-[1440px] px-4 py-6 sm:px-6">
        {/* TAB 1: OVERVIEW BENTO GRID */}
        {activeTab === "overview" ? (
          <div className="space-y-6">
            {/* Top Bento Row: Hero Score Ring + Threat Telemetry */}
            <div className="grid grid-cols-1 gap-5 lg:grid-cols-12">
              {/* Hero Score Card */}
              <section className="glass-panel-elevated flex flex-col justify-between rounded-2xl p-6 lg:col-span-5">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <span className="inline-flex items-center gap-1.5 rounded-full border border-primary/30 bg-primary-container/10 px-2.5 py-0.5 text-[11px] font-medium text-primary">
                      <span className="h-1.5 w-1.5 rounded-full bg-primary animate-pulse" />
                      Live Posture Telemetry
                    </span>
                    <h1 className="mt-2 font-display text-2xl font-bold tracking-tight text-on-surface">
                      Security Command Center
                    </h1>
                    <p className="mt-1 text-xs text-on-surface-variant">
                      Active target:{" "}
                      <span className="font-code text-primary">{fileName}</span>
                    </p>
                  </div>
                </div>

                <div className="my-5 flex flex-col items-center gap-5 sm:flex-row sm:items-center sm:justify-around">
                  <ScoreRing
                    score={liveScore}
                    letterGrade={liveGrade}
                    riskCategory={scoreReport?.riskCategory ?? "Evaluating..."}
                    size={164}
                  />

                  <div className="flex-1 space-y-3">
                    <div className="rounded-xl border border-outline-variant/35 bg-surface-container-low/80 p-3">
                      <div className="text-[11px] uppercase tracking-wider text-on-surface-variant">
                        Security Level
                      </div>
                      <div className="mt-0.5 flex items-center gap-2 font-display text-base font-semibold text-on-surface">
                        <span className="material-symbols-outlined text-[18px] text-primary">
                          shield
                        </span>
                        {scoreReport?.securityLevel ?? "Scanning..."}
                      </div>
                    </div>

                    <div className="rounded-xl border border-outline-variant/35 bg-surface-container-low/80 p-3">
                      <div className="text-[11px] uppercase tracking-wider text-on-surface-variant">
                        Developer Level
                      </div>
                      <div className="mt-0.5 flex items-center gap-2 font-display text-base font-semibold text-secondary">
                        <span className="material-symbols-outlined text-[18px] text-secondary">
                          workspace_premium
                        </span>
                        {scoreReport?.developerLevel ?? "Evaluating..."}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Score Breakdown Strip */}
                {scoreReport ? (
                  <div className="grid grid-cols-3 gap-2 border-t border-outline-variant/30 pt-4 text-center font-code text-xs tabular-nums">
                    <div className="rounded-lg bg-surface-container-lowest/70 px-2 py-2">
                      <div className="text-[10px] text-on-surface-variant">
                        Base
                      </div>
                      <div className="font-semibold text-on-surface">
                        {scoreReport.breakdown.baseScore}
                      </div>
                    </div>
                    <div className="rounded-lg bg-surface-container-lowest/70 px-2 py-2">
                      <div className="text-[10px] text-on-surface-variant">
                        Penalty
                      </div>
                      <div className="font-semibold text-error">
                        -{scoreReport.breakdown.severityPenalties.effectiveTotal}
                      </div>
                    </div>
                    <div className="rounded-lg bg-surface-container-lowest/70 px-2 py-2">
                      <div className="text-[10px] text-on-surface-variant">
                        Fix Bonus
                      </div>
                      <div className="font-semibold text-success">
                        +{scoreReport.breakdown.fixBonus}
                      </div>
                    </div>
                  </div>
                ) : null}
              </section>

              {/* Right 7 Columns: Threat Stats + Quick Launch */}
              <div className="flex flex-col gap-5 lg:col-span-7">
                {/* Threat Statistics Cards */}
                <section className="grid grid-cols-2 gap-3.5 sm:grid-cols-3">
                  <div className="glass-panel rounded-xl border-error/30 p-4">
                    <div className="flex items-center justify-between">
                      <span className="text-xs text-on-surface-variant">
                        Critical
                      </span>
                      <span className="h-2 w-2 rounded-full bg-error" />
                    </div>
                    <div className="mt-2 font-display text-3xl font-bold text-error tabular-nums">
                      {severityCounts.critical}
                    </div>
                    <div className="mt-0.5 text-[11px] text-on-surface-variant">
                      Immediate exploit risk
                    </div>
                  </div>

                  <div className="glass-panel rounded-xl border-warning/30 p-4">
                    <div className="flex items-center justify-between">
                      <span className="text-xs text-on-surface-variant">
                        High
                      </span>
                      <span className="h-2 w-2 rounded-full bg-warning" />
                    </div>
                    <div className="mt-2 font-display text-3xl font-bold text-warning tabular-nums">
                      {severityCounts.high}
                    </div>
                    <div className="mt-0.5 text-[11px] text-on-surface-variant">
                      High-impact findings
                    </div>
                  </div>

                  <div className="glass-panel rounded-xl p-4">
                    <div className="flex items-center justify-between">
                      <span className="text-xs text-on-surface-variant">
                        Medium / Low
                      </span>
                      <span className="h-2 w-2 rounded-full bg-secondary" />
                    </div>
                    <div className="mt-2 font-display text-3xl font-bold text-on-surface tabular-nums">
                      {severityCounts.medium + severityCounts.low}
                    </div>
                    <div className="mt-0.5 text-[11px] text-on-surface-variant tabular-nums">
                      {severityCounts.medium} med • {severityCounts.low} low
                    </div>
                  </div>

                  <div className="glass-panel rounded-xl border-success/30 p-4">
                    <div className="flex items-center justify-between">
                      <span className="text-xs text-on-surface-variant">
                        Threats Fixed
                      </span>
                      <span className="material-symbols-outlined text-[16px] text-success">
                        auto_fix_high
                      </span>
                    </div>
                    <div className="mt-2 font-display text-3xl font-bold text-success tabular-nums">
                      {scoreReport?.metrics.threatsFixed ?? appliedFixes.length}
                    </div>
                    <div className="mt-0.5 text-[11px] text-on-surface-variant tabular-nums">
                      {scoreReport?.metrics.fixRatePercentage ?? 0}% fix rate
                    </div>
                  </div>

                  <div className="glass-panel rounded-xl border-primary/30 p-4">
                    <div className="flex items-center justify-between">
                      <span className="text-xs text-on-surface-variant">
                        Time Saved
                      </span>
                      <span className="material-symbols-outlined text-[16px] text-primary">
                        schedule
                      </span>
                    </div>
                    <div className="mt-2 font-display text-3xl font-bold text-primary tabular-nums">
                      {scoreReport?.metrics.timeSaved.formatted ?? "0m"}
                    </div>
                    <div className="mt-0.5 text-[11px] text-on-surface-variant">
                      Est. AppSec triage saved
                    </div>
                  </div>

                  <div className="glass-panel rounded-xl p-4">
                    <div className="flex items-center justify-between">
                      <span className="text-xs text-on-surface-variant">
                        Scans Run
                      </span>
                      <span className="material-symbols-outlined text-[16px] text-secondary">
                        radar
                      </span>
                    </div>
                    <div className="mt-2 font-display text-3xl font-bold text-on-surface tabular-nums">
                      {scansRunCount}
                    </div>
                    <div className="mt-0.5 text-[11px] text-on-surface-variant tabular-nums">
                      {distinctFilesCount} file{distinctFilesCount === 1 ? "" : "s"} · {analysisReport?.executedRulesCount ?? 12} rules
                    </div>
                  </div>
                </section>

                {/* Quick-Launch Action Cards */}
                <section className="grid grid-cols-1 gap-3.5 sm:grid-cols-3">
                  <button
                    type="button"
                    onClick={() => setActiveTab("analysis")}
                    className="glass-panel group flex flex-col justify-between rounded-2xl p-4 text-left transition hover:border-primary/50 hover:bg-surface-container"
                  >
                    <div>
                      <span className="inline-flex h-9 w-9 items-center justify-center rounded-xl border border-primary/35 bg-primary-container/15 text-primary">
                        <span className="material-symbols-outlined text-[20px]">
                          code_blocks
                        </span>
                      </span>
                      <h3 className="mt-3 font-display text-sm font-semibold text-on-surface group-hover:text-primary">
                        Code Analysis &amp; Auto-Fix
                      </h3>
                      <p className="mt-1 text-xs text-on-surface-variant">
                        Inspect {analysisReport?.vulnerabilities.length ?? 0}{" "}
                        detected vulnerabilities and apply deterministic patches.
                      </p>
                    </div>
                    <span className="mt-3 inline-flex items-center gap-1 text-xs font-medium text-primary">
                      Open Workspace
                      <span className="material-symbols-outlined text-[15px] transition-transform group-hover:translate-x-0.5">
                        arrow_forward
                      </span>
                    </span>
                  </button>

                  <button
                    type="button"
                    onClick={() => setActiveTab("simulator")}
                    className="glass-panel group flex flex-col justify-between rounded-2xl p-4 text-left transition hover:border-primary/50 hover:bg-surface-container"
                  >
                    <div>
                      <span className="inline-flex h-9 w-9 items-center justify-center rounded-xl border border-warning/35 bg-warning-container/25 text-warning">
                        <span className="material-symbols-outlined text-[20px]">
                          security
                        </span>
                      </span>
                      <h3 className="mt-3 font-display text-sm font-semibold text-on-surface group-hover:text-primary">
                        Attack Simulator
                      </h3>
                      <p className="mt-1 text-xs text-on-surface-variant">
                        Replay 5 synthetic exploit flows Before vs After fix.
                      </p>
                    </div>
                    <span className="mt-3 inline-flex items-center gap-1 text-xs font-medium text-primary">
                      Launch Simulator
                      <span className="material-symbols-outlined text-[15px] transition-transform group-hover:translate-x-0.5">
                        arrow_forward
                      </span>
                    </span>
                  </button>

                  <button
                    type="button"
                    onClick={() => setActiveTab("report")}
                    className="glass-panel group flex flex-col justify-between rounded-2xl p-4 text-left transition hover:border-primary/50 hover:bg-surface-container"
                  >
                    <div>
                      <span className="inline-flex h-9 w-9 items-center justify-center rounded-xl border border-success/35 bg-success-container/25 text-success">
                        <span className="material-symbols-outlined text-[20px]">
                          description
                        </span>
                      </span>
                      <h3 className="mt-3 font-display text-sm font-semibold text-on-surface group-hover:text-primary">
                        Security Report Studio
                      </h3>
                      <p className="mt-1 text-xs text-on-surface-variant">
                        Export live HTML5, PDF-Ready AST, and JSON audit
                        bundles.
                      </p>
                    </div>
                    <span className="mt-3 inline-flex items-center gap-1 text-xs font-medium text-primary">
                      Generate Report
                      <span className="material-symbols-outlined text-[15px] transition-transform group-hover:translate-x-0.5">
                        arrow_forward
                      </span>
                    </span>
                  </button>
                </section>
              </div>
            </div>

            {/* Live Security Timeline Feed */}
            <section className="glass-panel rounded-2xl p-6">
              <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2.5">
                  <span className="material-symbols-outlined text-[20px] text-primary">
                    timeline
                  </span>
                  <h2 className="font-display text-base font-semibold text-on-surface">
                    Live Security Timeline
                  </h2>
                </div>
                <span className="font-code text-xs text-on-surface-variant tabular-nums">
                  {timelineEvents.length} event
                  {timelineEvents.length === 1 ? "" : "s"} recorded
                </span>
              </div>

              {timelineEvents.length === 0 ? (
                <div className="rounded-xl border border-outline-variant/30 bg-surface-container-low/60 p-6 text-center text-xs text-on-surface-variant">
                  Running initial live security scan... events will stream here
                  automatically.
                </div>
              ) : (
                <div className="space-y-2">
                  {timelineEvents.map((ev, idx) => (
                    <div
                      key={`${ev.timestamp}-${idx}`}
                      className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-outline-variant/30 bg-surface-container-low/75 px-4 py-3"
                    >
                      <div className="flex items-center gap-3 min-w-0">
                        <SeverityBadge variant={ev.severity} />
                        <span className="truncate text-xs font-medium text-on-surface">
                          {ev.label}
                        </span>
                      </div>
                      <div className="flex shrink-0 items-center gap-3 font-code text-[11px] text-on-surface-variant tabular-nums">
                        <span className="rounded-md bg-surface-container-lowest px-2 py-0.5 uppercase tracking-wide">
                          {ev.status}
                        </span>
                        <span>{formatTimelineTime(ev.timestamp)}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </section>
          </div>
        ) : null}

        {/* TAB 2: CODE ANALYSIS & AUTO-FIX */}
        {activeTab === "analysis" ? (
          <div className="space-y-4">
            {/* Semgrep Engine + Upload File / URL Bar */}
            <div className="glass-panel flex flex-wrap items-center justify-between gap-3 rounded-2xl px-4 py-3">
              <div className="flex flex-wrap items-center gap-2.5">
                <span className="inline-flex h-8 w-8 items-center justify-center rounded-lg border border-primary/30 bg-primary-container/15 text-primary">
                  <span className="material-symbols-outlined text-[18px]">
                    radar
                  </span>
                </span>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-display text-xs font-semibold text-on-surface">
                      Active Analysis Engine: {lastEngineLabel}
                    </span>
                    <span className="rounded-full border border-primary/30 bg-primary-container/10 px-2 py-0.5 font-code text-[10px] text-primary">
                      {semgrepStatus
                        ? semgrepStatus.cliAvailable
                          ? `Semgrep CLI ${semgrepStatus.cliVersion ?? ""}`.trim()
                          : `Semgrep Built-in (${semgrepStatus.builtinRulesCount} rules)`
                        : "Semgrep Ready"}
                    </span>
                  </div>
                  <p className="text-[11px] text-on-surface-variant">
                    Combines Sentinel AI&apos;s 12-rule engine with Semgrep SAST rules and deduplicates findings automatically.
                  </p>
                </div>
              </div>

              <button
                type="button"
                onClick={() => setUseSemgrep((prev) => !prev)}
                className={`inline-flex items-center gap-2 rounded-full border px-3.5 py-1.5 text-xs font-medium transition ${
                  useSemgrep
                    ? "border-primary/40 bg-primary-container/20 text-primary"
                    : "border-outline-variant/40 bg-surface-container-low text-on-surface-variant"
                }`}
              >
                <span
                  className={`h-2 w-2 rounded-full ${
                    useSemgrep ? "bg-primary" : "bg-outline"
                  }`}
                />
                <span>Semgrep Engine: {useSemgrep ? "ON" : "OFF"}</span>
              </button>
            </div>

            <UploadScanPanel onScanComplete={handleUploadScanComplete} />

            <CodeAnalysisWorkspace
              code={code}
              fileName={fileName}
              onCodeChange={handleCodeChange}
              report={analysisReport}
              isScanning={isScanning}
              onRunScan={handleRunScan}
              scoreReport={scoreReport}
              onFixApplied={handleFixApplied}
              onLogTimelineEvent={logTimelineEvent}
              onNavigateToSimulator={() => setActiveTab("simulator")}
            />
          </div>
        ) : null}

        {/* TAB 3: ATTACK SIMULATOR */}
        {activeTab === "simulator" ? (
          <AttackSimulatorPanel
            code={code}
            fileName={fileName}
            analysisReport={analysisReport}
            onApplyHardenedCode={(hardenedCode) => {
              setCode(hardenedCode);
              void runLiveScan(hardenedCode, fileName);
            }}
            onLogTimelineEvent={logTimelineEvent}
          />
        ) : null}

        {/* TAB 4: SECURITY REPORT STUDIO */}
        {activeTab === "report" ? (
          <SecurityReportPanel
            projectName={projectName}
            fileName={fileName}
            analysisReport={analysisReport}
            scoreReport={scoreReport}
            appliedFixes={appliedFixes}
            timelineEvents={timelineEvents}
            onLogTimelineEvent={logTimelineEvent}
          />
        ) : null}
      </main>
    </div>
  );
}
