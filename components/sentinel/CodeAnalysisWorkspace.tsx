"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type {
  StructuredSecurityReport,
  StructuredVulnerability,
} from "@/security/analyzer";
import type {
  BatchSecureFixResult,
  BeginnerFriendlyExplanation,
  FixVulnerabilityInput,
  SecureFixResult,
  SecurityScoreReport,
  Severity,
} from "@/types";
import {
  explainVulnerabilityApi,
  generateBatchFixApi,
  generateFixApi,
  SentinelApiError,
} from "./api-client";
import { CODE_PRESETS, type CodePreset } from "./presets";
import { ScoreRing } from "./ScoreRing";
import { SeverityBadge } from "./SeverityBadge";

export interface CodeAnalysisWorkspaceProps {
  code: string;
  fileName: string;
  onCodeChange: (code: string, fileName?: string) => void;
  report: StructuredSecurityReport | null;
  isScanning: boolean;
  onRunScan: (overrideCode?: string, overrideFileName?: string) => Promise<void>;
  scoreReport: SecurityScoreReport | null;
  onFixApplied: (fixResult: SecureFixResult, updatedCode: string) => void;
  onLogTimelineEvent: (
    action: string,
    label: string,
    severity: "critical" | "high" | "medium" | "low" | "info",
    status: string
  ) => void;
  onNavigateToSimulator?: () => void;
}

type CenterTab = "editor" | "diff";
type DiffViewMode = "hunks" | "split";

interface PendingFixState {
  mode: "single" | "batch";
  label: string;
  result: SecureFixResult;
  batchDetails?: BatchSecureFixResult;
}

function getVulnerabilityKey(
  vuln: StructuredVulnerability,
  index: number
): string {
  return `${vuln.ruleId}:${vuln.fileLine}:${vuln.column}:${index}`;
}

function toFixVulnerabilityInput(
  vuln: StructuredVulnerability,
  language?: StructuredSecurityReport["language"]
): FixVulnerabilityInput {
  return {
    ruleId: vuln.ruleId,
    name: vuln.name,
    category: vuln.category,
    severity: vuln.severity,
    fileLine: vuln.fileLine,
    matchedText: vuln.snippet,
    ...(language ? { language } : {}),
    cweId: vuln.cweId,
    description: vuln.description,
  };
}

function normalizeBatchFixResult(
  batch: BatchSecureFixResult
): SecureFixResult {
  return {
    originalCode: batch.originalCode,
    secureCode: batch.secureCode,
    linesChanged: batch.linesChanged,
    changedLineNumbers: batch.changedLineNumbers,
    summary: batch.summary,
    riskReduction: batch.riskReduction,
    fixerId: "batch-auto-fix",
    applied: batch.appliedFixes.some((item) => item.applied),
    notes: batch.appliedFixes.map((item) => `${item.ruleId}: ${item.summary}`),
  };
}

function getSeverityAccentClass(severity: Severity): string {
  switch (severity) {
    case "critical":
      return "bg-error/15 border-l-2 border-l-error";
    case "high":
      return "bg-warning/15 border-l-2 border-l-warning";
    case "medium":
      return "bg-[#FBBF24]/10 border-l-2 border-l-[#FBBF24]";
    case "low":
      return "bg-secondary/10 border-l-2 border-l-secondary";
    default:
      return "bg-primary/10 border-l-2 border-l-primary";
  }
}

function getSeverityDotClass(severity: Severity): string {
  switch (severity) {
    case "critical":
      return "bg-error";
    case "high":
      return "bg-warning";
    case "medium":
      return "bg-[#FBBF24]";
    case "low":
      return "bg-secondary";
    default:
      return "bg-primary";
  }
}

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

export function CodeAnalysisWorkspace({
  code,
  fileName,
  onCodeChange,
  report,
  isScanning,
  onRunScan,
  scoreReport,
  onFixApplied,
  onLogTimelineEvent,
  onNavigateToSimulator,
}: CodeAnalysisWorkspaceProps) {
  const [centerTab, setCenterTab] = useState<CenterTab>("editor");
  const [diffViewMode, setDiffViewMode] = useState<DiffViewMode>("hunks");
  const [selectedVulnKey, setSelectedVulnKey] = useState<string | null>(null);

  const [explanationCache, setExplanationCache] = useState<
    Record<string, BeginnerFriendlyExplanation>
  >({});
  const [activeExplanation, setActiveExplanation] =
    useState<BeginnerFriendlyExplanation | null>(null);
  const [isExplaining, setIsExplaining] = useState(false);
  const [explainError, setExplainError] = useState<string | null>(null);

  const [pendingFix, setPendingFix] = useState<PendingFixState | null>(null);
  const [isGeneratingFix, setIsGeneratingFix] = useState(false);
  const [isApplyingFix, setIsApplyingFix] = useState(false);
  const [fixError, setFixError] = useState<string | null>(null);
  const [copiedSecureCode, setCopiedSecureCode] = useState(false);

  const explainRequestSeq = useRef(0);
  const textareaRef = useRef<HTMLTextAreaElement | null>(null);
  const gutterRef = useRef<HTMLDivElement | null>(null);
  const highlightOverlayRef = useRef<HTMLDivElement | null>(null);

  const vulnerabilities = useMemo(
    () => report?.vulnerabilities ?? [],
    [report]
  );

  const activePresetId = useMemo(() => {
    const matched = CODE_PRESETS.find((p) => p.fileName === fileName);
    return matched?.id ?? "";
  }, [fileName]);

  const selectedEntry = useMemo(() => {
    if (vulnerabilities.length === 0) return null;
    if (selectedVulnKey) {
      for (let i = 0; i < vulnerabilities.length; i += 1) {
        const vuln = vulnerabilities[i];
        if (vuln && getVulnerabilityKey(vuln, i) === selectedVulnKey) {
          return { vuln, key: selectedVulnKey };
        }
      }
    }
    const first = vulnerabilities[0];
    if (!first) return null;
    return { vuln: first, key: getVulnerabilityKey(first, 0) };
  }, [vulnerabilities, selectedVulnKey]);

  const selectedVuln = selectedEntry?.vuln ?? null;
  const resolvedSelectedKey = selectedEntry?.key ?? null;

  const codeLines = useMemo(() => {
    const split = code.split("\n");
    return split.length > 0 ? split : [""];
  }, [code]);

  // Map 1-based line numbers to the highest severity vulnerability on that line
  const vulnerableLineSeverityMap = useMemo(() => {
    const map = new Map<number, Severity>();
    for (const vuln of vulnerabilities) {
      const existing = map.get(vuln.fileLine);
      if (!existing || SEVERITY_RANK[vuln.severity] > SEVERITY_RANK[existing]) {
        map.set(vuln.fileLine, vuln.severity);
      }
    }
    return map;
  }, [vulnerabilities]);

  const fetchExplanation = useCallback(
    async (vuln: StructuredVulnerability, cacheKey: string) => {
      const cached = explanationCache[cacheKey];
      if (cached) {
        setActiveExplanation(cached);
        setExplainError(null);
        setIsExplaining(false);
        return;
      }

      const seq = explainRequestSeq.current + 1;
      explainRequestSeq.current = seq;
      setIsExplaining(true);
      setExplainError(null);

      try {
        const explanation = await explainVulnerabilityApi({
          ruleId: vuln.ruleId,
          name: vuln.name,
          severity: vuln.severity,
          category: vuln.category,
          description: vuln.description,
          snippet: vuln.snippet,
          fileLine: vuln.fileLine,
          fileName,
          language: report?.language,
          cweId: vuln.cweId,
          owaspCategory: vuln.owaspCategory,
        });

        if (explainRequestSeq.current !== seq) return;
        setExplanationCache((prev) => ({ ...prev, [cacheKey]: explanation }));
        setActiveExplanation(explanation);
      } catch (error) {
        if (explainRequestSeq.current !== seq) return;
        const message =
          error instanceof SentinelApiError
            ? error.message
            : "Unable to load AI explanation. Try again.";
        setExplainError(message);
        setActiveExplanation(null);
      } finally {
        if (explainRequestSeq.current === seq) {
          setIsExplaining(false);
        }
      }
    },
    [explanationCache, fileName, report?.language]
  );

  // Sync selected vulnerability and automatically fetch explanation when selection changes
  useEffect(() => {
    if (!selectedVuln || !resolvedSelectedKey) {
      setActiveExplanation(null);
      setExplainError(null);
      setIsExplaining(false);
      return;
    }

    if (selectedVulnKey !== resolvedSelectedKey) {
      setSelectedVulnKey(resolvedSelectedKey);
    }

    void fetchExplanation(selectedVuln, resolvedSelectedKey);
  }, [selectedVuln, resolvedSelectedKey, selectedVulnKey, fetchExplanation]);

  // Reset pending fix when code changes externally (e.g., manual edit or preset switch)
  const handleSelectPreset = async (preset: CodePreset) => {
    setPendingFix(null);
    setFixError(null);
    setSelectedVulnKey(null);
    setExplanationCache({});
    setActiveExplanation(null);
    setCenterTab("editor");
    onCodeChange(preset.code, preset.fileName);
    onLogTimelineEvent(
      "preset_loaded",
      `Loaded preset: ${preset.label}`,
      "info",
      "Ready"
    );
    await onRunScan(preset.code, preset.fileName);
  };

  const handleSelectVulnerability = (
    vuln: StructuredVulnerability,
    index: number
  ) => {
    const key = getVulnerabilityKey(vuln, index);
    setSelectedVulnKey(key);
    setCenterTab("editor");

    // Scroll the source editor smoothly to the vulnerable line
    if (textareaRef.current) {
      const lineHeightPx = 22;
      const targetTop = Math.max(0, (vuln.fileLine - 4) * lineHeightPx);
      textareaRef.current.scrollTop = targetTop;
      if (gutterRef.current) gutterRef.current.scrollTop = targetTop;
      if (highlightOverlayRef.current) {
        highlightOverlayRef.current.scrollTop = targetTop;
      }
    }
  };

  const handleEditorScroll = () => {
    if (!textareaRef.current) return;
    const { scrollTop } = textareaRef.current;
    if (gutterRef.current) {
      gutterRef.current.scrollTop = scrollTop;
    }
    if (highlightOverlayRef.current) {
      highlightOverlayRef.current.scrollTop = scrollTop;
    }
  };

  const handleGenerateSingleFix = async (vuln: StructuredVulnerability) => {
    setIsGeneratingFix(true);
    setFixError(null);
    setCenterTab("diff");

    try {
      const fixResult = await generateFixApi({
        originalCode: code,
        vulnerability: toFixVulnerabilityInput(vuln, report?.language),
      });

      setPendingFix({
        mode: "single",
        label: vuln.name,
        result: fixResult,
      });

      onLogTimelineEvent(
        "fix_generated",
        `Generated secure patch for ${vuln.name} (L${vuln.fileLine})`,
        vuln.severity,
        `-${fixResult.riskReduction.reductionPercent}% Risk`
      );
    } catch (error) {
      const message =
        error instanceof SentinelApiError
          ? error.message
          : "Failed to generate secure fix.";
      setFixError(message);
    } finally {
      setIsGeneratingFix(false);
    }
  };

  const handleGenerateBatchFix = async () => {
    if (vulnerabilities.length === 0) return;

    setIsGeneratingFix(true);
    setFixError(null);
    setCenterTab("diff");

    try {
      const batchResult = await generateBatchFixApi({
        originalCode: code,
        vulnerabilities: vulnerabilities.map((v) =>
          toFixVulnerabilityInput(v, report?.language)
        ),
      });

      const normalized = normalizeBatchFixResult(batchResult);
      setPendingFix({
        mode: "batch",
        label: `Batch Auto-Fix (${vulnerabilities.length} findings)`,
        result: normalized,
        batchDetails: batchResult,
      });

      onLogTimelineEvent(
        "batch_fix_generated",
        `Generated batch remediation for ${vulnerabilities.length} vulnerabilities`,
        "info",
        `-${batchResult.riskReduction.reductionPercent}% Risk`
      );
    } catch (error) {
      const message =
        error instanceof SentinelApiError
          ? error.message
          : "Failed to generate batch auto-fix.";
      setFixError(message);
    } finally {
      setIsGeneratingFix(false);
    }
  };

  const handleApplyFixToEditor = async () => {
    if (!pendingFix) return;
    setIsApplyingFix(true);
    const updatedCode = pendingFix.result.secureCode;
    const appliedResult = pendingFix.result;
    const fixLabel = pendingFix.label;

    try {
      onCodeChange(updatedCode, fileName);
      onFixApplied(appliedResult, updatedCode);
      onLogTimelineEvent(
        "fix_applied",
        `Applied secure fix: ${fixLabel}`,
        "info",
        "Remediated"
      );
      setPendingFix(null);
      setExplanationCache({});
      setSelectedVulnKey(null);
      setCenterTab("editor");
    } finally {
      setIsApplyingFix(false);
    }
  };

  const handleCopySecurePattern = async (snippet: string) => {
    if (typeof navigator === "undefined" || !navigator.clipboard) return;
    try {
      await navigator.clipboard.writeText(snippet);
      setCopiedSecureCode(true);
      setTimeout(() => setCopiedSecureCode(false), 1800);
    } catch {
      // Ignore clipboard failures in restricted environments
    }
  };

  const displayScore =
    scoreReport?.score ?? (report ? Math.max(0, 100 - report.riskScore) : 100);
  const displayGrade = scoreReport?.letterGrade ?? report?.riskGrade ?? "A";
  const displayRiskCategory =
    scoreReport?.riskCategory ??
    (report
      ? report.vulnerabilities.length === 0
        ? "Minimal Risk"
        : `${report.vulnerabilities.length} Active ${
            report.vulnerabilities.length === 1 ? "Finding" : "Findings"
          }`
      : "Awaiting Scan");

  const severityBreakdown = report?.severityBreakdown ?? {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  return (
    <div className="flex flex-col gap-4">
      {/* Top Control Bar */}
      <section className="glass-panel rounded-xl px-4 py-3 flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
        {/* Sample Presets Pills */}
        <div className="flex flex-wrap items-center gap-2">
          <span className="inline-flex items-center gap-1.5 font-label text-[11px] uppercase tracking-wider text-on-surface-variant mr-1">
            <span className="material-symbols-outlined text-[16px] text-primary">
              code_blocks
            </span>
            Presets
          </span>

          {CODE_PRESETS.map((preset) => {
            const isActive = preset.id === activePresetId;
            return (
              <button
                key={preset.id}
                type="button"
                disabled={isScanning}
                onClick={() => void handleSelectPreset(preset)}
                title={preset.description}
                className={`px-3 py-1.5 rounded-lg text-xs font-label font-medium transition-all duration-150 border ${
                  isActive
                    ? "bg-primary/15 text-primary border-primary/50 shadow-[0_0_16px_-6px_rgba(34,211,238,0.5)]"
                    : "bg-surface-container-low/70 text-on-surface-variant border-outline-variant/40 hover:text-on-surface hover:border-outline-variant/80 hover:bg-surface-container-high/60"
                } disabled:opacity-50`}
              >
                {preset.label}
              </button>
            );
          })}
        </div>

        {/* File Badge & Primary Actions */}
        <div className="flex flex-wrap items-center gap-2.5">
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-surface-container-lowest/90 border border-outline-variant/40">
            <span className="material-symbols-outlined text-[15px] text-primary">
              description
            </span>
            <span className="font-code text-xs text-on-surface max-w-[200px] truncate">
              {fileName}
            </span>
            {report?.language ? (
              <span className="px-1.5 py-0.5 rounded bg-surface-container-high font-code text-[10px] uppercase text-primary">
                {report.language}
              </span>
            ) : null}
          </div>

          {vulnerabilities.length > 0 ? (
            <button
              type="button"
              disabled={isGeneratingFix || isScanning}
              onClick={() => void handleGenerateBatchFix()}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-label font-semibold bg-success-container/80 text-on-success-container border border-success/45 hover:bg-success-container transition-all duration-150 disabled:opacity-50"
            >
              <span className="material-symbols-outlined text-[16px]">
                {isGeneratingFix ? "progress_activity" : "auto_fix_high"}
              </span>
              Auto-Fix All ({vulnerabilities.length})
            </button>
          ) : null}

          <button
            type="button"
            disabled={isScanning}
            onClick={() => void onRunScan()}
            className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-label font-semibold bg-primary-container text-on-primary hover:bg-primary transition-all duration-150 cyan-glow disabled:opacity-60"
          >
            <span
              className={`material-symbols-outlined text-[16px] ${
                isScanning ? "animate-spin" : ""
              }`}
            >
              {isScanning ? "progress_activity" : "radar"}
            </span>
            {isScanning ? "Scanning…" : "Scan Code"}
          </button>
        </div>
      </section>

      {/* 3-Zone Fluid Bento Split */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-4 items-stretch">
        {/* LEFT RAIL: Compact Security Score Ring + Detected Vulnerabilities */}
        <aside className="xl:col-span-3 glass-panel rounded-xl p-4 flex flex-col gap-4 min-h-[580px] xl:max-h-[740px]">
          {/* Score Header */}
          <div className="flex flex-col items-center pb-4 border-b border-outline-variant/35">
            <div className="w-full flex items-center justify-between mb-2">
              <h2 className="font-display text-sm font-semibold text-on-surface tracking-tight">
                Security Posture
              </h2>
              {report ? (
                <span className="font-code text-[11px] text-on-surface-variant tabular-nums">
                  {report.durationMs}ms · {report.executedRulesCount} rules
                </span>
              ) : null}
            </div>

            <ScoreRing
              score={displayScore}
              letterGrade={displayGrade}
              riskCategory={displayRiskCategory}
              size={126}
            />

            {/* Severity Distribution Strip */}
            <div className="mt-3 w-full grid grid-cols-4 gap-1.5">
              <div className="rounded-lg bg-surface-container-lowest/80 border border-outline-variant/30 px-2 py-1.5 text-center">
                <div className="font-display text-sm font-bold tabular-nums text-error">
                  {severityBreakdown.critical}
                </div>
                <div className="font-label text-[10px] text-on-surface-variant">
                  Crit
                </div>
              </div>
              <div className="rounded-lg bg-surface-container-lowest/80 border border-outline-variant/30 px-2 py-1.5 text-center">
                <div className="font-display text-sm font-bold tabular-nums text-warning">
                  {severityBreakdown.high}
                </div>
                <div className="font-label text-[10px] text-on-surface-variant">
                  High
                </div>
              </div>
              <div className="rounded-lg bg-surface-container-lowest/80 border border-outline-variant/30 px-2 py-1.5 text-center">
                <div className="font-display text-sm font-bold tabular-nums text-[#FFE08A]">
                  {severityBreakdown.medium}
                </div>
                <div className="font-label text-[10px] text-on-surface-variant">
                  Med
                </div>
              </div>
              <div className="rounded-lg bg-surface-container-lowest/80 border border-outline-variant/30 px-2 py-1.5 text-center">
                <div className="font-display text-sm font-bold tabular-nums text-secondary">
                  {severityBreakdown.low}
                </div>
                <div className="font-label text-[10px] text-on-surface-variant">
                  Low
                </div>
              </div>
            </div>
          </div>

          {/* Vulnerability List Header */}
          <div className="flex items-center justify-between">
            <h3 className="font-display text-xs font-semibold uppercase tracking-wider text-on-surface-variant">
              Detected Vulnerabilities
            </h3>
            <span className="px-2 py-0.5 rounded-full bg-surface-container-high font-code text-[11px] text-primary tabular-nums">
              {vulnerabilities.length}
            </span>
          </div>

          {/* Scrollable Findings List */}
          <div className="flex-1 overflow-y-auto pr-1 space-y-2">
            {isScanning && vulnerabilities.length === 0 ? (
              <div className="space-y-2.5 py-2">
                {[1, 2, 3].map((item) => (
                  <div
                    key={item}
                    className="h-20 rounded-xl bg-surface-container-high/50 border border-outline-variant/25 animate-pulse"
                  />
                ))}
              </div>
            ) : vulnerabilities.length === 0 ? (
              <div className="rounded-xl bg-success-container/20 border border-success/35 p-4 text-center flex flex-col items-center gap-2 mt-2">
                <span className="material-symbols-outlined text-[28px] text-success">
                  verified_user
                </span>
                <p className="font-display text-sm font-semibold text-on-surface">
                  Zero Vulnerabilities Detected
                </p>
                <p className="font-body text-xs text-on-surface-variant leading-relaxed">
                  All active static security rules passed cleanly for this file.
                </p>
              </div>
            ) : (
              vulnerabilities.map((vuln, index) => {
                const key = getVulnerabilityKey(vuln, index);
                const isSelected = key === resolvedSelectedKey;
                const confidencePct = Math.round(vuln.confidenceScore * 100);

                return (
                  <button
                    key={key}
                    type="button"
                    onClick={() => handleSelectVulnerability(vuln, index)}
                    className={`w-full text-left rounded-xl p-3 border transition-all duration-150 ${
                      isSelected
                        ? "bg-surface-container-high/90 border-primary/55 shadow-[0_0_20px_-8px_rgba(34,211,238,0.45)]"
                        : "bg-surface-container-low/75 border-outline-variant/35 hover:bg-surface-container-high/55 hover:border-outline-variant/70"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2 mb-1.5">
                      <SeverityBadge variant={vuln.severity} size="sm" />
                      <span className="font-code text-[11px] text-primary tabular-nums">
                        L{vuln.fileLine}
                      </span>
                    </div>

                    <p className="font-display text-[13px] font-semibold text-on-surface leading-snug line-clamp-2">
                      {vuln.name}
                    </p>

                    <div className="mt-2 flex items-center justify-between gap-2 text-[11px] font-code text-on-surface-variant tabular-nums">
                      <span className="truncate">{vuln.cweId}</span>
                      <span className="inline-flex items-center gap-1 text-on-surface-variant">
                        <span className="w-1.5 h-1.5 rounded-full bg-primary/80" />
                        {confidencePct}% conf
                      </span>
                    </div>
                  </button>
                );
              })
            )}
          </div>
        </aside>

        {/* CENTER PANE: Source Editor & Auto-Fix Diff */}
        <section className="xl:col-span-5 glass-panel rounded-xl flex flex-col overflow-hidden min-h-[580px] xl:max-h-[740px]">
          {/* Pane Header with Tab Toggle */}
          <div className="px-4 py-3 border-b border-outline-variant/35 flex flex-wrap items-center justify-between gap-2 bg-surface-container-low/60">
            <div className="inline-flex items-center p-1 rounded-lg bg-surface-container-lowest border border-outline-variant/35">
              <button
                type="button"
                onClick={() => setCenterTab("editor")}
                className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-label font-medium transition-all duration-150 ${
                  centerTab === "editor"
                    ? "bg-surface-container-high text-primary shadow-sm"
                    : "text-on-surface-variant hover:text-on-surface"
                }`}
              >
                <span className="material-symbols-outlined text-[15px]">
                  code
                </span>
                Source Editor
              </button>

              <button
                type="button"
                onClick={() => setCenterTab("diff")}
                className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-label font-medium transition-all duration-150 ${
                  centerTab === "diff"
                    ? "bg-surface-container-high text-primary shadow-sm"
                    : "text-on-surface-variant hover:text-on-surface"
                }`}
              >
                <span className="material-symbols-outlined text-[15px]">
                  difference
                </span>
                Auto-Fix Diff
                {pendingFix ? (
                  <span className="ml-0.5 px-1.5 py-0.5 rounded-full bg-success-container text-on-success-container font-code text-[10px] tabular-nums">
                    {pendingFix.result.linesChanged.length}
                  </span>
                ) : null}
              </button>
            </div>

            {centerTab === "diff" && pendingFix ? (
              <div className="inline-flex items-center p-0.5 rounded-lg bg-surface-container-lowest border border-outline-variant/35">
                <button
                  type="button"
                  onClick={() => setDiffViewMode("hunks")}
                  className={`px-2.5 py-1 rounded text-[11px] font-label font-medium transition-colors ${
                    diffViewMode === "hunks"
                      ? "bg-surface-container-high text-primary"
                      : "text-on-surface-variant hover:text-on-surface"
                  }`}
                >
                  Patch Hunks
                </button>
                <button
                  type="button"
                  onClick={() => setDiffViewMode("split")}
                  className={`px-2.5 py-1 rounded text-[11px] font-label font-medium transition-colors ${
                    diffViewMode === "split"
                      ? "bg-surface-container-high text-primary"
                      : "text-on-surface-variant hover:text-on-surface"
                  }`}
                >
                  Before / After
                </button>
              </div>
            ) : (
              <span className="font-code text-[11px] text-on-surface-variant tabular-nums">
                {codeLines.length} lines
              </span>
            )}
          </div>

          {/* Center Body */}
          {centerTab === "editor" ? (
            <div className="flex-1 flex flex-col bg-surface-container-lowest overflow-hidden">
              <div className="relative flex-1 flex overflow-hidden">
                {/* Line Number Gutter */}
                <div
                  ref={gutterRef}
                  aria-hidden="true"
                  className="w-12 flex-shrink-0 bg-[#070C18] border-r border-outline-variant/25 py-3 overflow-hidden select-none text-right"
                >
                  {codeLines.map((_, idx) => {
                    const lineNum = idx + 1;
                    const lineSeverity = vulnerableLineSeverityMap.get(lineNum);
                    const isActiveLine = selectedVuln?.fileLine === lineNum;

                    return (
                      <div
                        key={lineNum}
                        className={`h-[22px] leading-[22px] pr-2.5 font-code text-[11px] tabular-nums flex items-center justify-end gap-1 ${
                          isActiveLine
                            ? "text-primary font-semibold bg-primary/15"
                            : lineSeverity
                            ? "text-error"
                            : "text-outline/75"
                        }`}
                      >
                        {lineSeverity ? (
                          <span
                            className={`w-1.5 h-1.5 rounded-full ${getSeverityDotClass(
                              lineSeverity
                            )} ${isActiveLine ? "animate-pulse" : ""}`}
                          />
                        ) : null}
                        <span>{lineNum}</span>
                      </div>
                    );
                  })}
                </div>

                {/* Highlight Overlay + Monospace Textarea */}
                <div className="relative flex-1 overflow-hidden">
                  {/* Line Highlight Underlay */}
                  <div
                    ref={highlightOverlayRef}
                    aria-hidden="true"
                    className="pointer-events-none absolute inset-0 py-3 overflow-hidden"
                  >
                    {codeLines.map((_, idx) => {
                      const lineNum = idx + 1;
                      const lineSeverity =
                        vulnerableLineSeverityMap.get(lineNum);
                      const isActiveLine = selectedVuln?.fileLine === lineNum;

                      return (
                        <div
                          key={lineNum}
                          className={`h-[22px] w-full ${
                            isActiveLine
                              ? "bg-primary/15 border-l-2 border-l-primary"
                              : lineSeverity
                              ? getSeverityAccentClass(lineSeverity)
                              : ""
                          }`}
                        />
                      );
                    })}
                  </div>

                  {/* Editable Code Textarea */}
                  <textarea
                    ref={textareaRef}
                    value={code}
                    onChange={(event) => {
                      onCodeChange(event.target.value, fileName);
                      if (pendingFix) {
                        setPendingFix(null);
                      }
                    }}
                    onScroll={handleEditorScroll}
                    spellCheck={false}
                    autoCapitalize="off"
                    autoCorrect="off"
                    wrap="off"
                    aria-label="Source code editor"
                    className="relative z-10 w-full h-full bg-transparent text-on-surface font-code text-[13px] leading-[22px] py-3 px-3.5 resize-none focus:outline-none overflow-auto whitespace-pre"
                  />
                </div>
              </div>

              {/* Editor Status Footer */}
              <div className="px-3.5 py-2 border-t border-outline-variant/25 bg-[#070C18] flex items-center justify-between gap-2 text-[11px] font-code text-on-surface-variant">
                <span className="truncate">
                  {selectedVuln
                    ? `Selected: L${selectedVuln.fileLine} · ${selectedVuln.ruleId}`
                    : "Edit code directly and click Scan Code to re-analyze"}
                </span>
                <span className="tabular-nums flex-shrink-0 text-primary">
                  UTF-8
                </span>
              </div>
            </div>
          ) : (
            /* Auto-Fix Diff Tab */
            <div className="flex-1 flex flex-col bg-surface-container-lowest overflow-hidden">
              {isGeneratingFix ? (
                <div className="flex-1 flex flex-col items-center justify-center gap-3 p-8 text-center">
                  <span className="material-symbols-outlined text-[34px] text-primary animate-spin">
                    progress_activity
                  </span>
                  <p className="font-display text-sm font-semibold text-on-surface">
                    Synthesizing Deterministic Secure Patch…
                  </p>
                  <p className="font-body text-xs text-on-surface-variant max-w-xs">
                    Computing AST-safe replacements and verifying risk reduction
                    metrics via /api/fix.
                  </p>
                </div>
              ) : fixError ? (
                <div className="flex-1 flex flex-col items-center justify-center gap-3 p-8 text-center">
                  <span className="material-symbols-outlined text-[32px] text-error">
                    error
                  </span>
                  <p className="font-display text-sm font-semibold text-on-surface">
                    Fix Generation Failed
                  </p>
                  <p className="font-body text-xs text-error max-w-sm">
                    {fixError}
                  </p>
                  {selectedVuln ? (
                    <button
                      type="button"
                      onClick={() => void handleGenerateSingleFix(selectedVuln)}
                      className="mt-1 px-3.5 py-1.5 rounded-lg text-xs font-label font-medium bg-surface-container-high text-primary border border-primary/40 hover:bg-primary/15"
                    >
                      Retry Fix
                    </button>
                  ) : null}
                </div>
              ) : !pendingFix ? (
                <div className="flex-1 flex flex-col items-center justify-center gap-3 p-8 text-center">
                  <div className="w-12 h-12 rounded-2xl bg-primary/10 border border-primary/30 flex items-center justify-center">
                    <span className="material-symbols-outlined text-[24px] text-primary">
                      auto_fix_high
                    </span>
                  </div>
                  <p className="font-display text-sm font-semibold text-on-surface">
                    No Pending Patch Generated
                  </p>
                  <p className="font-body text-xs text-on-surface-variant max-w-xs leading-relaxed">
                    Select a finding and click{" "}
                    <span className="text-primary font-medium">
                      Generate Secure Fix
                    </span>{" "}
                    or run{" "}
                    <span className="text-success font-medium">
                      Auto-Fix All
                    </span>{" "}
                    to preview the before/after diff.
                  </p>
                  <div className="flex items-center gap-2 mt-1">
                    {selectedVuln ? (
                      <button
                        type="button"
                        onClick={() =>
                          void handleGenerateSingleFix(selectedVuln)
                        }
                        className="px-3.5 py-2 rounded-lg text-xs font-label font-semibold bg-primary-container text-on-primary hover:bg-primary transition-colors cyan-glow"
                      >
                        Fix Selected Finding
                      </button>
                    ) : null}
                    {vulnerabilities.length > 1 ? (
                      <button
                        type="button"
                        onClick={() => void handleGenerateBatchFix()}
                        className="px-3.5 py-2 rounded-lg text-xs font-label font-semibold bg-success-container/80 text-on-success-container border border-success/45 hover:bg-success-container transition-colors"
                      >
                        Auto-Fix All ({vulnerabilities.length})
                      </button>
                    ) : null}
                  </div>
                </div>
              ) : (
                <>
                  {/* Risk Reduction Telemetry Banner */}
                  <div className="px-4 py-3 border-b border-outline-variant/30 bg-surface-container-low/75 flex flex-col gap-2">
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2 min-w-0">
                        <SeverityBadge
                          variant="fixed"
                          label={
                            pendingFix.mode === "batch"
                              ? "Batch Patch Ready"
                              : "Secure Patch Ready"
                          }
                        />
                        <span className="font-display text-xs font-semibold text-on-surface truncate">
                          {pendingFix.label}
                        </span>
                      </div>
                      <span className="font-code text-xs font-semibold text-success tabular-nums flex-shrink-0">
                        -{pendingFix.result.riskReduction.reductionPercent}%
                        risk (-{pendingFix.result.riskReduction.reductionPoints}{" "}
                        pts)
                      </span>
                    </div>

                    <p className="font-body text-xs text-on-surface-variant leading-relaxed">
                      {pendingFix.result.summary}
                    </p>

                    <div className="flex flex-wrap items-center gap-3 text-[11px] font-code text-on-surface-variant tabular-nums">
                      <span>
                        Risk Score:{" "}
                        <span className="text-error">
                          {pendingFix.result.riskReduction.beforeScore}
                        </span>{" "}
                        →{" "}
                        <span className="text-success">
                          {pendingFix.result.riskReduction.afterScore}
                        </span>
                      </span>
                      <span>
                        Lines Modified:{" "}
                        <span className="text-primary">
                          {pendingFix.result.linesChanged.length}
                        </span>
                      </span>
                    </div>
                  </div>

                  {/* Diff Content */}
                  <div className="flex-1 overflow-y-auto p-3.5 space-y-3">
                    {diffViewMode === "hunks" ? (
                      pendingFix.result.linesChanged.length > 0 ? (
                        pendingFix.result.linesChanged.map((change, idx) => (
                          <div
                            key={`${change.lineNumber}-${idx}`}
                            className="rounded-xl border border-outline-variant/35 bg-[#0A1020] overflow-hidden"
                          >
                            <div className="px-3 py-1.5 bg-surface-container-low/70 border-b border-outline-variant/25 flex items-center justify-between gap-2">
                              <span className="font-code text-[11px] text-primary tabular-nums">
                                Line {change.lineNumber}
                              </span>
                              <span className="font-body text-[11px] text-on-surface-variant truncate">
                                {change.reason}
                              </span>
                            </div>

                            <div className="font-code text-xs leading-relaxed overflow-x-auto">
                              <div className="px-3 py-1.5 bg-error-container/35 text-error flex gap-2 whitespace-pre">
                                <span className="select-none opacity-80">-</span>
                                <span>{change.originalLine}</span>
                              </div>
                              <div className="px-3 py-1.5 bg-success-container/35 text-success flex gap-2 whitespace-pre">
                                <span className="select-none opacity-80">+</span>
                                <span>{change.updatedLine}</span>
                              </div>
                            </div>
                          </div>
                        ))
                      ) : (
                        <div className="rounded-xl border border-outline-variant/35 bg-surface-container-low/50 p-4 text-xs font-body text-on-surface-variant">
                          No line-level changes were required for this rule.
                        </div>
                      )
                    ) : (
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <div className="rounded-xl border border-error/30 bg-[#0A1020] overflow-hidden">
                          <div className="px-3 py-1.5 bg-error-container/30 border-b border-error/25 font-label text-[11px] font-semibold text-error">
                            Before (Vulnerable)
                          </div>
                          <pre className="p-3 font-code text-[11px] leading-relaxed text-on-surface-variant overflow-x-auto whitespace-pre">
                            {pendingFix.result.originalCode}
                          </pre>
                        </div>

                        <div className="rounded-xl border border-success/35 bg-[#0A1020] overflow-hidden">
                          <div className="px-3 py-1.5 bg-success-container/30 border-b border-success/25 font-label text-[11px] font-semibold text-success">
                            After (Hardened)
                          </div>
                          <pre className="p-3 font-code text-[11px] leading-relaxed text-on-surface overflow-x-auto whitespace-pre">
                            {pendingFix.result.secureCode}
                          </pre>
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Apply Fix Footer */}
                  <div className="px-4 py-3 border-t border-outline-variant/35 bg-surface-container-low/80 flex items-center justify-between gap-3">
                    <button
                      type="button"
                      disabled={isApplyingFix}
                      onClick={() => {
                        setPendingFix(null);
                        setCenterTab("editor");
                      }}
                      className="px-3 py-2 rounded-lg text-xs font-label font-medium text-on-surface-variant hover:text-on-surface hover:bg-surface-container-high/70 transition-colors"
                    >
                      Discard
                    </button>

                    <button
                      type="button"
                      disabled={isApplyingFix}
                      onClick={() => void handleApplyFixToEditor()}
                      className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-label font-semibold bg-success text-on-success hover:bg-[#6FFBBE] transition-all duration-150 shadow-[0_0_24px_-6px_rgba(78,222,163,0.65)] disabled:opacity-60"
                    >
                      <span className="material-symbols-outlined text-[16px]">
                        {isApplyingFix ? "progress_activity" : "check_circle"}
                      </span>
                      {isApplyingFix
                        ? "Applying & Re-scanning…"
                        : "Apply Fix to Editor"}
                    </button>
                  </div>
                </>
              )}
            </div>
          )}
        </section>

        {/* RIGHT RAIL: AI Co-Pilot Explanation Panel */}
        <aside className="xl:col-span-4 glass-panel-elevated rounded-xl flex flex-col overflow-hidden min-h-[580px] xl:max-h-[740px]">
          {/* Header */}
          <div className="px-4 py-3 border-b border-outline-variant/35 flex items-center justify-between gap-2 bg-surface-container-low/65">
            <div className="flex items-center gap-2 min-w-0">
              <span className="material-symbols-outlined text-[18px] text-primary">
                psychology
              </span>
              <h2 className="font-display text-sm font-semibold text-on-surface truncate">
                AI Co-Pilot Explanation
              </h2>
            </div>

            {activeExplanation ? (
              <span className="px-2 py-0.5 rounded-full bg-primary/15 border border-primary/35 font-code text-[10px] uppercase tracking-wide text-primary flex-shrink-0">
                {activeExplanation.source === "ai-enhanced"
                  ? "AI Enhanced"
                  : "Sentinel Intel"}
              </span>
            ) : null}
          </div>

          {/* Scrollable Body */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4">
            {!selectedVuln ? (
              <div className="h-full flex flex-col items-center justify-center text-center gap-3 py-12">
                <div className="w-12 h-12 rounded-2xl bg-success-container/35 border border-success/40 flex items-center justify-center">
                  <span className="material-symbols-outlined text-[24px] text-success">
                    shield_with_heart
                  </span>
                </div>
                <p className="font-display text-sm font-semibold text-on-surface">
                  Codebase Posture Verified
                </p>
                <p className="font-body text-xs text-on-surface-variant max-w-xs leading-relaxed">
                  Select a vulnerability from the left rail or load a vulnerable
                  preset to inspect root cause, exploit path, and secure code.
                </p>
              </div>
            ) : isExplaining ? (
              <div className="space-y-3 animate-pulse">
                <div className="h-6 w-3/4 rounded-lg bg-surface-container-high/80" />
                <div className="h-16 rounded-xl bg-surface-container-high/55" />
                <div className="h-20 rounded-xl bg-surface-container-high/55" />
                <div className="h-24 rounded-xl bg-primary/10 border border-primary/25" />
                <div className="h-28 rounded-xl bg-surface-container-lowest/90" />
              </div>
            ) : explainError ? (
              <div className="rounded-xl border border-error/40 bg-error-container/25 p-4 flex flex-col gap-2">
                <div className="flex items-center gap-2 text-error font-display text-xs font-semibold">
                  <span className="material-symbols-outlined text-[16px]">
                    warning
                  </span>
                  Explanation Unavailable
                </div>
                <p className="font-body text-xs text-on-error-container">
                  {explainError}
                </p>
                {resolvedSelectedKey ? (
                  <button
                    type="button"
                    onClick={() =>
                      void fetchExplanation(selectedVuln, resolvedSelectedKey)
                    }
                    className="self-start mt-1 px-3 py-1.5 rounded-lg text-xs font-label font-medium bg-surface-container-high text-primary border border-primary/35 hover:bg-primary/15"
                  >
                    Retry Explanation
                  </button>
                ) : null}
              </div>
            ) : activeExplanation ? (
              <>
                {/* Selected Finding Meta */}
                <div className="space-y-2 pb-3 border-b border-outline-variant/30">
                  <div className="flex flex-wrap items-center gap-2">
                    <SeverityBadge variant={activeExplanation.severity} />
                    {activeExplanation.cweId ? (
                      <span className="px-2 py-0.5 rounded-full bg-surface-container-high font-code text-[11px] text-on-surface-variant">
                        {activeExplanation.cweId}
                      </span>
                    ) : null}
                    {activeExplanation.fileLine ? (
                      <span className="px-2 py-0.5 rounded-full bg-surface-container-lowest font-code text-[11px] text-primary tabular-nums">
                        Line {activeExplanation.fileLine}
                      </span>
                    ) : null}
                  </div>

                  <h3 className="font-display text-base font-semibold text-on-surface leading-snug">
                    {activeExplanation.vulnerabilityName}
                  </h3>

                  {activeExplanation.owaspCategory ? (
                    <p className="font-code text-[11px] text-on-surface-variant">
                      {activeExplanation.owaspCategory}
                    </p>
                  ) : null}
                </div>

                {/* What It Is */}
                <div className="space-y-1">
                  <h4 className="font-label text-[11px] font-semibold uppercase tracking-wider text-primary">
                    What It Is
                  </h4>
                  <p className="font-body text-[13px] text-on-surface leading-relaxed">
                    {activeExplanation.whatItIs}
                  </p>
                </div>

                {/* Why It Happens */}
                <div className="space-y-1">
                  <h4 className="font-label text-[11px] font-semibold uppercase tracking-wider text-on-surface-variant">
                    Why It Happens
                  </h4>
                  <p className="font-body text-[13px] text-on-surface-variant leading-relaxed">
                    {activeExplanation.whyItHappens}
                  </p>
                </div>

                {/* How Hackers Exploit It */}
                <div className="space-y-1">
                  <h4 className="font-label text-[11px] font-semibold uppercase tracking-wider text-error">
                    How Attackers Exploit It
                  </h4>
                  <p className="font-body text-[13px] text-on-surface-variant leading-relaxed">
                    {activeExplanation.howHackersExploitIt}
                  </p>
                </div>

                {/* Real-World Analogy Callout */}
                <div className="rounded-xl p-3.5 bg-primary/10 border border-primary/35 space-y-1.5">
                  <div className="flex items-center gap-1.5 font-label text-[11px] font-semibold uppercase tracking-wider text-primary">
                    <span className="material-symbols-outlined text-[16px]">
                      lightbulb
                    </span>
                    Real-World Analogy
                  </div>
                  <p className="font-body text-[13px] text-on-surface leading-relaxed">
                    {activeExplanation.realWorldAnalogy}
                  </p>
                </div>

                {/* Impact */}
                <div className="space-y-1">
                  <h4 className="font-label text-[11px] font-semibold uppercase tracking-wider text-warning">
                    Impact
                  </h4>
                  <p className="font-body text-[13px] text-on-surface-variant leading-relaxed">
                    {activeExplanation.impact}
                  </p>
                </div>

                {/* Best Practice */}
                <div className="space-y-1">
                  <h4 className="font-label text-[11px] font-semibold uppercase tracking-wider text-success">
                    Best Practice
                  </h4>
                  <p className="font-body text-[13px] text-on-surface-variant leading-relaxed">
                    {activeExplanation.bestPractice}
                  </p>
                </div>

                {/* Secure Version Code Block */}
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <h4 className="font-label text-[11px] font-semibold uppercase tracking-wider text-success">
                      Secure Version
                    </h4>
                    <button
                      type="button"
                      onClick={() =>
                        void handleCopySecurePattern(
                          activeExplanation.secureVersion
                        )
                      }
                      className="inline-flex items-center gap-1 text-[11px] font-label text-on-surface-variant hover:text-primary transition-colors"
                    >
                      <span className="material-symbols-outlined text-[14px]">
                        {copiedSecureCode ? "check" : "content_copy"}
                      </span>
                      {copiedSecureCode ? "Copied" : "Copy"}
                    </button>
                  </div>
                  <pre className="rounded-xl bg-surface-container-lowest border border-outline-variant/35 p-3 font-code text-[12px] leading-relaxed text-success/95 overflow-x-auto whitespace-pre">
                    {activeExplanation.secureVersion}
                  </pre>
                </div>
              </>
            ) : null}
          </div>

          {/* Sticky Bottom Remediation Actions */}
          {selectedVuln ? (
            <div className="p-3.5 border-t border-outline-variant/35 bg-surface-container-low/85 flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
              <button
                type="button"
                disabled={isGeneratingFix || isScanning}
                onClick={() => void handleGenerateSingleFix(selectedVuln)}
                className="flex-1 inline-flex items-center justify-center gap-1.5 px-3.5 py-2.5 rounded-lg text-xs font-label font-semibold bg-primary-container text-on-primary hover:bg-primary transition-all duration-150 cyan-glow disabled:opacity-60"
              >
                <span
                  className={`material-symbols-outlined text-[16px] ${
                    isGeneratingFix ? "animate-spin" : ""
                  }`}
                >
                  {isGeneratingFix ? "progress_activity" : "auto_fix_high"}
                </span>
                {isGeneratingFix ? "Generating Fix…" : "Generate Secure Fix"}
              </button>

              {onNavigateToSimulator ? (
                <button
                  type="button"
                  onClick={onNavigateToSimulator}
                  className="inline-flex items-center justify-center gap-1.5 px-3.5 py-2.5 rounded-lg text-xs font-label font-semibold bg-secondary-container/80 text-on-secondary-container border border-secondary/35 hover:bg-secondary-container transition-all duration-150"
                >
                  <span className="material-symbols-outlined text-[16px]">
                    terminal
                  </span>
                  Simulate Attack
                </button>
              ) : null}
            </div>
          ) : null}
        </aside>
      </div>
    </div>
  );
}
