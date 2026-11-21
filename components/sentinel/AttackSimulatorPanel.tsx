"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { StructuredSecurityReport } from "@/security/analyzer";
import type {
  FileAttackFrame,
  FileAttackNode,
  FileAttackNodeType,
  FileAttackRunResponse,
  FileAttackSimulation,
} from "@/types/file-attack.types";
import { runFileAttackSimulationApi } from "./api-client";
import { SeverityBadge } from "./SeverityBadge";

export interface AttackSimulatorPanelProps {
  code?: string;
  fileName?: string;
  analysisReport?: StructuredSecurityReport | null;
  onApplyHardenedCode?: (hardenedCode: string) => void;
  onLogTimelineEvent?: (
    action: string,
    label: string,
    severity: "critical" | "high" | "medium" | "low" | "info",
    status: string
  ) => void;
}

function getNodeIcon(type: FileAttackNodeType): string {
  switch (type) {
    case "attacker":
      return "bug_report";
    case "entry":
      return "input";
    case "code":
      return "code_blocks";
    case "sink":
      return "dns";
    case "asset":
      return "database";
    case "defense":
      return "shield_lock";
  }
}

function getActiveFrame(
  frames: readonly FileAttackFrame[],
  elapsedMs: number
): { frame: FileAttackFrame | null; index: number } {
  if (frames.length === 0) return { frame: null, index: -1 };
  let activeIndex = 0;
  for (let i = 0; i < frames.length; i += 1) {
    const candidate = frames[i];
    if (candidate && candidate.timestampMs <= elapsedMs) {
      activeIndex = i;
    }
  }
  return { frame: frames[activeIndex] ?? null, index: activeIndex };
}

interface FlowTrackProps {
  title: string;
  subtitle: string;
  variant: "before" | "after";
  nodes: readonly FileAttackNode[];
  frames: readonly FileAttackFrame[];
  elapsedMs: number;
  durationMs: number;
  blockedAfter: boolean;
}

function FileAttackFlowTrack({
  title,
  subtitle,
  variant,
  nodes,
  frames,
  elapsedMs,
  durationMs,
  blockedAfter,
}: FlowTrackProps) {
  const { frame: activeFrame, index: activeIndex } = useMemo(
    () => getActiveFrame(frames, elapsedMs),
    [frames, elapsedMs]
  );

  const progressPct =
    durationMs > 0
      ? Math.min(100, Math.max(0, Math.round((elapsedMs / durationMs) * 100)))
      : 0;

  const isBefore = variant === "before";
  const isProtected = !isBefore && blockedAfter;

  const borderClass = isBefore
    ? "border-error/40"
    : isProtected
      ? "border-success/40"
      : "border-warning/40";

  return (
    <div
      className={`glass-panel rounded-2xl border ${borderClass} p-4 transition-all`}
    >
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span
            className={`inline-flex h-7 w-7 items-center justify-center rounded-lg border ${
              isBefore
                ? "border-error/40 bg-error-container/40 text-error"
                : isProtected
                  ? "border-success/40 bg-success-container/40 text-success"
                  : "border-warning/40 bg-warning-container/40 text-warning"
            }`}
          >
            <span className="material-symbols-outlined text-[16px]">
              {isBefore ? "gpp_bad" : isProtected ? "verified_user" : "warning"}
            </span>
          </span>
          <div>
            <h4 className="font-display text-xs font-semibold text-on-surface">
              {title}
            </h4>
            <p className="text-[11px] text-on-surface-variant">{subtitle}</p>
          </div>
        </div>
        <SeverityBadge
          variant={isBefore ? "compromised" : isProtected ? "blocked" : "medium"}
          label={
            isBefore
              ? "Attack Succeeds on Your Code"
              : isProtected
                ? "Blocked After Auto-Fix"
                : "Manual Fix Needed"
          }
        />
      </div>

      {/* Node Graph Targeting the User's Exact File & Line */}
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-5">
        {nodes.map((node) => {
          const isSource = activeFrame?.from === node.id;
          const isTarget = activeFrame?.to === node.id;
          const isActive = isSource || isTarget;

          return (
            <div
              key={node.id}
              className={`rounded-xl border p-2.5 transition-all ${
                isActive
                  ? isBefore
                    ? "border-error bg-error-container/35 shadow-[0_0_16px_rgba(255,179,173,0.22)]"
                    : isProtected
                      ? "border-success bg-success-container/35 shadow-[0_0_16px_rgba(78,222,163,0.22)]"
                      : "border-warning bg-warning-container/35"
                  : "border-outline-variant/35 bg-[#080E1D]/75"
              }`}
            >
              <div className="flex items-center gap-1.5">
                <span
                  className={`material-symbols-outlined text-[16px] ${
                    isActive
                      ? isBefore
                        ? "text-error"
                        : isProtected
                          ? "text-success"
                          : "text-warning"
                      : "text-primary"
                  }`}
                >
                  {getNodeIcon(node.type)}
                </span>
                <span className="truncate font-code text-[11px] font-semibold text-on-surface">
                  {node.label}
                </span>
              </div>
              <p className="mt-1 truncate text-[10px] text-on-surface-variant">
                {node.detail}
              </p>
            </div>
          );
        })}
      </div>

      {/* Progress Bar */}
      <div className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-[#080E1D]">
        <div
          className={`h-full transition-all duration-150 ${
            isBefore
              ? "bg-error"
              : isProtected
                ? "bg-success"
                : "bg-warning"
          }`}
          style={{ width: `${progressPct}%` }}
        />
      </div>

      {/* Active Frame Caption */}
      {activeFrame && (
        <div className="mt-2.5 flex items-center justify-between gap-2 rounded-lg border border-outline-variant/30 bg-[#080E1D]/85 px-3 py-2 text-xs">
          <div className="flex items-center gap-2 min-w-0">
            <span className="rounded bg-surface-container px-1.5 py-0.5 font-code text-[10px] text-primary tabular-nums">
              Step {activeIndex + 1}/{frames.length}
            </span>
            <span className="truncate text-on-surface">{activeFrame.label}</span>
          </div>
          <span className="shrink-0 font-code text-[10px] uppercase text-on-surface-variant">
            {activeFrame.from} &rarr; {activeFrame.to}
          </span>
        </div>
      )}
    </div>
  );
}

export function AttackSimulatorPanel({
  code = "",
  fileName = "uploaded-file.ts",
  analysisReport = null,
  onApplyHardenedCode,
  onLogTimelineEvent,
}: AttackSimulatorPanelProps) {
  const [simResult, setSimResult] = useState<FileAttackRunResponse | null>(
    null
  );
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [isPlaying, setIsPlaying] = useState<boolean>(false);
  const [elapsedMs, setElapsedMs] = useState<number>(4800);
  const [copiedPayload, setCopiedPayload] = useState<boolean>(false);

  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const runFileSimulation = useCallback(async () => {
    if (!code || code.trim().length === 0) {
      setSimResult(null);
      return;
    }

    setIsLoading(true);
    setError(null);
    setIsPlaying(false);

    try {
      const response = await runFileAttackSimulationApi({
        code,
        fileName,
        language: analysisReport?.language,
        vulnerabilities: analysisReport?.vulnerabilities,
      });

      setSimResult(response);
      const firstSim = response.simulations[0];
      setSelectedId((prev) =>
        prev && response.simulations.some((s) => s.id === prev)
          ? prev
          : firstSim?.id ?? null
      );
      setElapsedMs(0);
      setIsPlaying(true);

      onLogTimelineEvent?.(
        "ATTACK_SIMULATED",
        `Simulated ${response.simulations.length} attack(s) on ${fileName} — ${response.summary.blockedAfterFix}/${response.simulations.length} blocked after fix`,
        response.simulations.length > 0 ? "high" : "info",
        "completed"
      );
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Failed to simulate attacks on the active file."
      );
    } finally {
      setIsLoading(false);
    }
  }, [
    code,
    fileName,
    analysisReport?.language,
    analysisReport?.vulnerabilities,
    onLogTimelineEvent,
  ]);

  useEffect(() => {
    void runFileSimulation();
  }, [runFileSimulation]);

  const activeSim: FileAttackSimulation | null = useMemo(() => {
    if (!simResult || simResult.simulations.length === 0) return null;
    return (
      simResult.simulations.find((s) => s.id === selectedId) ??
      simResult.simulations[0] ??
      null
    );
  }, [simResult, selectedId]);

  const durationMs = activeSim?.animation.durationMs ?? 4800;

  useEffect(() => {
    if (!isPlaying) {
      if (timerRef.current) clearInterval(timerRef.current);
      return;
    }

    timerRef.current = setInterval(() => {
      setElapsedMs((prev) => {
        const next = prev + 120;
        if (next >= durationMs) {
          setIsPlaying(false);
          return durationMs;
        }
        return next;
      });
    }, 120);

    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [isPlaying, durationMs]);

  const handlePlayReplay = () => {
    if (elapsedMs >= durationMs) {
      setElapsedMs(0);
      setIsPlaying(true);
    } else {
      setIsPlaying((prev) => !prev);
    }
  };

  const handleCopyPayload = async (payload: string) => {
    try {
      await navigator.clipboard.writeText(payload);
      setCopiedPayload(true);
      setTimeout(() => setCopiedPayload(false), 1800);
    } catch {
      // Clipboard API unavailable
    }
  };

  return (
    <div className="space-y-5">
      {/* Header Banner Showing Active Target File */}
      <div className="glass-panel-elevated flex flex-wrap items-center justify-between gap-4 rounded-2xl p-5">
        <div className="flex items-start gap-3.5">
          <div className="cyan-glow flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border border-primary/40 bg-primary-container/15 text-primary">
            <span className="material-symbols-outlined text-[24px]">
              crisis_alert
            </span>
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="font-display text-lg font-bold tracking-tight text-on-surface">
                Live File Attack Simulator
              </h2>
              <span className="rounded-full border border-primary/35 bg-primary-container/15 px-2.5 py-0.5 font-code text-xs text-primary">
                Target: {fileName}
              </span>
              {simResult && (
                <span className="rounded-full border border-outline-variant/45 bg-surface-container px-2.5 py-0.5 font-code text-xs text-on-surface-variant tabular-nums">
                  {simResult.simulations.length} exploitable vector
                  {simResult.simulations.length === 1 ? "" : "s"} in file
                </span>
              )}
            </div>
            <p className="mt-1 text-xs text-on-surface-variant">
              Simulates real exploit payloads directly against the vulnerable lines in{" "}
              <span className="font-code text-on-surface">{fileName}</span> and
              verifies whether the automated fix blocks each attack.
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <button
            type="button"
            disabled={isLoading || !activeSim}
            onClick={handlePlayReplay}
            className="cyan-glow inline-flex items-center gap-1.5 rounded-xl bg-primary-container px-4 py-2 text-xs font-semibold text-on-primary transition hover:bg-primary disabled:opacity-50"
          >
            <span className="material-symbols-outlined text-[16px]">
              {isPlaying
                ? "pause"
                : elapsedMs >= durationMs
                  ? "replay"
                  : "play_arrow"}
            </span>
            <span>
              {isPlaying
                ? "Pause"
                : elapsedMs >= durationMs
                  ? "Replay Attack on File"
                  : "Play Simulation"}
            </span>
          </button>

          {simResult &&
            simResult.hardenedCode !== code &&
            onApplyHardenedCode && (
              <button
                type="button"
                onClick={() => onApplyHardenedCode(simResult.hardenedCode)}
                className="inline-flex items-center gap-1.5 rounded-xl border border-success/45 bg-success-container/40 px-4 py-2 text-xs font-semibold text-success transition hover:bg-success-container/60"
              >
                <span className="material-symbols-outlined text-[16px]">
                  auto_fix_high
                </span>
                <span>
                  Apply All Hardened Fixes ({simResult.summary.blockedAfterFix}{" "}
                  blocked)
                </span>
              </button>
            )}

          <button
            type="button"
            disabled={isLoading}
            onClick={() => void runFileSimulation()}
            className="inline-flex items-center gap-1.5 rounded-xl border border-outline-variant/50 bg-surface-container-high px-3 py-2 text-xs font-medium text-on-surface transition hover:border-primary/40 hover:text-primary disabled:opacity-50"
          >
            <span className="material-symbols-outlined text-[16px]">
              refresh
            </span>
            <span>Re-test File</span>
          </button>
        </div>
      </div>

      {/* Summary Metrics Strip for This File */}
      {simResult && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <div className="glass-panel rounded-xl p-3.5">
            <div className="text-[11px] text-on-surface-variant">
              Attacks on {fileName}
            </div>
            <div className="mt-1 font-display text-xl font-bold text-on-surface tabular-nums">
              {simResult.summary.attacksLaunched}
            </div>
          </div>
          <div className="glass-panel rounded-xl border-error/30 p-3.5">
            <div className="text-[11px] text-error">
              Succeeded Before Fix
            </div>
            <div className="mt-1 font-display text-xl font-bold text-error tabular-nums">
              {simResult.summary.succeededBeforeFix} /{" "}
              {simResult.summary.attacksLaunched}
            </div>
          </div>
          <div className="glass-panel rounded-xl border-success/30 p-3.5">
            <div className="text-[11px] text-success">
              Blocked After Auto-Fix
            </div>
            <div className="mt-1 font-display text-xl font-bold text-success tabular-nums">
              {simResult.summary.blockedAfterFix} /{" "}
              {simResult.summary.attacksLaunched}
            </div>
          </div>
          <div className="glass-panel rounded-xl p-3.5">
            <div className="text-[11px] text-on-surface-variant">
              File Risk Reduction
            </div>
            <div className="mt-1 font-display text-xl font-bold text-primary tabular-nums">
              {simResult.summary.riskScoreBefore} ({simResult.summary.riskGradeBefore})
              {" → "}
              {simResult.summary.riskScoreAfter} ({simResult.summary.riskGradeAfter})
            </div>
          </div>
        </div>
      )}

      {error && (
        <div className="glass-panel rounded-xl border-error/40 bg-error-container/25 p-4 text-xs text-error">
          {error}
        </div>
      )}

      {isLoading ? (
        <div className="glass-panel flex items-center justify-center gap-3 rounded-2xl p-12 text-sm text-on-surface-variant">
          <span className="material-symbols-outlined animate-spin text-primary">
            progress_activity
          </span>
          <span>
            Tracing vulnerable lines and simulating attacks against{" "}
            <strong className="font-code text-on-surface">{fileName}</strong>...
          </span>
        </div>
      ) : !simResult || simResult.simulations.length === 0 ? (
        <div className="glass-panel rounded-2xl border-success/35 p-8 text-center">
          <span className="material-symbols-outlined text-[36px] text-success">
            verified_user
          </span>
          <h3 className="mt-2 font-display text-base font-semibold text-on-surface">
            No Exploitable Attack Vectors Detected in {fileName}
          </h3>
          <p className="mt-1 text-xs text-on-surface-variant">
            The current file passed all active security rules. Upload or select a
            vulnerable file in the Code Analysis tab to simulate attacks against
            its lines.
          </p>
        </div>
      ) : (
        <>
          {/* Vulnerability Target Selector Pills from the User's File */}
          <div className="glass-panel rounded-2xl p-4">
            <div className="mb-2.5 flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wider text-on-surface-variant">
                Select Vulnerable Line in {fileName} to Attack ({simResult.simulations.length})
              </span>
              <span className="font-code text-[11px] text-primary">
                Click any finding below to inspect its exact line &amp; payload
              </span>
            </div>
            <div className="flex flex-wrap gap-2">
              {simResult.simulations.map((sim) => {
                const isSelected = activeSim?.id === sim.id;
                return (
                  <button
                    key={sim.id}
                    type="button"
                    onClick={() => {
                      setSelectedId(sim.id);
                      setElapsedMs(0);
                      setIsPlaying(true);
                    }}
                    className={`inline-flex items-center gap-2 rounded-xl border px-3 py-2 text-left text-xs transition-all ${
                      isSelected
                        ? "border-primary bg-primary-container/20 text-primary shadow-[0_0_16px_rgba(34,211,238,0.2)]"
                        : "border-outline-variant/40 bg-[#080E1D]/80 text-on-surface hover:border-primary/40"
                    }`}
                  >
                    <span className="rounded bg-surface-container px-1.5 py-0.5 font-code text-[10px] font-bold text-primary tabular-nums">
                      L{sim.target.line}
                    </span>
                    <span className="max-w-[240px] truncate font-medium">
                      {sim.attackName}
                    </span>
                    <SeverityBadge
                      variant={
                        sim.after.blocked ? "blocked" : sim.severity
                      }
                      label={sim.after.blocked ? "Fix Blocks" : sim.cweId}
                      size="sm"
                    />
                  </button>
                );
              })}
            </div>
          </div>

          {activeSim && (
            <div className="space-y-5">
              {/* Target Code Context & Injected Payload Banner */}
              <div className="grid grid-cols-1 gap-4 lg:grid-cols-12">
                {/* Left: Actual Code Snippet from User's File */}
                <div className="glass-panel rounded-2xl p-4 lg:col-span-7">
                  <div className="mb-2.5 flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="material-symbols-outlined text-[18px] text-primary">
                        code
                      </span>
                      <span className="font-display text-xs font-semibold text-on-surface">
                        Targeted Code in Your File:{" "}
                        <span className="font-code text-primary">
                          {activeSim.target.fileName}:{activeSim.target.line}
                        </span>
                      </span>
                    </div>
                    <span className="font-code text-[11px] text-on-surface-variant">
                      Rule: {activeSim.ruleId} ({activeSim.cweId})
                    </span>
                  </div>

                  <div className="overflow-x-auto rounded-xl border border-outline-variant/40 bg-[#080E1D] p-3 font-code text-xs">
                    {activeSim.target.contextLines.map((cl) => (
                      <div
                        key={cl.lineNumber}
                        className={`flex items-start gap-3 rounded px-2 py-0.5 ${
                          cl.highlighted
                            ? "border-l-2 border-error bg-error-container/30 text-on-error-container"
                            : "text-on-surface-variant"
                        }`}
                      >
                        <span className="w-8 shrink-0 select-none text-right text-[11px] opacity-60 tabular-nums">
                          {cl.lineNumber}
                        </span>
                        <pre className="whitespace-pre-wrap break-all">
                          {cl.text || " "}
                        </pre>
                      </div>
                    ))}
                  </div>

                  <div className="mt-3 flex flex-wrap items-center gap-3 text-xs text-on-surface-variant">
                    <span>
                      <strong className="text-on-surface">Entry Point:</strong>{" "}
                      {activeSim.target.entryPoint}
                    </span>
                    <span>&bull;</span>
                    <span>
                      <strong className="text-on-surface">Tainted Input:</strong>{" "}
                      <code className="rounded bg-[#080E1D] px-1.5 py-0.5 font-code text-primary">
                        {activeSim.target.taintedInput ?? "Direct literal / route handler"}
                      </code>
                    </span>
                    <span>&bull;</span>
                    <span>
                      <strong className="text-on-surface">Sink:</strong>{" "}
                      {activeSim.target.sink}
                    </span>
                  </div>
                </div>

                {/* Right: Simulated Payload & Attack Steps on This Line */}
                <div className="glass-panel rounded-2xl p-4 lg:col-span-5">
                  <div className="mb-2 flex items-center justify-between gap-2">
                    <span className="font-display text-xs font-semibold text-on-surface">
                      Simulated Payload Sent to Line {activeSim.target.line}
                    </span>
                    <button
                      type="button"
                      onClick={() =>
                        void handleCopyPayload(activeSim.attackPayload)
                      }
                      className="inline-flex items-center gap-1 rounded-lg border border-outline-variant/40 bg-[#080E1D] px-2 py-1 text-[11px] text-on-surface-variant hover:text-primary"
                    >
                      <span className="material-symbols-outlined text-[13px]">
                        {copiedPayload ? "check" : "content_copy"}
                      </span>
                      <span>{copiedPayload ? "Copied" : "Copy"}</span>
                    </button>
                  </div>

                  <div className="rounded-xl border border-error/35 bg-[#080E1D] p-3 font-code text-xs text-error break-all">
                    {activeSim.attackPayload}
                  </div>

                  <div className="mt-3 space-y-1.5">
                    <div className="text-[11px] font-semibold uppercase tracking-wider text-on-surface-variant">
                      Kill-Chain Steps on {activeSim.target.fileName}
                    </div>
                    {activeSim.attackSteps.map((stepText, idx) => (
                      <div
                        key={idx}
                        className="flex items-start gap-2 text-xs text-on-surface"
                      >
                        <span className="mt-0.5 inline-flex h-4 w-4 shrink-0 items-center justify-center rounded-full bg-primary-container/20 font-code text-[10px] text-primary tabular-nums">
                          {idx + 1}
                        </span>
                        <span>{stepText}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Animated Before vs After Packet Flow Tracks */}
              <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                <FileAttackFlowTrack
                  title={`Before Fix — Attacking ${activeSim.target.fileName}:${activeSim.target.line}`}
                  subtitle="Payload flows straight into the vulnerable line"
                  variant="before"
                  nodes={activeSim.animation.nodes}
                  frames={activeSim.animation.beforeFrames}
                  elapsedMs={elapsedMs}
                  durationMs={durationMs}
                  blockedAfter={activeSim.after.blocked}
                />
                <FileAttackFlowTrack
                  title={`After Fix — Re-Attacking Hardened ${activeSim.target.fileName}:${activeSim.target.line}`}
                  subtitle={activeSim.after.defenseMechanism}
                  variant="after"
                  nodes={activeSim.animation.nodes}
                  frames={activeSim.animation.afterFrames}
                  elapsedMs={elapsedMs}
                  durationMs={durationMs}
                  blockedAfter={activeSim.after.blocked}
                />
              </div>

              {/* Side-by-Side Execution Result on Your Code: Before vs After */}
              <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                {/* BEFORE FIX CARD */}
                <div className="glass-panel rounded-2xl border border-error/40 p-5">
                  <div className="mb-3 flex items-center justify-between">
                    <span className="font-display text-sm font-bold text-error">
                      1. Vulnerable Line Execution (Before Fix)
                    </span>
                    <SeverityBadge
                      variant="compromised"
                      label="EXPLOITED"
                    />
                  </div>

                  <div className="space-y-3 text-xs">
                    <div>
                      <div className="mb-1 text-[11px] font-medium text-on-surface-variant">
                        Your Line {activeSim.target.line} With Attacker Payload Injected:
                      </div>
                      <pre className="overflow-x-auto rounded-xl border border-error/35 bg-[#080E1D] p-3 font-code text-xs text-error whitespace-pre-wrap break-all">
                        {activeSim.before.exploitedLine}
                      </pre>
                    </div>

                    <div>
                      <div className="mb-1 text-[11px] font-medium text-on-surface-variant">
                        Resulting Interpreter / Sink Execution:
                      </div>
                      <pre className="overflow-x-auto rounded-xl border border-outline-variant/40 bg-[#080E1D] p-3 font-code text-xs text-on-surface whitespace-pre-wrap break-all">
                        {activeSim.before.resultingExecution}
                      </pre>
                    </div>

                    <p className="text-on-surface-variant">
                      {activeSim.before.impactSummary}
                    </p>

                    <div>
                      <div className="mb-1 text-[11px] font-semibold text-on-surface">
                        Compromised Assets:
                      </div>
                      <ul className="list-inside list-disc space-y-1 text-on-surface-variant">
                        {activeSim.before.compromisedAssets.map((asset, i) => (
                          <li key={i}>{asset}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </div>

                {/* AFTER FIX CARD */}
                <div
                  className={`glass-panel rounded-2xl border p-5 ${
                    activeSim.after.blocked
                      ? "border-success/40"
                      : "border-warning/40"
                  }`}
                >
                  <div className="mb-3 flex items-center justify-between">
                    <span
                      className={`font-display text-sm font-bold ${
                        activeSim.after.blocked ? "text-success" : "text-warning"
                      }`}
                    >
                      2. Hardened Line Execution (After Fix)
                    </span>
                    <SeverityBadge
                      variant={activeSim.after.blocked ? "blocked" : "medium"}
                      label={
                        activeSim.after.blocked
                          ? "ATTACK BLOCKED"
                          : "MANUAL REMEDIATION"
                      }
                    />
                  </div>

                  <div className="space-y-3 text-xs">
                    {activeSim.after.fixedLines.length > 0 ? (
                      <div>
                        <div className="mb-1 text-[11px] font-medium text-on-surface-variant">
                          Automated Patch Applied to Your File:
                        </div>
                        <div className="overflow-x-auto rounded-xl border border-success/35 bg-[#080E1D] p-3 font-code text-xs space-y-1">
                          {activeSim.after.fixedLines.map((fl) => (
                            <div key={fl.lineNumber} className="space-y-0.5">
                              {fl.originalLine && (
                                <div className="text-error/90 line-through break-all">
                                  - L{fl.lineNumber}: {fl.originalLine}
                                </div>
                              )}
                              {fl.updatedLine && (
                                <div className="text-success break-all">
                                  + L{fl.lineNumber}: {fl.updatedLine}
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    ) : (
                      <div>
                        <div className="mb-1 text-[11px] font-medium text-on-surface-variant">
                          Recommended Secure Replacement for Line {activeSim.target.line}:
                        </div>
                        <pre className="overflow-x-auto rounded-xl border border-primary/30 bg-[#080E1D] p-3 font-code text-xs text-primary whitespace-pre-wrap">
                          {activeSim.after.recommendedSecureCode}
                        </pre>
                      </div>
                    )}

                    <div>
                      <div className="mb-1 text-[11px] font-medium text-on-surface-variant">
                        Re-Attack Outcome with Same Payload:
                      </div>
                      <div className="rounded-xl border border-outline-variant/40 bg-[#080E1D] p-3 font-code text-xs text-on-surface">
                        {activeSim.after.reattackResult}
                      </div>
                    </div>

                    <div className="rounded-xl border border-primary/25 bg-primary-container/10 p-3 text-xs text-primary">
                      <strong>Re-Scan Verification:</strong>{" "}
                      {activeSim.after.verification}
                    </div>
                  </div>
                </div>
              </div>

              {/* Defensive Disclaimer */}
              <div className="rounded-xl border border-outline-variant/30 bg-[#080E1D]/70 px-4 py-2.5 font-code text-[11px] text-on-surface-variant">
                {simResult.disclaimer}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
