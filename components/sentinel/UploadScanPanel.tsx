"use client";

import {
  useCallback,
  useRef,
  useState,
  type ChangeEvent,
  type DragEvent,
  type FormEvent,
} from "react";
import { SeverityBadge } from "@/components/sentinel/SeverityBadge";
import type {
  HeaderAuditItem,
  UploadScanResult,
} from "@/services/upload-scan.service";
import type { ApiErrorResponse, ApiSuccessResponse } from "@/types";

export interface UploadScanPanelProps {
  onScanComplete: (result: UploadScanResult) => void;
  className?: string;
}

type UploadMode = "file" | "url";

interface QuickUrlExample {
  label: string;
  url: string;
  icon: string;
}

const ACCEPTED_FILE_EXTENSIONS =
  ".zip,.ts,.tsx,.js,.jsx,.mjs,.cjs,.py,.sql,.java,.go,.php,.rb,.cs,.json,.env,.yaml,.yml,.html,.txt";

const QUICK_URL_EXAMPLES: readonly QuickUrlExample[] = [
  {
    label: "example.com (Headers)",
    url: "https://example.com",
    icon: "language",
  },
  {
    label: "GitHub Auth Example",
    url: "https://github.com/expressjs/express/blob/master/examples/auth/index.js",
    icon: "code",
  },
  {
    label: "GitHub package.json",
    url: "https://github.com/vercel/next.js/blob/canary/package.json",
    icon: "data_object",
  },
];

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) {
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  }
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function HeaderAuditSection({ items }: { items: HeaderAuditItem[] }) {
  const presentCount = items.filter((item) => item.present).length;

  return (
    <div className="mt-3 rounded-xl border border-outline-variant/40 bg-[#080E1D]/85 p-3">
      <div className="mb-2.5 flex items-center justify-between gap-2">
        <div className="flex items-center gap-1.5 text-xs font-medium text-[#8AEBFF]">
          <span className="material-symbols-outlined text-[16px]">
            verified_user
          </span>
          <span>HTTP Security Header Audit</span>
        </div>
        <span className="text-[11px] text-on-surface-variant tabular-nums">
          {presentCount}/{items.length} present
        </span>
      </div>

      <div className="flex flex-wrap gap-2">
        {items.map((item) => (
          <div
            key={item.header}
            title={
              item.present
                ? `${item.header}: ${item.value ?? ""}`
                : item.recommendation
            }
            className="flex items-center gap-2 rounded-lg border border-outline-variant/35 bg-surface-container/70 px-2.5 py-1.5 text-xs"
          >
            <span className="font-code text-[11px] text-on-surface">
              {item.header}
            </span>
            <SeverityBadge
              variant={item.present ? "fixed" : item.severity}
              label={item.present ? "Present" : `Missing (${item.severity})`}
              size="sm"
            />
          </div>
        ))}
      </div>
    </div>
  );
}

export function UploadScanPanel({
  onScanComplete,
  className = "",
}: UploadScanPanelProps) {
  const [mode, setMode] = useState<UploadMode>("file");
  const [urlInput, setUrlInput] = useState("");
  const [isDragging, setIsDragging] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [lastResult, setLastResult] = useState<UploadScanResult | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const handleApiResponse = useCallback(
    async (response: Response) => {
      const payload = (await response.json()) as
        | ApiSuccessResponse<UploadScanResult>
        | ApiErrorResponse;

      if (!response.ok || !payload.success) {
        const message =
          !payload.success && payload.error?.message
            ? payload.error.message
            : `Scan failed with HTTP ${response.status}.`;
        throw new Error(message);
      }

      setLastResult(payload.data);
      onScanComplete(payload.data);
    },
    [onScanComplete]
  );

  const uploadFile = useCallback(
    async (file: File) => {
      setIsScanning(true);
      setErrorMessage(null);
      try {
        const formData = new FormData();
        formData.append("file", file);

        const response = await fetch("/api/upload", {
          method: "POST",
          body: formData,
        });

        await handleApiResponse(response);
      } catch (err: unknown) {
        setErrorMessage(
          err instanceof Error ? err.message : "Failed to scan uploaded file."
        );
      } finally {
        setIsScanning(false);
      }
    },
    [handleApiResponse]
  );

  const submitUrl = useCallback(
    async (targetUrl: string) => {
      const trimmed = targetUrl.trim();
      if (!trimmed) {
        setErrorMessage("Enter a valid http:// or https:// URL to scan.");
        return;
      }

      setIsScanning(true);
      setErrorMessage(null);
      try {
        const response = await fetch("/api/upload", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: trimmed }),
        });

        await handleApiResponse(response);
      } catch (err: unknown) {
        setErrorMessage(
          err instanceof Error ? err.message : "Failed to scan remote URL."
        );
      } finally {
        setIsScanning(false);
      }
    },
    [handleApiResponse]
  );

  const handleFileChange = (event: ChangeEvent<HTMLInputElement>) => {
    const selected = event.target.files?.[0];
    if (selected) {
      void uploadFile(selected);
    }
    event.target.value = "";
  };

  const handleDragOver = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    if (!isDragging) setIsDragging(true);
  };

  const handleDragLeave = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setIsDragging(false);
    const dropped = event.dataTransfer.files?.[0];
    if (dropped) {
      void uploadFile(dropped);
    }
  };

  const handleUrlFormSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    void submitUrl(urlInput);
  };

  const handleExampleClick = (exampleUrl: string) => {
    setUrlInput(exampleUrl);
    void submitUrl(exampleUrl);
  };

  return (
    <section
      aria-label="File and URL Security Scanner"
      className={`glass-panel rounded-2xl p-4 sm:p-5 ${className}`.trim()}
    >
      {/* Header & Mode Switcher */}
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-[#22D3EE]/35 bg-[#080E1D] text-[#8AEBFF]">
            <span className="material-symbols-outlined text-[20px]">
              cloud_upload
            </span>
          </div>
          <div>
            <h2 className="font-headline text-sm font-semibold tracking-tight text-on-surface">
              File &amp; URL Security Scanner
            </h2>
            <p className="text-xs text-on-surface-variant">
              Upload local source files or scan live GitHub / web URLs
            </p>
          </div>
        </div>

        <div
          role="tablist"
          aria-label="Scan input mode"
          className="inline-flex rounded-xl border border-outline-variant/50 bg-[#080E1D] p-1"
        >
          <button
            type="button"
            role="tab"
            aria-selected={mode === "file"}
            onClick={() => {
              setMode("file");
              setErrorMessage(null);
            }}
            className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition-all ${
              mode === "file"
                ? "bg-[#22D3EE]/20 text-[#8AEBFF] shadow-[inset_0_0_0_1px_rgba(34,211,238,0.45)]"
                : "text-on-surface-variant hover:text-on-surface"
            }`}
          >
            <span className="material-symbols-outlined text-[16px]">
              upload_file
            </span>
            <span>Upload File</span>
          </button>

          <button
            type="button"
            role="tab"
            aria-selected={mode === "url"}
            onClick={() => {
              setMode("url");
              setErrorMessage(null);
            }}
            className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition-all ${
              mode === "url"
                ? "bg-[#22D3EE]/20 text-[#8AEBFF] shadow-[inset_0_0_0_1px_rgba(34,211,238,0.45)]"
                : "text-on-surface-variant hover:text-on-surface"
            }`}
          >
            <span className="material-symbols-outlined text-[16px]">link</span>
            <span>Scan URL</span>
          </button>
        </div>
      </div>

      {/* Mode Body */}
      {mode === "file" ? (
        <div
          role="button"
          tabIndex={0}
          onClick={() => fileInputRef.current?.click()}
          onKeyDown={(e) => {
            if (e.key === "Enter" || e.key === " ") {
              e.preventDefault();
              fileInputRef.current?.click();
            }
          }}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          className={`group relative flex cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed px-4 py-7 text-center transition-all ${
            isDragging
              ? "border-[#22D3EE] bg-[#22D3EE]/10"
              : "border-outline-variant/60 bg-[#080E1D]/80 hover:border-[#8AEBFF]/55 hover:bg-[#080E1D]"
          }`}
        >
          <input
            ref={fileInputRef}
            type="file"
            accept={ACCEPTED_FILE_EXTENSIONS}
            onChange={handleFileChange}
            disabled={isScanning}
            className="hidden"
          />
          <div className="mb-2.5 flex h-11 w-11 items-center justify-center rounded-full border border-[#22D3EE]/30 bg-[#22D3EE]/10 text-[#8AEBFF] transition-transform group-hover:scale-105">
            <span className="material-symbols-outlined text-[24px]">
              {isScanning ? "progress_activity" : "file_upload"}
            </span>
          </div>
          <p className="text-sm font-medium text-on-surface">
            {isScanning
              ? "Extracting & scanning uploaded file..."
              : "Drop a .zip project archive or source file here, or click to browse"}
          </p>
          <p className="mt-1 text-xs text-on-surface-variant">
            Supports .zip archives, .ts, .tsx, .js, .py, .sql, .java, .go, .php,
            .rb, .cs, .json, .env, .yaml, .html, .txt &bull; Unlimited file size
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          <form
            onSubmit={handleUrlFormSubmit}
            className="flex flex-col gap-2 sm:flex-row"
          >
            <div className="relative flex-1">
              <span className="material-symbols-outlined pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-[18px] text-on-surface-variant">
                public
              </span>
              <input
                type="url"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                placeholder="https://github.com/owner/repo/blob/main/app.ts or https://example.com"
                disabled={isScanning}
                required
                className="w-full rounded-xl border border-outline-variant/55 bg-[#080E1D] py-2.5 pl-10 pr-3 font-code text-xs text-on-surface placeholder:text-on-surface-variant/60 focus:border-[#22D3EE] focus:outline-none focus:ring-1 focus:ring-[#22D3EE]/50"
              />
            </div>

            <button
              type="submit"
              disabled={isScanning}
              className="inline-flex items-center justify-center gap-1.5 rounded-xl bg-[#22D3EE] px-4 py-2.5 text-xs font-semibold text-[#00363E] transition-all hover:bg-[#8AEBFF] disabled:cursor-not-allowed disabled:opacity-60"
            >
              <span
                className={`material-symbols-outlined text-[16px] ${
                  isScanning ? "animate-spin" : ""
                }`}
              >
                {isScanning ? "progress_activity" : "radar"}
              </span>
              <span>{isScanning ? "Scanning..." : "Scan URL"}</span>
            </button>
          </form>

          {/* Quick-Test Example Chips */}
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[11px] font-medium uppercase tracking-wider text-on-surface-variant">
              Quick test:
            </span>
            {QUICK_URL_EXAMPLES.map((example) => (
              <button
                key={example.url}
                type="button"
                disabled={isScanning}
                onClick={() => handleExampleClick(example.url)}
                className="inline-flex items-center gap-1.5 rounded-full border border-outline-variant/50 bg-[#080E1D]/90 px-2.5 py-1 text-[11px] text-on-surface-variant transition-colors hover:border-[#22D3EE]/50 hover:text-[#8AEBFF] disabled:opacity-50"
              >
                <span className="material-symbols-outlined text-[14px] text-[#22D3EE]">
                  {example.icon}
                </span>
                <span>{example.label}</span>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Error State */}
      {errorMessage && (
        <div
          role="alert"
          className="mt-3 flex items-start gap-2 rounded-xl border border-error/40 bg-error-container/35 px-3 py-2.5 text-xs text-on-error-container"
        >
          <span className="material-symbols-outlined mt-0.5 text-[16px] text-error">
            error
          </span>
          <span>{errorMessage}</span>
        </div>
      )}

      {/* Last Scan Metadata & Optional Header Audit */}
      {lastResult && !errorMessage && (
        <div className="mt-3 rounded-xl border border-[#22D3EE]/25 bg-[#080E1D]/75 p-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex flex-wrap items-center gap-2">
              <span className="inline-flex items-center gap-1 rounded-md border border-[#22D3EE]/35 bg-[#22D3EE]/15 px-2 py-0.5 font-code text-[10px] uppercase tracking-wider text-[#8AEBFF]">
                <span className="material-symbols-outlined text-[13px]">
                  {lastResult.source === "file" ? "description" : "public"}
                </span>
                {lastResult.source}
              </span>
              <span className="font-code text-xs font-medium text-on-surface">
                {lastResult.fileName}
              </span>
              <span className="text-[11px] text-on-surface-variant">
                {lastResult.language} &bull; {formatBytes(lastResult.sizeBytes)}
              </span>
            </div>

            <div className="flex items-center gap-2">
              <SeverityBadge
                variant={
                  lastResult.report.vulnerabilities.length === 0
                    ? "fixed"
                    : lastResult.report.severityBreakdown.critical > 0
                      ? "critical"
                      : lastResult.report.severityBreakdown.high > 0
                        ? "high"
                        : "medium"
                }
                label={`${lastResult.report.vulnerabilities.length} finding${
                  lastResult.report.vulnerabilities.length === 1 ? "" : "s"
                }`}
              />
              <span className="rounded-full border border-outline-variant/50 bg-surface-container px-2.5 py-0.5 font-code text-[11px] text-[#8AEBFF] tabular-nums">
                Score {lastResult.report.riskScore} ({lastResult.report.riskGrade})
              </span>
            </div>
          </div>

          {lastResult.source === "file" && lastResult.archiveSummary && (
            <div className="mt-3 rounded-xl border border-outline-variant/40 bg-[#080E1D]/85 p-3">
              <div className="mb-2 flex flex-wrap items-center justify-between gap-2 text-xs">
                <div className="flex items-center gap-1.5 font-medium text-[#8AEBFF]">
                  <span className="material-symbols-outlined text-[16px]">
                    folder_zip
                  </span>
                  <span>ZIP Archive Scan Summary</span>
                </div>
                <span className="font-code text-[11px] text-on-surface-variant tabular-nums">
                  {lastResult.archiveSummary.scannedFiles} scanned &bull;{" "}
                  {lastResult.archiveSummary.skippedFiles} skipped &bull;{" "}
                  {lastResult.archiveSummary.totalEntries} total entries
                </span>
              </div>
              {lastResult.archiveSummary.filesWithIssues.length > 0 ? (
                <div className="flex flex-wrap gap-1.5">
                  {lastResult.archiveSummary.filesWithIssues
                    .slice(0, 12)
                    .map((item) => (
                      <span
                        key={item.filePath}
                        className="inline-flex items-center gap-1.5 rounded-lg border border-error/30 bg-error-container/25 px-2.5 py-1 font-code text-[11px] text-on-surface"
                      >
                        <span className="max-w-[220px] truncate">
                          {item.filePath}
                        </span>
                        <span className="rounded-full bg-error/20 px-1.5 py-0.5 text-[10px] font-semibold text-error tabular-nums">
                          {item.findingsCount}
                        </span>
                      </span>
                    ))}
                </div>
              ) : (
                <p className="text-xs text-success">
                  All scanned files inside the archive passed with zero detected vulnerabilities.
                </p>
              )}
            </div>
          )}

          {lastResult.source === "url" &&
            lastResult.resolvedUrl !== lastResult.fetchedUrl && (
              <p className="mt-2 truncate font-code text-[11px] text-on-surface-variant">
                <span className="text-[#22D3EE]">Resolved:</span>{" "}
                {lastResult.resolvedUrl}
              </p>
            )}

          {lastResult.source === "url" && lastResult.headerAudit.length > 0 && (
            <HeaderAuditSection items={lastResult.headerAudit} />
          )}
        </div>
      )}
    </section>
  );
}
