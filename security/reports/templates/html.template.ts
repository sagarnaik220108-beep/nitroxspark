import type {
  CanonicalSecurityReport,
  ReportFixAppliedItem,
  ReportRecommendationItem,
  ReportRiskLevel,
  ReportTimelineEvent,
  ReportVulnerabilityItem,
  TimelineEventStatus,
} from "@/types/report-generator.types";
import type { Severity } from "@/types/security.types";

const HTML_ESCAPE_MAP: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
  "/": "&#x2F;",
  "`": "&#x60;",
};

/**
 * Strictly escapes any dynamic value for safe interpolation into HTML text
 * nodes and attribute values, preventing XSS in generated security reports.
 */
export function escapeHtml(value: unknown): string {
  if (value === null || value === undefined) {
    return "";
  }
  return String(value).replace(/[&<>"'/`]/g, (char) => HTML_ESCAPE_MAP[char] ?? char);
}

function getSeverityBadgeClass(severity: Severity): string {
  switch (severity) {
    case "critical":
      return "badge-critical";
    case "high":
      return "badge-high";
    case "medium":
      return "badge-medium";
    case "low":
      return "badge-low";
    case "info":
    default:
      return "badge-info";
  }
}

function getRiskBadgeClass(riskLevel: ReportRiskLevel): string {
  switch (riskLevel) {
    case "critical":
      return "badge-critical";
    case "high":
      return "badge-high";
    case "moderate":
      return "badge-medium";
    case "low":
      return "badge-low";
    case "minimal":
    default:
      return "badge-minimal";
  }
}

function getTimelineStatusClass(status: TimelineEventStatus): string {
  switch (status) {
    case "completed":
      return "status-completed";
    case "in_progress":
      return "status-progress";
    case "failed":
    case "blocked":
      return "status-failed";
    case "pending":
      return "status-pending";
    case "info":
    default:
      return "status-info";
  }
}

function formatLocation(fileName?: string, line?: number, column?: number): string {
  const parts: string[] = [];
  if (fileName) {
    parts.push(fileName);
  }
  if (typeof line === "number") {
    parts.push(typeof column === "number" ? `L${line}:${column}` : `L${line}`);
  }
  return parts.length > 0 ? parts.join(" · ") : "N/A";
}

function renderVulnerabilityCard(vuln: ReportVulnerabilityItem, index: number): string {
  const severityClass = getSeverityBadgeClass(vuln.severity);
  const location = formatLocation(vuln.fileName, vuln.line, vuln.column);
  const statusLabel = vuln.status ?? "open";

  const metaChips: string[] = [
    `<span class="meta-chip"><strong>Rule:</strong> <code>${escapeHtml(vuln.ruleId)}</code></span>`,
    `<span class="meta-chip"><strong>Location:</strong> <code>${escapeHtml(location)}</code></span>`,
    `<span class="meta-chip"><strong>Status:</strong> ${escapeHtml(statusLabel.replace("_", " "))}</span>`,
  ];

  if (vuln.cweId) {
    metaChips.push(
      `<span class="meta-chip"><strong>CWE:</strong> <code>${escapeHtml(vuln.cweId)}</code></span>`
    );
  }
  if (vuln.owaspCategory) {
    metaChips.push(
      `<span class="meta-chip"><strong>OWASP:</strong> ${escapeHtml(vuln.owaspCategory)}</span>`
    );
  }
  if (typeof vuln.confidence === "number") {
    const pct = Math.round(vuln.confidence * 100);
    metaChips.push(
      `<span class="meta-chip"><strong>Confidence:</strong> ${escapeHtml(`${pct}%`)}</span>`
    );
  }

  const snippetHtml = vuln.snippet
    ? `<div class="code-block">
         <div class="code-label">Affected Code Snippet</div>
         <pre><code>${escapeHtml(vuln.snippet)}</code></pre>
       </div>`
    : "";

  const explanationHtml = vuln.explanation
    ? `<p class="vuln-detail"><strong>Technical Explanation:</strong> ${escapeHtml(vuln.explanation)}</p>`
    : "";

  const remediationHtml = vuln.remediationSummary
    ? `<div class="remediation-box">
         <strong>Recommended Remediation:</strong> ${escapeHtml(vuln.remediationSummary)}
       </div>`
    : "";

  return `
    <article class="vuln-card avoid-break">
      <div class="vuln-header">
        <div class="vuln-title-group">
          <span class="vuln-index">#${escapeHtml(index + 1)}</span>
          <h3 class="vuln-title">${escapeHtml(vuln.title)}</h3>
        </div>
        <span class="badge ${severityClass}">${escapeHtml(vuln.severity.toUpperCase())}</span>
      </div>
      <div class="meta-row">${metaChips.join("")}</div>
      <p class="vuln-description">${escapeHtml(vuln.description)}</p>
      ${explanationHtml}
      ${snippetHtml}
      ${remediationHtml}
    </article>
  `;
}

function renderFixesTable(fixes: ReportFixAppliedItem[]): string {
  if (fixes.length === 0) {
    return `<p class="empty-state">No automated or manual fixes have been recorded for this report yet.</p>`;
  }

  const totalRiskReduction = fixes.reduce((sum, fix) => sum + fix.riskReduction, 0);

  const rowsHtml = fixes
    .map((fix) => {
      const loc = formatLocation(fix.fileName, fix.line);
      const verifiedBadge = fix.verified
        ? `<span class="badge badge-minimal">Verified</span>`
        : `<span class="badge badge-info">Applied</span>`;
      const reductionLabel = `-${fix.riskReduction} pts`;

      return `
        <tr>
          <td>
            <div class="cell-primary">${escapeHtml(fix.title)}</div>
            ${fix.ruleId ? `<div class="cell-sub"><code>${escapeHtml(fix.ruleId)}</code></div>` : ""}
          </td>
          <td>${escapeHtml(fix.summary)}</td>
          <td><code>${escapeHtml(loc)}</code></td>
          <td class="num-col"><strong class="text-success">${escapeHtml(reductionLabel)}</strong></td>
          <td>${verifiedBadge}</td>
        </tr>
      `;
    })
    .join("");

  return `
    <table class="data-table">
      <thead>
        <tr>
          <th>Fix</th>
          <th>Summary</th>
          <th>Location</th>
          <th class="num-col">Risk Reduction</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        ${rowsHtml}
      </tbody>
      <tfoot>
        <tr>
          <td colspan="3"><strong>Total Quantified Risk Reduction</strong></td>
          <td class="num-col"><strong class="text-success">${escapeHtml(`-${totalRiskReduction} pts`)}</strong></td>
          <td></td>
        </tr>
      </tfoot>
    </table>
  `;
}

function renderRecommendationGroup(
  heading: string,
  badgeClass: string,
  items: ReportRecommendationItem[]
): string {
  const listHtml =
    items.length === 0
      ? `<p class="empty-state">No recommendations in this horizon.</p>`
      : `<ul class="rec-list">
          ${items
            .map(
              (item) => `
              <li class="rec-item avoid-break">
                <div class="rec-item-header">
                  <strong>${escapeHtml(item.title)}</strong>
                  ${item.impact ? `<span class="meta-chip">Impact: ${escapeHtml(item.impact.toUpperCase())}</span>` : ""}
                  ${item.category ? `<span class="meta-chip">${escapeHtml(item.category)}</span>` : ""}
                </div>
                <p class="rec-description">${escapeHtml(item.description)}</p>
              </li>`
            )
            .join("")}
        </ul>`;

  return `
    <div class="rec-group avoid-break">
      <div class="rec-group-header">
        <span class="badge ${badgeClass}">${escapeHtml(heading)}</span>
        <span class="rec-count">${escapeHtml(`${items.length} item${items.length === 1 ? "" : "s"}`)}</span>
      </div>
      ${listHtml}
    </div>
  `;
}

function renderTimelineTable(timeline: ReportTimelineEvent[]): string {
  if (timeline.length === 0) {
    return `<p class="empty-state">No security timeline events recorded.</p>`;
  }

  const rowsHtml = timeline
    .map((event) => {
      const sevClass = getSeverityBadgeClass(event.severity);
      const statusClass = getTimelineStatusClass(event.status);
      const timeDisplay = event.formattedTime ?? event.timestamp;

      return `
        <tr>
          <td class="nowrap"><code>${escapeHtml(timeDisplay)}</code></td>
          <td>
            <div class="cell-primary">${escapeHtml(event.action)}</div>
            ${event.details ? `<div class="cell-sub">${escapeHtml(event.details)}</div>` : ""}
            ${event.actor ? `<div class="cell-sub">Actor: ${escapeHtml(event.actor)}</div>` : ""}
          </td>
          <td><span class="badge ${sevClass}">${escapeHtml(event.severity.toUpperCase())}</span></td>
          <td><span class="status-pill ${statusClass}">${escapeHtml(event.status.replace("_", " "))}</span></td>
        </tr>
      `;
    })
    .join("");

  return `
    <table class="data-table">
      <thead>
        <tr>
          <th>Timestamp</th>
          <th>Action</th>
          <th>Severity</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        ${rowsHtml}
      </tbody>
    </table>
  `;
}

/**
 * Renders a self-contained, XSS-escaped, print-friendly HTML5 security report
 * document suitable for direct download, email preview, or HTML-to-PDF rendering.
 */
export function renderSecurityReportHtml(report: CanonicalSecurityReport): string {
  const { threatSummary, securityScore, developer, date, metadata } = report;
  const riskBadgeClass = getRiskBadgeClass(report.riskLevel);
  const totalForPct = Math.max(1, threatSummary.totalDetected);

  const severityRows: { label: string; key: Severity; count: number }[] = [
    { label: "Critical", key: "critical", count: threatSummary.critical },
    { label: "High", key: "high", count: threatSummary.high },
    { label: "Medium", key: "medium", count: threatSummary.medium },
    { label: "Low", key: "low", count: threatSummary.low },
    { label: "Info", key: "info", count: threatSummary.info },
  ];

  const severityTableRowsHtml = severityRows
    .map((row) => {
      const pct =
        threatSummary.totalDetected === 0
          ? 0
          : Math.min(100, Math.max(0, Math.round((row.count / totalForPct) * 100)));
      return `
        <tr>
          <td><span class="badge ${getSeverityBadgeClass(row.key)}">${escapeHtml(row.label.toUpperCase())}</span></td>
          <td class="num-col"><strong>${escapeHtml(row.count)}</strong></td>
          <td class="num-col">${escapeHtml(`${pct}%`)}</td>
          <td class="bar-col">
            <div class="bar-track">
              <div class="bar-fill ${getSeverityBadgeClass(row.key)}" style="width: ${pct}%"></div>
            </div>
          </td>
        </tr>
      `;
    })
    .join("");

  const vulnerabilitiesHtml =
    report.vulnerabilities.length === 0
      ? `<p class="empty-state">No vulnerabilities were detected in this assessment.</p>`
      : report.vulnerabilities.map((v, idx) => renderVulnerabilityCard(v, idx)).join("");

  const metadataItems: string[] = [
    `<div><span class="meta-label">Report ID</span><span class="meta-value"><code>${escapeHtml(report.reportId)}</code></span></div>`,
    `<div><span class="meta-label">Developer</span><span class="meta-value">${escapeHtml(developer.name)}${developer.role ? ` (${escapeHtml(developer.role)})` : ""}${developer.email ? ` &lt;${escapeHtml(developer.email)}&gt;` : ""}</span></div>`,
    `<div><span class="meta-label">Report Date</span><span class="meta-value">${escapeHtml(date.formatted)} <small>(${escapeHtml(date.iso)})</small></span></div>`,
  ];

  if (metadata?.fileName) {
    metadataItems.push(
      `<div><span class="meta-label">Target File</span><span class="meta-value"><code>${escapeHtml(metadata.fileName)}</code></span></div>`
    );
  }
  if (metadata?.language) {
    metadataItems.push(
      `<div><span class="meta-label">Language</span><span class="meta-value"><code>${escapeHtml(metadata.language)}</code></span></div>`
    );
  }
  if (metadata?.branch || metadata?.commitSha) {
    const vcs = [metadata.branch, metadata.commitSha?.slice(0, 8)].filter(Boolean).join(" @ ");
    metadataItems.push(
      `<div><span class="meta-label">Source Ref</span><span class="meta-value"><code>${escapeHtml(vcs)}</code></span></div>`
    );
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Sentinel AI Security Report — ${escapeHtml(report.projectName)}</title>
  <style>
    :root {
      --bg: #ffffff;
      --surface: #f8fafc;
      --surface-alt: #f1f5f9;
      --text: #0f172a;
      --muted: #475569;
      --border: #e2e8f0;
      --primary: #0f172a;
      --accent: #2563eb;
      --critical: #b91c1c;
      --critical-bg: #fef2f2;
      --high: #c2410c;
      --high-bg: #fff7ed;
      --medium: #a16207;
      --medium-bg: #fefce8;
      --low: #1d4ed8;
      --low-bg: #eff6ff;
      --info: #475569;
      --info-bg: #f1f5f9;
      --success: #15803d;
      --success-bg: #f0fdf4;
    }

    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      padding: 32px 20px;
      background: #f1f5f9;
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      font-size: 14px;
      line-height: 1.55;
      -webkit-print-color-adjust: exact;
      print-color-adjust: exact;
    }

    .report-container {
      max-width: 960px;
      margin: 0 auto;
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 40px;
      box-shadow: 0 4px 20px rgba(15, 23, 42, 0.06);
    }

    .report-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 24px;
      padding-bottom: 24px;
      border-bottom: 2px solid var(--primary);
      margin-bottom: 24px;
    }

    .brand-eyebrow {
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: var(--accent);
      margin-bottom: 6px;
    }

    .report-title {
      margin: 0 0 6px 0;
      font-size: 26px;
      line-height: 1.2;
      color: var(--primary);
    }

    .report-subtitle {
      margin: 0;
      color: var(--muted);
      font-size: 14px;
    }

    .score-panel {
      text-align: right;
      min-width: 170px;
      padding: 14px 18px;
      border-radius: 10px;
      background: var(--surface);
      border: 1px solid var(--border);
    }

    .score-value {
      font-size: 30px;
      font-weight: 800;
      line-height: 1.1;
      color: var(--primary);
    }

    .score-grade {
      font-size: 13px;
      font-weight: 600;
      color: var(--muted);
      margin-top: 4px;
      margin-bottom: 8px;
    }

    .meta-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 12px 20px;
      padding: 16px;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      margin-bottom: 24px;
    }

    .meta-label {
      display: block;
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--muted);
      margin-bottom: 2px;
    }

    .meta-value {
      font-size: 13px;
      color: var(--text);
      word-break: break-word;
    }

    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 14px;
      margin-bottom: 28px;
    }

    .kpi-card {
      padding: 16px;
      border-radius: 8px;
      border: 1px solid var(--border);
      background: var(--bg);
    }

    .kpi-label {
      font-size: 12px;
      color: var(--muted);
      font-weight: 600;
      margin-bottom: 6px;
    }

    .kpi-number {
      font-size: 24px;
      font-weight: 800;
      color: var(--primary);
      line-height: 1.1;
    }

    .kpi-sub {
      font-size: 11px;
      color: var(--muted);
      margin-top: 4px;
    }

    .section {
      margin-top: 30px;
    }

    .section-title {
      margin: 0 0 14px 0;
      font-size: 18px;
      font-weight: 700;
      color: var(--primary);
      padding-bottom: 8px;
      border-bottom: 1px solid var(--border);
    }

    .overview-box {
      padding: 14px 16px;
      background: var(--surface);
      border-left: 4px solid var(--accent);
      border-radius: 4px;
      margin-bottom: 16px;
      color: var(--text);
    }

    .badge {
      display: inline-block;
      padding: 3px 9px;
      border-radius: 9999px;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      white-space: nowrap;
    }

    .badge-critical { background: var(--critical-bg); color: var(--critical); border: 1px solid #fecaca; }
    .badge-high { background: var(--high-bg); color: var(--high); border: 1px solid #fed7aa; }
    .badge-medium { background: var(--medium-bg); color: var(--medium); border: 1px solid #fef08a; }
    .badge-low { background: var(--low-bg); color: var(--low); border: 1px solid #bfdbfe; }
    .badge-info { background: var(--info-bg); color: var(--info); border: 1px solid #cbd5e1; }
    .badge-minimal { background: var(--success-bg); color: var(--success); border: 1px solid #bbf7d0; }

    .status-pill {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;
      text-transform: capitalize;
      white-space: nowrap;
    }

    .status-completed { background: var(--success-bg); color: var(--success); }
    .status-progress { background: var(--low-bg); color: var(--low); }
    .status-pending { background: var(--medium-bg); color: var(--medium); }
    .status-failed { background: var(--critical-bg); color: var(--critical); }
    .status-info { background: var(--info-bg); color: var(--info); }

    .data-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
      margin-bottom: 12px;
    }

    .data-table th,
    .data-table td {
      text-align: left;
      padding: 10px 12px;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }

    .data-table th {
      background: var(--surface);
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--muted);
    }

    .data-table tfoot td {
      background: var(--surface);
      border-top: 2px solid var(--border);
    }

    .num-col {
      text-align: right;
      white-space: nowrap;
    }

    .bar-col {
      width: 35%;
    }

    .bar-track {
      width: 100%;
      height: 8px;
      background: var(--surface-alt);
      border-radius: 9999px;
      overflow: hidden;
    }

    .bar-fill {
      height: 100%;
      border: none !important;
      padding: 0 !important;
    }

    .bar-fill.badge-critical { background: var(--critical); }
    .bar-fill.badge-high { background: var(--high); }
    .bar-fill.badge-medium { background: var(--medium); }
    .bar-fill.badge-low { background: var(--low); }
    .bar-fill.badge-info { background: var(--info); }

    .vuln-card {
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 14px;
      background: var(--bg);
    }

    .vuln-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 12px;
      margin-bottom: 10px;
    }

    .vuln-title-group {
      display: flex;
      align-items: baseline;
      gap: 8px;
    }

    .vuln-index {
      font-size: 12px;
      font-weight: 700;
      color: var(--muted);
    }

    .vuln-title {
      margin: 0;
      font-size: 15px;
      font-weight: 700;
      color: var(--primary);
    }

    .meta-row {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 10px;
    }

    .meta-chip {
      font-size: 12px;
      color: var(--muted);
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 4px;
      padding: 2px 7px;
    }

    .vuln-description,
    .vuln-detail {
      margin: 0 0 10px 0;
      color: var(--text);
    }

    .code-block {
      margin: 10px 0;
      border: 1px solid var(--border);
      border-radius: 6px;
      overflow: hidden;
    }

    .code-label {
      background: var(--surface-alt);
      padding: 5px 10px;
      font-size: 11px;
      font-weight: 600;
      color: var(--muted);
      border-bottom: 1px solid var(--border);
    }

    pre {
      margin: 0;
      padding: 12px;
      background: #0f172a;
      color: #e2e8f0;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 12px;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-word;
    }

    code {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.92em;
    }

    .remediation-box {
      padding: 10px 12px;
      background: var(--success-bg);
      border: 1px solid #bbf7d0;
      border-radius: 6px;
      font-size: 13px;
      color: #14532d;
    }

    .rec-group {
      margin-bottom: 18px;
    }

    .rec-group-header {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 10px;
    }

    .rec-count {
      font-size: 12px;
      color: var(--muted);
    }

    .rec-list {
      list-style: none;
      margin: 0;
      padding: 0;
      display: grid;
      gap: 10px;
    }

    .rec-item {
      padding: 12px 14px;
      border: 1px solid var(--border);
      border-radius: 6px;
      background: var(--surface);
    }

    .rec-item-header {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 8px;
      margin-bottom: 4px;
    }

    .rec-description {
      margin: 0;
      color: var(--muted);
      font-size: 13px;
    }

    .cell-primary {
      font-weight: 600;
      color: var(--text);
    }

    .cell-sub {
      font-size: 12px;
      color: var(--muted);
      margin-top: 2px;
    }

    .text-success {
      color: var(--success);
    }

    .nowrap {
      white-space: nowrap;
    }

    .empty-state {
      padding: 14px 16px;
      background: var(--surface);
      border: 1px dashed var(--border);
      border-radius: 6px;
      color: var(--muted);
      font-style: italic;
      margin: 0;
    }

    .report-footer {
      margin-top: 36px;
      padding-top: 16px;
      border-top: 1px solid var(--border);
      display: flex;
      justify-content: space-between;
      font-size: 12px;
      color: var(--muted);
    }

    .avoid-break {
      break-inside: avoid;
      page-break-inside: avoid;
    }

    @page {
      size: A4;
      margin: 16mm;
    }

    @media print {
      body {
        background: #ffffff;
        padding: 0;
      }

      .report-container {
        max-width: none;
        border: none;
        border-radius: 0;
        padding: 0;
        box-shadow: none;
      }

      .section {
        margin-top: 22px;
      }
    }

    @media (max-width: 720px) {
      .report-header {
        flex-direction: column;
      }

      .score-panel {
        text-align: left;
        width: 100%;
      }

      .kpi-grid {
        grid-template-columns: repeat(2, 1fr);
      }
    }
  </style>
</head>
<body>
  <main class="report-container">
    <header class="report-header">
      <div>
        <div class="brand-eyebrow">Sentinel AI · Security Assessment Report</div>
        <h1 class="report-title">${escapeHtml(report.projectName)}</h1>
        <p class="report-subtitle">
          Generated ${escapeHtml(date.formatted)} · Report Version ${escapeHtml(report.reportVersion)}
        </p>
      </div>
      <div class="score-panel">
        <div class="score-value">${escapeHtml(`${securityScore.percentage}%`)}</div>
        <div class="score-grade">
          Score ${escapeHtml(securityScore.score)} · Grade ${escapeHtml(securityScore.letterGrade)}${securityScore.securityLevel ? ` · ${escapeHtml(securityScore.securityLevel)}` : ""}
        </div>
        <span class="badge ${riskBadgeClass}">Risk: ${escapeHtml(report.riskLevel.toUpperCase())}</span>
      </div>
    </header>

    <section class="meta-grid" aria-label="Report Metadata">
      ${metadataItems.join("")}
    </section>

    <section class="kpi-grid" aria-label="Key Security Metrics">
      <div class="kpi-card">
        <div class="kpi-label">Detected Threats</div>
        <div class="kpi-number">${escapeHtml(threatSummary.totalDetected)}</div>
        <div class="kpi-sub">Total findings identified</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Fixes Applied</div>
        <div class="kpi-number">${escapeHtml(threatSummary.totalFixed)}</div>
        <div class="kpi-sub">Remediated findings</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Open Issues</div>
        <div class="kpi-number">${escapeHtml(threatSummary.openIssues)}</div>
        <div class="kpi-sub">Requiring attention</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Critical / High</div>
        <div class="kpi-number">${escapeHtml(threatSummary.critical + threatSummary.high)}</div>
        <div class="kpi-sub">${escapeHtml(threatSummary.critical)} critical · ${escapeHtml(threatSummary.high)} high</div>
      </div>
    </section>

    <section class="section avoid-break">
      <h2 class="section-title">Executive Threat Summary</h2>
      <div class="overview-box">${escapeHtml(threatSummary.executiveOverview)}</div>
      <table class="data-table">
        <thead>
          <tr>
            <th>Severity</th>
            <th class="num-col">Count</th>
            <th class="num-col">Share</th>
            <th>Distribution</th>
          </tr>
        </thead>
        <tbody>
          ${severityTableRowsHtml}
        </tbody>
      </table>
    </section>

    <section class="section">
      <h2 class="section-title">Detected Vulnerabilities (${escapeHtml(report.vulnerabilities.length)})</h2>
      ${vulnerabilitiesHtml}
    </section>

    <section class="section">
      <h2 class="section-title">Fixes Applied (${escapeHtml(report.fixesApplied.length)})</h2>
      ${renderFixesTable(report.fixesApplied)}
    </section>

    <section class="section">
      <h2 class="section-title">Prioritized Recommendations</h2>
      ${renderRecommendationGroup("Immediate Priority", "badge-critical", report.recommendations.immediate)}
      ${renderRecommendationGroup("Short-Term Priority", "badge-medium", report.recommendations.shortTerm)}
      ${renderRecommendationGroup("Long-Term Priority", "badge-low", report.recommendations.longTerm)}
    </section>

    <section class="section">
      <h2 class="section-title">Security Timeline (${escapeHtml(report.timeline.length)})</h2>
      ${renderTimelineTable(report.timeline)}
    </section>

    <footer class="report-footer">
      <span>Sentinel AI Security Engine · Report ID ${escapeHtml(report.reportId)}</span>
      <span>Generated ${escapeHtml(date.iso)}</span>
    </footer>
  </main>
</body>
</html>`;
}
