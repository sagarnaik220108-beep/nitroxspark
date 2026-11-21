"use client";

export interface ScoreRingProps {
  score: number;
  letterGrade: string;
  riskCategory?: string;
  size?: number;
  className?: string;
}

interface ScoreTone {
  stroke: string;
  glow: string;
  text: string;
  badgeBg: string;
}

function getScoreTone(score: number): ScoreTone {
  if (score >= 85) {
    return {
      stroke: "#4EDEA3",
      glow: "rgba(78, 222, 163, 0.45)",
      text: "text-success",
      badgeBg: "bg-success-container/70 text-on-success-container border-success/40",
    };
  }
  if (score >= 65) {
    return {
      stroke: "#22D3EE",
      glow: "rgba(34, 211, 238, 0.48)",
      text: "text-primary",
      badgeBg: "bg-surface-container-high/90 text-primary border-primary/40",
    };
  }
  if (score >= 45) {
    return {
      stroke: "#FFB95F",
      glow: "rgba(255, 185, 95, 0.45)",
      text: "text-warning",
      badgeBg: "bg-warning-container/75 text-on-warning-container border-warning/40",
    };
  }
  return {
    stroke: "#FFB3AD",
    glow: "rgba(255, 179, 173, 0.48)",
    text: "text-error",
    badgeBg: "bg-error-container/75 text-on-error-container border-error/40",
  };
}

export function ScoreRing({
  score,
  letterGrade,
  riskCategory,
  size = 152,
  className = "",
}: ScoreRingProps) {
  const clampedScore = Math.max(0, Math.min(100, Math.round(score)));
  const strokeWidth = Math.max(8, Math.round(size * 0.072));
  const center = size / 2;
  const radius = center - strokeWidth - 4;
  const circumference = 2 * Math.PI * radius;
  const dashOffset = circumference - (clampedScore / 100) * circumference;
  const tone = getScoreTone(clampedScore);

  return (
    <div
      className={`inline-flex flex-col items-center gap-2 select-none ${className}`.trim()}
    >
      <div
        className="relative flex items-center justify-center"
        style={{ width: size, height: size }}
        role="img"
        aria-label={`Security score ${clampedScore} out of 100, grade ${letterGrade}${
          riskCategory ? `, ${riskCategory}` : ""
        }`}
      >
        <svg
          width={size}
          height={size}
          viewBox={`0 0 ${size} ${size}`}
          className="-rotate-90 overflow-visible"
        >
          {/* Ambient track */}
          <circle
            cx={center}
            cy={center}
            r={radius}
            fill="none"
            stroke="rgba(60, 73, 76, 0.38)"
            strokeWidth={strokeWidth}
          />

          {/* Subtle inner tick ring */}
          <circle
            cx={center}
            cy={center}
            r={Math.max(4, radius - strokeWidth * 0.9)}
            fill="none"
            stroke="rgba(138, 235, 255, 0.08)"
            strokeWidth={1}
            strokeDasharray="2 6"
          />

          {/* Animated progress arc */}
          <circle
            cx={center}
            cy={center}
            r={radius}
            fill="none"
            stroke={tone.stroke}
            strokeWidth={strokeWidth}
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={dashOffset}
            style={{
              filter: `drop-shadow(0 0 8px ${tone.glow})`,
              transition:
                "stroke-dashoffset 700ms cubic-bezier(0.22, 1, 0.36, 1), stroke 240ms ease-out",
            }}
          />
        </svg>

        {/* Center numeric readout */}
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
          <div className="flex items-baseline gap-0.5">
            <span
              className={`font-display font-bold tabular-nums leading-none tracking-tight ${tone.text}`}
              style={{ fontSize: Math.round(size * 0.25) }}
            >
              {clampedScore}
            </span>
            <span className="font-code text-[11px] text-on-surface-variant tabular-nums">
              /100
            </span>
          </div>

          <span
            className={`mt-1.5 inline-flex items-center px-2 py-0.5 rounded-full border font-display text-[11px] font-semibold tracking-wide ${tone.badgeBg}`}
          >
            Grade {letterGrade}
          </span>
        </div>
      </div>

      {riskCategory ? (
        <span className="font-label text-xs font-medium text-on-surface-variant tracking-wide">
          {riskCategory}
        </span>
      ) : null}
    </div>
  );
}
