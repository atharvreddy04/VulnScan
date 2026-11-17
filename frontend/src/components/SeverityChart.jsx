import React from "react";

export default function SeverityChart({ counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 } }) {
  const total = Math.max(
    1,
    counts.critical + counts.high + counts.medium + counts.low + counts.info
  );

  const bars = [
    { label: "Critical", value: counts.critical, color: "bg-red-500" },
    { label: "High", value: counts.high, color: "bg-orange-500" },
    { label: "Medium", value: counts.medium, color: "bg-amber-400" },
    { label: "Low", value: counts.low, color: "bg-cyan-400" },
    { label: "Informational", value: counts.info, color: "bg-zinc-500" },
  ];

  return (
    <div className="bg-zinc-950 border border-zinc-900 rounded-lg p-5 space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-white">Severity Distribution</h3>
        <span className="text-xs text-zinc-500 font-mono">Total Findings: {total === 1 && counts.info === 0 && counts.critical === 0 ? 0 : Object.values(counts).reduce((a, b) => a + b, 0)}</span>
      </div>

      <div className="space-y-3">
        {bars.map((b) => {
          const pct = Math.round((b.value / total) * 100);
          return (
            <div key={b.label} className="space-y-1">
              <div className="flex justify-between text-xs">
                <span className="text-zinc-300">{b.label}</span>
                <span className="font-mono text-zinc-400">
                  {b.value} ({pct}%)
                </span>
              </div>
              <div className="w-full h-2 bg-black rounded-full overflow-hidden border border-zinc-900">
                <div
                  className={`h-full ${b.color} transition-all duration-500`}
                  style={{ width: `${pct}%` }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}