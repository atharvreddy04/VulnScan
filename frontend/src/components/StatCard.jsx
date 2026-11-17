import React from "react";

export default function StatCard({ title, value, subtitle, accent = "cyan", icon: Icon }) {
  const accentMap = {
    cyan: "text-cyan-400 border-cyan-500/20 bg-cyan-500/5",
    red: "text-red-400 border-red-500/20 bg-red-500/5",
    amber: "text-amber-400 border-amber-500/20 bg-amber-500/5",
    emerald: "text-emerald-400 border-emerald-500/20 bg-emerald-500/5",
  };

  return (
    <div className="bg-zinc-950 border border-zinc-900 rounded-lg p-5 flex items-start justify-between">
      <div>
        <p className="text-xs font-medium text-zinc-400">{title}</p>
        <p className="text-2xl font-bold text-white mt-1.5 font-mono">{value}</p>
        {subtitle && <p className="text-[11px] text-zinc-500 mt-1">{subtitle}</p>}
      </div>
      {Icon && (
        <div className={`p-2.5 rounded-lg border ${accentMap[accent] || accentMap.cyan}`}>
          <Icon className="w-5 h-5" />
        </div>
      )}
    </div>
  );
}