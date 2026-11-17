import React, { useEffect, useState } from "react";
import { ShieldAlert, Server, CheckCircle2, Gauge } from "lucide-react";
import StatCard from "../components/StatCard";
import SeverityChart from "../components/SeverityChart";
import { vulnScanApi } from "../services/api";

export default function Dashboard({ onNavigate }) {
  const [stats, setStats] = useState({
    total_scans: 0,
    total_assets: 0,
    security_score: 92,
    severity_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    recent_scans: [],
  });

  useEffect(() => {
    vulnScanApi
      .getDashboardSummary?.()
      .then((data) => {
        if (data) setStats(data);
      })
      .catch(() => {});
  }, []);

  return (
    <div className="p-6 space-y-6">
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Security Posture Score"
          value={`${stats.security_score}/100`}
          subtitle="Calculated from weighted CVSS risk"
          accent="cyan"
          icon={Gauge}
        />
        <StatCard
          title="Authorized Assets"
          value={stats.total_assets}
          subtitle="Verified RFC 1918 & lab targets"
          accent="emerald"
          icon={Server}
        />
        <StatCard
          title="Completed Assessments"
          value={stats.total_scans}
          subtitle="Stored in SQLite telemetry DB"
          accent="cyan"
          icon={CheckCircle2}
        />
        <StatCard
          title="Critical & High Risks"
          value={stats.severity_counts.critical + stats.severity_counts.high}
          subtitle="Immediate remediation priority"
          accent="red"
          icon={ShieldAlert}
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <SeverityChart counts={stats.severity_counts} />
        </div>

        <div className="bg-zinc-950 border border-zinc-900 rounded-lg p-5 flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-semibold text-white">Quick Assessment Launch</h3>
            <p className="text-xs text-zinc-400 mt-1 leading-relaxed">
              Run defensive port discovery, HTTP security header audits, TLS certificate validation, or export executive reports.
            </p>
          </div>
          <div className="space-y-2 mt-4">
            <button
              onClick={() => onNavigate("network")}
              className="w-full py-2 px-3 rounded-md bg-cyan-500 hover:bg-cyan-400 text-black font-medium text-xs transition-colors cursor-pointer"
            >
              Open Port & Service Scanner
            </button>
            <button
              onClick={() => onNavigate("web")}
              className="w-full py-2 px-3 rounded-md bg-black hover:bg-zinc-900 text-zinc-200 border border-zinc-800 font-medium text-xs transition-colors cursor-pointer"
            >
              Run Web Headers & TLS Audit
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}