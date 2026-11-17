import React from "react";
import {
  LayoutDashboard,
  Radar,
  Server,
  Globe,
  ShieldAlert,
  History,
  FileText,
  ShieldCheck,
} from "lucide-react";

const NAV_ITEMS = [
  { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { id: "recon", label: "Reconnaissance", icon: Radar },
  { id: "network", label: "Port Scanner", icon: Server },
  { id: "web", label: "Web Scanner", icon: Globe },
  { id: "vulns", label: "Vulnerabilities", icon: ShieldAlert },
  { id: "history", label: "Scan History", icon: History },
  { id: "reports", label: "Reports", icon: FileText },
];

export default function Sidebar({ activeTab, setActiveTab }) {
  return (
    <aside className="w-64 bg-zinc-950 border-r border-zinc-900 flex flex-col justify-between shrink-0 min-h-screen">
      <div>
        <div className="h-16 px-5 border-b border-zinc-900 flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/40 flex items-center justify-center">
            <ShieldCheck className="w-5 h-5 text-cyan-400" />
          </div>
          <div>
            <span className="font-bold tracking-wide text-white text-base block leading-none">
              VulnScan
            </span>
            <span className="text-[10px] text-zinc-500 tracking-wider uppercase">
              Security Assessment
            </span>
          </div>
        </div>

        <nav className="p-3 space-y-1">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const active = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-md text-xs font-medium transition-colors cursor-pointer ${
                  active
                    ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/30"
                    : "text-zinc-400 hover:text-zinc-100 hover:bg-zinc-900/60"
                }`}
              >
                <Icon className="w-4 h-4 shrink-0" />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>
      </div>

      <div className="p-4 m-3 rounded-lg bg-black border border-zinc-900 text-[11px] text-zinc-400 space-y-1">
        <div className="font-semibold text-cyan-400">Authorized Scope Only</div>
        <p className="leading-relaxed text-zinc-500">
          Restricted to RFC 1918 lab ranges and explicitly verified assets.
        </p>
      </div>
    </aside>
  );
}