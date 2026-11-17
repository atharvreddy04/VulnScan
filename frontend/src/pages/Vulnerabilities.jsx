// frontend/src/pages/Vulnerabilities.jsx
import React, { useEffect, useState } from "react";
import { ShieldAlert } from "lucide-react";
import { vulnScanApi } from "../services/api";

export default function Vulnerabilities() {
  const [findings, setFindings] = useState([]);

  useEffect(() => {
    vulnScanApi.listFindings?.().then((d) => setFindings(d || [])).catch(() => {});
  }, []);

  return (
    <div className="p-6 space-y-4">
      <div className="bg-zinc-950 border border-zinc-900 rounded-lg overflow-hidden">
        <div className="px-5 py-3.5 border-b border-zinc-900 flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold text-white">All Discovered Findings & CVEs</h3>
        </div>
        <div className="divide-y divide-zinc-900 text-xs">
          {findings.length === 0 ? (
            <p className="p-6 text-zinc-500 text-center">No findings recorded yet. Run a Network or Web scan first.</p>
          ) : (
            findings.map((f) => (
              <div key={f.id} className="p-4 flex items-start justify-between gap-4">
                <div>
                  <span className="text-[10px] uppercase font-mono text-cyan-400">{f.module}</span>
                  <p className="font-medium text-zinc-100 mt-0.5">{f.title}</p>
                  <p className="text-zinc-400 mt-1">{f.remediation}</p>
                </div>
                <span className="px-2.5 py-0.5 rounded bg-zinc-900 border border-zinc-800 uppercase font-mono text-[10px] text-zinc-300">
                  {f.severity}
                </span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}