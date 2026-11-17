// frontend/src/pages/ScanHistory.jsx
import React, { useEffect, useState } from "react";
import { History } from "lucide-react";
import { vulnScanApi } from "../services/api";

export default function ScanHistory() {
  const [scans, setScans] = useState([]);

  useEffect(() => {
    vulnScanApi.listScans?.().then((d) => setScans(d || [])).catch(() => {});
  }, []);

  return (
    <div className="p-6">
      <div className="bg-zinc-950 border border-zinc-900 rounded-lg overflow-hidden">
        <div className="px-5 py-3.5 border-b border-zinc-900 flex items-center gap-2">
          <History className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold text-white">Assessment History</h3>
        </div>
        <table className="w-full text-left text-xs">
          <thead>
            <tr className="border-b border-zinc-900 text-zinc-500 uppercase text-[11px] bg-black/40">
              <th className="py-3 px-5">Scan ID</th>
              <th className="py-3 px-4">Target</th>
              <th className="py-3 px-4">Module</th>
              <th className="py-3 px-4">Profile</th>
              <th className="py-3 px-5">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-900">
            {scans.map((s) => (
              <tr key={s.id}>
                <td className="py-3 px-5 font-mono text-cyan-400">#{s.id}</td>
                <td className="py-3 px-4 font-mono text-zinc-200">{s.target}</td>
                <td className="py-3 px-4 uppercase text-zinc-400">{s.scan_type}</td>
                <td className="py-3 px-4 capitalize text-zinc-400">{s.profile}</td>
                <td className="py-3 px-5 capitalize text-emerald-400">{s.status}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}