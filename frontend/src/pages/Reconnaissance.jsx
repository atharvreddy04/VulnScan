// frontend/src/pages/Reconnaissance.jsx
import React, { useState } from "react";
import { Radar, Search } from "lucide-react";
import { vulnScanApi } from "../services/api";

export default function Reconnaissance() {
  const [domain, setDomain] = useState("localhost");
  const [records, setRecords] = useState(null);

  const handleLookup = async (e) => {
    e.preventDefault();
    const res = await vulnScanApi.runDnsRecon?.(domain).catch(() => null);
    if (res) setRecords(res);
  };

  return (
    <div className="p-6 space-y-6">
      <form onSubmit={handleLookup} className="bg-zinc-950 border border-zinc-900 rounded-lg p-5 flex gap-3">
        <input
          type="text"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          placeholder="Enter authorized domain (e.g., lab.local)"
          className="flex-1 bg-black border border-zinc-800 focus:border-cyan-500 rounded-md px-3 py-2 text-sm text-zinc-100 font-mono outline-none"
        />
        <button
          type="submit"
          className="inline-flex items-center gap-2 px-4 py-2 rounded-md bg-cyan-500 hover:bg-cyan-400 text-black text-xs font-medium cursor-pointer"
        >
          <Search className="w-4 h-4" />
          <span>DNS Lookup</span>
        </button>
      </form>

      {records && (
        <div className="bg-zinc-950 border border-zinc-900 rounded-lg p-5 space-y-2 text-xs font-mono">
          <div className="flex items-center gap-2 text-cyan-400 font-sans font-semibold text-sm mb-2">
            <Radar className="w-4 h-4" />
            <span>DNS Records for {records.domain}</span>
          </div>
          <pre className="text-zinc-300 overflow-x-auto">{JSON.stringify(records.records, null, 2)}</pre>
        </div>
      )}
    </div>
  );
}