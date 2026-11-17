import React, { useState } from "react";
import { Globe, Play, Loader2, ShieldCheck, AlertTriangle } from "lucide-react";
import { vulnScanApi } from "../services/api";

export default function WebScanner() {
  const [url, setUrl] = useState("http://127.0.0.1:8000");
  const [authorized, setAuthorized] = useState(true);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  const handleScan = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const data = await vulnScanApi.runWebAudit({
        targetUrl: url.trim(),
        explicitAuthorization: authorized,
      });
      setResult(data);
    } catch (err) {
      setError(err.message || "Web security audit failed.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-6 space-y-6">
      <form onSubmit={handleScan} className="bg-zinc-950 border border-zinc-900 rounded-lg p-5 space-y-4">
        <div>
          <label className="block text-xs font-medium text-zinc-400 mb-1.5">
            Target Web Endpoint (Local / Authorized Lab URL)
          </label>
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="http://127.0.0.1:8000"
            className="w-full bg-black border border-zinc-800 focus:border-cyan-500 rounded-md px-3 py-2 text-sm text-zinc-100 font-mono outline-none"
          />
        </div>

        <div className="flex flex-wrap items-center justify-between gap-4 pt-2 border-t border-zinc-900">
          <label className="flex items-center gap-2 text-xs text-zinc-300 cursor-pointer">
            <input
              type="checkbox"
              checked={authorized}
              onChange={(e) => setAuthorized(e.target.checked)}
              className="rounded border-zinc-700 bg-black text-cyan-500"
            />
            <ShieldCheck className="w-4 h-4 text-cyan-400" />
            <span>Authorized target confirmation</span>
          </label>

          <button
            type="submit"
            disabled={loading}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-md text-xs font-medium bg-cyan-500 hover:bg-cyan-400 text-black cursor-pointer"
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
            <span>Audit HTTP Headers & TLS</span>
          </button>
        </div>

        {error && (
          <div className="flex items-center gap-2 text-xs text-red-400 bg-red-950/30 border border-red-900/60 rounded-md px-3 py-2">
            <AlertTriangle className="w-4 h-4" />
            <span>{error}</span>
          </div>
        )}
      </form>

      {result && (
        <div className="bg-zinc-950 border border-zinc-900 rounded-lg overflow-hidden">
          <div className="px-5 py-3.5 border-b border-zinc-900 flex items-center justify-between">
            <div className="flex items-center gap-2 text-sm font-semibold text-white">
              <Globe className="w-4 h-4 text-cyan-400" />
              <span>Security Headers & Configuration Findings ({result.findings?.length || 0})</span>
            </div>
            <span className="text-xs font-mono text-zinc-400">HTTP {result.status_code}</span>
          </div>
          <div className="divide-y divide-zinc-900">
            {result.findings?.map((f, idx) => (
              <div key={idx} className="p-4 flex items-start justify-between gap-4 text-xs">
                <div>
                  <p className="font-semibold text-zinc-100">{f.title}</p>
                  <p className="text-zinc-400 mt-1">{f.remediation}</p>
                </div>
                <span className="px-2 py-0.5 rounded uppercase font-mono text-[10px] bg-zinc-900 text-cyan-400 border border-zinc-800">
                  {f.severity}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}