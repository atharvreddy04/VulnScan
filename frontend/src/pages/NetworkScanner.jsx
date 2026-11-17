import React, { useEffect, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Loader2,
  Play,
  Server,
  ShieldCheck,
  Terminal,
} from "lucide-react";
import { vulnScanApi } from "../services/api";

export default function NetworkScanner() {
  const [target, setTarget] = useState("127.0.0.1");
  const [profile, setProfile] = useState("safe");
  const [authorized, setAuthorized] = useState(true);

  const [apiOnline, setApiOnline] = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [errorMsg, setErrorMsg] = useState("");

  const abortControllerRef = useRef(null);

  // Verify FastAPI connection on mount
  useEffect(() => {
    vulnScanApi
      .checkHealth()
      .then(() => setApiOnline(true))
      .catch(() => setApiOnline(false));

    return () => {
      abortControllerRef.current?.abort();
    };
  }, []);

  const handleStartScan = async (e) => {
    e.preventDefault();
    setErrorMsg("");

    if (!target.trim()) {
      setErrorMsg("Enter a valid target IPv4 address or local hostname.");
      return;
    }

    abortControllerRef.current?.abort();
    const controller = new AbortController();
    abortControllerRef.current = controller;

    setIsScanning(true);
    setScanResult(null);

    try {
      const queued = await vulnScanApi.startNetworkScan({
        target: target.trim(),
        profile,
        explicitAuthorization: authorized,
      });

      setScanResult({
        scan_id: queued.scan_id,
        target: queued.target,
        profile: queued.profile,
        status: queued.status,
        findings: [],
      });

      await vulnScanApi.pollNetworkScan(queued.scan_id, {
        intervalMs: 2000,
        signal: controller.signal,
        onUpdate: (latest) => {
          setScanResult(latest);
        },
      });
    } catch (err) {
      if (err.name !== "AbortError") {
        setErrorMsg(err.message || "Failed to execute network scan.");
      }
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <div className="min-h-screen bg-black text-zinc-100 p-6 space-y-6">
      {/* Header & Backend Status */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-zinc-900 pb-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-white flex items-center gap-2">
            <Server className="w-5 h-5 text-cyan-400" />
            Network & Port Scanner
          </h1>
          <p className="text-xs text-zinc-400 mt-1">
            Authorized Nmap service enumeration and open-port discovery
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs px-3 py-1.5 rounded-md bg-zinc-950 border border-zinc-800">
          <span
            className={`w-2 h-2 rounded-full ${
              apiOnline === true
                ? "bg-emerald-400"
                : apiOnline === false
                ? "bg-red-500"
                : "bg-zinc-500 animate-pulse"
            }`}
          />
          <span className="text-zinc-300">
            FastAPI Engine:{" "}
            {apiOnline === true
              ? "Connected"
              : apiOnline === false
              ? "Offline (Start uvicorn)"
              : "Checking..."}
          </span>
        </div>
      </div>

      {/* Scan Configuration Card */}
      <form
        onSubmit={handleStartScan}
        className="bg-zinc-950 border border-zinc-900 rounded-lg p-5 space-y-4"
      >
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="md:col-span-2">
            <label className="block text-xs font-medium text-zinc-400 mb-1.5">
              Target Host / RFC 1918 IP Address
            </label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="e.g., 127.0.0.1 or 192.168.1.10"
              className="w-full bg-black border border-zinc-800 focus:border-cyan-500 rounded-md px-3 py-2 text-sm text-zinc-100 font-mono outline-none"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-zinc-400 mb-1.5">
              Scan Profile
            </label>
            <select
              value={profile}
              onChange={(e) => setProfile(e.target.value)}
              className="w-full bg-black border border-zinc-800 focus:border-cyan-500 rounded-md px-3 py-2 text-sm text-zinc-100 outline-none"
            >
              <option value="safe">Safe (Top 100 TCP Ports)</option>
              <option value="standard">Standard (Top 1000 + Service Versions)</option>
              <option value="aggressive">Deep Lab Audit (All Ports + OS/Scripts)</option>
            </select>
          </div>
        </div>

        {/* Scope Authorization Guardrail */}
        <div className="flex flex-wrap items-center justify-between gap-4 pt-2 border-t border-zinc-900">
          <label className="flex items-center gap-2.5 text-xs text-zinc-300 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={authorized}
              onChange={(e) => setAuthorized(e.target.checked)}
              className="rounded border-zinc-700 bg-black text-cyan-500 focus:ring-cyan-500"
            />
            <ShieldCheck className="w-4 h-4 text-cyan-400 shrink-0" />
            <span>
              I confirm this target belongs to my local lab or I hold explicit authorization to assess it.
            </span>
          </label>

          <button
            type="submit"
            disabled={isScanning}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium bg-cyan-500 hover:bg-cyan-400 disabled:bg-zinc-800 disabled:text-zinc-500 text-black transition-colors cursor-pointer"
          >
            {isScanning ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Scanning Target...
              </>
            ) : (
              <>
                <Play className="w-4 h-4" />
                Launch Nmap Scan
              </>
            )}
          </button>
        </div>

        {errorMsg && (
          <div className="flex items-center gap-2 text-xs text-red-400 bg-red-950/30 border border-red-900/60 rounded-md px-3 py-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>{errorMsg}</span>
          </div>
        )}
      </form>

      {/* Live Status & Results */}
      {scanResult && (
        <div className="bg-zinc-950 border border-zinc-900 rounded-lg overflow-hidden">
          <div className="px-5 py-3.5 border-b border-zinc-900 flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <Terminal className="w-4 h-4 text-cyan-400" />
              <span className="text-sm font-medium text-white">
                Scan #{scanResult.scan_id} —{" "}
                <span className="font-mono text-cyan-400">{scanResult.target}</span>
              </span>
            </div>

            <div className="flex items-center gap-3 text-xs">
              <span className="text-zinc-400">
                Open Ports:{" "}
                <strong className="text-white">
                  {scanResult.summary?.open_ports_count ?? scanResult.findings?.length ?? 0}
                </strong>
              </span>
              <span
                className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full font-medium capitalize ${
                  scanResult.status === "completed"
                    ? "bg-emerald-950/60 text-emerald-400 border border-emerald-800/60"
                    : scanResult.status === "failed"
                    ? "bg-red-950/60 text-red-400 border border-red-800/60"
                    : "bg-cyan-950/60 text-cyan-400 border border-cyan-800/60"
                }`}
              >
                {scanResult.status === "completed" ? (
                  <CheckCircle2 className="w-3.5 h-3.5" />
                ) : (
                  <Activity className="w-3.5 h-3.5 animate-pulse" />
                )}
                {scanResult.status}
              </span>
            </div>
          </div>

          {scanResult.status === "failed" && scanResult.summary?.error && (
            <div className="p-4 text-xs font-mono text-red-400 bg-red-950/20">
              Scanner Error: {scanResult.summary.error}
            </div>
          )}

          {/* Open Ports Table */}
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-zinc-900 text-[11px] uppercase tracking-wider text-zinc-500 bg-black/40">
                  <th className="py-3 px-5">Port</th>
                  <th className="py-3 px-4">Protocol</th>
                  <th className="py-3 px-4">Service</th>
                  <th className="py-3 px-4">Version / Banner</th>
                  <th className="py-3 px-5">Remediation Note</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-900 text-xs">
                {scanResult.findings && scanResult.findings.length > 0 ? (
                  scanResult.findings.map((item) => (
                    <tr key={item.id} className="hover:bg-zinc-900/40 transition-colors">
                      <td className="py-3 px-5 font-mono font-semibold text-cyan-400">
                        {item.port}
                      </td>
                      <td className="py-3 px-4 uppercase text-zinc-400">{item.protocol}</td>
                      <td className="py-3 px-4 font-medium text-zinc-200">{item.service}</td>
                      <td className="py-3 px-4 font-mono text-zinc-400">
                        {item.details?.banner || "—"}
                      </td>
                      <td className="py-3 px-5 text-zinc-400 max-w-md">{item.remediation}</td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan="5" className="py-8 px-5 text-center text-zinc-500">
                      {isScanning
                        ? "Nmap is enumerating ports and services..."
                        : "No open ports reported for this scan."}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}