import React, { useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  ChevronUp,
  Code2,
  Cpu,
  Download,
  FileText,
  FolderSearch,
  Globe,
  Layers,
  LayoutDashboard,
  Lock,
  Play,
  Printer,
  Radar,
  RefreshCw,
  Search,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sliders,
  Terminal,
  X,
} from "lucide-react";
import { vulnScanApi } from "./services/api";

const INITIAL_HISTORY = [
  {
    id: "SCAN-2026-0894",
    target: "10.24.18.42",
    hostname: "staging-api.corp.local",
    profile: "Full Stack Audit (Nmap + Nuclei + SSLyze)",
    counts: { c: 2, h: 4, m: 7, l: 5 },
    score: 64,
    timestamp: "2026-11-17 09:42:18 UTC",
  },
  {
    id: "SCAN-2026-0891",
    target: "192.168.100.15",
    hostname: "auth-gateway.lab.local",
    profile: "TLS & Web Header Posture",
    counts: { c: 0, h: 2, m: 4, l: 6 },
    score: 82,
    timestamp: "2026-11-16 18:15:04 UTC",
  },
  {
    id: "SCAN-2026-0887",
    target: "172.16.40.10",
    hostname: "legacy-erp.corp.local",
    profile: "Deep CVE & Service Enumeration",
    counts: { c: 4, h: 7, m: 9, l: 3 },
    score: 41,
    timestamp: "2026-11-15 14:30:51 UTC",
  },
  {
    id: "SCAN-2026-0882",
    target: "10.24.18.90",
    hostname: "metrics-prometheus.corp.local",
    profile: "Quick Port & Directory Audit",
    counts: { c: 1, h: 1, m: 3, l: 4 },
    score: 76,
    timestamp: "2026-11-14 11:05:33 UTC",
  },
];

const INITIAL_PORTS = [
  {
    port: "22/tcp",
    state: "open",
    service: "ssh",
    version: "OpenSSH 8.9p1 Ubuntu 3ubuntu0.6",
    cpe: "cpe:/a:openbsd:openssh:8.9p1",
    banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\nssh-hostkey: 256 SHA256:9xK2... (ED25519)",
  },
  {
    port: "80/tcp",
    state: "open",
    service: "http",
    version: "nginx 1.22.1",
    cpe: "cpe:/a:igor_sysoev:nginx:1.22.1",
    banner: "HTTP/1.1 301 Moved Permanently\nServer: nginx/1.22.1\nLocation: https://staging-api.corp.local/",
  },
  {
    port: "443/tcp",
    state: "open",
    service: "https",
    version: "nginx 1.22.1 (Reverse Proxy -> Uvicorn)",
    cpe: "cpe:/a:igor_sysoev:nginx:1.22.1",
    banner: "HTTP/1.1 200 OK\nServer: nginx/1.22.1\nStrict-Transport-Security: max-age=31536000; includeSubDomains",
  },
  {
    port: "5432/tcp",
    state: "filtered",
    service: "postgresql",
    version: "PostgreSQL DB (Firewall Drop)",
    cpe: "cpe:/a:postgresql:postgresql",
    banner: "No response (filtered by host iptables / security group rule)",
  },
  {
    port: "6379/tcp",
    state: "open",
    service: "redis",
    version: "Redis key-value store 7.0.11",
    cpe: "cpe:/a:redis:redis:7.0.11",
    banner: "-NOAUTH Authentication required.\nredis_version:7.0.11\ntcp_port:6379",
  },
  {
    port: "8080/tcp",
    state: "open",
    service: "http-proxy",
    version: "Uvicorn / Python 3.11 ASGI",
    cpe: "cpe:/a:python:python:3.11",
    banner: 'HTTP/1.1 200 OK\nserver: uvicorn\ncontent-type: application/json\n{"service":"core-billing-api","env":"staging","debug":true}',
  },
];

const INITIAL_VULNS = [
  {
    id: "CVE-2024-21626",
    severity: "CRITICAL",
    cvss: "9.1",
    endpoint: "10.24.18.42:8080 (/api/v1/openapi.json)",
    title: "Exposed Debug Mode & Unauthenticated OpenAPI Schema Leak",
    description:
      "The staging ASGI worker directly exposes port 8080 bypassing the Nginx reverse proxy, returning full interactive Swagger documentation and stack trace verbosity with DEBUG=True enabled.",
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    template: "nuclei:http/exposures/apis/openapi-debug-leak",
    remediation:
      "Bind Uvicorn exclusively to 127.0.0.1:8080, disable FastAPI docs_url/openapi_url in non-local environments, and set DEBUG=False.",
  },
  {
    id: "CVE-2023-44487",
    severity: "CRITICAL",
    cvss: "8.6",
    endpoint: "10.24.18.42:443 (nginx/1.22.1)",
    title: "HTTP/2 Rapid Reset Stream Cancellation DoS Exposure",
    description:
      "Nginx 1.22.1 is vulnerable to rapid stream creation and cancellation over HTTP/2, enabling resource exhaustion against worker processes.",
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H",
    template: "nuclei:network/cve/2023/CVE-2023-44487",
    remediation:
      "Upgrade Nginx to >= 1.25.3 or apply vendor backport patches; configure keepalive_requests and limit_conn directives.",
  },
  {
    id: "CVE-2023-28432",
    severity: "HIGH",
    cvss: "7.8",
    endpoint: "10.24.18.42:443 (/.env.backup)",
    title: "Environment Configuration Backup File Publicly Accessible",
    description:
      "A backup configuration artifact (/.env.backup) returned HTTP 200 OK containing database connection strings and JWT signing secrets.",
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    template: "nuclei:http/exposures/configs/env-file-backup",
    remediation:
      "Immediately rotate all secrets found in .env.backup, remove backup files from the web root, and add a Nginx location ~ /\\. deny all rule.",
  },
  {
    id: "CWE-327-TLS",
    severity: "HIGH",
    cvss: "7.4",
    endpoint: "10.24.18.42:443 (TLS Listener)",
    title: "Deprecated TLS 1.0 / TLS 1.1 Protocols Enabled",
    description:
      "The TLS termination endpoint accepts legacy TLS 1.0 and TLS 1.1 handshakes, exposing sessions to downgrade and weak CBC cipher weaknesses.",
    vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    template: "sslyze:tls-deprecated-protocols",
    remediation:
      "Update ssl_protocols in nginx.conf to exclusively allow TLSv1.2 TLSv1.3 and prefer ECDHE-AEAD cipher suites.",
  },
  {
    id: "CWE-693-CSP",
    severity: "MEDIUM",
    cvss: "5.4",
    endpoint: "10.24.18.42:443 (HTTP Response Headers)",
    title: "Missing Content-Security-Policy & Referrer-Policy Headers",
    description:
      "Absence of Content-Security-Policy increases the blast radius of any future DOM or reflected script injection flaws.",
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    template: "nuclei:http/misconfiguration/http-missing-security-headers",
    remediation:
      "Add Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; object-src 'none'; to Nginx server block.",
  },
  {
    id: "CWE-200-REDIS",
    severity: "MEDIUM",
    cvss: "5.3",
    endpoint: "10.24.18.42:6379 (Redis 7.0.11)",
    title: "Redis Service Listening on All Interfaces (0.0.0.0:6379)",
    description:
      "Although requirepass is active, Redis is bound to 0.0.0.0 allowing lateral brute-force attempts from any compromised host in VLAN 18.",
    vector: "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    template: "nmap:redis-info-exposure",
    remediation:
      "Restrict Redis listener interface to 127.0.0.1 or internal management subnet and enforce firewall ACLs.",
  },
  {
    id: "CWE-200-BANNER",
    severity: "LOW",
    cvss: "3.1",
    endpoint: "10.24.18.42:443 (Server: nginx/1.22.1)",
    title: "Server Version Disclosure in HTTP Response Headers",
    description:
      "Exact Nginx and Uvicorn version strings are broadcast in HTTP response headers, aiding attacker fingerprinting.",
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    template: "zap:10036-server-leaks-version",
    remediation:
      "Set server_tokens off; in nginx.conf and launch Uvicorn with --no-server-header.",
  },
];

const INITIAL_LOGS = [
  { time: "09:41:02", tag: "[SCOPE-GUARD]", color: "text-emerald-400", text: "Verified 10.24.18.42 matches RFC1918 authorized CIDR 10.24.16.0/20" },
  { time: "09:41:05", tag: "[NMAP-WORKER]", color: "text-cyan-400", text: "Completed SYN service discovery: 5 open ports, 1 filtered" },
  { time: "09:41:48", tag: "[SSLYZE-WORKER]", color: "text-amber-400", text: "TLS handshake audit finished: TLS 1.0/1.1 deprecated protocols flagged" },
  { time: "09:42:03", tag: "[NUCLEI-ENGINE]", color: "text-red-400", text: "Evaluated 1,420 templates -> 2 Critical, 4 High, 7 Medium findings" },
  { time: "09:42:18", tag: "[REPORT-GEN]", color: "text-zinc-300", text: "Persisted scan telemetry SCAN-2026-0894 to PostgreSQL" },
];

const MODULES = [
  { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { id: "recon", label: "Reconnaissance", icon: Radar },
  { id: "ports", label: "Port Scanner", icon: Server },
  { id: "web", label: "Web Scanner", icon: Globe },
  { id: "vulns", label: "Vulnerability Scanner", icon: ShieldAlert, badge: 7 },
  { id: "dirs", label: "Directory Scanner", icon: FolderSearch },
  { id: "ssl", label: "SSL Analyzer", icon: Lock },
  { id: "testing", label: "Security Testing", icon: Sliders },
  { id: "reports", label: "Reports", icon: FileText },
];

export default function App() {
  const [activeModule, setActiveModule] = useState("dashboard");
  const [activeScope, setActiveScope] = useState("10.24.18.42");
  const [reconInput, setReconInput] = useState("10.24.18.42");
  const [authorized, setAuthorized] = useState(true);
  const [scopeError, setScopeError] = useState("");

  // Live pipeline & FastAPI state
  const [apiConnected, setApiConnected] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(100);
  const [logs, setLogs] = useState(INITIAL_LOGS);
  const [history, setHistory] = useState(INITIAL_HISTORY);
  const [ports, setPorts] = useState(INITIAL_PORTS);
  const [expandedPort, setExpandedPort] = useState("8080/tcp");

  // Vulnerability filters & modal
  const [sevFilter, setSevFilter] = useState("ALL");
  const [vulnSearch, setVulnSearch] = useState("");
  const [selectedVuln, setSelectedVuln] = useState(null);
  const [showBlueprint, setShowBlueprint] = useState(false);

  // Security testing controls
  const [rateCap, setRateCap] = useState(5);
  const [policies, setPolicies] = useState({
    sql: true,
    xss: true,
    csrf: true,
    cors: true,
  });

  // Report builder state
  const [selectedReportId, setSelectedReportId] = useState("SCAN-2026-0894");
  const [reportSections, setReportSections] = useState({
    exec: true,
    matrix: true,
    findings: true,
    roadmap: true,
  });

  useEffect(() => {
    vulnScanApi
      .checkHealth()
      .then(() => setApiConnected(true))
      .catch(() => setApiConnected(false));
  }, []);

  const isValidLabScope = (target) => {
    const t = target.trim().toLowerCase();
    if (!t) return false;
    if (t === "localhost" || t === "127.0.0.1" || t.endsWith(".local") || t.endsWith(".lab")) {
      return true;
    }
    return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(t);
  };

  const triggerPipeline = async (targetOverride) => {
    const target = (targetOverride || activeScope).trim();
    if (!isValidLabScope(target)) {
      setScopeError("Blocked by Scope Guardrail: Target must be RFC 1918 private IP or .local/.lab host.");
      return;
    }
    setScopeError("");
    setActiveScope(target);
    setIsScanning(true);
    setScanProgress(12);

    const nowTime = () => new Date().toTimeString().slice(0, 8);
    setLogs([
      {
        time: nowTime(),
        tag: "[SCOPE-GUARD]",
        color: "text-emerald-400",
        text: `Verified ${target} matches RFC1918 authorized lab policy`,
      },
    ]);

    // If local FastAPI backend is running, trigger a real background Nmap scan in parallel
    if (apiConnected) {
      vulnScanApi
        .startNetworkScan({ target, profile: "safe", explicitAuthorization: true })
        .then((queued) =>
          vulnScanApi.pollNetworkScan(queued.scan_id, {
            intervalMs: 1500,
            onUpdate: (latest) => {
              if (latest.status === "completed" && latest.findings?.length > 0) {
                setPorts(
                  latest.findings.map((f) => ({
                    port: `${f.port}/${f.protocol}`,
                    state: "open",
                    service: f.service,
                    version: f.details?.banner || "Detected via live Nmap worker",
                    cpe: `cpe:/a:${f.service}:${f.service}`,
                    banner: f.remediation,
                  }))
                );
              }
            },
          })
        )
        .catch(() => {});
    }

    const steps = [
      {
        pct: 36,
        delay: 550,
        log: {
          tag: "[NMAP-WORKER]",
          color: "text-cyan-400",
          text: `Completed SYN service discovery on ${target}: 5 open ports, 1 filtered`,
        },
      },
      {
        pct: 64,
        delay: 1150,
        log: {
          tag: "[SSLYZE-WORKER]",
          color: "text-amber-400",
          text: "TLS handshake audit finished: TLS 1.0/1.1 deprecated protocols flagged",
        },
      },
      {
        pct: 88,
        delay: 1750,
        log: {
          tag: "[NUCLEI-ENGINE]",
          color: "text-red-400",
          text: "Evaluated 1,420 templates -> 2 Critical, 4 High, 7 Medium findings",
        },
      },
      {
        pct: 100,
        delay: 2300,
        log: {
          tag: "[REPORT-GEN]",
          color: "text-zinc-300",
          text: `Persisted scan telemetry for ${target} to SQLite/PostgreSQL`,
        },
      },
    ];

    steps.forEach((step, idx) => {
      setTimeout(() => {
        setScanProgress(step.pct);
        setLogs((prev) => [...prev, { time: nowTime(), ...step.log }]);
        if (idx === steps.length - 1) {
          setIsScanning(false);
        }
      }, step.delay);
    });
  };

  const filteredVulns = useMemo(() => {
    return INITIAL_VULNS.filter((v) => {
      const matchesSev = sevFilter === "ALL" || v.severity === sevFilter;
      const q = vulnSearch.toLowerCase();
      const matchesQuery =
        !q ||
        v.id.toLowerCase().includes(q) ||
        v.title.toLowerCase().includes(q) ||
        v.endpoint.toLowerCase().includes(q);
      return matchesSev && matchesQuery;
    });
  }, [sevFilter, vulnSearch]);

  const activeReport =
    history.find((h) => h.id === selectedReportId) || history[0];

  const downloadJsonReport = () => {
    const payload = {
      platform: "VulnScan Security Assessment Platform",
      scan_id: activeReport.id,
      target: activeReport.target,
      hostname: activeReport.hostname,
      security_score: activeReport.score,
      generated_at: new Date().toISOString(),
      findings: INITIAL_VULNS,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${activeReport.id}_telemetry.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="min-h-screen bg-black text-zinc-100 flex flex-col">
      {/* Top Global Bar */}
      <header className="h-14 bg-zinc-950 border-b border-zinc-900 px-4 flex items-center justify-between sticky top-0 z-30 no-print">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/40 flex items-center justify-center">
            <ShieldCheck className="w-4 h-4 text-cyan-400" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold text-white text-sm tracking-tight">
                VulnScan
              </span>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-950/80 text-cyan-400 border border-cyan-800/60">
                V2.4-OBSIDIAN
              </span>
            </div>
            <span className="text-[10px] text-zinc-500 block leading-none mt-0.5">
              Security Assessment Platform
            </span>
          </div>
        </div>

        {/* Center Active Scope Pill */}
        <div className="hidden md:flex items-center gap-3 px-3.5 py-1.5 rounded-full bg-black border border-zinc-800 text-xs">
          <span className="w-2 h-2 rounded-full bg-emerald-400" />
          <span className="text-zinc-400 font-mono text-[11px]">
            ACTIVE SCOPE:{" "}
            <strong className="text-cyan-400">{activeScope}</strong>
          </span>
          <span className="text-zinc-700">|</span>
          <span className="inline-flex items-center gap-1 text-emerald-400 text-[11px]">
            <Shield className="w-3 h-3" />
            RFC1918 Guardrail Active
          </span>
        </div>

        {/* Right Actions */}
        <div className="flex items-center gap-2.5">
          <button
            onClick={() => setShowBlueprint(true)}
            className="hidden sm:inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-black hover:bg-zinc-900 border border-zinc-800 text-xs text-zinc-200 transition-colors cursor-pointer"
          >
            <Layers className="w-3.5 h-3.5 text-cyan-400" />
            <span>Architecture & Backend Blueprint</span>
          </button>
          <button
            onClick={() => triggerPipeline()}
            disabled={isScanning}
            className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-md bg-cyan-500 hover:bg-cyan-400 disabled:bg-zinc-800 text-black font-semibold text-xs transition-colors cursor-pointer"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>{isScanning ? `Scanning ${scanProgress}%` : "Run Full Scan"}</span>
          </button>
        </div>
      </header>

      <div className="flex-1 flex min-w-0">
        {/* Left Sidebar */}
        <aside className="w-56 bg-zinc-950 border-r border-zinc-900 flex flex-col justify-between shrink-0 no-print">
          <div className="p-3">
            <div className="px-2.5 py-2 text-[10px] font-semibold uppercase tracking-wider text-zinc-500">
              Assessment Modules
            </div>
            <nav className="space-y-1">
              {MODULES.map((m) => {
                const Icon = m.icon;
                const active = activeModule === m.id;
                return (
                  <button
                    key={m.id}
                    onClick={() => setActiveModule(m.id)}
                    className={`w-full flex items-center justify-between px-3 py-2 rounded-md text-xs font-medium transition-colors cursor-pointer ${
                      active
                        ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/40"
                        : "text-zinc-400 hover:text-zinc-100 hover:bg-zinc-900/50 border border-transparent"
                    }`}
                  >
                    <span className="flex items-center gap-2.5">
                      <Icon className="w-3.5 h-3.5" />
                      <span>{m.label}</span>
                    </span>
                    {m.badge && (
                      <span className="px-1.5 py-0.5 text-[10px] font-mono rounded bg-red-950/90 text-red-400 border border-red-800/70">
                        {m.badge}
                      </span>
                    )}
                  </button>
                );
              })}
            </nav>
          </div>

          {/* Celery Workers Status Box */}
          <div className="p-3 m-3 rounded-lg bg-black border border-zinc-900 space-y-2 text-[11px]">
            <div className="flex items-center justify-between border-b border-zinc-900 pb-1.5">
              <span className="font-semibold text-zinc-400 text-[10px] tracking-wider">
                CELERY WORKERS
              </span>
              <span className="text-emerald-400 font-mono text-[10px]">
                ● 4 ONLINE
              </span>
            </div>
            <div className="space-y-1.5 font-mono text-[10px]">
              <div className="flex justify-between">
                <span className="text-zinc-400">nmap-worker-01</span>
                <span className="text-cyan-400">READY</span>
              </div>
              <div className="flex justify-between">
                <span className="text-zinc-400">nuclei-engine</span>
                <span className="text-cyan-400">READY</span>
              </div>
              <div className="flex justify-between">
                <span className="text-zinc-400">sslyze-auditor</span>
                <span className="text-zinc-500">IDLE</span>
              </div>
              <div className="flex justify-between">
                <span className="text-zinc-400">zap-passive</span>
                <span className="text-zinc-500">SAFE-MODE</span>
              </div>
              <div className="pt-1 border-t border-zinc-900 flex justify-between">
                <span className="text-zinc-500">fastapi-api</span>
                <span className={apiConnected ? "text-emerald-400" : "text-zinc-500"}>
                  {apiConnected ? "LIVE" : "SANDBOX"}
                </span>
              </div>
            </div>
          </div>
        </aside>

        {/* Main Workspace */}
        <main className="flex-1 p-5 overflow-y-auto space-y-5">
          {/* MODULE 1: DASHBOARD */}
          {activeModule === "dashboard" && (
            <>
              {/* Top 5 KPI Cards */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3.5">
                <div className="bg-zinc-950 border border-zinc-900 rounded-lg p-4">
                  <div className="flex items-center justify-between text-xs text-zinc-400">
                    <span>Total Assets Scanned</span>
                    <Server className="w-3.5 h-3.5 text-cyan-400" />
                  </div>
                  <div className="mt-2 flex items-baseline justify-between">
                    <span className="text-2xl font-bold text-white font-mono">14</span>
                    <span className="text-[11px] font-mono text-emerald-400">+3 this week</span>
                  </div>
                  <p className="text-[11px] text-zinc-500 mt-1.5">Scoped across 3 internal VLANs</p>
                </div>

                <div className="bg-zinc-950 border border-red-950/80 rounded-lg p-4">
                  <div className="flex items-center justify-between text-xs text-red-400">
                    <span>Critical Findings</span>
                    <span className="w-2 h-2 rounded-full bg-red-500" />
                  </div>
                  <div className="mt-2 flex items-baseline justify-between">
                    <span className="text-2xl font-bold text-red-400 font-mono">2</span>
                    <span className="text-[11px] font-mono text-red-400/80">CVSS 9.0–10.0</span>
                  </div>
                  <p className="text-[11px] text-zinc-500 mt-1.5">Immediate remediation required</p>
                </div>

                <div className="bg-zinc-950 border border-orange-950/70 rounded-lg p-4">
                  <div className="flex items-center justify-between text-xs text-orange-400">
                    <span>High Findings</span>
                    <span className="w-2 h-2 rounded-full bg-orange-500" />
                  </div>
                  <div className="mt-2 flex items-baseline justify-between">
                    <span className="text-2xl font-bold text-orange-400 font-mono">4</span>
                    <span className="text-[11px] font-mono text-orange-400/80">CVSS 7.0–8.9</span>
                  </div>
                  <p className="text-[11px] text-zinc-500 mt-1.5">Exposed .env & legacy TLS 1.0</p>
                </div>

                <div className="bg-zinc-950 border border-amber-950/70 rounded-lg p-4">
                  <div className="flex items-center justify-between text-xs text-amber-400">
                    <span>Medium Findings</span>
                    <span className="w-2 h-2 rounded-full bg-amber-400" />
                  </div>
                  <div className="mt-2 flex items-baseline justify-between">
                    <span className="text-2xl font-bold text-amber-400 font-mono">7</span>
                    <span className="text-[11px] font-mono text-amber-400/80">CVSS 4.0–6.9</span>
                  </div>
                  <p className="text-[11px] text-zinc-500 mt-1.5">Missing CSP & Redis binding</p>
                </div>

                <div className="bg-zinc-950 border border-emerald-950/70 rounded-lg p-4">
                  <div className="flex items-center justify-between text-xs text-emerald-400">
                    <span>Low / Info</span>
                    <span className="w-2 h-2 rounded-full bg-emerald-400" />
                  </div>
                  <div className="mt-2 flex items-baseline justify-between">
                    <span className="text-2xl font-bold text-emerald-400 font-mono">5</span>
                    <span className="text-[11px] font-mono text-emerald-400/80">CVSS 0.1–3.9</span>
                  </div>
                  <p className="text-[11px] text-zinc-500 mt-1.5">Banner & header hardening</p>
                </div>
              </div>

              {/* Middle Row: Security Score Radial + Live Assessment Pipeline */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                {/* Radial Score Card */}
                <div className="bg-zinc-950 border border-zinc-900 rounded-lg p-5 flex flex-col justify-between">
                  <div className="flex items-start justify-between">
                    <div>
                      <h3 className="text-sm font-semibold text-white">Security Posture Score</h3>
                      <p className="text-[11px] text-zinc-500">Weighted CVSS v3.1 & TLS Index</p>
                    </div>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-amber-950/80 text-amber-400 border border-amber-800/60">
                      MODERATE RISK
                    </span>
                  </div>

                  <div className="my-5 flex items-center justify-center relative">
                    <svg className="w-36 h-36 -rotate-90" viewBox="0 0 120 120">
                      <circle cx="60" cy="60" r="48" stroke="#18181b" strokeWidth="10" fill="none" />
                      <circle
                        cx="60"
                        cy="60"
                        r="48"
                        stroke="#06b6d4"
                        strokeWidth="10"
                        strokeDasharray="301.6"
                        strokeDashoffset={301.6 * (1 - 0.64)}
                        strokeLinecap="round"
                        fill="none"
                      />
                    </svg>
                    <div className="absolute text-center">
                      <div className="text-3xl font-bold text-white font-mono">64</div>
                      <div className="text-[10px] text-zinc-500 font-mono">/ 100 PTS</div>
                    </div>
                  </div>

                  <div className="grid grid-cols-3 text-center border-t border-zinc-900 pt-3 text-xs">
                    <div>
                      <div className="text-[10px] text-zinc-500">NETWORK</div>
                      <div className="font-mono font-semibold text-cyan-400 mt-0.5">72%</div>
                    </div>
                    <div>
                      <div className="text-[10px] text-zinc-500">WEB/API</div>
                      <div className="font-mono font-semibold text-amber-400 mt-0.5">54%</div>
                    </div>
                    <div>
                      <div className="text-[10px] text-zinc-500">TLS/CRYPTO</div>
                      <div className="font-mono font-semibold text-emerald-400 mt-0.5">68%</div>
                    </div>
                  </div>
                </div>

                {/* Live Terminal Telemetry */}
                <div className="lg:col-span-2 bg-zinc-950 border border-zinc-900 rounded-lg p-5 flex flex-col justify-between">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-2">
                      <Terminal className="w-4 h-4 text-cyan-400" />
                      <h3 className="text-sm font-semibold text-white">
                        Live Assessment Pipeline & Worker Telemetry
                      </h3>
                    </div>
                    <span className="text-xs font-mono text-cyan-400">
                      {isScanning ? `Running (${scanProgress}%)` : "Idle — All Workers Ready"}
                    </span>
                  </div>

                  {isScanning && (
                    <div className="w-full h-1.5 bg-black rounded-full overflow-hidden mb-3 border border-zinc-900">
                      <div
                        className="h-full bg-cyan-400 transition-all duration-300"
                        style={{ width: `${scanProgress}%` }}
                      />
                    </div>
                  )}

                  <div className="bg-black border border-zinc-900 rounded-md p-4 font-mono text-xs space-y-2 min-h-[168px]">
                    {logs.map((entry, idx) => (
                      <div key={idx} className="leading-relaxed">
                        <span className="text-zinc-600">&gt; [{entry.time}] </span>
                        <span className={`${entry.color} font-semibold`}>{entry.tag}</span>{" "}
                        <span className="text-zinc-300">{entry.text}</span>
                      </div>
                    ))}
                  </div>

                  <div className="mt-3 pt-3 border-t border-zinc-900 flex flex-wrap items-center justify-between gap-2 text-[11px] text-zinc-500">
                    <span>Workers: Nmap 7.94 • Nuclei v3.2 • SSLyze 6.0 • ZAP 2.15 (Passive)</span>
                    <button
                      onClick={() => triggerPipeline()}
                      className="inline-flex items-center gap-1 text-cyan-400 hover:text-cyan-300 cursor-pointer"
                    >
                      <RefreshCw className="w-3 h-3" />
                      <span>Re-run Pipeline</span>
                    </button>
                  </div>
                </div>
              </div>

              {/* Third Row: Attack Surface Distribution + 7-Day Trend */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="bg-zinc-950 border border-zinc-900 rounded-lg p-5 space-y-4">
                  <div>
                    <h3 className="text-sm font-semibold text-white">
                      Vulnerability Distribution by Attack Surface
                    </h3>
                    <p className="text-[11px] text-zinc-500">
                      Categorized across Network, Web/API, TLS, and Configuration layers
                    </p>
                  </div>

                  <div className="space-y-3.5 text-xs">
                    {[
                      { label: "Web Application & APIs", count: "8 findings", segs: ["w-1/4 bg-red-500", "w-1/4 bg-orange-500", "w-1/3 bg-amber-400", "w-1/6 bg-emerald-400"] },
                      { label: "Network Services & Ports", count: "5 findings", segs: ["w-1/6 bg-orange-500", "w-1/3 bg-amber-400", "w-1/4 bg-emerald-400"] },
                      { label: "TLS / Cryptographic Posture", count: "3 findings", segs: ["w-1/5 bg-orange-500", "w-1/5 bg-amber-400", "w-1/6 bg-emerald-400"] },
                      { label: "Sensitive File Exposure", count: "2 findings", segs: ["w-1/6 bg-red-500", "w-1/5 bg-amber-400"] },
                    ].map((row) => (
                      <div key={row.label} className="space-y-1.5">
                        <div className="flex justify-between">
                          <span className="text-zinc-300">{row.label}</span>
                          <span className="font-mono text-zinc-500">{row.count}</span>
                        </div>
                        <div className="w-full h-2 bg-black rounded-full overflow-hidden flex gap-0.5 p-0.5 border border-zinc-900">
                          {row.segs.map((cls, i) => (
                            <div key={i} className={`h-full rounded-sm ${cls}`} />
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* 7-Day Trend SVG */}
                <div className="bg-zinc-950 border border-zinc-900 rounded-lg p-5 flex flex-col justify-between">
                  <div className="flex items-start justify-between">
                    <div>
                      <h3 className="text-sm font-semibold text-white">
                        7-Day Remediation & Security Score Trend
                      </h3>
                      <p className="text-[11px] text-zinc-500">
                        Posture improvement across staging sprint cycles
                      </p>
                    </div>
                    <span className="text-xs font-mono text-emerald-400">+22 pts (7d)</span>
                  </div>

                  <svg className="w-full h-40 mt-4" viewBox="0 0 420 130">
                    <defs>
                      <linearGradient id="scoreArea" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.28" />
                        <stop offset="100%" stopColor="#06b6d4" stopOpacity="0.0" />
                      </linearGradient>
                    </defs>
                    <polygon
                      points="30,85 90,74 150,62 210,55 270,48 330,42 390,42 390,105 30,105"
                      fill="url(#scoreArea)"
                    />
                    <polyline
                      fill="none"
                      stroke="#06b6d4"
                      strokeWidth="2.5"
                      points="30,85 90,74 150,62 210,55 270,48 330,42 390,42"
                    />
                    {[
                      { x: 30, y: 85, val: 42, day: "Nov 11" },
                      { x: 90, y: 74, val: 48, day: "Nov 12" },
                      { x: 150, y: 62, val: 54, day: "Nov 13" },
                      { x: 210, y: 55, val: 58, day: "Nov 14" },
                      { x: 270, y: 48, val: 61, day: "Nov 15" },
                      { x: 330, y: 42, val: 64, day: "Nov 16" },
                      { x: 390, y: 42, val: 64, day: "Nov 17" },
                    ].map((pt) => (
                      <g key={pt.day}>
                        <circle cx={pt.x} cy={pt.y} r="3.5" fill="#06b6d4" />
                        <text x={pt.x} y={pt.y - 8} textAnchor="middle" fill="#a1a1aa" fontSize="9" fontFamily="monospace">
                          {pt.val}
                        </text>
                        <text x={pt.x} y="122" textAnchor="middle" fill="#71717a" fontSize="9" fontFamily="monospace">
                          {pt.day}
                        </text>
                      </g>
                    ))}
                  </svg>
                </div>
              </div>

              {/* Recent Assessment History Table */}
              <div className="bg-zinc-950 border border-zinc-900 rounded-lg overflow-hidden">
                <div className="px-5 py-3.5 border-b border-zinc-900 flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-semibold text-white">Recent Assessment History</h3>
                    <p className="text-[11px] text-zinc-500">
                      Click any scan record to inspect findings or generate an executive PDF report
                    </p>
                  </div>
                  <button
                    onClick={() => setActiveModule("reports")}
                    className="text-xs text-cyan-400 hover:text-cyan-300 cursor-pointer"
                  >
                    Open Report Builder ↗
                  </button>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead>
                      <tr className="border-b border-zinc-900 text-[10px] uppercase tracking-wider text-zinc-500 bg-black/50">
                        <th className="py-3 px-5">Scan ID</th>
                        <th className="py-3 px-4">Target Asset</th>
                        <th className="py-3 px-4">Profile</th>
                        <th className="py-3 px-4">Findings (C / H / M / L)</th>
                        <th className="py-3 px-4">Score</th>
                        <th className="py-3 px-4">Timestamp</th>
                        <th className="py-3 px-5 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-zinc-900">
                      {history.map((row) => (
                        <tr key={row.id} className="hover:bg-zinc-900/40">
                          <td className="py-3 px-5 font-mono text-cyan-400 font-medium">{row.id}</td>
                          <td className="py-3 px-4">
                            <div className="font-mono text-zinc-100">{row.target}</div>
                            <div className="text-[11px] text-zinc-500">{row.hostname}</div>
                          </td>
                          <td className="py-3 px-4 text-zinc-300">{row.profile}</td>
                          <td className="py-3 px-4">
                            <div className="inline-flex items-center gap-1 font-mono text-[10px]">
                              <span className="px-1.5 py-0.5 rounded bg-red-950 text-red-400 border border-red-800/70">{row.counts.c}</span>
                              <span className="px-1.5 py-0.5 rounded bg-orange-950 text-orange-400 border border-orange-800/70">{row.counts.h}</span>
                              <span className="px-1.5 py-0.5 rounded bg-amber-950 text-amber-400 border border-amber-800/70">{row.counts.m}</span>
                              <span className="px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800/70">{row.counts.l}</span>
                            </div>
                          </td>
                          <td className="py-3 px-4 font-mono font-semibold text-white">{row.score}/100</td>
                          <td className="py-3 px-4 font-mono text-zinc-400 text-[11px]">{row.timestamp}</td>
                          <td className="py-3 px-5 text-right space-x-2">
                            <button
                              onClick={() => setActiveModule("vulns")}
                              className="px-2.5 py-1 rounded bg-black hover:bg-zinc-900 border border-zinc-800 text-zinc-200 text-[11px] cursor-pointer"
                            >
                              Inspect
                            </button>
                            <button
                              onClick={() => {
                                setSelectedReportId(row.id);
                                setActiveModule("reports");
                              }}
                              className="px-2.5 py-1 rounded bg-cyan-950/70 hover:bg-cyan-900/70 border border-cyan-700/60 text-cyan-300 text-[11px] cursor-pointer"
                            >
                              PDF
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </>
          )}

          {/* MODULE 2: RECONNAISSANCE */}
          {activeModule === "recon" && (
            <div className="space-y-5">
              <div className="bg-zinc-950 border border-zinc-900 rounded-lg p-5 space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                      <Globe className="w-4 h-4 text-cyan-400" />
                      Target Reconnaissance & Scope Authorization Guardrail
                    </h3>
                    <p className="text-xs text-zinc-500 mt-0.5">
                      Enforces RFC1918 private networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and authorized .local / .lab zones.
                    </p>
                  </div>
                  <span className="text-[11px] font-mono px-2.5 py-1 rounded bg-emerald-950/60 text-emerald-400 border border-emerald-800/60">
                    SCOPE VALID: RFC1918 Private / Loopback Network
                  </span>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-12 gap-3 items-center">
                  <div className="lg:col-span-5">
                    <label className="block text-[10px] font-mono uppercase text-zinc-500 mb-1">
                      Target IPv4 / Internal FQDN
                    </label>
                    <input
                      type="text"
                      value={reconInput}
                      onChange={(e) => setReconInput(e.target.value)}
                      className="w-full bg-black border border-zinc-800 focus:border-cyan-500 rounded-md px-3 py-2 text-xs font-mono text-white outline-none"
                    />
                  </div>
                  <div className="lg:col-span-5 pt-4">
                    <label className="flex items-center gap-2 text-xs text-zinc-300 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={authorized}
                        onChange={(e) => setAuthorized(e.target.checked)}
                        className="rounded border-zinc-700 bg-black text-cyan-500"
                      />
                      <span>I confirm explicit written authorization to assess this target within an isolated lab or owned network.</span>
                    </label>
                  </div>
                  <div className="lg:col-span-2 pt-4">
                    <button
                      onClick={() => triggerPipeline(reconInput)}
                      disabled={!authorized}
                      className="w-full py-2 px-3 rounded-md bg-cyan-500 hover:bg-cyan-400 disabled:bg-zinc-800 text-black font-semibold text-xs cursor-pointer"
                    >
                      Lock & Enumerate
                    </button>
                  </div>
                </div>

                {scopeError && (
                  <div className="text-xs text-red-400 bg-red-950/40 border border-red-900 rounded px-3 py-2">
                    {scopeError}
                  </div>
                )}

                <div className="flex flex-wrap items-center gap-2 text-[11px]">
                  <span className="text-zinc-500 font-mono">LAB PRESETS:</span>
                  {["10.24.18.42", "192.168.100.15", "172.16.40.10", "staging-api.corp.local"].map((preset) => (
                    <button
                      key={preset}
                      onClick={() => {
                        setReconInput(preset);
                        setActiveScope(preset);
                      }}
                      className="px-2 py-0.5 rounded bg-black hover:bg-zinc-900 border border-zinc-800 font-mono text-cyan-400 cursor-pointer"
                    >
                      {preset}
                    </button>
                  ))}
                </div>
              </div>

              {/* DNS + WHOIS Split */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                <div className="lg:col-span-2 bg-zinc-950 border border-zinc-900 rounded-lg overflow-hidden">
                  <div className="px-5 py-3 border-b border-zinc-900 flex justify-between items-center">
                    <h4 className="text-xs font-semibold text-white">DNS Zone & Resource Records</h4>
                    <span className="text-[11px] font-mono text-zinc-500">Resolver: 10.24.0.2 (CoreDNS)</span>
                  </div>
                  <table className="w-full text-left text-xs font-mono">
                    <thead>
                      <tr className="border-b border-zinc-900 text-[10px] text-zinc-500 bg-black/40">
                        <th className="py-2.5 px-5">Type</th>
                        <th className="py-2.5 px-4">Record Name</th>
                        <th className="py-2.5 px-4">Value</th>
                        <th className="py-2.5 px-5">TTL</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-zinc-900">
                      {[
                        ["A", "staging-api.corp.local", "10.24.18.42", "300s"],
                        ["AAAA", "staging-api.corp.local", "fd00:10:24:18::42", "300s"],
                        ["CNAME", "api-v2.corp.local", "staging-api.corp.local", "600s"],
                        ["MX", "corp.local", "10 mail-gw01.corp.local", "3600s"],
                        ["NS", "corp.local", "ns1.internal-dns.corp.local", "86400s"],
                        ["TXT", "corp.local", '"v=spf1 ip4:10.24.0.0/16 -all"', "3600s"],
                      ].map(([type, name, val, ttl], idx) => (
                        <tr key={idx}>
                          <td className="py-2.5 px-5">
                            <span className="px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800/60 text-[10px]">
                              {type}
                            </span>
                          </td>
                          <td className="py-2.5 px-4 text-zinc-200">{name}</td>
                          <td className="py-2.5 px-4 text-zinc-400">{val}</td>
                          <td className="py-2.5 px-5 text-zinc-500">{ttl}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                <div className="bg-zinc-950 border border-zinc-900 rounded-lg p-5 space-y-2.5 text-xs">
                  <h4 className="text-xs font-semibold text-white border-b border-zinc-900 pb-2">
                    WHOIS & Internal IPAM Registration
                  </h4>
                  {[
                    ["DOMAIN", "corp.local (Internal Split-Horizon Zone)"],
                    ["REGISTRAR", "Internal Enterprise IPAM / CoreDNS"],
                    ["ORG", "VulnScan Security Engineering Lab"],
                    ["ASN", "AS64512 (Private Autonomous System)"],
                    ["CIDR", "10.24.16.0/20"],
                    ["CREATED", "2023-03-14"],
                    ["UPDATED", "2026-10-02"],
                    ["ABUSECONTACT", "soc-ops@corp.local"],
                  ].map(([k, v]) => (
                    <div key={k} className="flex justify-between gap-2 border-b border-zinc-900/70 pb-1.5">
                      <span className="font-mono text-[10px] text-zinc-500">{k}</span>
                      <span className="font-mono text-[11px] text-zinc-200 text-right">{v}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Subdomains Table */}
              <div className="bg-zinc-950 border border-zinc-900 rounded-lg overflow-hidden">
                <div className="px-5 py-3 border-b border-zinc-900 flex justify-between items-center">
                  <h4 className="text-xs font-semibold text-white">Discovered Internal Subdomains & Virtual Hosts</h4>
                  <span className="text-xs font-mono text-cyan-400">6 Active Endpoints</span>
                </div>
                <table className="w-full text-left text-xs font-mono">
                  <thead>
                    <tr className="border-b border-zinc-900 text-[10px] text-zinc-500 bg-black/40">
                      <th className="py-2.5 px-5">Subdomain</th>
                      <th className="py-2.5 px-4">Resolved IP</th>
                      <th className="py-2.5 px-4">HTTP Status</th>
                      <th className="py-2.5 px-4">Server Banner</th>
                      <th className="py-2.5 px-5">Detected Stack</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-900">
                    {[
                      ["staging-api.corp.local", "10.24.18.42", "200", "nginx/1.22.1", "FastAPI / Uvicorn"],
                      ["auth.corp.local", "10.24.18.44", "200", "Envoy/1.28", "Keycloak OIDC"],
                      ["grafana.corp.local", "10.24.18.51", "302", "nginx/1.22.1", "Grafana v10.2"],
                      ["jenkins-ci.corp.local", "10.24.18.60", "403", "Jetty(10.0.15)", "Jenkins LTS"],
                      ["minio-s3.corp.local", "10.24.18.73", "200", "MinIO", "Object Storage"],
                      ["legacy-soap.corp.local", "10.24.18.88", "502", "Apache/2.4.52", "Tomcat 9"],
                    ].map(([sub, ip, code, banner, stack]) => (
                      <tr key={sub}>
                        <td className="py-2.5 px-5 text-cyan-400">{sub}</td>
                        <td className="py-2.5 px-4 text-zinc-300">{ip}</td>
                        <td className="py-2.5 px-4">
                          <span className="px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800/60 text-[10px]">
                            {code}
                          </span>
                        </td>
                        <td className="py-2.5 px-4 text-zinc-400">{banner}</td>
                        <td className="py-2.5 px-5 text-zinc-300">{stack}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* MODULE 3: PORT SCANNER */}
          {activeModule === "ports" && (
            <div className="bg-zinc-950 border border-zinc-900 rounded-lg overflow-hidden">
              <div className="px-5 py-4 border-b border-zinc-900 flex flex-wrap items-center justify-between gap-3">
                <div>
                  <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                    <Server className="w-4 h-4 text-cyan-400" />
                    Nmap Service & Version Enumeration ({activeScope})
                  </h3>
                  <p className="text-[11px] font-mono text-zinc-500 mt-0.5">
                    Command profile: nmap -sV -sC -O --version-intensity 5 {activeScope}
                  </p>
                </div>
                <button
                  onClick={() => triggerPipeline()}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-cyan-500 hover:bg-cyan-400 text-black font-semibold text-xs cursor-pointer"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  <span>Rescan Ports</span>
                </button>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead>
                    <tr className="border-b border-zinc-900 text-[10px] uppercase text-zinc-500 bg-black/50">
                      <th className="py-3 px-5">Port / Proto</th>
                      <th className="py-3 px-4">State</th>
                      <th className="py-3 px-4">Service</th>
                      <th className="py-3 px-4">Product & Version</th>
                      <th className="py-3 px-4">CPE 2.3 Identifier</th>
                      <th className="py-3 px-5 text-right">NSE / Banner</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-900">
                    {ports.map((p) => {
                      const isOpen = expandedPort === p.port;
                      return (
                        <React.Fragment key={p.port}>
                          <tr className="hover:bg-zinc-900/40">
                            <td className="py-3 px-5 text-cyan-400 font-semibold">{p.port}</td>
                            <td className="py-3 px-4">
                              <span
                                className={`px-2 py-0.5 rounded text-[10px] ${
                                  p.state === "open"
                                    ? "bg-emerald-950 text-emerald-400 border border-emerald-800/60"
                                    : "bg-amber-950 text-amber-400 border border-amber-800/60"
                                }`}
                              >
                                {p.state}
                              </span>
                            </td>
                            <td className="py-3 px-4 text-zinc-200">{p.service}</td>
                            <td className="py-3 px-4 text-zinc-300 font-sans">{p.version}</td>
                            <td className="py-3 px-4 text-zinc-500 text-[11px]">{p.cpe}</td>
                            <td className="py-3 px-5 text-right">
                              <button
                                onClick={() => setExpandedPort(isOpen ? null : p.port)}
                                className="inline-flex items-center gap-1 text-cyan-400 hover:text-cyan-300 cursor-pointer"
                              >
                                <span>{isOpen ? "Hide" : "Inspect"}</span>
                                {isOpen ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                              </button>
                            </td>
                          </tr>
                          {isOpen && (
                            <tr className="bg-black">
                              <td colSpan="6" className="p-4">
                                <div className="text-[10px] text-zinc-500 mb-1.5">
                                  RAW SERVICE BANNER & NSE SCRIPT OUTPUT:
                                </div>
                                <pre className="p-3 rounded bg-zinc-950 border border-zinc-900 text-cyan-300 text-xs overflow-x-auto">
                                  {p.banner}
                                </pre>
                              </td>
                            </tr>
                          )}
                        </React.Fragment>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* MODULE 4: WEB SCANNER */}
          {activeModule === "web" && (
            <div className="space-y-5">
              <div className="bg-zinc-950 border border-zinc-900 rounded-lg p-5 space-y-4">
                <div className="flex justify-between items-center">
                  <div>
                    <h3 className="text-sm font-semibold text-white">
                      WhatWeb Technology Stack Fingerprinting
                    </h3>
                    <p className="text-[11px] text-zinc-500">
                      Detected frameworks, runtimes, and reverse proxy components on https://{activeScope}
                    </p>
                  </div>
                  <span className="text-xs font-mono text-cyan-400">6 Technologies Identified</span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                  {[
                    ["Nginx", "Web Server", "v1.22.1"],
                    ["FastAPI", "Web Framework", "v0.109.2"],
                    ["Python", "Runtime", "v3.11.6"],
                    ["OpenSSL", "TLS Library", "v3.0.2"],
                    ["Swagger UI", "API Docs", "v5.9.0"],
                    ["PostgreSQL", "Database (Inferred)", "v15.4"],
                  ].map(([name, role, ver]) => (
                    <div
                      key={name}
                      className="bg-black border border-zinc-900 rounded-md p-3.5 flex items-center justify-between"
                    >
                      <div>
                        <div className="text-xs font-semibold text-white">{name}</div>
                        <div className="text-[11px] text-zinc-500">{role}</div>
                      </div>
                      <span className="px-2 py-0.5 rounded bg-cyan-950/70 text-cyan-400 border border-cyan-800/60 font-mono text-[11px]">
                        {ver}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="bg-zinc-950 border border-zinc-900 rounded-lg p-5 space-y-3">
                <div className="flex justify-between items-center">
                  <div>
                    <h3 className="text-sm font-semibold text-white">
                      HTTP Response Security Headers Audit
                    </h3>
                    <p className="text-[11px] text-zinc-500">
                      OWASP Secure Headers Project baseline verification
                    </p>
                  </div>
                  <div className="text-[11px] font-mono space-x-2">
                    <span className="text-emerald-400">2 PASS</span>
                    <span className="text-zinc-700">|</span>
                    <span className="text-amber-400">1 WARN</span>
                    <span className="text-zinc-700">|</span>
                    <span className="text-red-400">3 FAIL</span>
                  </div>
                </div>

                <div className="space-y-2.5">
                  {[
                    { name: "Strict-Transport-Security", status: "PASS", desc: "Enforces HTTPS connections for 1 year across subdomains.", val: "max-age=31536000; includeSubDomains" },
                    { name: "Content-Security-Policy", status: "FAIL", desc: "Define a strict default-src 'self' policy to mitigate XSS and data injection.", val: "Missing Header" },
                    { name: "X-Frame-Options", status: "WARN", desc: "Consider replacing or pairing with CSP frame-ancestors directive.", val: "SAMEORIGIN" },
                    { name: "X-Content-Type-Options", status: "PASS", desc: "Prevents MIME-sniffing attacks on uploaded or dynamic assets.", val: "nosniff" },
                    { name: "Referrer-Policy", status: "FAIL", desc: "Set to strict-origin-when-cross-origin to avoid leaking URL tokens.", val: "Missing Header" },
                    { name: "Permissions-Policy", status: "FAIL", desc: "Restrict unused browser APIs (geolocation=(), camera=(), microphone=()).", val: "Missing Header" },
                  ].map((h) => (
                    <div
                      key={h.name}
                      className="bg-black border border-zinc-900 rounded-md p-3.5 flex flex-wrap items-center justify-between gap-3"
                    >
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-mono font-semibold text-white">{h.name}</span>
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] font-mono ${
                              h.status === "PASS"
                                ? "bg-emerald-950 text-emerald-400 border border-emerald-800/60"
                                : h.status === "WARN"
                                ? "bg-amber-950 text-amber-400 border border-amber-800/60"
                                : "bg-red-950 text-red-400 border border-red-800/60"
                            }`}
                          >
                            {h.status}
                          </span>
                        </div>
                        <p className="text-[11px] text-zinc-500 mt-1">{h.desc}</p>
                      </div>
                      <span className="px-2.5 py-1 rounded bg-zinc-950 border border-zinc-800 font-mono text-[11px] text-zinc-300">
                        {h.val}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* MODULE 5: VULNERABILITY SCANNER */}
          {activeModule === "vulns" && (
            <div className="space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex flex-wrap items-center gap-1.5">
                  {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((lvl) => (
                    <button
                      key={lvl}
                      onClick={() => setSevFilter(lvl)}
                      className={`px-3 py-1.5 rounded-md text-xs font-mono cursor-pointer ${
                        sevFilter === lvl
                          ? "bg-cyan-500 text-black font-semibold"
                          : "bg-zinc-950 text-zinc-400 border border-zinc-900 hover:text-white"
                      }`}
                    >
                      {lvl}
                    </button>
                  ))}
                </div>

                <div className="relative w-full sm:w-72">
                  <Search className="w-3.5 h-3.5 text-zinc-500 absolute left-3 top-2.5" />
                  <input
                    type="text"
                    value={vulnSearch}
                    onChange={(e) => setVulnSearch(e.target.value)}
                    placeholder="Filter CVE, title, or endpoint..."
                    className="w-full bg-zinc-950 border border-zinc-900 focus:border-cyan-500 rounded-md pl-8 pr-3 py-1.5 text-xs text-zinc-200 outline-none"
                  />
                </div>
              </div>

              <div className="space-y-3">
                {filteredVulns.map((v) => {
                  const badgeStyle =
                    v.severity === "CRITICAL"
                      ? "bg-red-950 text-red-400 border-red-800/70"
                      : v.severity === "HIGH"
                      ? "bg-orange-950 text-orange-400 border-orange-800/70"
                      : v.severity === "MEDIUM"
                      ? "bg-amber-950 text-amber-400 border-amber-800/70"
                      : "bg-emerald-950 text-emerald-400 border-emerald-800/70";

                  return (
                    <div
                      key={v.id}
                      className="bg-zinc-950 border border-zinc-900 rounded-lg p-4 space-y-2.5"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
                          <span className={`px-2 py-0.5 rounded border text-[10px] font-semibold ${badgeStyle}`}>
                            {v.severity} ({v.cvss})
                          </span>
                          <span className="text-cyan-400 font-semibold">{v.id}</span>
                          <span className="text-zinc-500">• {v.endpoint}</span>
                        </div>
                        <button
                          onClick={() => setSelectedVuln(v)}
                          className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-black hover:bg-zinc-900 border border-zinc-800 text-cyan-400 text-xs cursor-pointer"
                        >
                          <span>Remediation</span>
                          <ChevronRight className="w-3.5 h-3.5" />
                        </button>
                      </div>

                      <h4 className="text-sm font-semibold text-white">{v.title}</h4>
                      <p className="text-xs text-zinc-400 leading-relaxed">{v.description}</p>

                      <div className="pt-2 border-t border-zinc-900 flex flex-wrap justify-between text-[11px] font-mono text-zinc-500">
                        <span>{v.vector}</span>
                        <span>{v.template}</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* MODULE 6: DIRECTORY SCANNER */}
          {activeModule === "dirs" && (
            <div className="bg-zinc-950 border border-zinc-900 rounded-lg overflow-hidden">
              <div className="px-5 py-4 border-b border-zinc-900 flex flex-wrap items-center justify-between gap-2">
                <div>
                  <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                    <FolderSearch className="w-4 h-4 text-cyan-400" />
                    Content Discovery & Exposed Endpoint Enumeration
                  </h3>
                  <p className="text-[11px] text-zinc-500">
                    Wordlist: raft-medium-directories-api.txt • Rate-limited to 15 req/sec
                  </p>
                </div>
                <span className="px-2.5 py-1 rounded bg-red-950/80 text-red-400 border border-red-800/60 text-xs font-mono">
                  2 Sensitive Artifacts Exposed
                </span>
              </div>

              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-zinc-900 text-[10px] uppercase text-zinc-500 bg-black/50">
                    <th className="py-3 px-5">Discovered Path</th>
                    <th className="py-3 px-4">HTTP Status</th>
                    <th className="py-3 px-4">Content Size</th>
                    <th className="py-3 px-4">Latency</th>
                    <th className="py-3 px-4">Risk Level</th>
                    <th className="py-3 px-5">Assessment Note</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-900">
                  {[
                    ["/.env.backup", "200", "1.4 KB", "14ms", "CRITICAL", "Exposed environment variables"],
                    ["/api/v1/swagger.json", "200", "48.2 KB", "29ms", "HIGH", "Full internal API specification"],
                    ["/api/v1/health", "200", "312 B", "8ms", "INFO", "Returns DB & Redis uptime metadata"],
                    ["/admin/", "302", "0 B", "11ms", "MEDIUM", "Redirects to /admin/login (IP unrestricted)"],
                    ["/server-status", "403", "548 B", "6ms", "LOW", "Endpoint exists but access denied"],
                    ["/metrics", "401", "128 B", "9ms", "LOW", "Prometheus exporter (Basic Auth)"],
                    ["/.git/HEAD", "404", "153 B", "5ms", "SAFE", "Not exposed"],
                  ].map(([path, code, size, lat, risk, note]) => (
                    <tr key={path}>
                      <td className="py-3 px-5 text-cyan-400">{path}</td>
                      <td className="py-3 px-4">
                        <span className="px-1.5 py-0.5 rounded bg-zinc-900 border border-zinc-800 text-emerald-400 text-[10px]">
                          {code}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-zinc-300">{size}</td>
                      <td className="py-3 px-4 text-zinc-400">{lat}</td>
                      <td className="py-3 px-4">
                        <span className="px-2 py-0.5 rounded bg-zinc-900 border border-zinc-800 text-[10px] text-amber-400">
                          {risk}
                        </span>
                      </td>
                      <td className="py-3 px-5 font-sans text-zinc-300">{note}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* MODULE 7: SSL ANALYZER */}
          {activeModule === "ssl" && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="bg-zinc-950 border border-zinc-900 rounded-lg p-5 space-y-3 text-xs">
                  <div className="flex justify-between items-center border-b border-zinc-900 pb-2.5">
                    <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                      <Lock className="w-4 h-4 text-cyan-400" />
                      X.509 Leaf Certificate Details
                    </h3>
                    <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800/60 font-mono text-[10px]">
                      VALID (59d left)
                    </span>
                  </div>
                  <div>
                    <div className="text-[10px] text-zinc-500">SUBJECT DN</div>
                    <div className="font-mono text-zinc-200 mt-0.5">
                      CN=*.corp.local, O=VulnScan Security Lab, L=Hyderabad, C=IN
                    </div>
                  </div>
                  <div>
                    <div className="text-[10px] text-zinc-500">ISSUER CA</div>
                    <div className="font-mono text-zinc-200 mt-0.5">
                      CN=VulnScan Internal Root CA G2, O=VulnScan Security Lab
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-3 pt-1">
                    <div>
                      <div className="text-[10px] text-zinc-500">PUBLIC KEY</div>
                      <div className="font-mono text-cyan-400 mt-0.5">RSA 2048-bit (SHA256withRSA)</div>
                    </div>
                    <div>
                      <div className="text-[10px] text-zinc-500">OCSP STAPLING</div>
                      <div className="font-mono text-emerald-400 mt-0.5">Enabled & Valid</div>
                    </div>
                  </div>
                  <div>
                    <div className="text-[10px] text-zinc-500 mb-1">SUBJECT ALTERNATIVE NAMES (SANs)</div>
                    <div className="flex flex-wrap gap-1.5 font-mono text-[11px]">
                      {["*.corp.local", "corp.local", "staging-api.corp.local", "10.24.18.42"].map((san) => (
                        <span key={san} className="px-2 py-0.5 rounded bg-black border border-zinc-800 text-zinc-300">
                          {san}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>

                <div className="bg-zinc-950 border border-zinc-900 rounded-lg p-5 space-y-2.5 text-xs">
                  <div>
                    <h3 className="text-sm font-semibold text-white">TLS Protocol Support Matrix (SSLyze)</h3>
                    <p className="text-[11px] text-zinc-500">Handshake negotiation test results on {activeScope}:443</p>
                  </div>
                  {[
                    ["SSL 3.0", "Disabled", "DISABLED", "text-zinc-500"],
                    ["TLS 1.0", "Deprecated - Disable immediately", "ENABLED", "text-amber-400"],
                    ["TLS 1.1", "Deprecated - Disable immediately", "ENABLED", "text-amber-400"],
                    ["TLS 1.2", "Supported (ECDHE ciphers)", "ENABLED", "text-emerald-400"],
                    ["TLS 1.3", "Preferred (TLS_AES_256_GCM_SHA384)", "ENABLED", "text-emerald-400"],
                  ].map(([proto, note, state, color]) => (
                    <div key={proto} className="bg-black border border-zinc-900 rounded px-3.5 py-2.5 flex justify-between items-center">
                      <div>
                        <span className="font-mono font-semibold text-white mr-3">{proto}</span>
                        <span className="text-zinc-400">{note}</span>
                      </div>
                      <span className={`font-mono text-[10px] px-2 py-0.5 rounded bg-zinc-950 border border-zinc-800 ${color}`}>
                        {state}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="bg-zinc-950 border border-zinc-900 rounded-lg overflow-hidden">
                <div className="px-5 py-3 border-b border-zinc-900">
                  <h4 className="text-xs font-semibold text-white">Negotiated Cipher Suites</h4>
                </div>
                <table className="w-full text-left text-xs font-mono">
                  <thead>
                    <tr className="border-b border-zinc-900 text-[10px] text-zinc-500 bg-black/50">
                      <th className="py-2.5 px-5">Cipher Suite</th>
                      <th className="py-2.5 px-4">Protocol</th>
                      <th className="py-2.5 px-4">Key Size</th>
                      <th className="py-2.5 px-4">Forward Secrecy</th>
                      <th className="py-2.5 px-5">Strength</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-900">
                    {[
                      ["TLS_AES_256_GCM_SHA384", "TLS 1.3", "256 bits", "Yes (ECDHE)", "STRONG", "text-emerald-400"],
                      ["TLS_CHACHA20_POLY1305_SHA256", "TLS 1.3", "256 bits", "Yes (ECDHE)", "STRONG", "text-emerald-400"],
                      ["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLS 1.2", "256 bits", "Yes (ECDHE)", "STRONG", "text-emerald-400"],
                      ["TLS_RSA_WITH_AES_128_CBC_SHA", "TLS 1.0", "128 bits", "No (Static RSA)", "WEAK", "text-red-400"],
                    ].map(([suite, proto, bits, fs, str, color]) => (
                      <tr key={suite}>
                        <td className="py-2.5 px-5 text-zinc-200">{suite}</td>
                        <td className="py-2.5 px-4 text-zinc-400">{proto}</td>
                        <td className="py-2.5 px-4 text-zinc-300">{bits}</td>
                        <td className={`py-2.5 px-4 ${fs.startsWith("Yes") ? "text-emerald-400" : "text-red-400"}`}>{fs}</td>
                        <td className={`py-2.5 px-5 ${color}`}>{str}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* MODULE 8: SECURITY TESTING (SAFE MODE) */}
          {activeModule === "testing" && (
            <div className="space-y-4">
              <div className="bg-emerald-950/20 border border-emerald-800/50 rounded-lg p-4 flex items-start gap-3 text-xs">
                <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
                <div>
                  <div className="font-semibold text-emerald-400 uppercase tracking-wide">
                    Safe / Non-Destructive Heuristic Verification Mode Active
                  </div>
                  <p className="text-zinc-300 mt-1">
                    This module performs passive response-pattern auditing and benign alphanumeric canary reflection checks. Destructive payloads, state-mutating requests, brute-force routines, and out-of-scope targets are strictly disabled at the worker middleware layer.
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="bg-zinc-950 border border-zinc-900 rounded-lg p-5 space-y-3">
                  <h3 className="text-sm font-semibold text-white">Passive Audit Policies</h3>
                  {[
                    ["sql", "SQL Error-Pattern Passive Inspection", "Detects unmasked database driver stack traces in HTTP 500 responses."],
                    ["xss", "Benign Alphanumeric Reflection Check", "Sends harmless token (vulnscan7749canary) to verify output encoding."],
                    ["csrf", "Anti-CSRF Token & Cookie Flag Audit", "Verifies SameSite attributes and CSRF headers on session forms."],
                    ["cors", "CORS Origin Reflection Policy Check", "Tests whether arbitrary Origin headers are echoed with credentials."],
                  ].map(([key, title, desc]) => (
                    <label
                      key={key}
                      className="flex items-start gap-3 p-3 rounded bg-black border border-zinc-900 cursor-pointer"
                    >
                      <input
                        type="checkbox"
                        checked={policies[key]}
                        onChange={(e) => setPolicies({ ...policies, [key]: e.target.checked })}
                        className="mt-1 rounded border-zinc-700 bg-black text-cyan-500"
                      />
                      <div>
                        <div className="text-xs font-semibold text-white">{title}</div>
                        <div className="text-[11px] text-zinc-500 mt-0.5">{desc}</div>
                      </div>
                    </label>
                  ))}

                  <div className="pt-2 space-y-1.5">
                    <div className="flex justify-between text-xs font-mono">
                      <span className="text-zinc-400">WORKER RATE LIMIT CAP</span>
                      <span className="text-cyan-400">{rateCap} req / sec</span>
                    </div>
                    <input
                      type="range"
                      min="1"
                      max="15"
                      value={rateCap}
                      onChange={(e) => setRateCap(Number(e.target.value))}
                      className="w-full accent-cyan-500"
                    />
                  </div>

                  <button
                    onClick={() => triggerPipeline()}
                    className="w-full py-2.5 rounded-md bg-cyan-500 hover:bg-cyan-400 text-black font-semibold text-xs flex items-center justify-center gap-2 cursor-pointer"
                  >
                    <RefreshCw className="w-3.5 h-3.5" />
                    <span>Run Safe Audit on {activeScope}</span>
                  </button>
                </div>

                <div className="bg-zinc-950 border border-zinc-900 rounded-lg p-5 space-y-3">
                  <h3 className="text-sm font-semibold text-white">Heuristic Verification Findings</h3>
                  {[
                    { title: "SQL Error-Pattern Passive Detection", ep: "/api/v1/users?sort=created_at", res: "PASS (No verbose SQL stack traces)", badge: "SAFE", color: "text-emerald-400" },
                    { title: "Benign Alphanumeric XSS Canary Reflection", ep: "/api/v1/search?q=vulnscan7749canary", res: "WARN (Reflected unencoded in JSON text/html fallback)", badge: "MEDIUM", color: "text-amber-400" },
                    { title: "Anti-CSRF Token & SameSite Cookie Audit", ep: "/admin/login", res: "PASS (SameSite=Lax + X-CSRF-Token enforced)", badge: "SAFE", color: "text-emerald-400" },
                    { title: "CORS Wildcard Origin Reflection Probe", ep: "/api/v1/profile", res: "PASS (Strict allowlist: https://portal.corp.local)", badge: "SAFE", color: "text-emerald-400" },
                  ].map((item) => (
                    <div key={item.title} className="p-3.5 rounded bg-black border border-zinc-900 space-y-1">
                      <div className="flex justify-between items-center">
                        <span className="text-xs font-semibold text-white">{item.title}</span>
                        <span className={`text-[10px] font-mono px-2 py-0.5 rounded bg-zinc-950 border border-zinc-800 ${item.color}`}>
                          {item.badge}
                        </span>
                      </div>
                      <div className="text-[11px] font-mono text-cyan-400">{item.ep}</div>
                      <div className="text-[11px] text-zinc-400">{item.res}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* MODULE 9: REPORTS (A4 PRINTABLE BUILDER) */}
          {activeModule === "reports" && (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
              {/* Left Controls */}
              <div className="lg:col-span-4 bg-zinc-950 border border-zinc-900 rounded-lg p-5 space-y-4 h-fit no-print">
                <div className="flex items-center gap-2 text-sm font-semibold text-white">
                  <FileText className="w-4 h-4 text-cyan-400" />
                  <span>Assessment Report Builder</span>
                </div>

                <div>
                  <label className="block text-[10px] font-mono uppercase text-zinc-500 mb-1.5">
                    Select Assessment Run
                  </label>
                  <select
                    value={selectedReportId}
                    onChange={(e) => setSelectedReportId(e.target.value)}
                    className="w-full bg-black border border-zinc-800 rounded-md px-3 py-2 text-xs font-mono text-white outline-none"
                  >
                    {history.map((h) => (
                      <option key={h.id} value={h.id}>
                        {h.id} — {h.target} ({h.score}/100)
                      </option>
                    ))}
                  </select>
                </div>

                <div className="space-y-2">
                  <div className="text-[10px] font-mono uppercase text-zinc-500">Report Sections</div>
                  {[
                    ["exec", "1. Executive Summary & Risk Score"],
                    ["matrix", "2. CVSS Severity Distribution Matrix"],
                    ["findings", "3. Detailed Vulnerability Findings"],
                    ["roadmap", "4. Prioritized Remediation Roadmap"],
                  ].map(([k, label]) => (
                    <label
                      key={k}
                      className="flex items-center gap-2.5 p-2.5 rounded bg-black border border-zinc-900 text-xs text-zinc-200 cursor-pointer"
                    >
                      <input
                        type="checkbox"
                        checked={reportSections[k]}
                        onChange={(e) => setReportSections({ ...reportSections, [k]: e.target.checked })}
                        className="rounded border-zinc-700 bg-black text-cyan-500"
                      />
                      <span>{label}</span>
                    </label>
                  ))}
                </div>

                <div className="space-y-2 pt-2">
                  <button
                    onClick={() => window.print()}
                    className="w-full py-2.5 rounded-md bg-cyan-500 hover:bg-cyan-400 text-black font-semibold text-xs flex items-center justify-center gap-2 cursor-pointer"
                  >
                    <Printer className="w-4 h-4" />
                    <span>Export / Print PDF Report</span>
                  </button>
                  <button
                    onClick={downloadJsonReport}
                    className="w-full py-2.5 rounded-md bg-black hover:bg-zinc-900 border border-zinc-800 text-zinc-200 font-medium text-xs flex items-center justify-center gap-2 cursor-pointer"
                  >
                    <Download className="w-4 h-4 text-cyan-400" />
                    <span>Download Raw JSON Telemetry</span>
                  </button>
                </div>
              </div>

              {/* Right A4 Printable Sheet */}
              <div className="lg:col-span-8 bg-white text-zinc-900 rounded-lg p-8 shadow-2xl space-y-6 print-sheet">
                <div className="flex flex-wrap justify-between items-start gap-4 border-b border-zinc-200 pb-5">
                  <div>
                    <div className="text-[10px] font-mono uppercase tracking-widest text-cyan-700 font-semibold">
                      CONFIDENTIAL — INTERNAL SECURITY ASSESSMENT
                    </div>
                    <h2 className="text-2xl font-bold text-zinc-950 mt-1">
                      Vulnerability Assessment & Posture Report
                    </h2>
                    <p className="text-xs text-zinc-500 mt-1">
                      Generated by VulnScan Security Assessment Platform • {activeReport.timestamp}
                    </p>
                  </div>
                  <div className="text-right font-mono text-xs bg-zinc-50 border border-zinc-200 rounded px-3 py-2">
                    <div className="font-bold text-zinc-900">{activeReport.id}</div>
                    <div className="text-zinc-600">Target: {activeReport.target}</div>
                    <div className="text-zinc-500">Host: {activeReport.hostname}</div>
                  </div>
                </div>

                {reportSections.exec && (
                  <div className="space-y-2">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-zinc-800">
                      1. Executive Summary
                    </h3>
                    <p className="text-xs text-zinc-700 leading-relaxed">
                      An authorized, scope-locked vulnerability assessment was conducted against{" "}
                      <strong>{activeReport.target}</strong> ({activeReport.hostname}). The target achieved an overall Security Posture Score of{" "}
                      <strong>{activeReport.score}/100</strong>. Key risk drivers include an exposed internal debug listener on port 8080, a publicly readable{" "}
                      <code className="bg-zinc-100 px-1 rounded">.env.backup</code> configuration file, and legacy TLS 1.0/1.1 protocol support.
                    </p>
                  </div>
                )}

                {reportSections.matrix && (
                  <div className="space-y-2">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-zinc-800">
                      2. Severity Breakdown
                    </h3>
                    <div className="grid grid-cols-4 gap-3 text-center">
                      <div className="p-3 rounded border border-red-200 bg-red-50">
                        <div className="text-lg font-bold text-red-700 font-mono">{activeReport.counts.c}</div>
                        <div className="text-[10px] font-semibold text-red-600">CRITICAL</div>
                      </div>
                      <div className="p-3 rounded border border-orange-200 bg-orange-50">
                        <div className="text-lg font-bold text-orange-700 font-mono">{activeReport.counts.h}</div>
                        <div className="text-[10px] font-semibold text-orange-600">HIGH</div>
                      </div>
                      <div className="p-3 rounded border border-amber-200 bg-amber-50">
                        <div className="text-lg font-bold text-amber-700 font-mono">{activeReport.counts.m}</div>
                        <div className="text-[10px] font-semibold text-amber-600">MEDIUM</div>
                      </div>
                      <div className="p-3 rounded border border-emerald-200 bg-emerald-50">
                        <div className="text-lg font-bold text-emerald-700 font-mono">{activeReport.counts.l}</div>
                        <div className="text-[10px] font-semibold text-emerald-600">LOW</div>
                      </div>
                    </div>
                  </div>
                )}

                {reportSections.findings && (
                  <div className="space-y-2.5">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-zinc-800">
                      3. Technical Vulnerability Findings
                    </h3>
                    {INITIAL_VULNS.slice(0, 5).map((v) => (
                      <div key={v.id} className="p-3 rounded border border-zinc-200 bg-zinc-50/60 text-xs space-y-1">
                        <div className="flex justify-between font-mono text-[11px]">
                          <span className="font-bold text-zinc-900">
                            [{v.severity}] {v.id} — CVSS {v.cvss}
                          </span>
                          <span className="text-zinc-500">{v.endpoint}</span>
                        </div>
                        <div className="font-semibold text-zinc-900">{v.title}</div>
                        <p className="text-zinc-600 text-[11px]">{v.description}</p>
                        <div className="text-[11px] text-zinc-800 pt-1">
                          <strong>Remediation:</strong> {v.remediation}
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                {reportSections.roadmap && (
                  <div className="space-y-1.5">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-zinc-800">
                      4. Prioritized Remediation Roadmap
                    </h3>
                    <ul className="list-disc pl-5 text-xs text-zinc-700 space-y-1">
                      <li><strong>Immediate (0–24 Hours):</strong> Remove <code>/.env.backup</code>, rotate exposed credentials, and bind Uvicorn port 8080 to localhost.</li>
                      <li><strong>Short-Term (1–7 Days):</strong> Disable TLS 1.0/1.1 in Nginx, upgrade Nginx to &gt;= 1.25.3, and enforce Content-Security-Policy headers.</li>
                      <li><strong>Hardening (7–30 Days):</strong> Restrict Redis listener interface to 127.0.0.1 and suppress HTTP version banners.</li>
                    </ul>
                  </div>
                )}
              </div>
            </div>
          )}
        </main>
      </div>

      {/* Vulnerability Remediation Drawer/Modal */}
      {selectedVuln && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-zinc-950 border border-zinc-800 rounded-lg max-w-xl w-full p-6 space-y-4">
            <div className="flex items-start justify-between gap-3">
              <div>
                <span className="text-xs font-mono text-cyan-400">
                  {selectedVuln.id} • CVSS {selectedVuln.cvss}
                </span>
                <h3 className="text-base font-bold text-white mt-0.5">{selectedVuln.title}</h3>
              </div>
              <button
                onClick={() => setSelectedVuln(null)}
                className="p-1 text-zinc-400 hover:text-white cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <p className="text-xs text-zinc-300 leading-relaxed">{selectedVuln.description}</p>
            <div className="p-3.5 rounded bg-black border border-emerald-900/50 text-xs space-y-1">
              <div className="font-semibold text-emerald-400">Recommended Remediation</div>
              <p className="text-zinc-300 leading-relaxed">{selectedVuln.remediation}</p>
            </div>
            <div className="text-[11px] font-mono text-zinc-500">{selectedVuln.vector}</div>
          </div>
        </div>
      )}

      {/* Architecture & Backend Blueprint Modal */}
      {showBlueprint && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-zinc-950 border border-zinc-800 rounded-lg max-w-2xl w-full p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-zinc-900 pb-3">
              <div className="flex items-center gap-2">
                <Code2 className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-bold text-white">
                  VulnScan Full-Stack Architecture & Scope Guardrail Blueprint
                </h3>
              </div>
              <button
                onClick={() => setShowBlueprint(false)}
                className="p-1 text-zinc-400 hover:text-white cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
              <div className="p-3 rounded bg-black border border-zinc-900">
                <div className="font-semibold text-cyan-400 mb-1">Frontend Layer</div>
                <p className="text-zinc-400">React 19 + Vite + Tailwind CSS v4 + Lucide Icons with A4 print CSS report export.</p>
              </div>
              <div className="p-3 rounded bg-black border border-zinc-900">
                <div className="font-semibold text-cyan-400 mb-1">Backend & Workers</div>
                <p className="text-zinc-400">Python FastAPI + SQLAlchemy (SQLite/PostgreSQL) + async subprocess wrappers for Nmap, Nuclei, SSLyze & ZAP.</p>
              </div>
            </div>

            <pre className="p-3.5 rounded bg-black border border-zinc-900 text-[11px] font-mono text-emerald-400 overflow-x-auto">
{`# backend/app/core/validator.py — Authorized Scope Guardrail
ALLOWED_RANGES = [ipaddress.ip_network("10.0.0.0/8"),
                  ipaddress.ip_network("172.16.0.0/12"),
                  ipaddress.ip_network("192.168.0.0/16")]`}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}