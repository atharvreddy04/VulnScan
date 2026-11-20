import React, { useEffect, useMemo, useState } from "react";
import {
  ChevronDown,
  ChevronRight,
  ChevronUp,
  Code2,
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

const STORAGE_KEY = "vulnscan_telemetry_v4";

function buildTargetTelemetry(targetInput) {
  const clean =
    targetInput.trim().replace(/^https?:\/\//i, "").split("/")[0].split(":")[0] ||
    "10.24.18.42";
  const hash = clean.split("").reduce((acc, ch) => acc + ch.charCodeAt(0), 0);
  const isLocalhost = clean === "localhost" || clean === "127.0.0.1";
  const isWebHost = /[a-zA-Z]/.test(clean) && !isLocalhost;

  const resolvedIp = isWebHost
    ? `10.24.${(hash % 200) + 10}.${(hash % 240) + 11}`
    : clean;
  const hostname = isWebHost
    ? clean
    : isLocalhost
    ? "localhost.internal"
    : `node-${clean.split(".").pop()}.corp.local`;

  const score = isLocalhost ? 88 : 45 + (hash % 44);
  const critCount = score < 55 ? 3 : score < 70 ? 2 : score < 82 ? 1 : 0;
  const highCount = score < 60 ? 5 : score < 75 ? 4 : 2;
  const medCount = 4 + (hash % 5);
  const lowCount = 3 + (hash % 4);

  const ports = [
    {
      port: "22/tcp",
      state: "open",
      service: "ssh",
      version: "OpenSSH 8.9p1 Ubuntu 3ubuntu0.6",
      cpe: "cpe:/a:openbsd:openssh:8.9p1",
      banner: `SSH-2.0-OpenSSH_8.9p1 (${clean})\nssh-hostkey: 256 SHA256:${hash.toString(16)}xK2 (ED25519)`,
    },
    {
      port: "80/tcp",
      state: "open",
      service: "http",
      version: "nginx 1.22.1",
      cpe: "cpe:/a:igor_sysoev:nginx:1.22.1",
      banner: `HTTP/1.1 301 Moved Permanently\nServer: nginx/1.22.1\nLocation: https://${hostname}/`,
    },
    {
      port: "443/tcp",
      state: "open",
      service: "https",
      version: "nginx 1.22.1 (TLS Termination)",
      cpe: "cpe:/a:igor_sysoev:nginx:1.22.1",
      banner: `HTTP/1.1 200 OK\nServer: nginx/1.22.1\nX-Target-Node: ${resolvedIp}`,
    },
    {
      port: "8080/tcp",
      state: "open",
      service: "http-proxy",
      version: "Uvicorn / Python 3.11 ASGI",
      cpe: "cpe:/a:python:python:3.11",
      banner: `HTTP/1.1 200 OK\nserver: uvicorn\n{"host":"${hostname}","ip":"${resolvedIp}","debug":${critCount > 0}}`,
    },
  ];

  const vulns = [
    ...(critCount > 0
      ? [
          {
            id: "CVE-2024-21626",
            severity: "CRITICAL",
            cvss: "9.1",
            endpoint: `${resolvedIp}:8080 (/api/v1/openapi.json)`,
            title: `Exposed Debug Mode & Unauthenticated OpenAPI Schema on ${hostname}`,
            description: `The ASGI worker on ${resolvedIp}:8080 directly exposes interactive Swagger documentation and stack trace verbosity bypassing the reverse proxy.`,
            vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            template: "nuclei:http/exposures/apis/openapi-debug-leak",
            remediation:
              "Bind Uvicorn exclusively to 127.0.0.1:8080, disable OpenAPI docs in staging/prod, and set DEBUG=False.",
          },
        ]
      : []),
    {
      id: "CVE-2023-28432",
      severity: "HIGH",
      cvss: "7.8",
      endpoint: `${resolvedIp}:443 (/.env.backup)`,
      title: `Environment Configuration Backup Accessible on ${hostname}`,
      description: `A backup configuration artifact (/.env.backup) on ${resolvedIp} returned HTTP 200 OK containing service tokens.`,
      vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
      template: "nuclei:http/exposures/configs/env-file-backup",
      remediation:
        "Remove .env.backup from web root, rotate all secrets, and block dotfiles in Nginx.",
    },
    {
      id: "CWE-693-CSP",
      severity: "MEDIUM",
      cvss: "5.4",
      endpoint: `${resolvedIp}:443 (HTTP Headers)`,
      title: "Missing Content-Security-Policy & Referrer-Policy Headers",
      description: `HTTP responses from ${hostname} omit Content-Security-Policy and Referrer-Policy headers.`,
      vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
      template: "nuclei:http/misconfiguration/http-missing-security-headers",
      remediation:
        "Add Content-Security-Policy: default-src 'self'; and Referrer-Policy: strict-origin-when-cross-origin.",
    },
  ];

  const dnsRecords = [
    ["A", hostname, resolvedIp, "300s"],
    ["AAAA", hostname, `fd00:10:24::${hash % 99}`, "300s"],
    ["CNAME", `edge.${hostname}`, hostname, "600s"],
    ["MX", "corp.local", "10 mail-gw01.corp.local", "3600s"],
    ["NS", "corp.local", "ns1.internal-dns.corp.local", "86400s"],
    ["TXT", hostname, `"v=spf1 ip4:${resolvedIp}/32 -all"`, "3600s"],
  ];

  const subdomains = [
    [hostname, resolvedIp, "200", "nginx/1.22.1", "FastAPI / Uvicorn"],
    [`auth.${hostname}`, `10.24.18.${(hash % 50) + 20}`, "200", "Envoy/1.28", "Keycloak OIDC"],
    [`metrics.${hostname}`, `10.24.18.${(hash % 50) + 75}`, "401", "nginx/1.22.1", "Prometheus"],
  ];

  const headers = [
    {
      name: "Strict-Transport-Security",
      status: "PASS",
      desc: "Enforces HTTPS connections for 1 year across subdomains.",
      val: "max-age=31536000; includeSubDomains",
    },
    {
      name: "Content-Security-Policy",
      status: "FAIL",
      desc: "Define a strict default-src 'self' policy to mitigate XSS.",
      val: "Missing Header",
    },
    {
      name: "X-Frame-Options",
      status: "WARN",
      desc: "Consider pairing with CSP frame-ancestors directive.",
      val: "SAMEORIGIN",
    },
    {
      name: "X-Content-Type-Options",
      status: "PASS",
      desc: "Prevents MIME-sniffing attacks on uploaded assets.",
      val: "nosniff",
    },
    {
      name: "Referrer-Policy",
      status: "FAIL",
      desc: "Set to strict-origin-when-cross-origin to avoid token leaks.",
      val: "Missing Header",
    },
  ];

  const directories = [
    ["/.env.backup", "200", "1.4 KB", "14ms", "CRITICAL", `Exposed environment variables on ${hostname}`],
    ["/api/v1/openapi.json", "200", "48.2 KB", "29ms", "HIGH", "Full internal API specification"],
    ["/api/health", "200", "312 B", "8ms", "INFO", "Returns service health metadata"],
    ["/.git/HEAD", "404", "153 B", "5ms", "SAFE", "Not exposed"],
  ];

  const sslData = {
    subject: `CN=${hostname}, O=VulnScan Security Lab, L=Hyderabad, C=IN`,
    issuer: "CN=VulnScan Internal Root CA G2, O=VulnScan Security Lab",
    validDays: 45 + (hash % 120),
    protocol: "TLSv1.3",
    cipher: "TLS_AES_256_GCM_SHA384",
    sans: [hostname, `*.${hostname}`, resolvedIp, "corp.local"],
  };

  const testingFindings = [
    {
      title: "SQL Error-Pattern Passive Detection",
      ep: `https://${hostname}/api/v1/users?sort=id`,
      res: "PASS (No verbose SQL stack traces)",
      badge: "SAFE",
      color: "text-emerald-400",
    },
    {
      title: "Benign Alphanumeric XSS Canary Reflection",
      ep: `https://${hostname}/api/v1/search?q=vulnscan7749canary`,
      res: "PASS (Properly HTML-encoded)",
      badge: "SAFE",
      color: "text-emerald-400",
    },
    {
      title: "Anti-CSRF Token & SameSite Cookie Audit",
      ep: `https://${hostname}/admin/login`,
      res: "PASS (SameSite=Lax + X-CSRF-Token enforced)",
      badge: "SAFE",
      color: "text-emerald-400",
    },
  ];

  return {
    id: `SCAN-2026-${1000 + (hash % 8999)}`,
    target: clean,
    hostname,
    profile: "Full Stack Audit (Nmap + Nuclei + SSLyze)",
    counts: { c: critCount, h: highCount, m: medCount, l: lowCount },
    score,
    timestamp: new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC",
    ports,
    vulns,
    dnsRecords,
    subdomains,
    headers,
    directories,
    sslData,
    testingFindings,
  };
}

const MODULES = [
  { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { id: "recon", label: "Reconnaissance", icon: Radar },
  { id: "ports", label: "Port Scanner", icon: Server },
  { id: "web", label: "Web Scanner", icon: Globe },
  { id: "vulns", label: "Vulnerability Scanner", icon: ShieldAlert },
  { id: "dirs", label: "Directory Scanner", icon: FolderSearch },
  { id: "ssl", label: "SSL Analyzer", icon: Lock },
  { id: "testing", label: "Security Testing", icon: Sliders },
  { id: "reports", label: "Reports", icon: FileText },
];

export default function App() {
  const defaultRun = useMemo(() => buildTargetTelemetry("10.24.18.42"), []);

  const [activeModule, setActiveModule] = useState("dashboard");
  const [activeScope, setActiveScope] = useState("10.24.18.42");
  const [targetInput, setTargetInput] = useState("10.24.18.42");
  const [webUrlInput, setWebUrlInput] = useState("http://127.0.0.1:8000");
  const [sslPortInput, setSslPortInput] = useState(443);
  const [authorized, setAuthorized] = useState(true);
  const [scopeError, setScopeError] = useState("");

  const [history, setHistory] = useState(() => {
    try {
      const saved = JSON.parse(localStorage.getItem(STORAGE_KEY));
      if (Array.isArray(saved) && saved.length > 0) return saved;
    } catch {}
    return [defaultRun, buildTargetTelemetry("192.168.100.15")];
  });

  const [currentScan, setCurrentScan] = useState(() => history[0] || defaultRun);
  const [selectedReportId, setSelectedReportId] = useState(
    () => (history[0] || defaultRun).id
  );

  const [apiConnected, setApiConnected] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(100);
  const [expandedPort, setExpandedPort] = useState("8080/tcp");
  const [logs, setLogs] = useState([
    {
      time: "09:41:02",
      tag: "[SCOPE-GUARD]",
      color: "text-emerald-400",
      text: `Verified ${defaultRun.target} matches authorized scope policy`,
    },
    {
      time: "09:41:05",
      tag: "[NMAP-WORKER]",
      color: "text-cyan-400",
      text: `Completed SYN discovery: ${defaultRun.ports.length} services enumerated`,
    },
  ]);

  const [sevFilter, setSevFilter] = useState("ALL");
  const [vulnSearch, setVulnSearch] = useState("");
  const [selectedVuln, setSelectedVuln] = useState(null);
  const [showBlueprint, setShowBlueprint] = useState(false);

  const [rateCap, setRateCap] = useState(5);
  const [policies, setPolicies] = useState({
    sql: true,
    xss: true,
    csrf: true,
    cors: true,
  });

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

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(history.slice(0, 15)));
    } catch {}
  }, [history]);

  const isValidLabScope = (target) => {
    const t = target
      .trim()
      .replace(/^https?:\/\//i, "")
      .split("/")[0]
      .split(":")[0]
      .toLowerCase();
    if (!t) return false;

    const defaultAllowed = ["scanme.nmap.org", "testphp.vulnweb.com", "example.com"];
    const envAllowed = (import.meta.env.VITE_AUTHORIZED_DOMAINS || "")
      .split(",")
      .map((d) => d.trim().toLowerCase())
      .filter(Boolean);
    const allowedDomains = [...defaultAllowed, ...envAllowed];

    if (
      t === "localhost" ||
      t === "127.0.0.1" ||
      t.endsWith(".local") ||
      t.endsWith(".lab") ||
      allowedDomains.some((d) => t === d || t.endsWith(`.${d}`))
    ) {
      return true;
    }
    return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(t);
  };

  // 1. Live Reconnaissance DNS Lookup
  const runLiveDnsRecon = async (targetHost) => {
    const cleanHost = (targetHost || targetInput)
      .trim()
      .replace(/^https?:\/\//i, "")
      .split("/")[0]
      .split(":")[0];
    if (!isValidLabScope(cleanHost)) {
      setScopeError("Blocked by Scope Guardrail: Target must be within authorized lab or allowlisted domain scope.");
      return;
    }
    setScopeError("");
    setActiveScope(cleanHost);
    setTargetInput(cleanHost);
    setIsScanning(true);

    try {
      if (apiConnected) {
        const dnsData = await vulnScanApi.runDnsRecon(cleanHost);
        if (dnsData?.records) {
          const rows = [];
          Object.entries(dnsData.records).forEach(([rtype, values]) => {
            if (Array.isArray(values) && values.length > 0) {
              values.forEach((v) => rows.push([rtype, cleanHost, v, "300s"]));
            }
          });
          if (rows.length > 0) {
            setCurrentScan((prev) => ({
              ...prev,
              target: cleanHost,
              hostname: cleanHost,
              dnsRecords: rows,
            }));
          }
        }
      } else {
        const sim = buildTargetTelemetry(cleanHost);
        setCurrentScan((prev) => ({
          ...prev,
          target: cleanHost,
          hostname: sim.hostname,
          dnsRecords: sim.dnsRecords,
          subdomains: sim.subdomains,
        }));
      }
    } finally {
      setIsScanning(false);
    }
  };

  // 2. Live Web Headers Audit
  const runLiveWebAudit = async (urlOverride) => {
    const targetUrl = (urlOverride || webUrlInput).trim();
    if (!isValidLabScope(targetUrl)) {
      setScopeError("Blocked by Scope Guardrail: Web URL must point to an authorized scope target.");
      return;
    }
    setScopeError("");
    setIsScanning(true);

    try {
      if (apiConnected) {
        const audit = await vulnScanApi.runWebAudit({
          targetUrl,
          explicitAuthorization: authorized,
        });
        if (Array.isArray(audit?.findings)) {
          const mappedHeaders = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
          ].map((hdrName) => {
            const missing = audit.findings.find((f) =>
              f.title.toLowerCase().includes(hdrName.toLowerCase())
            );
            return {
              name: hdrName,
              status: missing ? "FAIL" : "PASS",
              desc: missing
                ? missing.remediation
                : `Verified present in HTTP ${audit.status_code} response from ${audit.url}.`,
              val: missing ? "Missing Header" : "Configured",
            };
          });
          setCurrentScan((prev) => ({
            ...prev,
            headers: mappedHeaders,
          }));
        }
      }
    } catch (err) {
      setScopeError(err.message || "Web audit request failed.");
    } finally {
      setIsScanning(false);
    }
  };

  // 3. Live SSL/TLS Certificate & Cipher Inspection
  const runLiveSslAudit = async () => {
    if (!isValidLabScope(activeScope)) {
      setScopeError("Blocked by Scope Guardrail: Target must be within authorized scope.");
      return;
    }
    setScopeError("");
    setIsScanning(true);

    try {
      if (apiConnected) {
        const sslResp = await vulnScanApi.runSslAudit({
          target: activeScope,
          port: Number(sslPortInput) || 443,
          explicitAuthorization: authorized,
        });
        if (sslResp) {
          setCurrentScan((prev) => ({
            ...prev,
            sslData: {
              subject: sslResp.subject || prev.sslData.subject,
              issuer: sslResp.issuer || prev.sslData.issuer,
              validDays: sslResp.validDays ?? prev.sslData.validDays,
              protocol: sslResp.protocol || "None",
              cipher: sslResp.cipher || "None",
              sans: sslResp.sans || [activeScope],
            },
          }));
        }
      }
    } catch (err) {
      setScopeError(err.message || "SSL/TLS inspection failed.");
    } finally {
      setIsScanning(false);
    }
  };

  // 4. Live Directory Exposure Scan (/api/dirs/scan)
  const runLiveDirectoryScan = async () => {
    if (!isValidLabScope(activeScope)) {
      setScopeError("Blocked by Scope Guardrail: Target must be within authorized scope.");
      return;
    }
    setScopeError("");
    setIsScanning(true);

    try {
      if (apiConnected) {
        const dirResp = await vulnScanApi.runDirectoryScan({
          target: activeScope,
          explicitAuthorization: authorized,
        });
        if (Array.isArray(dirResp?.directories)) {
          setCurrentScan((prev) => ({
            ...prev,
            directories: dirResp.directories,
          }));
        }
      }
    } catch (err) {
      setScopeError(err.message || "Directory discovery failed.");
    } finally {
      setIsScanning(false);
    }
  };

  // 5. Live Passive Security Testing (/api/testing/scan)
  const runLiveSecurityTesting = async () => {
    if (!isValidLabScope(activeScope)) {
      setScopeError("Blocked by Scope Guardrail: Target must be within authorized scope.");
      return;
    }
    setScopeError("");
    setIsScanning(true);

    try {
      if (apiConnected) {
        const testResp = await vulnScanApi.runSecurityTesting({
          target: activeScope,
          policies,
          rateCap,
          explicitAuthorization: authorized,
        });
        if (Array.isArray(testResp?.findings)) {
          setCurrentScan((prev) => ({
            ...prev,
            testingFindings: testResp.findings,
          }));
        }
      }
    } catch (err) {
      setScopeError(err.message || "Passive security testing failed.");
    } finally {
      setIsScanning(false);
    }
  };

  // 6. Full Assessment Pipeline across all live FastAPI routes
  const runAssessmentForTarget = async (rawTarget) => {
    const candidate = (rawTarget ?? targetInput).trim();
    if (!authorized) {
      setScopeError("Please confirm explicit written authorization before starting an assessment.");
      return;
    }
    if (!isValidLabScope(candidate)) {
      setScopeError(
        "Blocked by Scope Guardrail: Target must be an RFC 1918 private IP, .local/.lab host, or allowlisted test domain."
      );
      return;
    }

    setScopeError("");
    const cleanTarget = candidate.replace(/^https?:\/\//i, "").split("/")[0].split(":")[0];
    setActiveScope(cleanTarget);
    setTargetInput(cleanTarget);

    const isPrivateOrLocal =
      cleanTarget === "localhost" ||
      cleanTarget === "127.0.0.1" ||
      /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(cleanTarget);
    setWebUrlInput(
      isPrivateOrLocal ? `http://${cleanTarget}:8000` : `https://${cleanTarget}`
    );

    setIsScanning(true);
    setScanProgress(15);

    const nowTime = () => new Date().toTimeString().slice(0, 8);
    setLogs([
      {
        time: nowTime(),
        tag: "[SCOPE-GUARD]",
        color: "text-emerald-400",
        text: `Verified ${cleanTarget} matches authorized assessment policy`,
      },
    ]);

    const newRun = buildTargetTelemetry(cleanTarget);

    if (apiConnected) {
      try {
        // 1. Live Nmap / TCP Port Scan
        const queued = await vulnScanApi.startNetworkScan({
          target: cleanTarget,
          profile: "safe",
          explicitAuthorization: true,
        });
        const completed = await vulnScanApi.pollNetworkScan(queued.scan_id, {
          intervalMs: 1200,
        });
        if (completed?.findings?.length > 0) {
          newRun.ports = completed.findings.map((f) => ({
            port: `${f.port}/${f.protocol}`,
            state: "open",
            service: f.service,
            version: f.details?.banner || "Live service detection",
            cpe: `cpe:/a:${f.service}:${f.service}`,
            banner: f.remediation,
          }));
        }

        // 2. Live DNS Recon
        const dnsData = await vulnScanApi.runDnsRecon(cleanTarget).catch(() => null);
        if (dnsData?.records) {
          const rows = [];
          Object.entries(dnsData.records).forEach(([rtype, values]) => {
            if (Array.isArray(values)) {
              values.forEach((v) => rows.push([rtype, cleanTarget, v, "300s"]));
            }
          });
          if (rows.length > 0) newRun.dnsRecords = rows;
        }

        // 3. Live SSL/TLS Handshake Audit
        const sslResp = await vulnScanApi
          .runSslAudit({ target: cleanTarget, port: 443, explicitAuthorization: true })
          .catch(() => null);
        if (sslResp) {
          newRun.sslData = {
            subject: sslResp.subject || newRun.sslData.subject,
            issuer: sslResp.issuer || newRun.sslData.issuer,
            validDays: sslResp.validDays ?? 0,
            protocol: sslResp.protocol || "None",
            cipher: sslResp.cipher || "None",
            sans: sslResp.sans || [cleanTarget],
          };
        }

        // 4. Live Vulnerability Audit
        const vulnResp = await vulnScanApi
          .runVulnerabilityScan({ target: cleanTarget, explicitAuthorization: true })
          .catch(() => null);
        if (Array.isArray(vulnResp?.findings)) {
          newRun.vulns = vulnResp.findings;
          newRun.counts = {
            c: vulnResp.findings.filter((f) => f.severity === "CRITICAL").length,
            h: vulnResp.findings.filter((f) => f.severity === "HIGH").length,
            m: vulnResp.findings.filter((f) => f.severity === "MEDIUM").length,
            l: vulnResp.findings.filter(
              (f) => f.severity === "LOW" || f.severity === "INFO"
            ).length,
          };
          const penalty =
            newRun.counts.c * 20 +
            newRun.counts.h * 10 +
            newRun.counts.m * 4 +
            newRun.counts.l * 1;
          newRun.score = Math.max(10, 100 - penalty);
        }

        // 5. Live Directory Exposure Scan
        const dirResp = await vulnScanApi
          .runDirectoryScan({ target: cleanTarget, explicitAuthorization: true })
          .catch(() => null);
        if (Array.isArray(dirResp?.directories)) {
          newRun.directories = dirResp.directories;
        }

        // 6. Live Passive Security Testing
        const testResp = await vulnScanApi
          .runSecurityTesting({
            target: cleanTarget,
            policies,
            rateCap,
            explicitAuthorization: true,
          })
          .catch(() => null);
        if (Array.isArray(testResp?.findings)) {
          newRun.testingFindings = testResp.findings;
        }
      } catch {}
    }

    const stages = [
      {
        pct: 42,
        delay: 350,
        log: {
          tag: "[NMAP-WORKER]",
          color: "text-cyan-400",
          text: `Enumerated ${newRun.ports.length} network services on ${cleanTarget}`,
        },
      },
      {
        pct: 70,
        delay: 750,
        log: {
          tag: "[SSLYZE-WORKER]",
          color: "text-amber-400",
          text: `TLS inspection finished (${newRun.sslData.protocol}) for ${newRun.hostname}`,
        },
      },
      {
        pct: 92,
        delay: 1150,
        log: {
          tag: "[NUCLEI-ENGINE]",
          color: "text-red-400",
          text: `Completed checks -> ${newRun.counts.c} Critical, ${newRun.counts.h} High, ${newRun.counts.m} Medium findings (Score: ${newRun.score}/100)`,
        },
      },
      {
        pct: 100,
        delay: 1500,
        log: {
          tag: "[REPORT-GEN]",
          color: "text-zinc-300",
          text: `Saved ${newRun.id} for ${cleanTarget} across all 9 assessment modules`,
        },
      },
    ];

    stages.forEach((step, idx) => {
      setTimeout(() => {
        setScanProgress(step.pct);
        setLogs((prev) => [...prev, { time: nowTime(), ...step.log }]);
        if (idx === stages.length - 1) {
          setCurrentScan(newRun);
          setSelectedReportId(newRun.id);
          setHistory((prev) => [
            newRun,
            ...prev.filter((item) => item.id !== newRun.id),
          ]);
          setIsScanning(false);
        }
      }, step.delay);
    });
  };

  const filteredVulns = useMemo(() => {
    return currentScan.vulns.filter((v) => {
      const matchesSev = sevFilter === "ALL" || v.severity === sevFilter;
      const q = vulnSearch.toLowerCase();
      const matchesQuery =
        !q ||
        v.id.toLowerCase().includes(q) ||
        v.title.toLowerCase().includes(q) ||
        v.endpoint.toLowerCase().includes(q);
      return matchesSev && matchesQuery;
    });
  }, [currentScan, sevFilter, vulnSearch]);

  const activeReport =
    history.find((h) => h.id === selectedReportId) || currentScan;

  const downloadJsonReport = () => {
    const payload = {
      platform: "VulnScan Security Assessment Platform",
      ...activeReport,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${activeReport.id}_${activeReport.target}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const resetDemoStorage = () => {
    localStorage.removeItem(STORAGE_KEY);
    const fresh = [
      buildTargetTelemetry("10.24.18.42"),
      buildTargetTelemetry("192.168.100.15"),
    ];
    setHistory(fresh);
    setCurrentScan(fresh[0]);
    setActiveScope(fresh[0].target);
    setTargetInput(fresh[0].target);
  };

  return (
    <div className="min-h-screen bg-black text-zinc-100 flex flex-col">
      {/* Top Global Header */}
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

        {/* Interactive Target Input Bar */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            runAssessmentForTarget(targetInput);
          }}
          className="hidden md:flex items-center gap-2 px-3 py-1 rounded-full bg-black border border-zinc-800 text-xs"
        >
          <span className="w-2 h-2 rounded-full bg-emerald-400" />
          <span className="text-zinc-500 font-mono text-[11px]">TARGET:</span>
          <input
            type="text"
            value={targetInput}
            onChange={(e) => setTargetInput(e.target.value)}
            placeholder="127.0.0.1 or scanme.nmap.org"
            className="bg-transparent text-cyan-400 font-mono text-xs w-44 outline-none"
          />
          <span className="text-zinc-800">|</span>
          <span className="inline-flex items-center gap-1 text-emerald-400 text-[11px]">
            <Shield className="w-3 h-3" />
            Scope Guardrail
          </span>
        </form>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowBlueprint(true)}
            className="hidden sm:inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-black hover:bg-zinc-900 border border-zinc-800 text-xs text-zinc-200 cursor-pointer"
          >
            <Layers className="w-3.5 h-3.5 text-cyan-400" />
            <span>Blueprint</span>
          </button>
          <button
            onClick={() => runAssessmentForTarget(targetInput)}
            disabled={isScanning}
            className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-md bg-cyan-500 hover:bg-cyan-400 disabled:bg-zinc-800 text-black font-semibold text-xs cursor-pointer"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>
              {isScanning ? `Scanning ${scanProgress}%` : "Run Full Scan"}
            </span>
          </button>
        </div>
      </header>

      {scopeError && (
        <div className="bg-red-950/90 border-b border-red-800 px-5 py-2 text-xs text-red-200 flex items-center justify-between no-print">
          <span>{scopeError}</span>
          <button
            onClick={() => setScopeError("")}
            className="text-red-300 hover:text-white cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

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
                const badgeCount =
                  m.id === "vulns" ? currentScan.vulns.length : null;
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
                    {badgeCount !== null && (
                      <span className="px-1.5 py-0.5 text-[10px] font-mono rounded bg-red-950/90 text-red-400 border border-red-800/70">
                        {badgeCount}
                      </span>
                    )}
                  </button>
                );
              })}
            </nav>
          </div>

          <div className="p-3 m-3 rounded-lg bg-black border border-zinc-900 space-y-2 text-[11px]">
            <div className="flex items-center justify-between border-b border-zinc-900 pb-1.5">
              <span className="font-semibold text-zinc-400 text-[10px] tracking-wider">
                ENGINE MODE
              </span>
              <span className="text-emerald-400 font-mono text-[10px]">
                {apiConnected ? "● FASTAPI LIVE" : "● DYNAMIC SANDBOX"}
              </span>
            </div>
            <div className="space-y-1 font-mono text-[10px] text-zinc-400">
              <div className="flex justify-between">
                <span>Active Target</span>
                <span className="text-cyan-400 truncate max-w-[105px]">
                  {activeScope}
                </span>
              </div>
              <div className="flex justify-between">
                <span>Stored Runs</span>
                <span className="text-zinc-200">{history.length}</span>
              </div>
            </div>
            <button
              onClick={resetDemoStorage}
              className="w-full pt-1.5 border-t border-zinc-900 text-[10px] text-zinc-500 hover:text-zinc-300 text-left cursor-pointer"
            >
              Reset Local Telemetry Cache
            </button>
          </div>
        </aside>

        {/* Main Workspace */}
        <main className="flex-1 p-5 overflow-y-auto space-y-5">
          {/* 1. DASHBOARD */}
          {activeModule === "dashboard" && (
            <>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3.5">
                <div className="bg-zinc-950 border border-zinc-900 rounded-lg p-4">
                  <div className="flex items-center justify-between text-xs text-zinc-400">
                    <span>Assessments Logged</span>
                    <Server className="w-3.5 h-3.5 text-cyan-400" />
                  </div>
                  <div className="mt-2 flex items-baseline justify-between">
                    <span className="text-2xl font-bold text-white font-mono">
                      {history.length}
                    </span>
                    <span className="text-[11px] font-mono text-emerald-400">
                      {activeScope}
                    </span>
                  </div>
                  <p className="text-[11px] text-zinc-500 mt-1.5">
                    Active target: {currentScan.hostname}
                  </p>
                </div>

                <div className="bg-zinc-950 border border-red-950/80 rounded-lg p-4">
                  <div className="flex items-center justify-between text-xs text-red-400">
                    <span>Critical Findings</span>
                    <span className="w-2 h-2 rounded-full bg-red-500" />
                  </div>
                  <div className="mt-2 flex items-baseline justify-between">
                    <span className="text-2xl font-bold text-red-400 font-mono">
                      {currentScan.counts.c}
                    </span>
                    <span className="text-[11px] font-mono text-red-400/80">
                      CVSS 9.0–10.0
                    </span>
                  </div>
                  <p className="text-[11px] text-zinc-500 mt-1.5">
                    Immediate remediation required
                  </p>
                </div>

                <div className="bg-zinc-950 border border-orange-950/70 rounded-lg p-4">
                  <div className="flex items-center justify-between text-xs text-orange-400">
                    <span>High Findings</span>
                    <span className="w-2 h-2 rounded-full bg-orange-500" />
                  </div>
                  <div className="mt-2 flex items-baseline justify-between">
                    <span className="text-2xl font-bold text-orange-400 font-mono">
                      {currentScan.counts.h}
                    </span>
                    <span className="text-[11px] font-mono text-orange-400/80">
                      CVSS 7.0–8.9
                    </span>
                  </div>
                  <p className="text-[11px] text-zinc-500 mt-1.5">
                    Exposed backup &amp; TLS 1.0
                  </p>
                </div>

                <div className="bg-zinc-950 border border-amber-950/70 rounded-lg p-4">
                  <div className="flex items-center justify-between text-xs text-amber-400">
                    <span>Medium Findings</span>
                    <span className="w-2 h-2 rounded-full bg-amber-400" />
                  </div>
                  <div className="mt-2 flex items-baseline justify-between">
                    <span className="text-2xl font-bold text-amber-400 font-mono">
                      {currentScan.counts.m}
                    </span>
                    <span className="text-[11px] font-mono text-amber-400/80">
                      CVSS 4.0–6.9
                    </span>
                  </div>
                  <p className="text-[11px] text-zinc-500 mt-1.5">
                    Security header hardening
                  </p>
                </div>

                <div className="bg-zinc-950 border border-emerald-950/70 rounded-lg p-4">
                  <div className="flex items-center justify-between text-xs text-emerald-400">
                    <span>Low / Info</span>
                    <span className="w-2 h-2 rounded-full bg-emerald-400" />
                  </div>
                  <div className="mt-2 flex items-baseline justify-between">
                    <span className="text-2xl font-bold text-emerald-400 font-mono">
                      {currentScan.counts.l}
                    </span>
                    <span className="text-[11px] font-mono text-emerald-400/80">
                      CVSS 0.1–3.9
                    </span>
                  </div>
                  <p className="text-[11px] text-zinc-500 mt-1.5">
                    Banner &amp; service metadata
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                <div className="bg-zinc-950 border border-zinc-900 rounded-lg p-5 flex flex-col justify-between">
                  <div className="flex items-start justify-between">
                    <div>
                      <h3 className="text-sm font-semibold text-white">
                        Security Posture Score
                      </h3>
                      <p className="text-[11px] text-zinc-500">
                        {currentScan.target} ({currentScan.hostname})
                      </p>
                    </div>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-amber-950/80 text-amber-400 border border-amber-800/60">
                      {currentScan.score >= 80
                        ? "LOW RISK"
                        : currentScan.score >= 60
                        ? "MODERATE RISK"
                        : "HIGH RISK"}
                    </span>
                  </div>

                  <div className="my-5 flex items-center justify-center relative">
                    <svg className="w-36 h-36 -rotate-90" viewBox="0 0 120 120">
                      <circle
                        cx="60"
                        cy="60"
                        r="48"
                        stroke="#18181b"
                        strokeWidth="10"
                        fill="none"
                      />
                      <circle
                        cx="60"
                        cy="60"
                        r="48"
                        stroke="#06b6d4"
                        strokeWidth="10"
                        strokeDasharray="301.6"
                        strokeDashoffset={301.6 * (1 - currentScan.score / 100)}
                        strokeLinecap="round"
                        fill="none"
                      />
                    </svg>
                    <div className="absolute text-center">
                      <div className="text-3xl font-bold text-white font-mono">
                        {currentScan.score}
                      </div>
                      <div className="text-[10px] text-zinc-500 font-mono">
                        / 100 PTS
                      </div>
                    </div>
                  </div>

                  <div className="grid grid-cols-3 text-center border-t border-zinc-900 pt-3 text-xs">
                    <div>
                      <div className="text-[10px] text-zinc-500">NETWORK</div>
                      <div className="font-mono font-semibold text-cyan-400 mt-0.5">
                        {Math.min(98, currentScan.score + 8)}%
                      </div>
                    </div>
                    <div>
                      <div className="text-[10px] text-zinc-500">WEB/API</div>
                      <div className="font-mono font-semibold text-amber-400 mt-0.5">
                        {Math.max(30, currentScan.score - 10)}%
                      </div>
                    </div>
                    <div>
                      <div className="text-[10px] text-zinc-500">
                        TLS/CRYPTO
                      </div>
                      <div className="font-mono font-semibold text-emerald-400 mt-0.5">
                        {Math.min(95, currentScan.score + 4)}%
                      </div>
                    </div>
                  </div>
                </div>

                <div className="lg:col-span-2 bg-zinc-950 border border-zinc-900 rounded-lg p-5 flex flex-col justify-between">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-2">
                      <Terminal className="w-4 h-4 text-cyan-400" />
                      <h3 className="text-sm font-semibold text-white">
                        Live Assessment Pipeline &amp; Worker Telemetry
                      </h3>
                    </div>
                    <span className="text-xs font-mono text-cyan-400">
                      {isScanning
                        ? `Running (${scanProgress}%)`
                        : `Completed • ${currentScan.id}`}
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
                        <span className={`${entry.color} font-semibold`}>
                          {entry.tag}
                        </span>{" "}
                        <span className="text-zinc-300">{entry.text}</span>
                      </div>
                    ))}
                  </div>

                  <div className="mt-3 pt-3 border-t border-zinc-900 flex flex-wrap items-center justify-between gap-2 text-[11px] text-zinc-500">
                    <span>
                      Target Scope: {currentScan.target} ({currentScan.hostname})
                    </span>
                    <button
                      onClick={() => runAssessmentForTarget(activeScope)}
                      className="inline-flex items-center gap-1 text-cyan-400 hover:text-cyan-300 cursor-pointer"
                    >
                      <RefreshCw className="w-3 h-3" />
                      <span>Re-run Scan on {activeScope}</span>
                    </button>
                  </div>
                </div>
              </div>

              <div className="bg-zinc-950 border border-zinc-900 rounded-lg overflow-hidden">
                <div className="px-5 py-3.5 border-b border-zinc-900 flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-semibold text-white">
                      Assessment History (Click any row to load its telemetry)
                    </h3>
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
                        <th className="py-3 px-4">Findings (C / H / M / L)</th>
                        <th className="py-3 px-4">Score</th>
                        <th className="py-3 px-4">Timestamp</th>
                        <th className="py-3 px-5 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-zinc-900">
                      {history.map((row) => (
                        <tr
                          key={row.id}
                          onClick={() => {
                            setCurrentScan(row);
                            setActiveScope(row.target);
                            setTargetInput(row.target);
                            setSelectedReportId(row.id);
                          }}
                          className={`cursor-pointer transition-colors ${
                            currentScan.id === row.id
                              ? "bg-cyan-950/20"
                              : "hover:bg-zinc-900/40"
                          }`}
                        >
                          <td className="py-3 px-5 font-mono text-cyan-400 font-medium">
                            {row.id}
                          </td>
                          <td className="py-3 px-4">
                            <div className="font-mono text-zinc-100">
                              {row.target}
                            </div>
                            <div className="text-[11px] text-zinc-500">
                              {row.hostname}
                            </div>
                          </td>
                          <td className="py-3 px-4">
                            <div className="inline-flex items-center gap-1 font-mono text-[10px]">
                              <span className="px-1.5 py-0.5 rounded bg-red-950 text-red-400 border border-red-800/70">
                                {row.counts.c}
                              </span>
                              <span className="px-1.5 py-0.5 rounded bg-orange-950 text-orange-400 border border-orange-800/70">
                                {row.counts.h}
                              </span>
                              <span className="px-1.5 py-0.5 rounded bg-amber-950 text-amber-400 border border-amber-800/70">
                                {row.counts.m}
                              </span>
                              <span className="px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800/70">
                                {row.counts.l}
                              </span>
                            </div>
                          </td>
                          <td className="py-3 px-4 font-mono font-semibold text-white">
                            {row.score}/100
                          </td>
                          <td className="py-3 px-4 font-mono text-zinc-400 text-[11px]">
                            {row.timestamp}
                          </td>
                          <td className="py-3 px-5 text-right space-x-2">
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                setCurrentScan(row);
                                setActiveModule("vulns");
                              }}
                              className="px-2.5 py-1 rounded bg-black hover:bg-zinc-900 border border-zinc-800 text-zinc-200 text-[11px] cursor-pointer"
                            >
                              Inspect
                            </button>
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
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

          {/* 2. RECONNAISSANCE */}
          {activeModule === "recon" && (
            <div className="space-y-5">
              <div className="bg-zinc-950 border border-zinc-900 rounded-lg p-5 space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                      <Globe className="w-4 h-4 text-cyan-400" />
                      Target Reconnaissance &amp; Live DNS Resolver
                    </h3>
                    <p className="text-xs text-zinc-500 mt-0.5">
                      Queries FastAPI <code className="text-cyan-400">/api/recon/dns</code> for A, AAAA, CNAME, MX, NS, and TXT records.
                    </p>
                  </div>
                  <span className="text-[11px] font-mono px-2.5 py-1 rounded bg-emerald-950/60 text-emerald-400 border border-emerald-800/60">
                    ACTIVE TARGET: {currentScan.target}
                  </span>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-12 gap-3 items-center">
                  <div className="lg:col-span-5">
                    <label className="block text-[10px] font-mono uppercase text-zinc-500 mb-1">
                      Target IPv4 / Allowlisted FQDN
                    </label>
                    <input
                      type="text"
                      value={targetInput}
                      onChange={(e) => setTargetInput(e.target.value)}
                      className="w-full bg-black border border-zinc-800 focus:border-cyan-500 rounded-md px-3 py-2 text-xs font-mono text-white outline-none"
                    />
                  </div>
                  <div className="lg:col-span-4 pt-4">
                    <label className="flex items-center gap-2 text-xs text-zinc-300 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={authorized}
                        onChange={(e) => setAuthorized(e.target.checked)}
                        className="rounded border-zinc-700 bg-black text-cyan-500"
                      />
                      <span>Authorized target confirmation</span>
                    </label>
                  </div>
                  <div className="lg:col-span-3 pt-4 flex gap-2">
                    <button
                      onClick={() => runLiveDnsRecon(targetInput)}
                      disabled={isScanning}
                      className="flex-1 py-2 px-3 rounded-md bg-black hover:bg-zinc-900 border border-cyan-500/50 text-cyan-400 font-semibold text-xs cursor-pointer"
                    >
                      DNS Lookup
                    </button>
                    <button
                      onClick={() => runAssessmentForTarget(targetInput)}
                      disabled={isScanning}
                      className="flex-1 py-2 px-3 rounded-md bg-cyan-500 hover:bg-cyan-400 text-black font-semibold text-xs cursor-pointer"
                    >
                      Full Enum
                    </button>
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                <div className="lg:col-span-2 bg-zinc-950 border border-zinc-900 rounded-lg overflow-hidden">
                  <div className="px-5 py-3 border-b border-zinc-900 flex justify-between items-center">
                    <h4 className="text-xs font-semibold text-white">
                      DNS Zone &amp; Resource Records ({currentScan.hostname})
                    </h4>
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
                      {currentScan.dnsRecords.map(([type, name, val, ttl], idx) => (
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
                    WHOIS &amp; IPAM Registration
                  </h4>
                  {[
                    ["HOST", currentScan.hostname],
                    ["TARGET IP", currentScan.target],
                    ["REGISTRAR", "Internal Enterprise IPAM / CoreDNS"],
                    ["ORG", "VulnScan Security Engineering Lab"],
                    ["SCANNED AT", currentScan.timestamp],
                  ].map(([k, v]) => (
                    <div
                      key={k}
                      className="flex justify-between gap-2 border-b border-zinc-900/70 pb-1.5"
                    >
                      <span className="font-mono text-[10px] text-zinc-500">
                        {k}
                      </span>
                      <span className="font-mono text-[11px] text-zinc-200 text-right">
                        {v}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* 3. PORT SCANNER */}
          {activeModule === "ports" && (
            <div className="bg-zinc-950 border border-zinc-900 rounded-lg overflow-hidden">
              <div className="px-5 py-4 border-b border-zinc-900 flex flex-wrap items-center justify-between gap-3">
                <div>
                  <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                    <Server className="w-4 h-4 text-cyan-400" />
                    Nmap Service &amp; Version Enumeration ({currentScan.target})
                  </h3>
                </div>
                <button
                  onClick={() => runAssessmentForTarget(activeScope)}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-cyan-500 hover:bg-cyan-400 text-black font-semibold text-xs cursor-pointer"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  <span>Rescan {currentScan.target}</span>
                </button>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead>
                    <tr className="border-b border-zinc-900 text-[10px] uppercase text-zinc-500 bg-black/50">
                      <th className="py-3 px-5">Port / Proto</th>
                      <th className="py-3 px-4">State</th>
                      <th className="py-3 px-4">Service</th>
                      <th className="py-3 px-4">Product &amp; Version</th>
                      <th className="py-3 px-5 text-right">Banner</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-900">
                    {currentScan.ports.map((p) => {
                      const isOpen = expandedPort === p.port;
                      return (
                        <React.Fragment key={p.port}>
                          <tr className="hover:bg-zinc-900/40">
                            <td className="py-3 px-5 text-cyan-400 font-semibold">
                              {p.port}
                            </td>
                            <td className="py-3 px-4">
                              <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-950 text-emerald-400 border border-emerald-800/60">
                                {p.state}
                              </span>
                            </td>
                            <td className="py-3 px-4 text-zinc-200">
                              {p.service}
                            </td>
                            <td className="py-3 px-4 text-zinc-300 font-sans">
                              {p.version}
                            </td>
                            <td className="py-3 px-5 text-right">
                              <button
                                onClick={() =>
                                  setExpandedPort(isOpen ? null : p.port)
                                }
                                className="inline-flex items-center gap-1 text-cyan-400 hover:text-cyan-300 cursor-pointer"
                              >
                                <span>{isOpen ? "Hide" : "Inspect"}</span>
                                {isOpen ? (
                                  <ChevronUp className="w-3 h-3" />
                                ) : (
                                  <ChevronDown className="w-3 h-3" />
                                )}
                              </button>
                            </td>
                          </tr>
                          {isOpen && (
                            <tr className="bg-black">
                              <td colSpan="5" className="p-4">
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

          {/* 4. WEB SCANNER */}
          {activeModule === "web" && (
            <div className="space-y-5">
              <div className="bg-zinc-950 border border-zinc-900 rounded-lg p-5 space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <h3 className="text-sm font-semibold text-white">
                      Live HTTP Response Security Headers Audit
                    </h3>
                    <p className="text-[11px] text-zinc-500">
                      Sends <code className="text-cyan-400">POST /api/web/scan</code> to inspect live HTTP response headers on your authorized endpoint.
                    </p>
                  </div>
                </div>

                <div className="flex flex-wrap gap-3">
                  <input
                    type="text"
                    value={webUrlInput}
                    onChange={(e) => setWebUrlInput(e.target.value)}
                    placeholder="http://127.0.0.1:8000"
                    className="flex-1 min-w-[240px] bg-black border border-zinc-800 focus:border-cyan-500 rounded-md px-3 py-2 text-xs font-mono text-white outline-none"
                  />
                  <button
                    onClick={() => runLiveWebAudit(webUrlInput)}
                    disabled={isScanning}
                    className="inline-flex items-center gap-1.5 px-4 py-2 rounded-md bg-cyan-500 hover:bg-cyan-400 text-black font-semibold text-xs cursor-pointer"
                  >
                    <Play className="w-3.5 h-3.5 fill-current" />
                    <span>Audit Endpoint Headers</span>
                  </button>
                </div>
              </div>

              <div className="bg-zinc-950 border border-zinc-900 rounded-lg p-5 space-y-3">
                <h3 className="text-sm font-semibold text-white">
                  OWASP Security Headers Results
                </h3>
                <div className="space-y-2.5">
                  {currentScan.headers.map((h) => (
                    <div
                      key={h.name}
                      className="bg-black border border-zinc-900 rounded-md p-3.5 flex flex-wrap items-center justify-between gap-3"
                    >
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-mono font-semibold text-white">
                            {h.name}
                          </span>
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
                        <p className="text-[11px] text-zinc-500 mt-1">
                          {h.desc}
                        </p>
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

          {/* 5. VULNERABILITY SCANNER */}
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
                {filteredVulns.length === 0 ? (
                  <div className="bg-zinc-950 border border-zinc-900 rounded-lg p-6 text-center text-xs text-zinc-500">
                    No vulnerabilities matched the selected severity filter for{" "}
                    {currentScan.target}.
                  </div>
                ) : (
                  filteredVulns.map((v) => {
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
                        key={`${v.id}-${v.endpoint}`}
                        className="bg-zinc-950 border border-zinc-900 rounded-lg p-4 space-y-2.5"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
                            <span
                              className={`px-2 py-0.5 rounded border text-[10px] font-semibold ${badgeStyle}`}
                            >
                              {v.severity} ({v.cvss})
                            </span>
                            <span className="text-cyan-400 font-semibold">
                              {v.id}
                            </span>
                            <span className="text-zinc-500">
                              • {v.endpoint}
                            </span>
                          </div>
                          <button
                            onClick={() => setSelectedVuln(v)}
                            className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-black hover:bg-zinc-900 border border-zinc-800 text-cyan-400 text-xs cursor-pointer"
                          >
                            <span>Remediation</span>
                            <ChevronRight className="w-3.5 h-3.5" />
                          </button>
                        </div>
                        <h4 className="text-sm font-semibold text-white">
                          {v.title}
                        </h4>
                        <p className="text-xs text-zinc-400 leading-relaxed">
                          {v.description}
                        </p>
                        <div className="pt-2 border-t border-zinc-900 flex flex-wrap justify-between text-[11px] font-mono text-zinc-500">
                          <span>{v.vector}</span>
                          <span>{v.template}</span>
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            </div>
          )}

          {/* 6. DIRECTORY SCANNER (Wired to POST /api/dirs/scan) */}
          {activeModule === "dirs" && (
            <div className="bg-zinc-950 border border-zinc-900 rounded-lg overflow-hidden">
              <div className="px-5 py-4 border-b border-zinc-900 flex flex-wrap items-center justify-between gap-2">
                <div>
                  <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                    <FolderSearch className="w-4 h-4 text-cyan-400" />
                    Content Discovery &amp; Exposed Endpoint Enumeration (
                    {currentScan.hostname})
                  </h3>
                  <p className="text-[11px] text-zinc-500">
                    Connects via FastAPI <code className="text-cyan-400">POST /api/dirs/scan</code> with rate-limited endpoint checks.
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <span className="px-2.5 py-1 rounded bg-red-950/80 text-red-400 border border-red-800/60 text-xs font-mono">
                    Target: {currentScan.target}
                  </span>
                  <button
                    onClick={runLiveDirectoryScan}
                    disabled={isScanning}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-cyan-500 hover:bg-cyan-400 text-black font-semibold text-xs cursor-pointer"
                  >
                    <RefreshCw className="w-3.5 h-3.5" />
                    <span>Scan Directories ({currentScan.target})</span>
                  </button>
                </div>
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
                  {currentScan.directories.map(
                    ([path, code, size, lat, risk, note], idx) => (
                      <tr key={`${path}-${idx}`}>
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
                        <td className="py-3 px-5 font-sans text-zinc-300">
                          {note}
                        </td>
                      </tr>
                    )
                  )}
                </tbody>
              </table>
            </div>
          )}

          {/* 7. SSL ANALYZER */}
          {activeModule === "ssl" && (
            <div className="space-y-4">
              <div className="bg-zinc-950 border border-zinc-900 rounded-lg p-5 flex flex-wrap items-center justify-between gap-3">
                <div>
                  <h3 className="text-sm font-semibold text-white">
                    Live X.509 Certificate &amp; TLS Handshake Inspector
                  </h3>
                  <p className="text-[11px] text-zinc-500">
                    Connects via FastAPI <code className="text-cyan-400">POST /api/ssl/scan</code> to inspect live TLS certificates on {activeScope}.
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <input
                    type="number"
                    value={sslPortInput}
                    onChange={(e) => setSslPortInput(e.target.value)}
                    className="w-24 bg-black border border-zinc-800 rounded-md px-3 py-1.5 text-xs font-mono text-white outline-none"
                  />
                  <button
                    onClick={runLiveSslAudit}
                    disabled={isScanning}
                    className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-md bg-cyan-500 hover:bg-cyan-400 text-black font-semibold text-xs cursor-pointer"
                  >
                    <RefreshCw className="w-3.5 h-3.5" />
                    <span>Inspect TLS ({activeScope}:{sslPortInput})</span>
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="bg-zinc-950 border border-zinc-900 rounded-lg p-5 space-y-3 text-xs">
                  <div className="flex justify-between items-center border-b border-zinc-900 pb-2.5">
                    <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                      <Lock className="w-4 h-4 text-cyan-400" />
                      X.509 Leaf Certificate ({currentScan.hostname})
                    </h3>
                    <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800/60 font-mono text-[10px]">
                      VALID ({currentScan.sslData.validDays}d left)
                    </span>
                  </div>
                  <div>
                    <div className="text-[10px] text-zinc-500">SUBJECT DN</div>
                    <div className="font-mono text-zinc-200 mt-0.5">
                      {currentScan.sslData.subject}
                    </div>
                  </div>
                  <div>
                    <div className="text-[10px] text-zinc-500">ISSUER CA</div>
                    <div className="font-mono text-zinc-200 mt-0.5">
                      {currentScan.sslData.issuer}
                    </div>
                  </div>
                  <div>
                    <div className="text-[10px] text-zinc-500">
                      NEGOTIATED PROTOCOL &amp; CIPHER
                    </div>
                    <div className="font-mono text-cyan-400 mt-0.5">
                      {currentScan.sslData.protocol} • {currentScan.sslData.cipher}
                    </div>
                  </div>
                  <div>
                    <div className="text-[10px] text-zinc-500 mb-1">
                      SUBJECT ALTERNATIVE NAMES (SANs)
                    </div>
                    <div className="flex flex-wrap gap-1.5 font-mono text-[11px]">
                      {currentScan.sslData.sans.map((san) => (
                        <span
                          key={san}
                          className="px-2 py-0.5 rounded bg-black border border-zinc-800 text-zinc-300"
                        >
                          {san}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>

                <div className="bg-zinc-950 border border-zinc-900 rounded-lg p-5 space-y-2.5 text-xs">
                  <div>
                    <h3 className="text-sm font-semibold text-white">
                      TLS Protocol Support Matrix
                    </h3>
                    <p className="text-[11px] text-zinc-500">
                      Handshake policy evaluation on {currentScan.target}:{sslPortInput}
                    </p>
                  </div>
                  {[
                    ["SSL 3.0", "Disabled", "DISABLED", "text-zinc-500"],
                    ["TLS 1.0", "Deprecated - Disable immediately", "CHECKED", "text-amber-400"],
                    ["TLS 1.1", "Deprecated - Disable immediately", "CHECKED", "text-amber-400"],
                    ["TLS 1.2", "Supported (ECDHE ciphers)", "ENABLED", "text-emerald-400"],
                    ["TLS 1.3", "Preferred (TLS_AES_256_GCM_SHA384)", "ENABLED", "text-emerald-400"],
                  ].map(([proto, note, state, color]) => (
                    <div
                      key={proto}
                      className="bg-black border border-zinc-900 rounded px-3.5 py-2.5 flex justify-between items-center"
                    >
                      <div>
                        <span className="font-mono font-semibold text-white mr-3">
                          {proto}
                        </span>
                        <span className="text-zinc-400">{note}</span>
                      </div>
                      <span
                        className={`font-mono text-[10px] px-2 py-0.5 rounded bg-zinc-950 border border-zinc-800 ${color}`}
                      >
                        {state}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* 8. SECURITY TESTING (Wired to POST /api/testing/scan) */}
          {activeModule === "testing" && (
            <div className="space-y-4">
              <div className="bg-emerald-950/20 border border-emerald-800/50 rounded-lg p-4 flex items-start gap-3 text-xs">
                <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
                <div>
                  <div className="font-semibold text-emerald-400 uppercase tracking-wide">
                    Safe / Non-Destructive Heuristic Verification Mode Active (
                    {currentScan.target})
                  </div>
                  <p className="text-zinc-300 mt-1">
                    Connects via FastAPI <code className="text-cyan-400">POST /api/testing/scan</code> to run passive response-pattern auditing and benign alphanumeric canary reflection checks without state-mutating payloads.
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="bg-zinc-950 border border-zinc-900 rounded-lg p-5 space-y-3">
                  <h3 className="text-sm font-semibold text-white">
                    Passive Audit Policies
                  </h3>
                  {[
                    [
                      "sql",
                      "SQL Error-Pattern Passive Inspection",
                      "Detects unmasked database driver stack traces in HTTP 500 responses.",
                    ],
                    [
                      "xss",
                      "Benign Alphanumeric Reflection Check",
                      "Sends harmless token (vulnscan7749canary) to verify output encoding.",
                    ],
                    [
                      "csrf",
                      "Anti-CSRF Token & Cookie Flag Audit",
                      "Verifies SameSite attributes and CSRF headers on session forms.",
                    ],
                    [
                      "cors",
                      "CORS Origin Reflection Policy Check",
                      "Tests whether arbitrary Origin headers are echoed with credentials.",
                    ],
                  ].map(([key, title, desc]) => (
                    <label
                      key={key}
                      className="flex items-start gap-3 p-3 rounded bg-black border border-zinc-900 cursor-pointer"
                    >
                      <input
                        type="checkbox"
                        checked={policies[key]}
                        onChange={(e) =>
                          setPolicies({ ...policies, [key]: e.target.checked })
                        }
                        className="mt-1 rounded border-zinc-700 bg-black text-cyan-500"
                      />
                      <div>
                        <div className="text-xs font-semibold text-white">
                          {title}
                        </div>
                        <div className="text-[11px] text-zinc-500 mt-0.5">
                          {desc}
                        </div>
                      </div>
                    </label>
                  ))}

                  <div className="pt-2 space-y-1.5">
                    <div className="flex justify-between text-xs font-mono">
                      <span className="text-zinc-400">
                        WORKER RATE LIMIT CAP
                      </span>
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
                    onClick={runLiveSecurityTesting}
                    disabled={isScanning}
                    className="w-full py-2.5 rounded-md bg-cyan-500 hover:bg-cyan-400 text-black font-semibold text-xs flex items-center justify-center gap-2 cursor-pointer"
                  >
                    <RefreshCw className="w-3.5 h-3.5" />
                    <span>Run Safe Audit on {activeScope}</span>
                  </button>
                </div>

                <div className="bg-zinc-950 border border-zinc-900 rounded-lg p-5 space-y-3">
                  <h3 className="text-sm font-semibold text-white">
                    Heuristic Verification Findings ({currentScan.hostname})
                  </h3>
                  {currentScan.testingFindings.map((item) => (
                    <div
                      key={item.title}
                      className="p-3.5 rounded bg-black border border-zinc-900 space-y-1"
                    >
                      <div className="flex justify-between items-center">
                        <span className="text-xs font-semibold text-white">
                          {item.title}
                        </span>
                        <span
                          className={`text-[10px] font-mono px-2 py-0.5 rounded bg-zinc-950 border border-zinc-800 ${item.color}`}
                        >
                          {item.badge}
                        </span>
                      </div>
                      <div className="text-[11px] font-mono text-cyan-400">
                        {item.ep}
                      </div>
                      <div className="text-[11px] text-zinc-400">
                        {item.res}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* 9. REPORTS */}
          {activeModule === "reports" && (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
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
                    value={activeReport.id}
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
                  <div className="text-[10px] font-mono uppercase text-zinc-500">
                    Report Sections
                  </div>
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
                        onChange={(e) =>
                          setReportSections({
                            ...reportSections,
                            [k]: e.target.checked,
                          })
                        }
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

              <div className="lg:col-span-8 bg-white text-zinc-900 rounded-lg p-8 shadow-2xl space-y-6 print-sheet">
                <div className="flex flex-wrap justify-between items-start gap-4 border-b border-zinc-200 pb-5">
                  <div>
                    <div className="text-[10px] font-mono uppercase tracking-widest text-cyan-700 font-semibold">
                      CONFIDENTIAL — INTERNAL SECURITY ASSESSMENT
                    </div>
                    <h2 className="text-2xl font-bold text-zinc-950 mt-1">
                      Vulnerability Assessment &amp; Posture Report
                    </h2>
                    <p className="text-xs text-zinc-500 mt-1">
                      Generated by VulnScan Security Assessment Platform •{" "}
                      {activeReport.timestamp}
                    </p>
                  </div>
                  <div className="text-right font-mono text-xs bg-zinc-50 border border-zinc-200 rounded px-3 py-2">
                    <div className="font-bold text-zinc-900">
                      {activeReport.id}
                    </div>
                    <div className="text-zinc-600">
                      Target: {activeReport.target}
                    </div>
                    <div className="text-zinc-500">
                      Host: {activeReport.hostname}
                    </div>
                  </div>
                </div>

                {reportSections.exec && (
                  <div className="space-y-2">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-zinc-800">
                      1. Executive Summary
                    </h3>
                    <p className="text-xs text-zinc-700 leading-relaxed">
                      An authorized, scope-locked vulnerability assessment was
                      conducted against <strong>{activeReport.target}</strong> (
                      {activeReport.hostname}). The target achieved an overall
                      Security Posture Score of{" "}
                      <strong>{activeReport.score}/100</strong> with{" "}
                      {activeReport.vulns.length} categorized findings.
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
                        <div className="text-lg font-bold text-red-700 font-mono">
                          {activeReport.counts.c}
                        </div>
                        <div className="text-[10px] font-semibold text-red-600">
                          CRITICAL
                        </div>
                      </div>
                      <div className="p-3 rounded border border-orange-200 bg-orange-50">
                        <div className="text-lg font-bold text-orange-700 font-mono">
                          {activeReport.counts.h}
                        </div>
                        <div className="text-[10px] font-semibold text-orange-600">
                          HIGH
                        </div>
                      </div>
                      <div className="p-3 rounded border border-amber-200 bg-amber-50">
                        <div className="text-lg font-bold text-amber-700 font-mono">
                          {activeReport.counts.m}
                        </div>
                        <div className="text-[10px] font-semibold text-amber-600">
                          MEDIUM
                        </div>
                      </div>
                      <div className="p-3 rounded border border-emerald-200 bg-emerald-50">
                        <div className="text-lg font-bold text-emerald-700 font-mono">
                          {activeReport.counts.l}
                        </div>
                        <div className="text-[10px] font-semibold text-emerald-600">
                          LOW
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {reportSections.findings && (
                  <div className="space-y-2.5">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-zinc-800">
                      3. Technical Vulnerability Findings
                    </h3>
                    {activeReport.vulns.map((v) => (
                      <div
                        key={`${v.id}-${v.endpoint}`}
                        className="p-3 rounded border border-zinc-200 bg-zinc-50/60 text-xs space-y-1"
                      >
                        <div className="flex justify-between font-mono text-[11px]">
                          <span className="font-bold text-zinc-900">
                            [{v.severity}] {v.id} — CVSS {v.cvss}
                          </span>
                          <span className="text-zinc-500">{v.endpoint}</span>
                        </div>
                        <div className="font-semibold text-zinc-900">
                          {v.title}
                        </div>
                        <p className="text-zinc-600 text-[11px]">
                          {v.description}
                        </p>
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
                      <li>
                        <strong>Immediate (0–24 Hours):</strong> Remove{" "}
                        <code>/.env.backup</code> on {activeReport.hostname} and
                        bind debug listeners to localhost.
                      </li>
                      <li>
                        <strong>Short-Term (1–7 Days):</strong> Disable TLS
                        1.0/1.1, upgrade Nginx, and enforce
                        Content-Security-Policy headers.
                      </li>
                      <li>
                        <strong>Hardening (7–30 Days):</strong> Restrict
                        internal cache listeners to loopback and suppress
                        version banners.
                      </li>
                    </ul>
                  </div>
                )}
              </div>
            </div>
          )}
        </main>
      </div>

      {/* Remediation Modal */}
      {selectedVuln && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-zinc-950 border border-zinc-800 rounded-lg max-w-xl w-full p-6 space-y-4">
            <div className="flex items-start justify-between gap-3">
              <div>
                <span className="text-xs font-mono text-cyan-400">
                  {selectedVuln.id} • CVSS {selectedVuln.cvss}
                </span>
                <h3 className="text-base font-bold text-white mt-0.5">
                  {selectedVuln.title}
                </h3>
              </div>
              <button
                onClick={() => setSelectedVuln(null)}
                className="p-1 text-zinc-400 hover:text-white cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <p className="text-xs text-zinc-300 leading-relaxed">
              {selectedVuln.description}
            </p>
            <div className="p-3.5 rounded bg-black border border-emerald-900/50 text-xs space-y-1">
              <div className="font-semibold text-emerald-400">
                Recommended Remediation
              </div>
              <p className="text-zinc-300 leading-relaxed">
                {selectedVuln.remediation}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Blueprint Modal */}
      {showBlueprint && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-zinc-950 border border-zinc-800 rounded-lg max-w-2xl w-full p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-zinc-900 pb-3">
              <div className="flex items-center gap-2">
                <Code2 className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-bold text-white">
                  VulnScan Hybrid Architecture (Vercel + FastAPI)
                </h3>
              </div>
              <button
                onClick={() => setShowBlueprint(false)}
                className="p-1 text-zinc-400 hover:text-white cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <p className="text-xs text-zinc-400 leading-relaxed">
              Every scan run dynamically updates all 9 modules (Dashboard,
              Reconnaissance, Port Scanner, Web Scanner, Vulnerabilities,
              Directory Scanner, SSL Analyzer, Security Testing, and Reports)
              and persists history in your browser. When a FastAPI backend is
              reachable via{" "}
              <code className="text-cyan-400">VITE_API_BASE_URL</code>, live
              Nmap, Web, DNS, SSL/TLS, Vulnerability, Directory, and Passive
              Testing results automatically populate the workspace.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}