import asyncio
import json
import shutil
from typing import Any, Dict, List
import httpx


EXPOSURE_PROBES = [
    {
        "path": "/.env",
        "id": "CVE-2023-28432",
        "severity": "CRITICAL",
        "cvss": "9.1",
        "title": "Publicly Accessible .env Environment Configuration File",
        "template": "builtin:http/exposures/configs/dotenv-exposure",
        "remediation": "Remove .env from the web root immediately, rotate all exposed secrets, and block dotfiles in Nginx/Apache.",
        "match": lambda status, body: status == 200 and ("DB_" in body or "SECRET" in body or "API_KEY" in body or "PASSWORD" in body),
    },
    {
        "path": "/.env.backup",
        "id": "CVE-2023-28432-BAK",
        "severity": "HIGH",
        "cvss": "7.8",
        "title": "Environment Backup File (.env.backup) Exposed",
        "template": "builtin:http/exposures/configs/env-file-backup",
        "remediation": "Delete backup configuration files from public directories and restrict access via web server rules.",
        "match": lambda status, body: status == 200 and len(body.strip()) > 0 and "<html" not in body.lower(),
    },
    {
        "path": "/openapi.json",
        "id": "CWE-200-OPENAPI",
        "severity": "MEDIUM",
        "cvss": "5.3",
        "title": "Unauthenticated OpenAPI / Swagger Schema Exposed",
        "template": "builtin:http/exposures/apis/openapi-schema",
        "remediation": "Disable docs_url and openapi_url in production FastAPI configurations.",
        "match": lambda status, body: status == 200 and '"openapi"' in body and '"paths"' in body,
    },
    {
        "path": "/.git/HEAD",
        "id": "CWE-538-GIT",
        "severity": "HIGH",
        "cvss": "7.5",
        "title": "Exposed Git Repository Metadata (/.git/HEAD)",
        "template": "builtin:http/exposures/configs/git-config",
        "remediation": "Block all requests matching /.git/ at the reverse proxy layer.",
        "match": lambda status, body: status == 200 and "ref: refs/" in body,
    },
]


async def run_vulnerability_audit(target: str) -> List[Dict[str, Any]]:
    clean_host = target.strip().replace("http://", "").replace("https://", "").split("/")[0]
    base_urls = (
        [target.rstrip("/")]
        if target.startswith(("http://", "https://"))
        else [f"http://{clean_host}:8000", f"http://{clean_host}", f"https://{clean_host}"]
    )

    findings: List[Dict[str, Any]] = []
    active_base = None

    async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=5.0) as client:
        for candidate in base_urls:
            try:
                r = await client.get(candidate)
                active_base = candidate
                # Check security headers on live response
                hdrs = {k.lower(): v for k, v in r.headers.items()}
                if "content-security-policy" not in hdrs:
                    findings.append({
                        "id": "CWE-693-CSP",
                        "severity": "MEDIUM",
                        "cvss": "5.4",
                        "endpoint": f"{candidate} (HTTP Headers)",
                        "title": "Missing Content-Security-Policy (CSP) Header",
                        "description": f"The HTTP response from {candidate} lacks a Content-Security-Policy header, increasing XSS impact.",
                        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                        "template": "builtin:http/misconfiguration/missing-csp",
                        "remediation": "Add Content-Security-Policy: default-src 'self'; to your HTTP response headers.",
                    })
                if "server" in hdrs:
                    findings.append({
                        "id": "CWE-200-BANNER",
                        "severity": "LOW",
                        "cvss": "3.1",
                        "endpoint": f"{candidate} (Server: {hdrs['server']})",
                        "title": f"Server Version Banner Disclosed ({hdrs['server']})",
                        "description": "Server software and version details are broadcast in HTTP response headers.",
                        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        "template": "builtin:http/misconfiguration/server-banner",
                        "remediation": "Suppress the Server header in Nginx (server_tokens off) or Uvicorn (--no-server-header).",
                    })
                break
            except Exception:
                continue

        if active_base:
            for probe in EXPOSURE_PROBES:
                try:
                    resp = await client.get(f"{active_base}{probe['path']}")
                    if probe["match"](resp.status_code, resp.text):
                        findings.append({
                            "id": probe["id"],
                            "severity": probe["severity"],
                            "cvss": probe["cvss"],
                            "endpoint": f"{active_base}{probe['path']}",
                            "title": probe["title"],
                            "description": f"Probing {active_base}{probe['path']} returned HTTP {resp.status_code} matching sensitive exposure signatures.",
                            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            "template": probe["template"],
                            "remediation": probe["remediation"],
                        })
                except Exception:
                    continue

    # Optional: Run real Nuclei CLI if installed on PATH
    nuclei_bin = shutil.which("nuclei")
    if nuclei_bin and active_base:
        try:
            proc = await asyncio.create_subprocess_exec(
                nuclei_bin,
                "-u",
                active_base,
                "-severity",
                "critical,high,medium,low",
                "-jsonl",
                "-silent",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=45.0)
            for line in stdout.decode(errors="ignore").splitlines():
                if not line.strip():
                    continue
                data = json.loads(line)
                info = data.get("info", {})
                findings.append({
                    "id": data.get("template-id", "NUCLEI-FINDING").upper(),
                    "severity": info.get("severity", "info").upper(),
                    "cvss": str(info.get("classification", {}).get("cvss-score", "5.0")),
                    "endpoint": data.get("matched-at", active_base),
                    "title": info.get("name", "Nuclei Vulnerability Match"),
                    "description": info.get("description", "Detected by Nuclei template engine."),
                    "vector": info.get("classification", {}).get("cvss-metrics", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
                    "template": f"nuclei:{data.get('template-id', 'custom')}",
                    "remediation": info.get("remediation", "Review vendor advisory and apply security patch."),
                })
        except Exception:
            pass

    return findings