import asyncio
import time
from typing import List
import httpx

SAFE_WORDLIST = [
    ("/.env", "CRITICAL", "Environment variable configuration file"),
    ("/.env.backup", "HIGH", "Backup environment configuration artifact"),
    ("/openapi.json", "MEDIUM", "OpenAPI / Swagger API schema"),
    ("/docs", "LOW", "Interactive Swagger UI documentation"),
    ("/api/health", "INFO", "Service health telemetry endpoint"),
    ("/admin", "MEDIUM", "Administrative portal route"),
    ("/metrics", "LOW", "Prometheus / application metrics endpoint"),
    ("/.git/HEAD", "HIGH", "Git repository HEAD reference"),
    ("/robots.txt", "INFO", "Crawler indexing rules"),
]


def _format_size(num_bytes: int) -> str:
    if num_bytes >= 1024:
        return f"{num_bytes / 1024:.1f} KB"
    return f"{num_bytes} B"


async def run_directory_audit(target: str) -> List[List[str]]:
    clean = target.strip().replace("http://", "").replace("https://", "").split("/")[0]
    base_candidates = (
        [target.rstrip("/")]
        if target.startswith(("http://", "https://"))
        else [f"http://{clean}:8000", f"https://{clean}", f"http://{clean}"]
    )

    active_base = None
    async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=4.0) as client:
        for base in base_candidates:
            try:
                await client.get(base)
                active_base = base
                break
            except Exception:
                continue

        if not active_base:
            return [["/", "ERR", "0 B", "0ms", "INFO", f"No reachable HTTP listener on {clean}"]]

        rows: List[List[str]] = []
        for path, default_risk, desc in SAFE_WORDLIST:
            t0 = time.perf_counter()
            try:
                resp = await client.get(f"{active_base}{path}")
                latency_ms = f"{int((time.perf_counter() - t0) * 1000)}ms"
                status = str(resp.status_code)
                size = _format_size(len(resp.content))

                if resp.status_code == 200:
                    risk = default_risk
                    note = f"Accessible ({desc})"
                elif resp.status_code in (301, 302, 307, 308):
                    risk = "MEDIUM" if path == "/admin" else "INFO"
                    note = f"Redirects to {resp.headers.get('location', '/')}"
                elif resp.status_code in (401, 403):
                    risk = "LOW"
                    note = "Protected / Access Denied"
                else:
                    risk = "SAFE"
                    note = "Not exposed"

                rows.append([path, status, size, latency_ms, risk, note])
            except Exception:
                rows.append([path, "TIMEOUT", "0 B", "-", "INFO", "Request timed out"])

            await asyncio.sleep(0.08)  # Rate-limit cap (~12 req/sec)

        return rows