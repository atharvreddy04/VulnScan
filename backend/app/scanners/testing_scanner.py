import asyncio
from typing import Any, Dict, List
import httpx


async def run_passive_security_tests(
    target: str,
    policies: Dict[str, bool],
    rate_cap: int = 5,
) -> List[Dict[str, str]]:
    clean = target.strip().replace("http://", "").replace("https://", "").split("/")[0]
    base_candidates = (
        [target.rstrip("/")]
        if target.startswith(("http://", "https://"))
        else [f"http://{clean}:8000", f"https://{clean}", f"http://{clean}"]
    )

    delay = 1.0 / max(1, min(15, rate_cap))
    findings: List[Dict[str, str]] = []

    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=5.0) as client:
        active_base = None
        for base in base_candidates:
            try:
                await client.get(base)
                active_base = base
                break
            except Exception:
                continue

        if not active_base:
            return [
                {
                    "title": "Target HTTP Reachability Check",
                    "ep": clean,
                    "res": f"UNREACHABLE (No active HTTP service on {clean})",
                    "badge": "INFO",
                    "color": "text-zinc-400",
                }
            ]

        # 1. Passive SQL Error-Pattern Inspection
        if policies.get("sql", True):
            ep = f"{active_base}/?id=1"
            try:
                r = await client.get(ep)
                body_lower = r.text.lower()
                leaked = any(
                    sig in body_lower
                    for sig in ("sql syntax", "sqlite3.operationalerror", "psycopg2", "mysql_fetch", "ora-")
                )
                findings.append({
                    "title": "SQL Error-Pattern Passive Detection",
                    "ep": ep,
                    "res": "FAIL (Verbose database stack trace detected)" if leaked else "PASS (No verbose SQL stack traces)",
                    "badge": "HIGH" if leaked else "SAFE",
                    "color": "text-red-400" if leaked else "text-emerald-400",
                })
            except Exception:
                pass
            await asyncio.sleep(delay)

        # 2. Benign Alphanumeric Canary Reflection Check
        if policies.get("xss", True):
            canary = "vulnscan7749canary"
            ep = f"{active_base}/?q={canary}"
            try:
                r = await client.get(ep)
                reflected = canary in r.text
                findings.append({
                    "title": "Benign Alphanumeric Canary Reflection",
                    "ep": ep,
                    "res": (
                        "WARN (Canary reflected in response body; verify context encoding)"
                        if reflected
                        else "PASS (Canary not echoed unencoded in response)"
                    ),
                    "badge": "MEDIUM" if reflected else "SAFE",
                    "color": "text-amber-400" if reflected else "text-emerald-400",
                })
            except Exception:
                pass
            await asyncio.sleep(delay)

        # 3. Cookie Security Attributes & Anti-CSRF Header Audit
        if policies.get("csrf", True):
            try:
                r = await client.get(active_base)
                set_cookies = r.headers.get_list("set-cookie")
                if not set_cookies:
                    findings.append({
                        "title": "Session Cookie & SameSite Flag Audit",
                        "ep": active_base,
                        "res": "PASS (Stateless endpoint; no insecure session cookies issued)",
                        "badge": "SAFE",
                        "color": "text-emerald-400",
                    })
                else:
                    weak = [c for c in set_cookies if "samesite" not in c.lower() or "httponly" not in c.lower()]
                    findings.append({
                        "title": "Session Cookie & SameSite Flag Audit",
                        "ep": active_base,
                        "res": (
                            f"WARN ({len(weak)} cookie(s) missing SameSite or HttpOnly attributes)"
                            if weak
                            else "PASS (SameSite and HttpOnly flags enforced)"
                        ),
                        "badge": "MEDIUM" if weak else "SAFE",
                        "color": "text-amber-400" if weak else "text-emerald-400",
                    })
            except Exception:
                pass
            await asyncio.sleep(delay)

        # 4. CORS Origin Reflection Policy Audit
        if policies.get("cors", True):
            test_origin = "https://untrusted-audit-check.example"
            try:
                r = await client.get(active_base, headers={"Origin": test_origin})
                acao = r.headers.get("access-control-allow-origin", "")
                acac = r.headers.get("access-control-allow-credentials", "").lower()
                misconfigured = (acao == test_origin and acac == "true") or (acao == "*" and acac == "true")
                findings.append({
                    "title": "CORS Origin Reflection Policy Audit",
                    "ep": active_base,
                    "res": (
                        f"FAIL (Reflects arbitrary Origin '{acao}' with Allow-Credentials: true)"
                        if misconfigured
                        else f"PASS (CORS policy: {acao or 'Restricted / Same-Origin'})"
                    ),
                    "badge": "HIGH" if misconfigured else "SAFE",
                    "color": "text-red-400" if misconfigured else "text-emerald-400",
                })
            except Exception:
                pass

    return findings