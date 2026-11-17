from typing import Any, Dict, List
import httpx

REQUIRED_HEADERS = {
    "Strict-Transport-Security": ("medium", "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to enforce HTTPS."),
    "Content-Security-Policy": ("medium", "Define a restrictive Content-Security-Policy header to mitigate XSS and injection."),
    "X-Frame-Options": ("low", "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent clickjacking."),
    "X-Content-Type-Options": ("low", "Set 'X-Content-Type-Options: nosniff' to prevent MIME-type sniffing."),
    "Referrer-Policy": ("info", "Configure 'Referrer-Policy: strict-origin-when-cross-origin' to limit referrer leakage."),
}


async def run_web_header_audit(url: str) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15.0) as client:
        response = await client.get(url)

    headers = {k.lower(): v for k, v in response.headers.items()}

    for header_name, (severity, remediation) in REQUIRED_HEADERS.items():
        if header_name.lower() not in headers:
            findings.append({
                "module": "headers",
                "title": f"Missing Security Header: {header_name}",
                "severity": severity,
                "remediation": remediation,
            })

    server_banner = headers.get("server")
    if server_banner:
        findings.append({
            "module": "fingerprint",
            "title": f"Server Header Exposed ({server_banner})",
            "severity": "info",
            "remediation": "Suppress verbose Server version banners in your web server configuration.",
        })

    return {
        "url": str(response.url),
        "status_code": response.status_code,
        "findings": findings,
    }