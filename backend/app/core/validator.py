import ipaddress
import os
import socket
import sqlite3
from urllib.parse import urlparse
from fastapi import HTTPException

# Permission-granted public security testing sandboxes
DEFAULT_TEST_DOMAINS = {
    "scanme.nmap.org",
    "testphp.vulnweb.com",
    "example.com",
}

# Cloud metadata and link-local ranges that must always be blocked on Render/AWS/GCP
BLOCKED_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),  # AWS/Render/GCP metadata & link-local
    ipaddress.ip_network("100.64.0.0/10"),   # Carrier-grade NAT / internal cloud mesh
]

PRIVATE_LAB_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def _get_allowed_domains() -> set[str]:
    env_domains = os.getenv("AUTHORIZED_EXTERNAL_DOMAINS", "")
    extra = {
        d.strip().lower()
        for d in env_domains.split(",")
        if d.strip()
    }
    return DEFAULT_TEST_DOMAINS | extra


def _extract_host(raw_target: str) -> str:
    candidate = raw_target.strip()
    if "://" in candidate:
        parsed = urlparse(candidate)
        return (parsed.hostname or "").lower()
    return candidate.split("/")[0].split(":")[0].lower()


def validate_and_authorize_target(
    raw_target: str,
    db: sqlite3.Connection,
    explicit_authorization: bool,
) -> int:
    if not explicit_authorization:
        raise HTTPException(
            status_code=403,
            detail="Explicit written authorization checkbox must be confirmed.",
        )

    host = _extract_host(raw_target)
    if not host:
        raise HTTPException(status_code=400, detail="Invalid target host or URL.")

    allowed_domains = _get_allowed_domains()
    is_allowed = False

    # 1. Check if input is a direct IPv4/IPv6 address
    try:
        ip_obj = ipaddress.ip_address(host)
        if any(ip_obj in net for net in BLOCKED_NETWORKS):
            raise HTTPException(
                status_code=403,
                detail="Blocked by SSRF Guardrail: Link-local and cloud metadata IPs are forbidden.",
            )
        if any(ip_obj in net for net in PRIVATE_LAB_NETWORKS):
            is_allowed = True
    except ValueError:
        # 2. Input is a hostname/domain
        if host == "localhost" or host.endswith((".local", ".lab")):
            is_allowed = True
        elif host in allowed_domains or any(
            host.endswith(f".{domain}") for domain in allowed_domains
        ):
            # Resolve DNS to verify the domain does not point to a blocked metadata IP
            try:
                resolved_ip = ipaddress.ip_address(socket.gethostbyname(host))
                if any(resolved_ip in net for net in BLOCKED_NETWORKS):
                    raise HTTPException(
                        status_code=403,
                        detail="Blocked by SSRF Guardrail: Domain resolves to restricted internal metadata space.",
                    )
            except socket.gaierror:
                pass
            is_allowed = True

    if not is_allowed:
        raise HTTPException(
            status_code=403,
            detail=(
                f"Target '{host}' is outside the authorized scope. "
                "Use an RFC 1918 lab IP, .local/.lab host, or add the domain to AUTHORIZED_EXTERNAL_DOMAINS."
            ),
        )

    cur = db.cursor()
    cur.execute(
        "INSERT OR IGNORE INTO targets (host, is_authorized) VALUES (?, 1)",
        (host,),
    )
    cur.execute("SELECT id FROM targets WHERE host = ?", (host,))
    target_id = cur.fetchone()[0]
    db.commit()
    return target_id