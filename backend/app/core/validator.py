import ipaddress
import re
import socket
from urllib.parse import urlparse
from fastapi import HTTPException
from sqlalchemy.orm import Session
from app.models.models import Target, AuditLog

DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

def normalize_target(raw_target: str) -> str:
    """Extracts clean hostname or IP from a URL, IP, or domain string."""
    cleaned = raw_target.strip()
    if "://" in cleaned:
        parsed = urlparse(cleaned)
        cleaned = parsed.hostname or ""
    else:
        cleaned = cleaned.split("/")[0].split(":")[0]
    return cleaned.lower()

def is_private_or_loopback(host: str) -> bool:
    """Checks if an IP or resolved domain belongs to RFC 1918 private or loopback ranges."""
    if host in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        ip_obj = ipaddress.ip_address(host)
        return ip_obj.is_private or ip_obj.is_loopback
    except ValueError:
        try:
            resolved_ip = socket.gethostbyname(host)
            ip_obj = ipaddress.ip_address(resolved_ip)
            return ip_obj.is_private or ip_obj.is_loopback
        except socket.gaierror:
            return False

def validate_and_authorize_target(
    raw_target: str, db: Session, explicit_authorization: bool = False
) -> Target:
    host = normalize_target(raw_target)
    if not host:
        raise HTTPException(status_code=400, detail="Invalid target host.")

    # Validate syntax (IP or valid domain/localhost)
    is_valid_ip = False
    try:
        ipaddress.ip_address(host)
        is_valid_ip = True
    except ValueError:
        pass

    if not is_valid_ip and host != "localhost" and not DOMAIN_REGEX.match(host):
        raise HTTPException(status_code=400, detail=f"Malformed target format: {host}")

    target_record = db.query(Target).filter(Target.host == host).first()
    private_scope = is_private_or_loopback(host)

    # Allow if RFC 1918/loopback OR explicitly authorized in DB / confirmed by user
    authorized = private_scope or explicit_authorization or (
        target_record is not None and target_record.is_authorized
    )

    if not authorized:
        db.add(AuditLog(
            action="scope_validation",
            target_host=host,
            status="blocked",
            reason="Public target requires explicit authorization confirmation."
        ))
        db.commit()
        raise HTTPException(
            status_code=403,
            detail=f"Target '{host}' is a public address and requires explicit authorization before scanning."
        )

    if not target_record:
        target_record = Target(host=host, is_authorized=True)
        db.add(target_record)
    elif explicit_authorization and not target_record.is_authorized:
        target_record.is_authorized = True

    db.add(AuditLog(
        action="scope_validation",
        target_host=host,
        status="allowed",
        reason="RFC1918/Loopback" if private_scope else "Explicitly Authorized"
    ))
    db.commit()
    db.refresh(target_record)
    return target_record