import json
import sqlite3
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from app.core.validator import validate_and_authorize_target
from app.database import get_db
from app.scanners.ssl_scanner import run_ssl_audit

router = APIRouter(prefix="/api/ssl", tags=["SSL Analyzer"])


class SslScanRequest(BaseModel):
    target: str
    port: int = 443
    explicit_authorization: bool = False


@router.post("/scan")
async def scan_ssl_endpoint(
    payload: SslScanRequest,
    db: sqlite3.Connection = Depends(get_db),
):
    target_id = validate_and_authorize_target(
        payload.target,
        db,
        payload.explicit_authorization,
    )

    audit = await run_ssl_audit(payload.target, payload.port)
    cur = db.cursor()
    cur.execute(
        "INSERT INTO scans (target_id, scan_type, profile, status, summary) VALUES (?, ?, ?, ?, ?)",
        (
            target_id,
            "ssl",
            "tls-audit",
            "completed",
            json.dumps({"protocol": audit.get("protocol")}),
        ),
    )
    db.commit()
    return audit