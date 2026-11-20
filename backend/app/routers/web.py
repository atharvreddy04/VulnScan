import json
import sqlite3
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from app.core.validator import validate_and_authorize_target
from app.database import get_db
from app.scanners.web_scanner import run_web_header_audit

router = APIRouter(prefix="/api/web", tags=["Web Scanner"])


class WebScanRequest(BaseModel):
    url: str
    explicit_authorization: bool = False


@router.post("/scan")
async def scan_web_endpoint(
    payload: WebScanRequest,
    db: sqlite3.Connection = Depends(get_db),
):
    target_id = validate_and_authorize_target(
        payload.url,
        db,
        payload.explicit_authorization,
    )

    audit = await run_web_header_audit(payload.url)
    cur = db.cursor()
    cur.execute(
        "INSERT INTO scans (target_id, scan_type, profile, status, summary) VALUES (?, ?, ?, ?, ?)",
        (
            target_id,
            "web",
            "safe",
            "completed",
            json.dumps({"status_code": audit["status_code"]}),
        ),
    )
    scan_id = cur.lastrowid

    for item in audit["findings"]:
        cur.execute(
            "INSERT INTO findings (scan_id, module, title, severity, remediation, details) VALUES (?, ?, ?, ?, ?, ?)",
            (
                scan_id,
                item["module"],
                item["title"],
                item["severity"],
                item["remediation"],
                json.dumps(item),
            ),
        )
    db.commit()
    return audit