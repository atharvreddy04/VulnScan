import json
import sqlite3
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from app.core.validator import validate_and_authorize_target
from app.database import get_db
from app.scanners.nuclei_scanner import run_vulnerability_audit

router = APIRouter(prefix="/api/vulnerabilities", tags=["Vulnerabilities"])


class VulnScanRequest(BaseModel):
    target: str
    explicit_authorization: bool = False


@router.post("/scan")
async def trigger_vulnerability_scan(
    payload: VulnScanRequest,
    db: sqlite3.Connection = Depends(get_db),
):
    target_id = validate_and_authorize_target(
        payload.target,
        db,
        payload.explicit_authorization,
    )

    results = await run_vulnerability_audit(payload.target)
    cur = db.cursor()
    cur.execute(
        "INSERT INTO scans (target_id, scan_type, profile, status, summary) VALUES (?, ?, ?, ?, ?)",
        (
            target_id,
            "vulnerability",
            "active-safe",
            "completed",
            json.dumps({"count": len(results)}),
        ),
    )
    scan_id = cur.lastrowid

    for item in results:
        cur.execute(
            "INSERT INTO findings (scan_id, module, title, severity, remediation, details) VALUES (?, ?, ?, ?, ?, ?)",
            (
                scan_id,
                item["id"],
                item["title"],
                item["severity"].lower(),
                item["remediation"],
                json.dumps(item),
            ),
        )
    db.commit()
    return {"scan_id": scan_id, "target": payload.target, "findings": results}


@router.get("")
def get_all_findings(db: sqlite3.Connection = Depends(get_db)):
    cur = db.cursor()
    cur.execute(
        "SELECT id, module, title, severity, remediation, details FROM findings ORDER BY id DESC LIMIT 100"
    )
    out = []
    for fid, mod, title, sev, rem, det in cur.fetchall():
        parsed = json.loads(det) if det else {}
        out.append(
            {
                "id": mod or f"FINDING-{fid}",
                "severity": (sev or "info").upper(),
                "cvss": parsed.get("cvss", "5.0"),
                "endpoint": parsed.get("endpoint", "Target Endpoint"),
                "title": title,
                "description": parsed.get("description", title),
                "vector": parsed.get(
                    "vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
                ),
                "template": parsed.get("template", "vulnscan:audit"),
                "remediation": rem,
            }
        )
    return out