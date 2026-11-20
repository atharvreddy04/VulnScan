import json
import sqlite3
from typing import Dict
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from app.core.validator import validate_and_authorize_target
from app.database import get_db
from app.scanners.testing_scanner import run_passive_security_tests

router = APIRouter(prefix="/api/testing", tags=["Security Testing"])


class SecurityTestRequest(BaseModel):
    target: str
    policies: Dict[str, bool] = {"sql": True, "xss": True, "csrf": True, "cors": True}
    rate_cap: int = 5
    explicit_authorization: bool = False


@router.post("/scan")
async def run_security_testing(
    payload: SecurityTestRequest,
    db: sqlite3.Connection = Depends(get_db),
):
    target_id = validate_and_authorize_target(
        payload.target,
        db,
        payload.explicit_authorization,
    )
    findings = await run_passive_security_tests(
        payload.target,
        payload.policies,
        payload.rate_cap,
    )

    cur = db.cursor()
    cur.execute(
        "INSERT INTO scans (target_id, scan_type, profile, status, summary) VALUES (?, ?, ?, ?, ?)",
        (target_id, "testing", "passive-safe", "completed", json.dumps({"checks": len(findings)})),
    )
    db.commit()
    return {"target": payload.target, "findings": findings}