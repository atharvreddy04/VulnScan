import json
import sqlite3
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from app.core.validator import validate_and_authorize_target
from app.database import get_db
from app.scanners.dir_scanner import run_directory_audit

router = APIRouter(prefix="/api/dirs", tags=["Directory Scanner"])


class DirScanRequest(BaseModel):
    target: str
    explicit_authorization: bool = False


@router.post("/scan")
async def scan_directories(
    payload: DirScanRequest,
    db: sqlite3.Connection = Depends(get_db),
):
    target_id = validate_and_authorize_target(
        payload.target,
        db,
        payload.explicit_authorization,
    )
    rows = await run_directory_audit(payload.target)

    cur = db.cursor()
    cur.execute(
        "INSERT INTO scans (target_id, scan_type, profile, status, summary) VALUES (?, ?, ?, ?, ?)",
        (target_id, "directory", "safe-wordlist", "completed", json.dumps({"paths_checked": len(rows)})),
    )
    db.commit()
    return {"target": payload.target, "directories": rows}