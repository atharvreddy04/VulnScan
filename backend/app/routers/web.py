# backend/app/routers/web.py
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.core.validator import validate_and_authorize_target
from app.database import get_db
from app.models.models import Finding, Scan
from app.scanners.web_scanner import run_web_header_audit

router = APIRouter(prefix="/api/web", tags=["Web Scanner"])


class WebScanRequest(BaseModel):
    url: str
    explicit_authorization: bool = False


@router.post("/scan")
async def scan_web_endpoint(payload: WebScanRequest, db: Session = Depends(get_db)):
    target = validate_and_authorize_target(payload.url, db, payload.explicit_authorization)
    audit = await run_web_header_audit(payload.url)

    scan = Scan(target_id=target.id, scan_type="web", profile="safe", status="completed", summary={"status_code": audit["status_code"]})
    db.add(scan)
    db.commit()
    db.refresh(scan)

    for item in audit["findings"]:
        db.add(Finding(
            scan_id=scan.id,
            module=item["module"],
            title=item["title"],
            severity=item["severity"],
            remediation=item["remediation"],
        ))
    db.commit()
    return audit