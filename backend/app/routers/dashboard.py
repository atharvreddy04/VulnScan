# backend/app/routers/dashboard.py
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.models import Finding, Scan, Target

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


@router.get("/summary")
def dashboard_summary(db: Session = Depends(get_db)):
    findings = db.query(Finding).all()
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = (f.severity or "info").lower()
        counts[sev] = counts.get(sev, 0) + 1

    penalty = counts["critical"] * 20 + counts["high"] * 10 + counts["medium"] * 4 + counts["low"] * 1
    score = max(10, 100 - penalty)

    return {
        "total_scans": db.query(Scan).count(),
        "total_assets": db.query(Target).count(),
        "security_score": score,
        "severity_counts": counts,
    }


@router.get("/scans")
def list_all_scans(db: Session = Depends(get_db)):
    scans = db.query(Scan).order_by(Scan.id.desc()).limit(25).all()
    return [
        {
            "id": s.id,
            "target": s.target.host,
            "scan_type": s.scan_type,
            "profile": s.profile,
            "status": s.status,
        }
        for s in scans
    ]