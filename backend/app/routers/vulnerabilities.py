# backend/app/routers/vulnerabilities.py
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.models import Finding

router = APIRouter(prefix="/api/vulnerabilities", tags=["Vulnerabilities"])


@router.get("")
def get_all_findings(db: Session = Depends(get_db)):
    items = db.query(Finding).order_by(Finding.id.desc()).limit(100).all()
    return [
        {
            "id": f.id,
            "module": f.module,
            "title": f.title,
            "severity": f.severity,
            "remediation": f.remediation,
        }
        for f in items
    ]