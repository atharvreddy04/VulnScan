import sqlite3
from fastapi import APIRouter, Depends
from app.database import get_db

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


@router.get("/summary")
def dashboard_summary(db: sqlite3.Connection = Depends(get_db)):
    cur = db.cursor()
    cur.execute("SELECT severity FROM findings")
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for (sev,) in cur.fetchall():
        key = (sev or "info").lower()
        counts[key] = counts.get(key, 0) + 1

    penalty = counts["critical"] * 20 + counts["high"] * 10 + counts["medium"] * 4 + counts["low"] * 1
    score = max(10, 100 - penalty)

    cur.execute("SELECT COUNT(*) FROM scans")
    total_scans = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM targets")
    total_assets = cur.fetchone()[0]

    return {
        "total_scans": total_scans,
        "total_assets": total_assets,
        "security_score": score,
        "severity_counts": counts,
    }


@router.get("/scans")
def list_all_scans(db: sqlite3.Connection = Depends(get_db)):
    cur = db.cursor()
    cur.execute(
        """
        SELECT s.id, t.host, s.scan_type, s.profile, s.status
        FROM scans s
        LEFT JOIN targets t ON s.target_id = t.id
        ORDER BY s.id DESC LIMIT 25
        """
    )
    return [
        {
            "id": r[0],
            "target": r[1] or "127.0.0.1",
            "scan_type": r[2],
            "profile": r[3],
            "status": r[4],
        }
        for r in cur.fetchall()
    ]