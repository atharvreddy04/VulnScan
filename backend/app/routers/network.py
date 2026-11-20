import asyncio
import json
import sqlite3
from typing import Any, Dict, List
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from app.core.validator import validate_and_authorize_target
from app.database import DB_PATH, get_db

router = APIRouter(prefix="/api/network", tags=["Network Scanner"])

COMMON_PORTS = [
    (21, "ftp"),
    (22, "ssh"),
    (25, "smtp"),
    (53, "dns"),
    (80, "http"),
    (443, "https"),
    (3306, "mysql"),
    (5432, "postgresql"),
    (6379, "redis"),
    (8000, "http-alt"),
    (8080, "http-proxy"),
]


class NetworkScanRequest(BaseModel):
    target: str
    profile: str = "safe"
    explicit_authorization: bool = False


async def _probe_port(host: str, port: int, service: str) -> Dict[str, Any] | None:
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=1.2)
        banner = ""
        try:
            if port in (80, 8000, 8080):
                writer.write(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
                await writer.drain()
            raw = await asyncio.wait_for(reader.read(256), timeout=1.0)
            banner = raw.decode(errors="ignore").strip()
        except Exception:
            pass
        writer.close()
        await writer.wait_closed()
        return {
            "port": port,
            "protocol": "tcp",
            "service": service,
            "remediation": f"Verify whether {service} on port {port} needs to be exposed.",
            "details": {"banner": banner or f"Open TCP port {port} ({service})"},
        }
    except Exception:
        return None


async def _execute_scan_task(scan_id: int, target: str, db_path: str):
    clean_host = (
        target.strip()
        .replace("http://", "")
        .replace("https://", "")
        .split("/")[0]
        .split(":")[0]
    )
    tasks = [_probe_port(clean_host, p, svc) for p, svc in COMMON_PORTS]
    probed = await asyncio.gather(*tasks)
    results: List[Dict[str, Any]] = [item for item in probed if item is not None]

    with sqlite3.connect(db_path) as conn:
        for f in results:
            conn.execute(
                "INSERT INTO findings (scan_id, module, title, severity, remediation, details) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    scan_id,
                    "network",
                    f"Open Port {f['port']}/tcp ({f['service']})",
                    "info",
                    f["remediation"],
                    json.dumps(f),
                ),
            )
        conn.execute(
            "UPDATE scans SET status = ?, summary = ? WHERE id = ?",
            ("completed", json.dumps({"open_ports": len(results)}), scan_id),
        )


@router.post("/scan")
async def start_network_scan(
    payload: NetworkScanRequest,
    background_tasks: BackgroundTasks,
    db: sqlite3.Connection = Depends(get_db),
):
    target_id = validate_and_authorize_target(
        payload.target,
        db,
        payload.explicit_authorization,
    )

    clean_host = (
        payload.target.strip()
        .replace("http://", "")
        .replace("https://", "")
        .split("/")[0]
        .split(":")[0]
    )
    cur = db.cursor()
    cur.execute(
        "INSERT INTO scans (target_id, scan_type, profile, status, summary) VALUES (?, ?, ?, ?, ?)",
        (target_id, "network", payload.profile, "running", "{}"),
    )
    scan_id = cur.lastrowid
    db.commit()

    background_tasks.add_task(_execute_scan_task, scan_id, clean_host, str(DB_PATH))
    return {"scan_id": scan_id, "target": clean_host, "status": "running"}


@router.get("/scans/{scan_id}")
def get_network_scan(scan_id: int, db: sqlite3.Connection = Depends(get_db)):
    cur = db.cursor()
    cur.execute("SELECT id, status, summary FROM scans WHERE id = ?", (scan_id,))
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")

    cur.execute(
        "SELECT details FROM findings WHERE scan_id = ? AND module = 'network'",
        (scan_id,),
    )
    findings = [json.loads(r[0]) for r in cur.fetchall() if r[0]]
    return {
        "scan_id": row[0],
        "status": row[1],
        "findings": findings,
    }