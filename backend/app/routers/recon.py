# backend/app/routers/recon.py
import dns.resolver
from fastapi import APIRouter

router = APIRouter(prefix="/api/recon", tags=["Reconnaissance"])


@router.get("/dns")
def dns_lookup(domain: str):
    records = {}
    for rtype in ["A", "AAAA", "MX", "NS", "TXT"]:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=4.0)
            records[rtype] = [r.to_text() for r in answers]
        except Exception:
            records[rtype] = []
    return {"domain": domain, "records": records}