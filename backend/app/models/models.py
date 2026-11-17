from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON, Boolean
from sqlalchemy.orm import relationship
from app.database import Base

def utcnow():
    return datetime.now(timezone.utc)

class Target(Base):
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True, index=True)
    host = Column(String, unique=True, index=True, nullable=False)
    label = Column(String, nullable=True)
    is_authorized = Column(Boolean, default=False)
    created_at = Column(DateTime, default=utcnow)

    scans = relationship("Scan", back_populates="target", cascade="all, delete-orphan")

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    scan_type = Column(String, nullable=False)  # e.g., "network", "web", "nuclei", "recon"
    profile = Column(String, default="standard")  # "safe", "standard", "aggressive"
    status = Column(String, default="queued")     # "queued", "running", "completed", "failed"
    started_at = Column(DateTime, default=utcnow)
    completed_at = Column(DateTime, nullable=True)
    summary = Column(JSON, default=dict)

    target = relationship("Target", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")

class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    module = Column(String, nullable=False)       # "nmap", "headers", "tls", "zap", "nuclei"
    title = Column(String, nullable=False)
    severity = Column(String, default="info")     # "critical", "high", "medium", "low", "info"
    port = Column(Integer, nullable=True)
    protocol = Column(String, nullable=True)
    service = Column(String, nullable=True)
    cve_id = Column(String, nullable=True)
    details = Column(JSON, default=dict)
    remediation = Column(String, nullable=True)

    scan = relationship("Scan", back_populates="findings")

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    action = Column(String, nullable=False)
    target_host = Column(String, nullable=False)
    status = Column(String, nullable=False)       # "allowed", "blocked"
    reason = Column(String, nullable=True)
    timestamp = Column(DateTime, default=utcnow)