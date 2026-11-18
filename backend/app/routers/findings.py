"""Findings API (Feature H)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models import Finding
from app.schemas import FindingOut

router = APIRouter(prefix="/api/findings", tags=["findings"])

_SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}


@router.get("", response_model=list[FindingOut])
def list_findings(
    scan_id: int | None = None,
    severity: str | None = None,
    status: str | None = None,
    db: Session = Depends(get_db),
):
    q = db.query(Finding)
    if scan_id is not None:
        q = q.filter(Finding.scan_id == scan_id)
    if severity:
        q = q.filter(Finding.severity == severity)
    if status:
        q = q.filter(Finding.status == status)
    findings = q.order_by(Finding.id.desc()).all()
    return sorted(findings, key=lambda f: (_SEVERITY_ORDER.get(f.severity, 9), -f.id))


@router.get("/{finding_id}", response_model=FindingOut)
def get_finding(finding_id: int, db: Session = Depends(get_db)):
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(404, "Finding not found")
    return f
