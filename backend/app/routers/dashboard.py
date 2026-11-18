"""Dashboard API (Feature A) - all numbers derived from actual DB results."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.engine.detector import AUTHORIZED, BLOCKED, CONFIRMED_BOLA, POTENTIAL_BOLA
from app.models import Finding, Scan, ScanResult, Target
from app.schemas import DashboardStats, ScanOut, SeverityBucket

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

SEVERITY_LEVELS = ["Critical", "High", "Medium", "Low", "Informational"]


@router.get("/stats", response_model=DashboardStats)
def stats(db: Session = Depends(get_db)):
    total_scans = db.query(Scan).count()
    endpoints_tested = (
        db.query(func.coalesce(func.sum(Scan.endpoints_tested), 0))
        .filter(Scan.status == "completed")
        .scalar()
    )
    confirmed = (
        db.query(Finding)
        .filter(Finding.classification == CONFIRMED_BOLA, Finding.status == "open")
        .count()
    )
    potential = (
        db.query(Finding)
        .filter(Finding.classification == POTENTIAL_BOLA, Finding.status == "open")
        .count()
    )

    # Protected endpoints: in each endpoint's MOST RECENT completed scan, all
    # cross-account results are only BLOCKED / AUTHORIZED.
    completed_ids = [
        row[0]
        for row in db.query(Scan.id).filter(Scan.status == "completed").order_by(Scan.id).all()
    ]
    protected = 0
    bad = {CONFIRMED_BOLA, POTENTIAL_BOLA, "INCONCLUSIVE"}
    classes_by_ep: dict[int, set[str]] = {}
    for sid in completed_ids:  # ascending: later scans overwrite earlier ones
        rows = (
            db.query(ScanResult.endpoint_id, ScanResult.classification)
            .filter(ScanResult.scan_id == sid)
            .all()
        )
        grouped: dict[int, set[str]] = {}
        for ep_id, cls in rows:
            grouped.setdefault(ep_id, set()).add(cls)
        classes_by_ep.update(grouped)
    protected = sum(
        1 for classes in classes_by_ep.values() if classes and not (classes & bad)
    )

    recent = (
        db.query(Scan).order_by(Scan.id.desc()).limit(8).all()
    )
    recent_out = []
    for s in recent:
        o = ScanOut.model_validate(s)
        t = db.get(Target, s.target_id)
        o.target_name = t.name if t else None
        recent_out.append(o)

    # severity chart from OPEN findings (current exposure)
    chart = []
    for sev in SEVERITY_LEVELS:
        cnt = (
            db.query(Finding)
            .filter(Finding.severity == sev, Finding.status == "open")
            .count()
        )
        chart.append(SeverityBucket(severity=sev, count=cnt))

    return DashboardStats(
        total_scans=total_scans,
        endpoints_tested=endpoints_tested,
        confirmed_vulnerabilities=confirmed + potential,
        protected_endpoints=protected,
        recent_scans=recent_out,
        severity_chart=chart,
    )
