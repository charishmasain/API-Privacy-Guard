"""Scan control API (Features E + I): start, list, inspect, rescan, verify fixes."""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.engine.detector import BLOCKED, AUTHORIZED, CONFIRMED_BOLA, POTENTIAL_BOLA
from app.engine.scanner import run_scan
from app.models import ApiEndpoint, Finding, Scan, ScanResult, Target
from app.schemas import ScanCreate, ScanDetailOut, ScanOut, ScanResultOut

router = APIRouter(prefix="/api/scans", tags=["scans"])

_VULN_CLASSES = {CONFIRMED_BOLA, POTENTIAL_BOLA}
_SAFE_CLASSES = {BLOCKED, AUTHORIZED}


def _out(db: Session, scan: Scan) -> ScanOut:
    o = ScanOut.model_validate(scan)
    t = db.get(Target, scan.target_id)
    o.target_name = t.name if t else None
    return o


def _require_completed(db: Session, scan_id: int) -> Scan:
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


@router.post("", response_model=ScanOut, status_code=201)
def start_scan(payload: ScanCreate, background: BackgroundTasks, db: Session = Depends(get_db)):
    target = db.get(Target, payload.target_id)
    if not target:
        raise HTTPException(404, "Target not found")
    if not target.authorization_confirmed:
        raise HTTPException(400, "Target authorization must be confirmed before scanning")
    accounts = target.accounts
    if len(accounts) < 2:
        raise HTTPException(400, "At least two test accounts are required to detect BOLA")
    if not target.endpoints:
        raise HTTPException(400, "Configure at least one endpoint before scanning")

    ep_ids = payload.endpoint_ids
    if ep_ids:
        valid = {e.id for e in db.query(ApiEndpoint).filter(ApiEndpoint.id.in_(ep_ids)).all()}
        ep_ids = [i for i in ep_ids if i in valid]

    scan = Scan(
        target_id=target.id,
        name=payload.name or f"Scan {target.name} {datetime.utcnow():%Y-%m-%d %H:%M}",
        status="pending",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    def _job(scan_id: int, endpoint_ids):
        from app.core.database import SessionLocal

        s = SessionLocal()
        try:
            run_scan(s, scan_id, endpoint_ids=endpoint_ids)
        finally:
            s.close()

    background.add_task(_job, scan.id, ep_ids)
    return _out(db, scan)


@router.get("", response_model=list[ScanOut])
def list_scans(db: Session = Depends(get_db)):
    scans = db.query(Scan).order_by(Scan.id.desc()).all()
    return [_out(db, s) for s in scans]


@router.get("/{scan_id}", response_model=ScanDetailOut)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = _require_completed(db, scan_id)
    base = _out(db, scan)
    detail = ScanDetailOut(**base.model_dump())
    detail.results = [ScanResultOut.model_validate(r) for r in scan.results]
    return detail


@router.post("/{scan_id}/rescan", response_model=ScanOut, status_code=201)
def rescan(scan_id: int, background: BackgroundTasks, db: Session = Depends(get_db)):
    """Re-run ONLY the endpoints that had vulnerable results in the given scan."""
    old = _require_completed(db, scan_id)
    vuln_endpoint_ids = sorted({
        r.endpoint_id for r in old.results if r.classification in _VULN_CLASSES and r.endpoint_id
    })
    if not vuln_endpoint_ids:
        raise HTTPException(400, "This scan has no vulnerable endpoints to rescan")
    payload = ScanCreate(target_id=old.target_id, name=f"Rescan of #{old.id}", endpoint_ids=vuln_endpoint_ids)
    return start_scan(payload, background, db)


@router.get("/{scan_id}/verification")
def verify_fixes(scan_id: int, db: Session = Depends(get_db)):
    """Compare a (newer) scan with the previous completed scan of the same target."""
    new_scan = _require_completed(db, scan_id)
    prev = (
        db.query(Scan)
        .filter(
            Scan.target_id == new_scan.target_id,
            Scan.id < new_scan.id,
            Scan.status == "completed",
        )
        .order_by(Scan.id.desc())
        .first()
    )
    if prev is None:
        return {"previous_scan_id": None, "comparisons": [], "summary": {}}

    def key(r: ScanResult):
        return (r.endpoint_id, r.requester_name, r.owner_name, r.resource_id)

    prev_map = {key(r): r for r in prev.results}
    comparisons = []
    summary = {"fixed": 0, "still_vulnerable": 0, "regressed": 0, "unchanged": 0}
    for r in new_scan.results:
        p = prev_map.get(key(r))
        if p is None:
            continue
        was_vuln = p.classification in _VULN_CLASSES
        is_vuln = r.classification in _VULN_CLASSES
        if was_vuln and not is_vuln:
            state = "fixed"
        elif was_vuln and is_vuln:
            state = "still_vulnerable"
        elif not was_vuln and is_vuln:
            state = "regressed"
        else:
            state = "unchanged"
        summary[state] += 1
        comparisons.append({
            "endpoint_id": r.endpoint_id,
            "endpoint_name": r.endpoint_name,
            "path": r.path,
            "resource_id": r.resource_id,
            "requester_name": r.requester_name,
            "owner_name": r.owner_name,
            "previous_classification": p.classification,
            "previous_status": p.cross_status,
            "current_classification": r.classification,
            "current_status": r.cross_status,
            "state": state,
        })

        # keep finding lifecycle in sync
        if state == "fixed":
            (
                db.query(Finding)
                .filter(Finding.endpoint_id == r.endpoint_id, Finding.status == "open")
                .update({"status": "fixed", "resolved_at": datetime.utcnow(), "last_seen_at": datetime.utcnow()})
            )
        elif state == "still_vulnerable":
            (
                db.query(Finding)
                .filter(Finding.endpoint_id == r.endpoint_id, Finding.status.in_(["fixed", "reopened"]))
                .update({"status": "open", "last_seen_at": datetime.utcnow()})
            )
    db.commit()
    return {"previous_scan_id": prev.id, "comparisons": comparisons, "summary": summary}
