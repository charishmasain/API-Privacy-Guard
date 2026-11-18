"""Access-control matrix API (Feature G).

Rows = test accounts, columns = endpoints/resources of the latest scan.
Cell classification:
  OWNER            - the account owns this resource (authorized baseline)
  BLOCKED / AUTHORIZED / CONFIRMED_BOLA / POTENTIAL_BOLA / INCONCLUSIVE
                     - worst outcome of that account's cross-access attempts
  UNTESTED         - no data for this pairing in the scan
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.engine.detector import worst_verdict, Verdict
from app.models import ApiEndpoint, Scan, ScanResult, Target, TestAccount

router = APIRouter(prefix="/api/matrix", tags=["matrix"])


@router.get("/latest")
def latest_matrix(db: Session = Depends(get_db)):
    scan = (
        db.query(Scan)
        .filter(Scan.status == "completed")
        .order_by(Scan.id.desc())
        .first()
    )
    if scan is None:
        raise HTTPException(404, "No completed scan yet")
    return build_matrix(db, scan)


@router.get("/{scan_id}")
def matrix_for_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return build_matrix(db, scan)


def build_matrix(db: Session, scan: Scan) -> dict:
    target = db.get(Target, scan.target_id)
    accounts = db.query(TestAccount).filter(TestAccount.target_id == target.id).all()
    endpoints = (
        db.query(ApiEndpoint).filter(ApiEndpoint.id.in_(
            {r.endpoint_id for r in scan.results if r.endpoint_id}
        )).all()
    ) if scan.results else []

    results = list(scan.results)
    cells = []
    for acct in accounts:
        for ep in endpoints:
            if acct.id == ep.owner_account_id:
                # owner access was the legitimate baseline of this endpoint
                cls = "OWNER"
                status = None
                sim = None
                owned_resource = ep.resource_id
            else:
                rows = [
                    r for r in results
                    if r.endpoint_id == ep.id and r.requester_account_id == acct.id
                ]
                if rows:
                    worst = max(rows, key=lambda r: Verdict(r.classification).rank)
                    cls = worst.classification
                    status = worst.cross_status
                    sim = worst.similarity
                    owned_resource = worst.resource_id
                else:
                    cls = "UNTESTED"
                    status = None
                    sim = None
                    owned_resource = ep.resource_id
            cells.append({
                "account_id": acct.id,
                "endpoint_id": ep.id,
                "resource_id": owned_resource,
                "classification": cls,
                "cross_status": status,
                "similarity": sim,
            })

    return {
        "scan_id": scan.id,
        "scan_name": scan.name,
        "target": {"id": target.id, "name": target.name, "base_url": target.base_url},
        "accounts": [{"id": a.id, "name": a.name, "home_resource_id": a.home_resource_id}
                     for a in accounts],
        "endpoints": [{"id": e.id, "name": e.name, "path_template": e.path_template,
                       "method": e.method, "resource_id": e.resource_id,
                       "owner_name": e.owner_account.name if e.owner_account else None}
                      for e in endpoints],
        "cells": cells,
    }
