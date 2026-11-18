"""Reports API (Feature J): downloadable PDF per scan."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models import Finding, Scan, Target
from app.reporting.pdf_generator import build_report_pdf

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("/{scan_id}/pdf")
def download_pdf(scan_id: int, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.status not in ("completed", "failed"):
        raise HTTPException(409, f"Scan is {scan.status}; report available after completion")
    target = db.get(Target, scan.target_id)
    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    results = list(scan.results)

    pdf = build_report_pdf(scan, target, findings, results)
    filename = f"privacyguard-report-scan-{scan.id}.pdf"
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
