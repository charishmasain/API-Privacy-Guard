"""Target configuration API (Feature B)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.ssrf_guard import normalize_host
from app.models import ApiEndpoint, Target, TestAccount
from app.schemas import TargetCreate, TargetOut, TargetUpdate

router = APIRouter(prefix="/api/targets", tags=["targets"])


def _with_counts(t: Target) -> TargetOut:
    out = TargetOut.model_validate(t)
    out.account_count = len(t.accounts)
    out.endpoint_count = len(t.endpoints)
    return out


@router.get("", response_model=list[TargetOut])
def list_targets(db: Session = Depends(get_db)):
    return [_with_counts(t) for t in db.query(Target).order_by(Target.id).all()]


@router.get("/{target_id}", response_model=TargetOut)
def get_target(target_id: int, db: Session = Depends(get_db)):
    t = db.get(Target, target_id)
    if not t:
        raise HTTPException(404, "Target not found")
    return _with_counts(t)


@router.post("", response_model=TargetOut, status_code=201)
def create_target(payload: TargetCreate, db: Session = Depends(get_db)):
    """Register an authorised target. Testing without confirmed authorization is refused."""
    if not payload.authorization_confirmed:
        raise HTTPException(400, "Authorization to test this API must be confirmed")
    try:
        host = normalize_host(payload.base_url)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    t = Target(
        name=payload.name,
        base_url=payload.base_url.rstrip("/"),
        host=host,
        authorization_confirmed=True,
        allow_localhost=payload.allow_localhost,
        notes=payload.notes,
    )
    db.add(t)
    db.commit()
    db.refresh(t)
    return _with_counts(t)


@router.put("/{target_id}", response_model=TargetOut)
def update_target(target_id: int, payload: TargetUpdate, db: Session = Depends(get_db)):
    t = db.get(Target, target_id)
    if not t:
        raise HTTPException(404, "Target not found")
    data = payload.model_dump(exclude_unset=True)
    if "base_url" in data and data["base_url"]:
        data["base_url"] = data["base_url"].rstrip("/")
        data["host"] = normalize_host(data["base_url"])
    if data.get("authorization_confirmed") is False:
        raise HTTPException(400, "Authorization confirmation cannot be withdrawn while target exists")
    for k, v in data.items():
        setattr(t, k, v)
    db.commit()
    db.refresh(t)
    return _with_counts(t)


@router.delete("/{target_id}", status_code=204)
def delete_target(target_id: int, db: Session = Depends(get_db)):
    t = db.get(Target, target_id)
    if not t:
        raise HTTPException(404, "Target not found")
    db.delete(t)
    db.commit()
