"""Endpoint configuration API (Feature D)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.config import ALLOWED_METHODS
from app.core.database import get_db
from app.models import ApiEndpoint, Target, TestAccount
from app.schemas import EndpointCreate, EndpointOut, EndpointUpdate

router = APIRouter(prefix="/api", tags=["endpoints"])


def _to_out(ep: ApiEndpoint) -> EndpointOut:
    out = EndpointOut.model_validate(ep)
    out.owner_name = ep.owner_account.name if ep.owner_account else None
    return out


@router.get("/targets/{target_id}/endpoints", response_model=list[EndpointOut])
def list_endpoints(target_id: int, db: Session = Depends(get_db)):
    eps = (
        db.query(ApiEndpoint)
        .filter(ApiEndpoint.target_id == target_id)
        .order_by(ApiEndpoint.id)
        .all()
    )
    return [_to_out(e) for e in eps]


@router.post("/targets/{target_id}/endpoints", response_model=EndpointOut, status_code=201)
def create_endpoint(target_id: int, payload: EndpointCreate, db: Session = Depends(get_db)):
    if not db.get(Target, target_id):
        raise HTTPException(404, "Target not found")
    owner = db.get(TestAccount, payload.owner_account_id)
    if not owner or owner.target_id != target_id:
        raise HTTPException(400, "Owner account must belong to the same target")
    if "{resource_id}" not in payload.path_template:
        raise HTTPException(
            400, "path_template must contain the {resource_id} placeholder, "
            "e.g. /v1/profiles/{resource_id}"
        )
    ep = ApiEndpoint(
        target_id=target_id,
        name=payload.name,
        path_template=payload.path_template,
        method=payload.method.upper(),
        resource_id=payload.resource_id,
        owner_account_id=payload.owner_account_id,
        expected_access=payload.expected_access,
        notes=payload.notes,
    )
    db.add(ep)
    db.commit()
    db.refresh(ep)
    return _to_out(ep)


@router.put("/endpoints/{endpoint_id}", response_model=EndpointOut)
def update_endpoint(endpoint_id: int, payload: EndpointUpdate, db: Session = Depends(get_db)):
    ep = db.get(ApiEndpoint, endpoint_id)
    if not ep:
        raise HTTPException(404, "Endpoint not found")
    data = payload.model_dump(exclude_unset=True)
    if data.get("method", "GET").upper() not in ALLOWED_METHODS:
        raise HTTPException(400, "Only read-only methods (GET/HEAD) are supported")
    owner = db.get(TestAccount, data.get("owner_account_id", ep.owner_account_id))
    if not owner or owner.target_id != ep.target_id:
        raise HTTPException(400, "Owner account must belong to the same target")
    for k, v in data.items():
        setattr(ep, k, v)
    db.commit()
    db.refresh(ep)
    return _to_out(ep)


@router.delete("/endpoints/{endpoint_id}", status_code=204)
def delete_endpoint(endpoint_id: int, db: Session = Depends(get_db)):
    ep = db.get(ApiEndpoint, endpoint_id)
    if not ep:
        raise HTTPException(404, "Endpoint not found")
    db.delete(ep)
    db.commit()
