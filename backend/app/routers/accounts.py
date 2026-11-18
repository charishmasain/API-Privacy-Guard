"""Test account management API (Feature C). Tokens are encrypted at rest."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.crypto import encrypt_token, mask_token
from app.core.database import get_db
from app.models import Target, TestAccount
from app.schemas import AccountCreate, AccountOut, AccountUpdate

router = APIRouter(prefix="/api", tags=["accounts"])


@router.get("/targets/{target_id}/accounts", response_model=list[AccountOut])
def list_accounts(target_id: int, db: Session = Depends(get_db)):
    return (
        db.query(TestAccount)
        .filter(TestAccount.target_id == target_id)
        .order_by(TestAccount.id)
        .all()
    )


@router.post("/targets/{target_id}/accounts", response_model=AccountOut, status_code=201)
def create_account(target_id: int, payload: AccountCreate, db: Session = Depends(get_db)):
    if not db.get(Target, target_id):
        raise HTTPException(404, "Target not found")
    acct = TestAccount(
        target_id=target_id,
        name=payload.name,
        description=payload.description,
        token_encrypted=encrypt_token(payload.token),
        token_masked=mask_token(payload.token),
        home_resource_id=payload.home_resource_id,
    )
    db.add(acct)
    db.commit()
    db.refresh(acct)
    return acct


@router.put("/accounts/{account_id}", response_model=AccountOut)
def update_account(account_id: int, payload: AccountUpdate, db: Session = Depends(get_db)):
    acct = db.get(TestAccount, account_id)
    if not acct:
        raise HTTPException(404, "Account not found")
    data = payload.model_dump(exclude_unset=True)
    token = data.pop("token", None)
    if token:
        acct.token_encrypted = encrypt_token(token)
        acct.token_masked = mask_token(token)
    for k, v in data.items():
        setattr(acct, k, v)
    db.commit()
    db.refresh(acct)
    return acct


@router.delete("/accounts/{account_id}", status_code=204)
def delete_account(account_id: int, db: Session = Depends(get_db)):
    acct = db.get(TestAccount, account_id)
    if not acct:
        raise HTTPException(404, "Account not found")
    db.delete(acct)
    db.commit()
