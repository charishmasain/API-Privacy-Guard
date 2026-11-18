"""
API PrivacyGuard - Mock API Server
===================================
Local-only FastAPI app used to exercise the BOLA/IDOR detection engine.

Two modes:
  * "vulnerable" - object endpoints perform NO ownership validation.
  * "secure"     - object endpoints enforce ownership (403 for foreign objects).

Run (from the project root):
    python mock_api/server.py --mode vulnerable --port 8011
    python mock_api/server.py --mode secure     --port 8012

Endpoints (both modes):
    GET /health
    GET /v1/me                        -> identity of the bearer-token caller
    GET /v1/profiles/{id}             -> secure: ownership enforced
    GET /v1/insecure/profiles/{id}    -> vulnerable: NO ownership check
    GET /v1/me/profiles               -> profiles owned by the caller

THIS SERVER IS FOR LOCAL DEVELOPMENT ONLY. Never expose it to real data.
"""
from __future__ import annotations

import argparse
import os
import sys
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException

# Allow running from any working directory (mock_api is self-contained).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database import (  # noqa: E402
    get_resource,
    get_user_by_token,
    init_mock_db,
    list_resources_for_owner,
)


def create_app(mode: str = "vulnerable") -> FastAPI:
    if mode not in ("vulnerable", "secure"):
        raise ValueError(f"unknown mode: {mode}")

    app = FastAPI(title=f"API PrivacyGuard Mock API [{mode}]")

    def require_user(authorization: Optional[str] = Header(None)):
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="Missing bearer token")
        token = authorization.split(" ", 1)[1].strip()
        user = get_user_by_token(token)
        if user is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return user

    def resource_payload(res, caller_username: str) -> dict:
        # Deliberately include the owner username so the detection engine can
        # verify ownership claims inside the response body.
        return {
            "id": res.id,
            "owner": res.owner_username,
            "requested_by": caller_username,
            "title": res.title,
            "description": res.description,
            "contact": {
                "email": res.email,
                "phone": res.phone,
                "address": res.address,
            },
            "pii": {
                "date_of_birth": res.date_of_birth,
                "national_id": res.national_id,
                "credit_card": res.credit_card,
            },
        }

    def contact_payload(res, caller_username: str) -> dict:
        # Lower-sensitivity variant: exposes only contact PII (email/phone/
        # address) with NO national_id / credit_card, so a confirmed BOLA here
        # classifies as High rather than Critical.
        return {
            "id": res.id,
            "owner": res.owner_username,
            "requested_by": caller_username,
            "title": res.title,
            "contact": {
                "email": res.email,
                "phone": res.phone,
                "address": res.address,
            },
        }

    @app.get("/health")
    def health():
        return {"status": "ok", "mode": mode}

    @app.get("/v1/me")
    def me(user=Depends(require_user)):
        return {
            "id": user.id,
            "username": user.username,
            "full_name": user.full_name,
            "email": user.email,
        }

    @app.get("/v1/profiles/{resource_id}")
    def profiles_secure(resource_id: int, user=Depends(require_user)):
        """Secure variant: enforces object-level authorization."""
        res = get_resource(resource_id)
        if res is None:
            raise HTTPException(status_code=404, detail="Resource not found")
        if mode == "secure" and res.owner_username != user.username:
            raise HTTPException(status_code=403, detail="Forbidden: not your resource")
        # In "vulnerable" mode this path intentionally skips the check above.
        return resource_payload(res, user.username)

    @app.get("/v1/insecure/profiles/{resource_id}")
    def profiles_insecure(resource_id: int, user=Depends(require_user)):
        """Vulnerable variant: NEVER validates ownership (classic BOLA)."""
        res = get_resource(resource_id)
        if res is None:
            raise HTTPException(status_code=404, detail="Resource not found")
        return resource_payload(res, user.username)

    @app.get("/v1/insecure/contacts/{resource_id}")
    def contacts_insecure(resource_id: int, user=Depends(require_user)):
        """Vulnerable contact-only endpoint: no ownership check and no SSN/card.
        A confirmed BOLA here exposes email/phone/address -> High severity."""
        res = get_resource(resource_id)
        if res is None:
            raise HTTPException(status_code=404, detail="Resource not found")
        if mode == "secure" and res.owner_username != user.username:
            raise HTTPException(status_code=403, detail="Forbidden: not your resource")
        return contact_payload(res, user.username)

    @app.get("/v1/me/profiles")
    def my_profiles(user=Depends(require_user)):
        items = list_resources_for_owner(user.username)
        return {"count": len(items), "items": [resource_payload(r, user.username) for r in items]}

    return app


init_mock_db()

if __name__ == "__main__":
    import uvicorn

    parser = argparse.ArgumentParser(description="API PrivacyGuard mock API (local only)")
    parser.add_argument("--mode", choices=["vulnerable", "secure"], default="vulnerable")
    parser.add_argument("--port", type=int, default=8011)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    uvicorn.run(create_app(args.mode), host=args.host, port=args.port)
