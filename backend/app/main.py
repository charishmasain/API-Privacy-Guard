"""API PrivacyGuard - FastAPI backend entrypoint."""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import FRONTEND_ORIGINS
from app.core.database import init_db
from app.routers import accounts, dashboard, endpoints, findings, matrix, scans, targets

app = FastAPI(
    title="API PrivacyGuard",
    description="BOLA/IDOR security assessment platform - authorised testing only",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=FRONTEND_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.get("/api/health")
def health():
    return {"status": "ok", "app": "API PrivacyGuard backend"}


@app.get("/api/policy")
def policy():
    """Live safety-policy configuration surfaced on the Settings page."""
    from app.core import config

    return {
        "allowed_methods": sorted(config.ALLOWED_METHODS),
        "request_timeout_seconds": config.REQUEST_TIMEOUT_SECONDS,
        "max_response_bytes": config.MAX_RESPONSE_BYTES,
        "token_encryption": "Fernet (AES-128-CBC + HMAC-SHA256), key in data/.secret.key",
        "redirects_followed": False,
        "ssrf_protection": "Approved-host allow-list, per-request DNS revalidation, "
        "metadata/link-local/private ranges blocked (loopback only via explicit allow_localhost)",
        "mock_api_commands": [
            "python mock_api/server.py --mode vulnerable --port 8011",
            "python mock_api/server.py --mode secure --port 8012",
        ],
    }


app.include_router(targets.router)
app.include_router(accounts.router)
app.include_router(endpoints.router)
app.include_router(scans.router)
app.include_router(findings.router)
app.include_router(matrix.router)
app.include_router(dashboard.router)

from app.routers import reports  # noqa: E402  (PDF report generation)

app.include_router(reports.router)
