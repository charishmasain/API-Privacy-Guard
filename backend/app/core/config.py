"""Central configuration for the API PrivacyGuard backend."""
from __future__ import annotations

import os

APP_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # backend/app
DATA_DIR = os.path.join(os.path.dirname(APP_ROOT), "data")  # <project>/data
os.makedirs(DATA_DIR, exist_ok=True)

DATABASE_URL = os.environ.get(
    "PG_DATABASE_URL", f"sqlite:///{os.path.join(DATA_DIR, 'privacyguard.db')}"
)
KEY_FILE = os.path.join(DATA_DIR, ".secret.key")

# HTTP safety limits enforced by the detection engine
REQUEST_TIMEOUT_SECONDS = float(os.environ.get("PG_TIMEOUT", "15"))
MAX_RESPONSE_BYTES = int(os.environ.get("PG_MAX_BYTES", str(2 * 1024 * 1024)))  # 2 MB

# Only these HTTP methods may ever be issued by the scanner (read-only testing).
ALLOWED_METHODS = {"GET", "HEAD"}

# CORS: the dev frontend origins
FRONTEND_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:4173",
    "http://127.0.0.1:4173",
]
