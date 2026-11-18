"""SQLAlchemy ORM models for API PrivacyGuard (main application DB)."""
from __future__ import annotations

import json
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.core.database import Base


def utcnow() -> datetime:
    return datetime.utcnow()


class Target(Base):
    """An explicitly authorised API that may be scanned."""

    __tablename__ = "targets"

    id = Column(Integer, primary_key=True)
    name = Column(String(120), nullable=False)
    base_url = Column(String(500), nullable=False)
    host = Column(String(255), nullable=False, index=True)  # normalised lowercase host
    authorization_confirmed = Column(Boolean, nullable=False, default=False)
    allow_localhost = Column(Boolean, nullable=False, default=False)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow)

    accounts = relationship("TestAccount", back_populates="target", cascade="all, delete-orphan")
    endpoints = relationship("ApiEndpoint", back_populates="target", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="target", cascade="all, delete-orphan")


class TestAccount(Base):
    """A credentialed test user of the target API. Token is stored encrypted."""

    __tablename__ = "test_accounts"

    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    name = Column(String(120), nullable=False)
    description = Column(String(300), nullable=True)
    token_encrypted = Column(Text, nullable=False)
    token_masked = Column(String(60), nullable=False)  # e.g. "mock****3f8a"
    # Optional: the resource this account owns, used for reverse-direction testing
    home_resource_id = Column(String(60), nullable=True)
    created_at = Column(DateTime, default=utcnow)

    target = relationship("Target", back_populates="accounts")


class ApiEndpoint(Base):
    """A configured object-level endpoint to test for BOLA/IDOR."""

    __tablename__ = "api_endpoints"

    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    name = Column(String(160), nullable=False)
    path_template = Column(
        String(500), nullable=False
    )  # e.g. /v1/insecure/profiles/{resource_id}
    method = Column(String(10), nullable=False, default="GET")
    resource_id = Column(String(60), nullable=False)  # primary test resource id
    owner_account_id = Column(Integer, ForeignKey("test_accounts.id"), nullable=False)
    # Expected behaviour: "owner_only" (only the owner may read the object)
    expected_access = Column(String(30), nullable=False, default="owner_only")
    enabled = Column(Boolean, nullable=False, default=True)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow)

    target = relationship("Target", back_populates="endpoints")
    owner_account = relationship("TestAccount")


class Scan(Base):
    """One assessment run against a target."""

    __tablename__ = "scans"

    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    name = Column(String(160), nullable=False)
    status = Column(String(20), nullable=False, default="pending")  # pending/running/completed/failed
    endpoints_tested = Column(Integer, nullable=False, default=0)
    confirmed_count = Column(Integer, nullable=False, default=0)
    potential_count = Column(Integer, nullable=False, default=0)
    blocked_count = Column(Integer, nullable=False, default=0)
    authorized_count = Column(Integer, nullable=False, default=0)
    inconclusive_count = Column(Integer, nullable=False, default=0)
    error_message = Column(Text, nullable=True)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utcnow)

    target = relationship("Target", back_populates="scans")
    results = relationship("ScanResult", back_populates="scan", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")


class ScanResult(Base):
    """Per-endpoint, per-direction outcome of a BOLA test."""

    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    endpoint_id = Column(Integer, ForeignKey("api_endpoints.id"), nullable=True)
    endpoint_name = Column(String(160), nullable=False)
    path = Column(String(500), nullable=False)
    method = Column(String(10), nullable=False, default="GET")
    direction = Column(String(8), nullable=False)  # "A->B" or "B->A"
    requester_account_id = Column(Integer, nullable=True)
    requester_name = Column(String(120), nullable=False)
    owner_account_id = Column(Integer, nullable=True)
    owner_name = Column(String(120), nullable=False)
    resource_id = Column(String(60), nullable=False)
    baseline_status = Column(Integer, nullable=True)   # owner -> own resource
    cross_status = Column(Integer, nullable=True)     # requester -> foreign resource
    classification = Column(String(30), nullable=False)
    similarity = Column(Float, nullable=True)         # 0..1 body similarity vs baseline
    identity_check = Column(String(40), nullable=True)  # victim_data|caller_scoped|generic|unknown
    sensitive_categories = Column(Text, nullable=True)  # JSON list
    evidence = Column(Text, nullable=True)              # JSON, masked
    explanation = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow)

    scan = relationship("Scan", back_populates="results")

    def categories_list(self) -> list:
        return json.loads(self.sensitive_categories) if self.sensitive_categories else []


class Finding(Base):
    """A user-facing vulnerability derived from CONFIRMED/POTENTIAL scan results."""

    __tablename__ = "findings"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    result_id = Column(Integer, ForeignKey("scan_results.id"), nullable=True)
    target_id = Column(Integer, nullable=False)
    endpoint_id = Column(Integer, nullable=True)
    name = Column(String(200), nullable=False)
    severity = Column(String(15), nullable=False)  # Critical/High/Medium/Low/Informational
    classification = Column(String(30), nullable=False)
    endpoint_name = Column(String(160), nullable=False)
    path = Column(String(500), nullable=False)
    method = Column(String(10), nullable=False)
    requester_name = Column(String(120), nullable=False)
    owner_name = Column(String(120), nullable=False)
    resource_id = Column(String(60), nullable=False)
    http_status = Column(Integer, nullable=True)
    exposed_categories = Column(Text, nullable=True)  # JSON list
    evidence = Column(Text, nullable=True)            # masked JSON evidence
    technical_explanation = Column(Text, nullable=False)
    potential_impact = Column(Text, nullable=False)
    remediation = Column(Text, nullable=False)
    status = Column(String(20), nullable=False, default="open")  # open|fixed|reopened
    first_seen_at = Column(DateTime, default=utcnow)
    last_seen_at = Column(DateTime, default=utcnow)
    resolved_at = Column(DateTime, nullable=True)

    scan = relationship("Scan", back_populates="findings")

    def categories_list(self) -> list:
        return json.loads(self.exposed_categories) if self.exposed_categories else []
