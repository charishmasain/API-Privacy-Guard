"""Pydantic request/response schemas."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator


# ---------- Targets ----------
class TargetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    base_url: str
    authorization_confirmed: bool = Field(False)
    allow_localhost: bool = False
    notes: Optional[str] = None

    @field_validator("authorization_confirmed")
    @classmethod
    def must_be_authorized(cls, v):
        if not v:
            raise ValueError("You must confirm authorization to test this API")
        return v


class TargetUpdate(BaseModel):
    name: Optional[str] = None
    base_url: Optional[str] = None
    authorization_confirmed: Optional[bool] = None
    allow_localhost: Optional[bool] = None
    notes: Optional[str] = None


class TargetOut(BaseModel):
    id: int
    name: str
    base_url: str
    host: str
    authorization_confirmed: bool
    allow_localhost: bool
    notes: Optional[str]
    created_at: datetime
    account_count: int = 0
    endpoint_count: int = 0

    model_config = {"from_attributes": True}


# ---------- Accounts ----------
class AccountCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    token: str = Field(min_length=4, description="Bearer token (stored encrypted)")
    description: Optional[str] = None
    home_resource_id: Optional[str] = None


class AccountUpdate(BaseModel):
    name: Optional[str] = None
    token: Optional[str] = None  # omit to keep existing token
    description: Optional[str] = None
    home_resource_id: Optional[str] = None


class AccountOut(BaseModel):
    id: int
    target_id: int
    name: str
    description: Optional[str]
    token_masked: str
    home_resource_id: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}


# ---------- Endpoints ----------
class EndpointCreate(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    path_template: str
    method: str = "GET"
    resource_id: str
    owner_account_id: int
    expected_access: str = "owner_only"  # owner_only | public
    notes: Optional[str] = None

    @field_validator("method")
    @classmethod
    def read_only(cls, v: str) -> str:
        from app.core.config import ALLOWED_METHODS

        vu = v.upper()
        if vu not in ALLOWED_METHODS:
            raise ValueError(f"only read-only methods are supported {sorted(ALLOWED_METHODS)}")
        return vu

    @field_validator("expected_access")
    @classmethod
    def valid_access(cls, v: str) -> str:
        if v not in ("owner_only", "public"):
            raise ValueError("expected_access must be owner_only or public")
        return v


class EndpointUpdate(EndpointCreate):
    enabled: Optional[bool] = True


class EndpointOut(BaseModel):
    id: int
    target_id: int
    name: str
    path_template: str
    method: str
    resource_id: str
    owner_account_id: int
    owner_name: Optional[str] = None
    expected_access: str
    enabled: bool
    notes: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}


# ---------- Scans ----------
class ScanCreate(BaseModel):
    target_id: int
    name: Optional[str] = None
    endpoint_ids: Optional[list[int]] = None  # limit scan scope (rescan)


class ScanOut(BaseModel):
    id: int
    target_id: int
    target_name: Optional[str] = None
    name: str
    status: str
    endpoints_tested: int
    confirmed_count: int
    potential_count: int
    blocked_count: int
    authorized_count: int
    inconclusive_count: int
    error_message: Optional[str]
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanResultOut(BaseModel):
    id: int
    scan_id: int
    endpoint_id: Optional[int]
    endpoint_name: str
    path: str
    method: str
    direction: str
    requester_name: str
    owner_name: str
    resource_id: str
    baseline_status: Optional[int]
    cross_status: Optional[int]
    classification: str
    similarity: Optional[float]
    identity_check: Optional[str]
    sensitive_categories: Optional[str]
    evidence: Optional[str]
    explanation: Optional[str]

    model_config = {"from_attributes": True}


class ScanDetailOut(ScanOut):
    results: list[ScanResultOut] = []


# ---------- Findings ----------
class FindingOut(BaseModel):
    id: int
    scan_id: int
    result_id: Optional[int]
    target_id: int
    endpoint_id: Optional[int]
    name: str
    severity: str
    classification: str
    endpoint_name: str
    path: str
    method: str
    requester_name: str
    owner_name: str
    resource_id: str
    http_status: Optional[int]
    exposed_categories: Optional[str]
    evidence: Optional[str]
    technical_explanation: str
    potential_impact: str
    remediation: str
    status: str
    first_seen_at: datetime
    last_seen_at: datetime
    resolved_at: Optional[datetime]

    model_config = {"from_attributes": True}


# ---------- Dashboard ----------
class SeverityBucket(BaseModel):
    severity: str
    count: int


class DashboardStats(BaseModel):
    total_scans: int
    endpoints_tested: int
    confirmed_vulnerabilities: int
    protected_endpoints: int
    recent_scans: list[ScanOut]
    severity_chart: list[SeverityBucket]


# ---------- Matrix ----------
class MatrixCell(BaseModel):
    account_id: int
    endpoint_id: int
    resource_id: str
    classification: str
    cross_status: Optional[int]
    similarity: Optional[float]


class MatrixOut(BaseModel):
    scan_id: int
    accounts: list[dict]
    endpoints: list[dict]
    cells: list[MatrixCell]
