"""Scan orchestrator: executes the BOLA/IDOR workflow against a target and
persists results, evidence (masked) and findings to SQLite.

For every enabled endpoint with owner account A and a second account B:
  1. A accesses A's resource            (legitimate baseline)
  2. B accesses A's resource            (cross request  -> classify)
  3. B accesses B's own resource        (attacker baseline / caller-scope check)
  4. Reverse: B baseline, then A accesses B's resource
Evidence is scanned for sensitive data and masked before storage.
"""
from __future__ import annotations

import json
from datetime import datetime

from sqlalchemy.orm import Session

from app.core.crypto import decrypt_token
from app.engine import detector as D
from app.engine import sensitive
from app.engine.safe_http import SafeHttpClient
from app.models import ApiEndpoint, Finding, Scan, ScanResult, Target, TestAccount

REMEDIATION = (
    "Enforce object-level authorization: verify the authenticated caller owns (or is "
    "explicitly granted access to) the requested resource id before returning data. "
    "Deny with 403/404, log the attempt, and add regression tests covering "
    "cross-account access for this endpoint."
)


def _fmt_path(template: str, resource_id: str) -> str:
    if "{resource_id}" in template:
        return template.replace("{resource_id}", str(resource_id))
    # allow bare trailing {} or :id style? keep simple - append if no placeholder
    return template.format(resource_id=resource_id) if "{" in template else template


def _evidence_json(outcome, masked_body) -> str:
    return json.dumps(
        {
            "url": outcome.url,
            "status": outcome.status,
            "elapsed_ms": round(outcome.elapsed_ms, 1),
            "truncated": outcome.truncated,
            "masked_response_body": masked_body,
        },
        ensure_ascii=False,
    )


def _process_verdict(v: D.Verdict, cross_outcome) -> tuple[list[str], str]:
    """Return (sensitive categories, masked evidence JSON) for a verdict."""
    categories: list[str] = []
    masked_body = None
    body = v.raw_cross_body or ""
    try:
        parsed = json.loads(body) if body else None
    except ValueError:
        parsed = None
    if parsed is not None:
        categories, masked_body = sensitive.scan_json(parsed)
    else:
        categories = sensitive.detect_categories(body)
        masked_body = sensitive.mask_text(body[:4000])
    evidence = _evidence_json(cross_outcome, masked_body)
    return categories, evidence


def _run_direction(
    client: SafeHttpClient,
    endpoint: ApiEndpoint,
    victim: TestAccount,
    attacker: TestAccount,
    victim_resource: str,
    attacker_resource: str | None,
) -> ScanResult:
    path = _fmt_path(endpoint.path_template, victim_resource)
    victim_token = decrypt_token(victim.token_encrypted)
    attacker_token = decrypt_token(attacker.token_encrypted)

    baseline = client.request(endpoint.method, path, token=victim_token)
    cross = client.request(endpoint.method, path, token=attacker_token)

    attacker_own_body = None
    if attacker_resource:
        own_path = _fmt_path(endpoint.path_template, attacker_resource)
        own = client.request(endpoint.method, own_path, token=attacker_token)
        attacker_own_body = own.body_text

    verdict = D.classify_direction(
        baseline_status=baseline.status,
        baseline_body=baseline.body_text,
        cross=cross,
        victim_username=victim.name,
        attacker_username=attacker.name,
        resource_id=str(victim_resource),
        expected_access=endpoint.expected_access,
        attacker_own_body=attacker_own_body,
    )
    categories, evidence = _process_verdict(verdict, cross)

    return ScanResult(
        endpoint_id=endpoint.id,
        endpoint_name=endpoint.name,
        path=path,
        method=endpoint.method.upper(),
        direction=f"{attacker.name[:3].upper()}->{victim.name[:3].upper()}",
        requester_account_id=attacker.id,
        requester_name=attacker.name,
        owner_account_id=victim.id,
        owner_name=victim.name,
        resource_id=str(victim_resource),
        baseline_status=baseline.status,
        cross_status=cross.status,
        classification=verdict.classification,
        similarity=verdict.similarity,
        identity_check=verdict.identity_check,
        sensitive_categories=json.dumps(categories),
        evidence=evidence,
        explanation=verdict.explanation,
    )


def run_scan(db: Session, scan_id: int, endpoint_ids: list[int] | None = None) -> Scan:
    """Execute a full scan; safe to call from a FastAPI background task.

    When *endpoint_ids* is given, only those endpoints are tested (rescan)."""
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise ValueError(f"scan {scan_id} not found")
    target: Target = db.get(Target, scan.target_id)
    scan.status = "running"
    scan.started_at = datetime.utcnow()
    db.commit()

    try:
        client = SafeHttpClient(
            base_url=target.base_url,
            approved_host=target.host,
            allow_localhost=bool(target.allow_localhost),
        )
        accounts: list[TestAccount] = (
            db.query(TestAccount).filter(TestAccount.target_id == target.id).all()
        )
        query = db.query(ApiEndpoint).filter(
            ApiEndpoint.target_id == target.id, ApiEndpoint.enabled.is_(True)
        )
        if endpoint_ids:
            query = query.filter(ApiEndpoint.id.in_(endpoint_ids))
        endpoints: list[ApiEndpoint] = query.all()
        if len(accounts) < 2:
            raise ValueError("At least two test accounts are required for BOLA testing")

        counters = {
            D.CONFIRMED_BOLA: "confirmed_count",
            D.POTENTIAL_BOLA: "potential_count",
            D.BLOCKED: "blocked_count",
            D.AUTHORIZED: "authorized_count",
            D.INCONCLUSIVE: "inconclusive_count",
        }
        tested = 0

        for ep in endpoints:
            owner = db.get(TestAccount, ep.owner_account_id)
            if owner is None:
                continue
            tested += 1
            direction_results: list[ScanResult] = []

            # every other account attempts to access the owner's resource
            for attacker in accounts:
                if attacker.id == owner.id:
                    continue
                r = _run_direction(client, ep, owner, attacker, ep.resource_id, attacker.home_resource_id)
                direction_results.append(r)

            # reverse direction: owner attacks each attacker's own resource
            for other in accounts:
                if other.id == owner.id or not other.home_resource_id:
                    continue
                r = _run_direction(client, ep, other, owner, other.home_resource_id, owner.home_resource_id or ep.resource_id)
                direction_results.append(r)

            for r in direction_results:
                r.scan_id = scan.id
                db.add(r)
                db.flush()
                # endpoint-level counters use the WORST classification
                if r.classification in (D.CONFIRMED_BOLA, D.POTENTIAL_BOLA):
                    setattr(scan, counters[r.classification],
                            getattr(scan, counters[r.classification]) + 1)
                    db.add(_build_finding(scan, target, ep, r))
                db.commit()

            worst = D.worst_verdict(
                    [D.Verdict(classification=r.classification) for r in direction_results]
            )
            if worst and worst.classification in counters and worst.classification not in (
                D.CONFIRMED_BOLA, D.POTENTIAL_BOLA
            ):
                setattr(scan, counters[worst.classification],
                        getattr(scan, counters[worst.classification]) + 1)

        scan.endpoints_tested = tested
        scan.status = "completed"
    except Exception as exc:  # noqa: BLE001 - surface errors to the UI
        scan.status = "failed"
        scan.error_message = f"{type(exc).__name__}: {exc}"
    finally:
        scan.finished_at = datetime.utcnow()
        db.commit()
        db.refresh(scan)
    return scan


def _build_finding(scan: Scan, target: Target, ep: ApiEndpoint, r: ScanResult) -> Finding:
    categories = r.categories_list()
    severity = D.severity_for(r.classification, categories)
    confirmed = r.classification == D.CONFIRMED_BOLA
    name = (
        f"Broken Object Level Authorization (BOLA/IDOR) on {ep.name}"
        if confirmed
        else f"Potential BOLA/IDOR on {ep.name}"
    )
    impact_parts = [
        f"Account '{r.requester_name}' was able to {'read' if confirmed else 'possibly read'} "
        f"object '{r.resource_id}' belonging to '{r.owner_name}' via {r.method} {r.path}."
    ]
    if categories:
        impact_parts.append(
            "Exposed data categories: " + ", ".join(categories) + "."
        )
    return Finding(
        scan_id=scan.id,
        result_id=r.id,
        target_id=target.id,
        endpoint_id=ep.id,
        name=name,
        severity=severity,
        classification=r.classification,
        endpoint_name=ep.name,
        path=r.path,
        method=r.method,
        requester_name=r.requester_name,
        owner_name=r.owner_name,
        resource_id=r.resource_id,
        http_status=r.cross_status,
        exposed_categories=r.sensitive_categories,
        evidence=r.evidence,
        technical_explanation=(
            f"The endpoint did not enforce object-level authorization for the tested "
            f"resource id. {r.explanation}"
            if confirmed
            else r.explanation
        ),
        potential_impact=" ".join(impact_parts),
        remediation=REMEDIATION,
        status="open",
    )
