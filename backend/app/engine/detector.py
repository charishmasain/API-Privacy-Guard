"""BOLA/IDOR classification logic (Feature E) - pure, DB-free, unit-testable.

Direction workflow implemented here:
  1. owner (User A) accesses own resource        -> legitimate baseline
  2. other user (User B) accesses A's resource   -> cross request
  3. compare responses with evidence rules       -> classification
The caller (scanner) runs this in BOTH directions.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from app.engine import comparator as C

# Classification constants (spec Feature E)
AUTHORIZED = "AUTHORIZED"
BLOCKED = "BLOCKED"
CONFIRMED_BOLA = "CONFIRMED_BOLA"
POTENTIAL_BOLA = "POTENTIAL_BOLA"
INCONCLUSIVE = "INCONCLUSIVE"

_SEVERITY_RANK = {CONFIRMED_BOLA: 4, POTENTIAL_BOLA: 3, INCONCLUSIVE: 2, BLOCKED: 1, AUTHORIZED: 0}

PII_CATEGORIES = {"EMAIL", "PHONE", "NATIONAL_ID", "DATE_OF_BIRTH", "ADDRESS", "CREDIT_CARD"}


@dataclass
class Verdict:
    classification: str
    identity_check: str = "unknown"   # victim_data | caller_scoped | generic | unknown
    similarity: Optional[float] = None
    structure_similarity: Optional[float] = None
    victim_markers: list[str] = field(default_factory=list)
    explanation: str = ""
    raw_cross_body: Optional[str] = None
    raw_baseline_body: Optional[str] = None

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK.get(self.classification, 0)


def _markers_for(username: str, external_identity: Optional[dict]) -> list[str]:
    """Strings that identify a principal inside response bodies."""
    markers = set()
    if username:
        markers.add(username.lower())
        markers.add(username.split("@")[0].lower())
    if external_identity:
        for v in external_identity.values():
            if isinstance(v, (str, int)) and str(v).strip():
                markers.add(str(v).lower())
    return sorted(markers)


def baseline_verdict(baseline_status: Optional[int]) -> Optional[str]:
    """Sanity-check the owner baseline; returns a classification when invalid."""
    if baseline_status is None:
        return INCONCLUSIVE
    if baseline_status in (401, 403):
        return INCONCLUSIVE  # owner cannot read own resource - credentials suspect
    if baseline_status == 404:
        return INCONCLUSIVE  # configured resource does not exist
    if not (200 <= baseline_status < 300):
        return INCONCLUSIVE
    return None  # baseline OK


def classify_direction(
    *,
    baseline_status: Optional[int],
    baseline_body: Optional[str],
    cross: "ResponseLike",
    victim_username: str,
    attacker_username: str,
    resource_id: str,
    expected_access: str = "owner_only",
    victim_identity: Optional[dict] = None,
    attacker_identity: Optional[dict] = None,
    attacker_own_body: Optional[str] = None,
) -> Verdict:
    """Classify ONE cross-account access attempt."""
    victim_markers = _markers_for(victim_username, victim_identity)
    attacker_markers = _markers_for(attacker_username, attacker_identity)

    # ---- transport / policy failures on the cross request ----
    if cross.error is not None:
        reason = "policy-blocked" if cross.blocked_by_policy else "network error"
        return Verdict(INCONCLUSIVE, explanation=f"Cross request failed ({reason}): {cross.error}")

    # ---- owner baseline must be valid before trusting any comparison ----
    bad = baseline_verdict(baseline_status)
    if bad:
        return Verdict(
            INCONCLUSIVE,
            explanation=(
                f"Owner baseline request returned {baseline_status}; cannot establish a "
                "legitimate reference response, so cross-access results are unreliable."
            ),
        )
    baseline_obj = C.parse_json(baseline_body or "")

    status = cross.status or 0

    # ---- explicit denials mean authorization IS enforced ----
    if status in (401, 403):
        return Verdict(
            BLOCKED,
            identity_check="none",
            explanation=f"Cross-account request denied with HTTP {status}; object-level authorization enforced.",
            raw_cross_body=cross.body_text, raw_baseline_body=baseline_body,
        )
    if status in (400, 404, 405, 406, 422):
        return Verdict(
            BLOCKED,
            identity_check="none",
            explanation=f"Foreign object not exposed (HTTP {status}).",
            raw_cross_body=cross.body_text, raw_baseline_body=baseline_body,
        )
    if status in (301, 302, 303, 307, 308):
        return Verdict(
            INCONCLUSIVE,
            explanation=f"Redirect (HTTP {status}) not followed by design; manual review needed.",
            raw_cross_body=cross.body_text, raw_baseline_body=baseline_body,
        )
    if status >= 500:
        return Verdict(
            INCONCLUSIVE,
            explanation=f"Server error HTTP {status} on cross request.",
            raw_cross_body=cross.body_text, raw_baseline_body=baseline_body,
        )

    # ---- HTTP 2xx: A 200 ALONE IS NOT A VULNERABILITY - examine the body ----
    cross_obj = C.parse_json(cross.body_text)
    if C.is_generic_body(cross_obj) and not cross.body_text.strip():
        return Verdict(
            BLOCKED,
            identity_check="generic",
            explanation="HTTP 2xx with empty/generic body - no object data disclosed.",
            raw_cross_body=cross.body_text, raw_baseline_body=baseline_body,
        )

    if expected_access == "public":
        return Verdict(
            AUTHORIZED,
            identity_check="public",
            explanation="Endpoint is configured as publicly readable; access is expected.",
            raw_cross_body=cross.body_text, raw_baseline_body=baseline_body,
        )

    sim = C.value_similarity(baseline_obj, cross_obj) if baseline_obj is not None and cross_obj is not None else None
    struct = C.structure_similarity(baseline_obj, cross_obj) if cross_obj is not None else 0.0
    victim_hits = sorted(C.contains_marker(cross_obj or cross.body_text, victim_markers))
    attacker_hits = sorted(C.contains_marker(cross_obj or cross.body_text, attacker_markers))
    echo = C.echoes_resource_id(cross_obj or {}, resource_id)
    own_claims = C.ownership_claims(cross_obj or {})
    victim_claimed = any(v.lower() in {m.lower() for m in victim_markers} for v in own_claims)

    # Does the body equal the ATTACKER's own data (API ignores id, scopes to caller)?
    caller_scoped = False
    if attacker_own_body is not None and cross_obj is not None:
        attacker_own_obj = C.parse_json(attacker_own_body)
        if attacker_own_obj is not None and C.value_similarity(attacker_own_obj, cross_obj) >= 0.8:
            caller_scoped = True

    common = dict(similarity=sim, structure_similarity=struct, victim_markers=victim_hits,
                  raw_cross_body=cross.body_text, raw_baseline_body=baseline_body)

    if caller_scoped and not victim_hits:
        return Verdict(AUTHORIZED, identity_check="caller_scoped",
                       explanation=("Cross response matches the requester's OWN data - the API "
                                    "scopes results to the caller despite the foreign id."), **common)

    # ---- strong, evidence-backed confirmation ----
    strong_similarity = sim is not None and sim >= 0.85
    if victim_hits and (echo or strong_similarity or struct >= 0.9) and (strong_similarity or victim_claimed):
        return Verdict(CONFIRMED_BOLA, identity_check="victim_data",
                       explanation=(f"Requester '{attacker_username}' received victim '{victim_username}'s "
                                    f"object data: victim identity fields present ({', '.join(victim_hits[:3])}), "
                                    f"resource id echoed={echo}, body similarity={sim:.2f}."
                                    if sim is not None else
                                    f"Victim identity markers {victim_hits[:3]} present in response."), **common)

    # ---- partial evidence ----
    probable = (
        (victim_hits and (echo or (sim is not None and sim >= 0.6)))
        or (echo and struct >= 0.8 and (sim is None or sim >= 0.5))
        or victim_claimed
        or (sim is not None and 0.75 <= sim < 0.85 and struct >= 0.85)
    )
    if probable:
        return Verdict(POTENTIAL_BOLA, identity_check="victim_data_partial",
                       explanation=("Cross-account response shows partial signs of the victim's object "
                                    f"(markers={victim_hits[:3]}, id echoed={echo}, similarity={sim}). "
                                    "Manual verification recommended."), **common)

    # 200 but no evidence the victim's object was returned -> not automatically a vuln
    return Verdict(INCONCLUSIVE, identity_check="unknown",
                   explanation=(f"HTTP {status} returned but response content could not be tied to the "
                                f"victim's object (similarity={sim}, victim markers absent). "
                                "Not classified as a vulnerability without evidence."), **common)


@dataclass
class ResponseLike:
    """Minimal duck-typed response used by unit tests (mirrors ResponseOutcome)."""

    status: Optional[int] = None
    body_text: str = ""
    error: Optional[str] = None
    blocked_by_policy: bool = False


def worst_verdict(verdicts: list[Verdict]) -> Optional[Verdict]:
    if not verdicts:
        return None
    return max(verdicts, key=lambda v: v.rank)


def severity_for(classification: str, categories: list[str]) -> str:
    """Map classification + exposed PII categories to a severity level."""
    pii = [c for c in categories if c in PII_CATEGORIES]
    if classification == CONFIRMED_BOLA:
        if "CREDIT_CARD" in pii or "NATIONAL_ID" in pii:
            return "Critical"
        if pii:
            return "High"
        return "High"
    if classification == POTENTIAL_BOLA:
        return "High" if pii else "Medium"
    if classification == BLOCKED:
        return "Informational"
    if classification == AUTHORIZED:
        return "Informational"
    return "Low"
