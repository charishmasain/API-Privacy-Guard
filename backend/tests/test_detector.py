"""Unit tests for the evidence-based BOLA classifier (no network, no DB)."""
import json

import pytest

from app.engine.detector import (
    AUTHORIZED,
    BLOCKED,
    CONFIRMED_BOLA,
    INCONCLUSIVE,
    POTENTIAL_BOLA,
    ResponseLike,
    classify_direction,
    severity_for,
    worst_verdict,
)

VICTIM_OBJ = {
    "id": 101,
    "owner": "alice",
    "requested_by": "alice",
    "title": "Alice's Customer Profile",
    "contact": {"email": "alice.johnson@example.com", "phone": "+1-555-010-1010"},
    "pii": {"date_of_birth": "1988-04-12", "national_id": "SSN 123-45-6789"},
}
ATTACKER_OBJ = {
    "id": 202,
    "owner": "bob",
    "requested_by": "bob",
    "title": "Bob's Customer Profile",
    "contact": {"email": "bob.smith@example.com", "phone": "+1-555-020-2020"},
    "pii": {"date_of_birth": "1975-09-30", "national_id": "SSN 987-65-4321"},
}
BASELINE = json.dumps(VICTIM_OBJ)
LEAK = json.dumps({**VICTIM_OBJ, "requested_by": "bob"})
OWN_SCOPED = json.dumps(ATTACKER_OBJ)


def call(cross: ResponseLike, **kw) -> str:
    kwargs = dict(
        baseline_status=200,
        baseline_body=BASELINE,
        cross=cross,
        victim_username="alice",
        attacker_username="bob",
        resource_id="101",
        attacker_own_body=OWN_SCOPED,
    )
    kwargs.update(kw)
    return classify_direction(**kwargs).classification


class TestBlockedAndInconclusive:
    def test_403_is_blocked_not_vuln(self):
        assert call(ResponseLike(status=403, body_text="Forbidden")) == BLOCKED

    def test_401_is_blocked(self):
        assert call(ResponseLike(status=401, body_text="")) == BLOCKED

    def test_404_is_blocked(self):
        assert call(ResponseLike(status=404, body_text="not found")) == BLOCKED

    def test_network_error_inconclusive(self):
        assert call(ResponseLike(error="connect timeout")) == INCONCLUSIVE

    def test_policy_blocked_inconclusive(self):
        assert call(ResponseLike(error="host mismatch", blocked_by_policy=True)) == INCONCLUSIVE

    def test_5xx_inconclusive(self):
        assert call(ResponseLike(status=500, body_text="boom")) == INCONCLUSIVE

    def test_failed_baseline_inconclusive(self):
        # owner cannot read own resource -> everything is unreliable
        assert call(ResponseLike(status=200, body_text=LEAK), baseline_status=403) == INCONCLUSIVE

    def test_redirect_not_followed(self):
        assert call(ResponseLike(status=302, body_text="")) == INCONCLUSIVE


class TestNotEveryHttp200IsAVuln:
    def test_200_empty_body_is_blocked(self):
        assert call(ResponseLike(status=200, body_text="")) == BLOCKED

    def test_200_generic_json_body_is_not_confirmed(self):
        v = classify_direction(
            baseline_status=200, baseline_body=BASELINE,
            cross=ResponseLike(status=200, body_text=json.dumps({"ok": True})),
            victim_username="alice", attacker_username="bob", resource_id="101",
        )
        assert v.classification == INCONCLUSIVE
        assert v.classification not in (CONFIRMED_BOLA, POTENTIAL_BOLA)

    def test_200_returning_callers_own_data_is_authorized(self):
        # API ignores the id and scopes to caller -> NOT a vulnerability
        assert call(ResponseLike(status=200, body_text=OWN_SCOPED)) == AUTHORIZED

    def test_public_endpoint_is_authorized(self):
        assert call(ResponseLike(status=200, body_text=LEAK), expected_access="public") == AUTHORIZED


class TestConfirmedAndPotential:
    def test_full_victim_data_leak_confirmed(self):
        assert call(ResponseLike(status=200, body_text=LEAK)) == CONFIRMED_BOLA

    def test_near_identical_leak_with_owner_field_confirmed(self):
        leaked = json.dumps({**VICTIM_OBJ, "requested_by": "mallory"})
        assert call(ResponseLike(status=200, body_text=leaked)) == CONFIRMED_BOLA

    def test_partial_evidence_is_potential_not_confirmed(self):
        # id echoed + same structure but DIFFERENT content values
        body = json.dumps({
            "id": 101, "owner": "someone-else", "requested_by": "bob",
            "title": "Other", "contact": {"email": "x@y.z", "phone": "0"},
            "pii": {"date_of_birth": "1999-01-01", "national_id": "n"},
        })
        result = classify_direction(
            baseline_status=200, baseline_body=BASELINE,
            cross=ResponseLike(status=200, body_text=body),
            victim_username="alice", attacker_username="bob", resource_id="101",
            attacker_own_body=OWN_SCOPED,
        )
        assert result.classification == POTENTIAL_BOLA

    def test_confirmed_explanation_carries_evidence(self):
        v = classify_direction(
            baseline_status=200, baseline_body=BASELINE,
            cross=ResponseLike(status=200, body_text=LEAK),
            victim_username="alice", attacker_username="bob", resource_id="101",
            attacker_own_body=OWN_SCOPED,
        )
        assert v.similarity is not None and v.similarity >= 0.85
        assert "alice" in v.victim_markers


class TestSeverityAndAggregation:
    def test_severity_confirmed_with_national_id_is_critical(self):
        assert severity_for(CONFIRMED_BOLA, ["NATIONAL_ID", "EMAIL"]) == "Critical"

    def test_severity_confirmed_with_email_is_high(self):
        assert severity_for(CONFIRMED_BOLA, ["EMAIL"]) == "High"

    def test_severity_confirmed_without_pii_is_high(self):
        assert severity_for(CONFIRMED_BOLA, []) == "High"

    def test_severity_potential(self):
        assert severity_for(POTENTIAL_BOLA, ["EMAIL"]) == "High"
        assert severity_for(POTENTIAL_BOLA, []) == "Medium"

    def test_worst_verdict_prefers_confirmed(self):
        from app.engine.detector import Verdict

        worst = worst_verdict(
            [Verdict(BLOCKED), Verdict(CONFIRMED_BOLA), Verdict(POTENTIAL_BOLA)]
        )
        assert worst.classification == CONFIRMED_BOLA

    def test_worst_verdict_none_when_empty(self):
        assert worst_verdict([]) is None
