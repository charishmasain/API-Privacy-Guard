"""End-to-end tests of the BOLA detection engine against the LIVE mock APIs.

Spins up the vulnerable and secure mock servers on 127.0.0.1 and runs the
full scan orchestrator, asserting evidence-based classifications, PII
masking of stored evidence and correct Finding generation.
"""
import json

import pytest

from app.core.crypto import encrypt_token, mask_token
from app.engine.scanner import run_scan
from app.models import ApiEndpoint, Finding, Scan, ScanResult, Target, TestAccount

ALICE_TOKEN = "mock-token-alice-3f8a9c"
BOB_TOKEN = "mock-token-bob-77d1e0"


@pytest.fixture()
def seeded_target(db, mock_servers):
    """Target + 2 accounts + 2 endpoints (one vulnerable, one secure) for each server."""
    db.query(Finding).delete()
    db.query(ScanResult).delete()
    db.query(Scan).delete()
    db.query(ApiEndpoint).delete()
    db.query(TestAccount).delete()
    db.query(Target).delete()
    db.commit()

    targets = {}
    for mode in ("vulnerable", "secure"):
        from app.core.ssrf_guard import normalize_host

        t = Target(
            name=f"Mock {mode}",
            base_url=mock_servers[mode],
            host=normalize_host(mock_servers[mode]),
            authorization_confirmed=True,
            allow_localhost=True,
        )
        db.add(t)
        db.flush()
        alice = TestAccount(
            target_id=t.id, name="alice", description="synthetic user A",
            token_encrypted=encrypt_token(ALICE_TOKEN), token_masked=mask_token(ALICE_TOKEN),
            home_resource_id="101",
        )
        bob = TestAccount(
            target_id=t.id, name="bob", description="synthetic user B",
            token_encrypted=encrypt_token(BOB_TOKEN), token_masked=mask_token(BOB_TOKEN),
            home_resource_id="202",
        )
        db.add_all([alice, bob])
        db.flush()
        if mode == "vulnerable":
            db.add(ApiEndpoint(
                target_id=t.id, name="Insecure profile",
                path_template="/v1/insecure/profiles/{resource_id}", method="GET",
                resource_id="101", owner_account_id=alice.id, expected_access="owner_only",
            ))
        else:
            db.add(ApiEndpoint(
                target_id=t.id, name="Secure profile",
                path_template="/v1/profiles/{resource_id}", method="GET",
                resource_id="202", owner_account_id=bob.id, expected_access="owner_only",
            ))
        db.commit()
        targets[mode] = t
    return targets


def _run(db, target):
    scan = Scan(target_id=target.id, name="e2e")
    db.add(scan)
    db.commit()
    return run_scan(db, scan.id)


class TestVulnerableTargetDetection:
    def test_scan_completes(self, db, seeded_target):
        scan = _run(db, seeded_target["vulnerable"])
        assert scan.status == "completed", scan.error_message
        assert scan.endpoints_tested == 1

    def test_insecure_endpoint_confirmed_bola_both_directions(self, db, seeded_target):
        scan = _run(db, seeded_target["vulnerable"])
        results = [r for r in scan.results if "insecure" in r.path]
        assert {r.classification for r in results} == {"CONFIRMED_BOLA"}
        # both directions present: bob->alice and alice->bob
        pairs = {(r.requester_name, r.owner_name) for r in results}
        assert pairs == {("bob", "alice"), ("alice", "bob")}
        # similarity evidence recorded
        assert all(r.similarity is not None and r.similarity >= 0.85 for r in results)

    def test_findings_generated_with_pii_severity(self, db, seeded_target):
        scan = _run(db, seeded_target["vulnerable"])
        findings = [f for f in scan.findings]
        assert len(findings) == 2  # 1 endpoint x 2 directions
        assert all(f.status == "open" for f in findings)
        conf = [f for f in findings if f.classification == "CONFIRMED_BOLA"]
        assert any(f.severity == "Critical" for f in conf)  # SSN/CC exposed
        for f in conf:
            cats = f.categories_list()
            assert "EMAIL" in cats and "NATIONAL_ID" in cats
            assert f.remediation and f.potential_impact and f.technical_explanation

    def test_evidence_is_masked_and_never_leaks_full_pii(self, db, seeded_target):
        scan = _run(db, seeded_target["vulnerable"])
        for r in scan.results:
            text = r.evidence
            for raw in [
                "alice.johnson@example.com",
                "bob.smith@example.com",
                "123-45-6789",
                "987-65-4321",
                "4111 1111 1111 1111",
                ALICE_TOKEN,
                BOB_TOKEN,
            ]:
                assert raw not in text
            json.loads(r.evidence)  # evidence stays valid JSON

    def test_tokens_never_stored_in_plaintext(self, db, seeded_target):
        t = seeded_target["vulnerable"]
        for acct in t.accounts:
            assert ALICE_TOKEN not in acct.token_encrypted
            assert BOB_TOKEN not in acct.token_encrypted
            assert "*" in acct.token_masked


class TestSecureTargetDetection:
    def test_cross_access_blocked_not_confirmed(self, db, seeded_target):
        scan = _run(db, seeded_target["secure"])
        for r in scan.results:
            if r.classification == "CONFIRMED_BOLA":
                pytest.fail(f"secure server misclassified as BOLA: {r.path} {r.explanation}")
        # every cross attempt on the secure server is BLOCKED (403)
        assert {r.classification for r in scan.results} == {"BLOCKED"}
        assert scan.blocked_count == 1  # one endpoint, worst-classified blocked
        assert scan.confirmed_count == 0 and scan.potential_count == 0

    def test_no_findings_for_secure_target(self, db, seeded_target):
        scan = _run(db, seeded_target["secure"])
        assert len(scan.findings) == 0


class TestScannerPolicyEnforcement:
    def test_target_host_mismatch_blocks_requests(self, db, seeded_target, mock_servers):
        """A target whose stored host no longer matches its URL is refused."""
        t = seeded_target["vulnerable"]
        t.base_url = "http://127.0.0.1:1"  # dead port, host stays approved
        db.commit()
        scan = _run(db, t)
        # baseline fails -> inconclusive, never confirmed
        assert scan.confirmed_count == 0
        assert all(r.classification == "INCONCLUSIVE" for r in scan.results)
