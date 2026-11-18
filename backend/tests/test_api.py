"""Functional tests of the complete HTTP API against the live mock servers."""
import json

import pytest
from fastapi.testclient import TestClient

ALICE_TOKEN = "mock-token-alice-3f8a9c"
BOB_TOKEN = "mock-token-bob-77d1e0"


@pytest.fixture()
def client(db_engine):
    # fresh tables per test so aggregate-based assertions are deterministic
    from app.core.database import Base
    import app.models  # noqa: F401

    Base.metadata.drop_all(db_engine)
    Base.metadata.create_all(db_engine)

    from app.main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture()
def setup_target(client, mock_servers):
    """Create authorised target + accounts + endpoints on the vulnerable mock."""
    r = client.post("/api/targets", json={
        "name": "Vuln Shop API",
        "base_url": mock_servers["vulnerable"],
        "authorization_confirmed": True,
        "allow_localhost": True,
    })
    assert r.status_code == 201, r.text
    target = r.json()
    for name, token, home in [("alice", ALICE_TOKEN, "101"), ("bob", BOB_TOKEN, "202")]:
        r = client.post(f"/api/targets/{target['id']}/accounts", json={
            "name": name, "token": token, "description": f"synthetic {name}",
            "home_resource_id": home,
        })
        assert r.status_code == 201
        assert token not in json.dumps(r.json())  # never returns raw token
    r = client.post(f"/api/targets/{target['id']}/endpoints", json={
        "name": "Profile by id (insecure)",
        "path_template": "/v1/insecure/profiles/{resource_id}",
        "method": "GET",
        "resource_id": "101",
        "owner_account_id": target["id"] and _alice_id(client, target["id"]),
    })
    assert r.status_code == 201, r.text
    return target


def _alice_id(client, target_id):
    return client.get(f"/api/targets/{target_id}/accounts").json()[0]["id"]


class TestTargetPolicy:
    def test_requires_authorization_confirmation(self, client):
        r = client.post("/api/targets", json={
            "name": "x", "base_url": "https://api.example.com",
            "authorization_confirmed": False,
        })
        assert r.status_code == 422  # schema-level refusal

    def test_rejects_invalid_base_url(self, client):
        r = client.post("/api/targets", json={
            "name": "x", "base_url": "ftp://api.example.com",
            "authorization_confirmed": True,
        })
        assert r.status_code == 400


class TestAccountSecurity:
    def test_tokens_masked_in_all_responses(self, client, setup_target):
        accts = client.get(f"/api/targets/{setup_target['id']}/accounts").json()
        assert len(accts) == 2
        for a in accts:
            assert "****" in a["token_masked"]
            assert a["token_masked"] not in (ALICE_TOKEN, BOB_TOKEN)

    def test_update_token_keeps_masked(self, client, setup_target):
        acct = client.get(f"/api/targets/{setup_target['id']}/accounts").json()[0]
        r = client.put(f"/api/accounts/{acct['id']}", json={"token": "new-secret-token-abcdef12"})
        assert r.status_code == 200
        masked = r.json()["token_masked"]
        assert "****" in masked and masked.endswith("ef12")
        assert "new-secret-token-abcdef12" not in masked


class TestEndpointValidation:
    def test_rejects_non_placeholder_path(self, client, setup_target):
        acct = client.get(f"/api/targets/{setup_target['id']}/accounts").json()[0]
        r = client.post(f"/api/targets/{setup_target['id']}/endpoints", json={
            "name": "bad", "path_template": "/v1/profiles/fixed",
            "method": "GET", "resource_id": "1", "owner_account_id": acct["id"],
        })
        assert r.status_code == 400

    def test_rejects_destructive_method(self, client, setup_target):
        acct = client.get(f"/api/targets/{setup_target['id']}/accounts").json()[0]
        r = client.post(f"/api/targets/{setup_target['id']}/endpoints", json={
            "name": "bad", "path_template": "/v1/profiles/{resource_id}",
            "method": "DELETE", "resource_id": "1", "owner_account_id": acct["id"],
        })
        assert r.status_code == 422


class TestScanFlow:
    def _wait_done(self, client, scan_id):
        for _ in range(100):
            s = client.get(f"/api/scans/{scan_id}").json()
            if s["status"] in ("completed", "failed"):
                return s
            import time

            time.sleep(0.05)
        pytest.fail("scan did not finish")

    def test_scan_detects_confirmed_bola(self, client, setup_target):
        r = client.post("/api/scans", json={"target_id": setup_target["id"]})
        assert r.status_code == 201
        scan = self._wait_done(client, r.json()["id"])
        assert scan["status"] == "completed", scan["error_message"]
        assert scan["confirmed_count"] == 2  # both directions
        for res in scan["results"]:
            assert res["classification"] == "CONFIRMED_BOLA"
            assert "alice.johnson@example.com" not in (res["evidence"] or "")

    def test_findings_and_dashboard(self, client, setup_target):
        r = client.post("/api/scans", json={"target_id": setup_target["id"]})
        scan_id = self._wait_done(client, r.json()["id"])["id"]
        findings = client.get("/api/findings", params={"scan_id": scan_id}).json()
        assert len(findings) == 2
        f = findings[0]
        for field in ["name", "severity", "path", "requester_name", "owner_name",
                      "http_status", "evidence", "exposed_categories",
                      "technical_explanation", "potential_impact", "remediation"]:
            assert field in f
        stats = client.get("/api/dashboard/stats").json()
        assert stats["total_scans"] >= 1
        assert stats["confirmed_vulnerabilities"] == 2
        assert any(b["count"] > 0 for b in stats["severity_chart"])

    def test_matrix_cells(self, client, setup_target):
        r = client.post("/api/scans", json={"target_id": setup_target["id"]})
        scan_id = self._wait_done(client, r.json()["id"])["id"]
        m = client.get(f"/api/matrix/{scan_id}").json()
        assert len(m["accounts"]) == 2 and len(m["endpoints"]) == 1
        classes = {c["classification"] for c in m["cells"]}
        assert "OWNER" in classes and "CONFIRMED_BOLA" in classes

    def test_pdf_report(self, client, setup_target):
        r = client.post("/api/scans", json={"target_id": setup_target["id"]})
        scan_id = self._wait_done(client, r.json()["id"])["id"]
        pdf = client.get(f"/api/reports/{scan_id}/pdf")
        assert pdf.status_code == 200
        assert pdf.content[:5] == b"%PDF-"
        assert ALICE_TOKEN.encode() not in pdf.content
        assert b"alice.johnson@example.com" not in pdf.content

    def test_scan_requires_two_accounts(self, client, mock_servers):
        r = client.post("/api/targets", json={
            "name": "solo", "base_url": mock_servers["secure"],
            "authorization_confirmed": True, "allow_localhost": True,
        })
        tid = r.json()["id"]
        client.post(f"/api/targets/{tid}/accounts", json={"name": "only", "token": "tok-123456"})
        client.post(f"/api/targets/{tid}/endpoints", json={
            "name": "e", "path_template": "/v1/profiles/{resource_id}",
            "method": "GET", "resource_id": "101", "owner_account_id": 999,
        })
        r = client.post("/api/scans", json={"target_id": tid})
        assert r.status_code == 400


class TestFixVerification:
    def test_verification_endpoint_reports_first_scan_baseline(self, client, setup_target):
        r = client.post("/api/scans", json={"target_id": setup_target["id"]})
        for _ in range(100):
            s = client.get(f"/api/scans/{r.json()['id']}").json()
            if s["status"] in ("completed", "failed"):
                break
            import time

            time.sleep(0.05)
        v = client.get(f"/api/scans/{s['id']}/verification").json()
        assert v["previous_scan_id"] is None  # no earlier scan -> nothing to compare
