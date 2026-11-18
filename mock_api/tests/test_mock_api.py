"""
Automated tests for the mock API environment (Phase 1).

Verifies the expected behaviour matrix from the specification:

| Test                 | Vulnerable API | Secure API |
|----------------------|----------------|------------|
| Alice accesses 101   | 200            | 200        |
| Alice accesses 202   | 200            | 403        |
| Bob accesses 202     | 200            | 200        |
| Bob accesses 101     | 200            | 403        |
"""
import pytest

ALICE = {"Authorization": "Bearer mock-token-alice-3f8a9c"}
BOB = {"Authorization": "Bearer mock-token-bob-77d1e0"}

VULN_PATH = "/v1/insecure/profiles/{id}"
SECURE_PATH = "/v1/profiles/{id}"


class TestHealthAndAuth:
    def test_health_vulnerable(self, vulnerable_client):
        r = vulnerable_client.get("/health")
        assert r.status_code == 200
        assert r.json()["mode"] == "vulnerable"

    def test_health_secure(self, secure_client):
        r = secure_client.get("/health")
        assert r.status_code == 200
        assert r.json()["mode"] == "secure"

    def test_missing_token_is_401(self, secure_client):
        assert secure_client.get("/v1/me").status_code == 401

    def test_invalid_token_is_401(self, secure_client):
        r = secure_client.get("/v1/me", headers={"Authorization": "Bearer nope"})
        assert r.status_code == 401

    def test_me_returns_caller_identity(self, secure_client):
        assert secure_client.get("/v1/me", headers=ALICE).json()["username"] == "alice"
        assert secure_client.get("/v1/me", headers=BOB).json()["username"] == "bob"


class TestVulnerableApiMatrix:
    """The vulnerable endpoint must leak ANY object to ANY authenticated user."""

    @pytest.mark.parametrize(
        "headers,resource_id,expected_owner",
        [
            (ALICE, 101, "alice"),
            (ALICE, 202, "bob"),
            (BOB, 202, "bob"),
            (BOB, 101, "alice"),
        ],
    )
    def test_access_matrix(self, vulnerable_client, headers, resource_id, expected_owner):
        r = vulnerable_client.get(VULN_PATH.format(id=resource_id), headers=headers)
        assert r.status_code == 200
        body = r.json()
        assert body["id"] == resource_id
        assert body["owner"] == expected_owner
        # Sensitive data present so the scanner's PII detection has something to find
        assert "@" in body["contact"]["email"]
        assert body["pii"]["national_id"]

    def test_unknown_resource_is_404(self, vulnerable_client):
        r = vulnerable_client.get(VULN_PATH.format(id=999999), headers=ALICE)
        assert r.status_code == 404


class TestSecureApiMatrix:
    """The secure endpoint must return 403 when the caller does not own the object."""

    @pytest.mark.parametrize(
        "headers,resource_id,expected_status",
        [
            (ALICE, 101, 200),  # own object -> allowed
            (ALICE, 202, 403),  # foreign object -> denied
            (BOB, 202, 200),    # own object -> allowed
            (BOB, 101, 403),    # foreign object -> denied
        ],
    )
    def test_access_matrix(self, secure_client, headers, resource_id, expected_status):
        r = secure_client.get(SECURE_PATH.format(id=resource_id), headers=headers)
        assert r.status_code == expected_status

    def test_own_object_payload_not_leaked_on_403(self, secure_client):
        r = secure_client.get(SECURE_PATH.format(id=101), headers=BOB)
        assert r.status_code == 403
        assert "alice" not in r.text.lower() or "forbidden" in r.text.lower()


class TestOwnershipScopedListings:
    def test_alice_sees_only_own_profiles(self, secure_client):
        r = secure_client.get("/v1/me/profiles", headers=ALICE)
        assert r.status_code == 200
        items = r.json()["items"]
        assert len(items) >= 1
        assert all(i["owner"] == "alice" for i in items)

    def test_bob_sees_only_own_profiles(self, secure_client):
        r = secure_client.get("/v1/me/profiles", headers=BOB)
        items = r.json()["items"]
        assert all(i["owner"] == "bob" for i in items)
        assert {i["id"] for i in items} == {202}
