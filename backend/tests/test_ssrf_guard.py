"""Tests for the SSRF / destination allow-list guard."""
import pytest

from app.core.ssrf_guard import (
    SSRFBlockedError,
    assert_method_allowed,
    normalize_host,
    validate_destination,
)


class TestHostAllowList:
    def test_unapproved_host_blocked(self):
        with pytest.raises(SSRFBlockedError, match="not the explicitly approved host"):
            validate_destination(
                "https://evil.example/x", approved_host="api.owned-by-us.com", allow_localhost=True
            )

    def test_non_http_scheme_blocked(self):
        with pytest.raises(SSRFBlockedError, match="scheme"):
            validate_destination(
                "file:///etc/passwd", approved_host="api.owned-by-us.com", allow_localhost=True
            )

    def test_no_host_blocked(self):
        with pytest.raises(SSRFBlockedError):
            validate_destination("http:///x", approved_host="", allow_localhost=True)

    def test_localhost_requires_explicit_flag(self):
        # default policy: private/loopback destinations are refused
        with pytest.raises(SSRFBlockedError, match="private/loopback"):
            validate_destination("http://127.0.0.1:9999/x", approved_host="127.0.0.1", allow_localhost=False)

    def test_localhost_allowed_with_flag(self):
        validate_destination("http://127.0.0.1:9999/x", approved_host="127.0.0.1", allow_localhost=True)

    def test_case_insensitive_host_match(self):
        validate_destination("http://LocalHost:8011/x", approved_host="localhost", allow_localhost=True)


class TestProhibitedDestinations:
    def test_metadata_ip_always_blocked(self, monkeypatch):
        import app.core.ssrf_guard as g

        # Simulate DNS rebinding of an approved host to the cloud metadata IP
        monkeypatch.setattr(
            g.socket, "getaddrinfo",
            lambda *a, **k: [(2, 1, 6, "", ("169.254.169.254", 80))],
        )
        with pytest.raises(SSRFBlockedError, match="prohibited"):
            g.validate_destination(
                "https://rebind.example/x", approved_host="rebind.example", allow_localhost=True
            )

    def test_dns_failure_blocked(self):
        with pytest.raises(SSRFBlockedError, match="DNS resolution failed"):
            validate_destination(
                "https://this-host-does-not-exist.invalid/x",
                approved_host="this-host-does-not-exist.invalid",
                allow_localhost=True,
            )


class TestMethodPolicy:
    def test_get_allowed(self):
        assert_method_allowed("get")
        assert_method_allowed("HEAD")

    @pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
    def test_destructive_methods_blocked(self, method):
        with pytest.raises(ValueError, match="prohibited"):
            assert_method_allowed(method)


class TestNormalizeHost:
    def test_extracts_lowercase_host(self):
        assert normalize_host("https://API.Example.COM:443/v1") == "api.example.com"

    @pytest.mark.parametrize("bad", ["ftp://x.com", "not a url", "//x.com"])
    def test_rejects_invalid(self, bad):
        with pytest.raises(ValueError):
            normalize_host(bad)
