"""Tests for sensitive-data detection and masking (Feature F)."""
from app.engine import sensitive

SAMPLE = (
    "Email alice.johnson@example.com, phone +1-555-010-1010, "
    "DOB 1988-04-12, SSN 123-45-6789, "
    "address 42 Maple Street, Springfield, IL 62701, "
    "card 4111 1111 1111 1111"
)


class TestDetection:
    def test_detects_all_categories(self):
        found = sensitive.detect(SAMPLE)
        assert set(found) >= {"EMAIL", "PHONE", "DATE_OF_BIRTH", "NATIONAL_ID", "ADDRESS", "CREDIT_CARD"}

    def test_email_value(self):
        assert "alice.johnson@example.com" in sensitive.detect(SAMPLE)["EMAIL"]

    def test_luhn_filters_fake_cards(self):
        # 1234 5678 9012 3456 fails Luhn -> must NOT be flagged as CREDIT_CARD
        assert "CREDIT_CARD" not in sensitive.detect("num 1234 5678 9012 3456")

    def test_no_false_positive_on_plain_text(self):
        assert sensitive.detect("hello world, nothing personal here") == {}

    def test_categories_sorted_list(self):
        cats = sensitive.detect_categories("contact: bob@example.com")
        assert cats == ["EMAIL"]


class TestMasking:
    def test_mask_email(self):
        m = sensitive.mask_value("EMAIL", "alice.johnson@example.com")
        assert "alice.johnson" not in m
        assert m.startswith("a")

    def test_mask_ssn(self):
        m = sensitive.mask_value("NATIONAL_ID", "SSN 123-45-6789")
        assert "123-45" not in m
        assert "6789" in m  # last-4 retained for evidence context

    def test_mask_credit_card(self):
        m = sensitive.mask_value("CREDIT_CARD", "4111 1111 1111 1111")
        assert "4111 1111" not in m
        assert m.endswith("1111")

    def test_mask_text_replaces_all_values(self):
        masked = sensitive.mask_text(SAMPLE)
        for raw in ["alice.johnson@example.com", "123-45-6789", "4111 1111 1111 1111"]:
            assert raw not in masked

    def test_mask_json_deep_by_key_and_value(self):
        obj = {
            "username": "bob",
            "contact": {"email": "alice@example.com"},
            "salary": 98000,
            "national_id": "SSN 123-45-6789",
        }
        masked = sensitive.mask_json_deep(obj)
        text = str(masked)
        assert "alice@example.com" not in text
        assert "123-45-6789" not in text
        assert "98000" not in text          # masked by suspicious key
        assert masked["username"] == "bob"  # non-sensitive values preserved

    def test_scan_json_returns_categories_and_masked_copy(self):
        cats, masked = sensitive.scan_json({"email": "x.y@example.com"})
        assert "EMAIL" in cats
        assert "x.y@example.com" not in str(masked)
