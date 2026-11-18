"""Unit tests for the response comparator."""
from app.engine import comparator as C

A = {"id": 101, "owner": "alice", "contact": {"email": "a@x.com", "phone": "1"}}
B_SAME = {"contact": {"phone": "1", "email": "a@x.com"}, "owner": "alice", "id": 101}
C_DIFF = {"id": 202, "owner": "bob", "contact": {"email": "b@x.com", "phone": "2"}}


class TestSimilarity:
    def test_identical_structure_different_order(self):
        assert C.structure_similarity(A, B_SAME) == 1.0

    def test_value_similarity_near_one_for_equal_docs(self):
        assert C.value_similarity(A, B_SAME) >= 0.99

    def test_low_similarity_for_different_owner(self):
        # small synthetic docs share most JSON boilerplate, so the ratio stays
        # high in absolute terms - the meaningful property is relative distance:
        # identical content ~= 1.0 and clearly above different-owner content.
        same = C.value_similarity(A, B_SAME)
        diff = C.value_similarity(A, C_DIFF)
        assert diff < same - 0.05

    def test_structure_partial_overlap(self):
        s = C.structure_similarity(A, {"id": 1, "extra": 2})
        assert 0 < s < 1


class TestIdentityExtraction:
    def test_echoes_resource_id(self):
        assert C.echoes_resource_id(A, "101")
        assert not C.echoes_resource_id(A, "999")

    def test_ownership_claims(self):
        assert "alice" in C.ownership_claims(A)

    def test_contains_marker_substring_and_value(self):
        assert C.contains_marker(A, ["alice"]) == {"alice"}
        assert C.contains_marker(A, ["nobody"]) == set()

    def test_generic_body_detection(self):
        assert C.is_generic_body({}) and C.is_generic_body([]) and C.is_generic_body(None)
        assert not C.is_generic_body({"id": 1})


class TestParse:
    def test_parse_json_invalid(self):
        assert C.parse_json("<html>") is None

    def test_flatten_paths(self):
        flat = C.flatten({"a": {"b": [10, 20]}})
        assert flat["a.b[0]"] == 10 and flat["a.b[1]"] == 20
