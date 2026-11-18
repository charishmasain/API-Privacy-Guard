"""Response comparison utilities for evidence-based BOLA classification.

A plain HTTP 200 is NOT a vulnerability signal by itself. The engine must
verify that the cross-account response actually contains the *victim's*
object: identical resource identifiers, matching ownership fields and high
structural/value similarity to the owner's legitimate baseline response.
Conversely, an API that ignores the supplied id and always returns the
caller's own data must be classified AUTHORIZED, not BOLA.
"""
from __future__ import annotations

import difflib
import json
import re
from typing import Any, Optional

# key names commonly used for object identity / ownership
ID_KEY_RE = re.compile(r"^(id|_id|id$|uuid|guid|(resource|object|user|account|profile|order|document|file)s?_?ids?)$", re.I)
OWNER_KEY_RE = re.compile(
    r"(owner|user|account|customer|member|author|subject|requested_by|username|login)", re.I
)


def parse_json(text: str) -> Optional[Any]:
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def normalize(obj: Any) -> str:
    """Stable serialisation (sorted keys) used for similarity scoring."""
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, default=str)


def flatten(obj: Any, prefix: str = "") -> dict[str, Any]:
    """Flatten nested JSON into {dotted.path: scalar} pairs."""
    out: dict[str, Any] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.update(flatten(v, f"{prefix}.{k}" if prefix else str(k)))
    elif isinstance(obj, list):
        # treat lists positionally but also as multisets of scalar leaves
        for i, v in enumerate(obj):
            out.update(flatten(v, f"{prefix}[{i}]"))
    else:
        out[prefix or "$"] = obj
    return out


def structure_similarity(a: Any, b: Any) -> float:
    """Jaccard similarity of key-path sets (0..1)."""
    ka, kb = set(flatten(a)), set(flatten(b))
    if not ka and not kb:
        return 1.0
    if not ka or not kb:
        return 0.0
    return len(ka & kb) / len(ka | kb)


def value_similarity(a: Any, b: Any) -> float:
    """difflib ratio over normalised JSON strings (0..1)."""
    return difflib.SequenceMatcher(None, normalize(a), normalize(b)).ratio()


def collect_identity_strings(obj: Any) -> set[str]:
    """All scalar string/number values lowercased - used for marker matching."""
    out: set[str] = set()

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)
        elif isinstance(node, (str, int, float)):
            s = str(node).strip().lower()
            if s:
                out.add(s)

    walk(obj)
    return out


def extract_field_values(obj: Any, key_pattern: re.Pattern) -> set[str]:
    """Values of any dict key matching *key_pattern* anywhere in the document."""
    out: set[str] = set()

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                if key_pattern.search(str(k)) and isinstance(v, (str, int, float)):
                    out.add(str(v).strip().lower())
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(obj)
    return out


def echoes_resource_id(obj: Any, resource_id: str) -> bool:
    """True if the response body repeats the requested resource identifier."""
    rid = str(resource_id).strip().lower()
    id_values = extract_field_values(obj, ID_KEY_RE)
    return rid in id_values


def ownership_claims(obj: Any) -> set[str]:
    """Owner-ish identity strings found in the body (owner/user fields)."""
    vals = extract_field_values(obj, OWNER_KEY_RE)
    # drop pure booleans / noise
    return {v for v in vals if v not in {"true", "false", "none", "null", ""}}


def contains_marker(obj: Any, markers: list[str]) -> set[str]:
    """Which of *markers* appear anywhere in the document (as full values or substrings)."""
    hay = normalize(obj).lower()
    identity = collect_identity_strings(obj)
    hits = set()
    for m in markers:
        ml = str(m).strip().lower()
        if not ml:
            continue
        if ml in identity or ml in hay:
            hits.add(ml)
    return hits


def is_generic_body(obj: Any) -> bool:
    """Empty-ish bodies ({}, [], null, '') carry no evidence of data access."""
    if obj is None:
        return True
    if isinstance(obj, (dict, list)):
        return len(obj) == 0
    if isinstance(obj, str):
        return not obj.strip()
    return False
