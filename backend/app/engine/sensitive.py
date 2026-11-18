"""Sensitive-data detection and masking (Feature F).

Scans API response bodies for PII categories (email, phone, national
identifiers, dates of birth, addresses, payment cards) and produces masked
versions so stored evidence and UI displays never leak full values.
"""
from __future__ import annotations

import re
from typing import Any

# category -> compiled pattern
PATTERNS: dict[str, re.Pattern] = {
    "EMAIL": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "PHONE": re.compile(r"(?:\+?\d{1,3}[-\s.])?\(?\d{3}\)?[-\s.]\d{3}[-\s.]\d{4}\b"),
    "NATIONAL_ID": re.compile(
        r"(?:(?:SSN|ID|NRN|NIN)\s*[:#-]?\s*)?\b\d{3}-\d{2}-\d{4}\b"
        r"|\b\d{9,12}\b(?=\D*$)"
    ),
    "DATE_OF_BIRTH": re.compile(
        r"\b(?:19|20)\d{2}[-/](?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12]\d|3[01])\b"
        r"|\b(?:date\s*of\s*birth|dob)\b\s*[:=]?\s*\S+",
        re.IGNORECASE,
    ),
    "ADDRESS": re.compile(
        r"\b\d{1,6}\s+(?:[A-Za-z]\s+)?(?:[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)\s+"
        r"(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b"
        r"(?:[,.]\s*[^,;.]{1,40})?"
    ),
    "CREDIT_CARD": re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
}

# Keys whose very names hint at PII even when values look opaque
SUSPICIOUS_KEYS = {
    "email", "phone", "mobile", "ssn", "national_id", "nationalid", "dob",
    "date_of_birth", "birthdate", "address", "credit_card", "creditcard",
    "card_number", "ccnumber", "passport", "salary", "iban",
}


def _luhn_ok(num_str: str) -> bool:
    digits = [int(c) for c in re.sub(r"\D", "", num_str)]
    if not 13 <= len(digits) <= 19:
        return False
    checksum, double = 0, False
    for d in reversed(digits):
        if double:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
        double = not double
    return checksum % 10 == 0


def detect(text: str) -> dict[str, list[str]]:
    """Return {category: [matched raw values]} found in *text*."""
    if not text:
        return {}
    found: dict[str, list[str]] = {}
    for category, pattern in PATTERNS.items():
        for match in pattern.findall(text):
            value = match if isinstance(match, str) else match[0]
            value = value.strip()
            if category == "CREDIT_CARD" and not _luhn_ok(value):
                continue
            if category == "NATIONAL_ID" and value.isdigit() and len(value) < 9:
                continue
            found.setdefault(category, [])
            if value not in found[category]:
                found[category].append(value)
    return found


def detect_categories(text: str) -> list[str]:
    return sorted(detect(text).keys())


def mask_value(category: str, value: str) -> str:
    """Mask one sensitive value, keeping just enough context for evidence."""
    v = value.strip()
    if category == "EMAIL" and "@" in v:
        local, _, domain = v.partition("@")
        head = local[:1]
        return f"{head}***@{'***' if len(domain) > 5 else domain}"
    if category == "CREDIT_CARD":
        digits = re.sub(r"\D", "", v)
        return f"****-****-****-{digits[-4:]}" if len(digits) >= 4 else "****"
    if category == "NATIONAL_ID":
        tail = re.sub(r"\D", "", v)[-4:]
        prefix = "SSN " if v.upper().startswith("SSN") else ""
        return f"{prefix}***-**-{tail}" if tail else "****"
    if category in ("PHONE",):
        digits = re.sub(r"\D", "", v)
        return f"+** ({digits[:3]}) ***-{digits[-4:]}" if len(digits) >= 10 else "**"
    if category == "DATE_OF_BIRTH":
        m = re.search(r"(19|20)\d{2}", v)
        return f"****-**-** (year {m.group(0)} known)" if m else "****"
    if category == "ADDRESS":
        parts = v.split(" ", 1)
        return f"{parts[0]} *** {('' if len(parts) < 2 else parts[1][:6] + '***')}".strip()
    # generic fallback: keep first char
    return (v[:1] + "***") if v else "****"


def mask_text(text: str) -> str:
    """Replace every detected sensitive value in *text* with a masked form."""
    masked = text
    for category, values in detect(text).items():
        for value in values:
            masked = masked.replace(value, mask_value(category, value))
    return masked


def scan_json(obj: Any) -> tuple[list[str], Any]:
    """Scan a parsed JSON document; return (categories, structure-masked copy).

    The masked copy keeps keys/structure but replaces sensitive string values,
    suitable for storing as evidence.
    """
    text = json_dumps(obj)
    categories = detect_categories(text)
    return categories, mask_json_deep(obj)


def json_dumps(obj: Any) -> str:
    import json

    return json.dumps(obj, ensure_ascii=False, default=str)


def mask_json_deep(obj: Any) -> Any:
    """Recursively mask string values that contain detected PII."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            masked_v = mask_json_deep(v)
            # Also mask by key hint (e.g. "salary": 98000 -> "***")
            if isinstance(k, str) and k.lower() in SUSPICIOUS_KEYS and not isinstance(v, (dict, list)):
                masked_v = f"[{k.upper()} masked]"
            out[k] = masked_v
        return out
    if isinstance(obj, list):
        return [mask_json_deep(x) for x in obj]
    if isinstance(obj, str):
        return mask_text(obj)
    return obj
