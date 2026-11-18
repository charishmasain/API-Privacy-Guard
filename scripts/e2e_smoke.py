"""End-to-end smoke test through the real backend HTTP API.

Prerequisites (already running):
  - backend on 127.0.0.1:8000
  - mock vulnerable API on 127.0.0.1:8011
  - mock secure API on 127.0.0.1:8012

Drives the full user flow: target -> accounts -> endpoints -> scan ->
findings -> matrix -> rescan -> verification -> PDF report.
Cleans up its own data afterwards.
"""
import json
import sys
import time

import httpx

BASE = "http://127.0.0.1:8000/api"
C = httpx.Client(timeout=30)
failures = []


def check(name, cond, extra=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name} {extra}")
    if not cond:
        failures.append(name)


def wait_done(scan_id):
    for _ in range(80):
        s = C.get(f"{BASE}/scans/{scan_id}").json()
        if s["status"] in ("completed", "failed"):
            return s
        time.sleep(0.5)
    raise RuntimeError("scan timed out")


def setup_target(name, port):
    """Create target + Alice/Bob accounts; returns (target_id, {name: account})."""
    r = C.post(f"{BASE}/targets", json={
        "name": name, "base_url": f"http://127.0.0.1:{port}",
        "authorization_confirmed": True, "allow_localhost": True,
        "notes": "e2e smoke (auto-cleaned)",
    })
    check(f"create target {name}", r.status_code == 201, r.text[:160])
    tid = r.json()["id"]
    accounts = {}
    for aname, tok, home in [
        ("Alice", "mock-token-alice-3f8a9c", "101"),
        ("Bob", "mock-token-bob-77d1e0", "202"),
    ]:
        r = C.post(f"{BASE}/targets/{tid}/accounts",
                   json={"name": aname, "token": tok, "home_resource_id": home})
        check(f"  account {aname}", r.status_code == 201, r.text[:160])
        check(f"  token masked in response", tok not in r.text)
        accounts[aname] = r.json()
    return tid, accounts


# ---- policy endpoint (Settings page) ----
print("== /api/policy ==")
r = C.get(f"{BASE}/policy")
check("policy 200", r.status_code == 200)
p = r.json()
check("methods GET/HEAD only", p["allowed_methods"] == ["GET", "HEAD"])

# ---- authorization enforcement ----
r = C.post(f"{BASE}/targets", json={
    "name": "Unauthorized", "base_url": "http://127.0.0.1:8011",
    "authorization_confirmed": False, "allow_localhost": True,
})
check("authorization required at creation", r.status_code == 422)

# ---- vulnerable target setup ----
vuln_tid, vuln_accts = setup_target("E2E Vulnerable Mock", 8011)
r = C.post(f"{BASE}/targets/{vuln_tid}/endpoints", json={
    "name": "Profile (insecure)", "path_template": "/v1/insecure/profiles/{resource_id}",
    "method": "GET", "resource_id": "101", "owner_account_id": vuln_accts["Alice"]["id"],
    "expected_access": "owner_only",
})
check("endpoint on vulnerable target", r.status_code in (200, 201), r.text[:160])

# ---- secure target setup ----
sec_tid, sec_accts = setup_target("E2E Secure Mock", 8012)
r = C.post(f"{BASE}/targets/{sec_tid}/endpoints", json={
    "name": "Profile (secure)", "path_template": "/v1/profiles/{resource_id}",
    "method": "GET", "resource_id": "101", "owner_account_id": sec_accts["Alice"]["id"],
    "expected_access": "owner_only",
})
check("endpoint on secure target", r.status_code in (200, 201), r.text[:160])

# ---- scan vulnerable target ----
print("== scan (vulnerable) ==")
r = C.post(f"{BASE}/scans", json={"target_id": vuln_tid, "name": "E2E vulnerable"})
check("scan started", r.status_code == 201, r.text[:200])
scan1 = wait_done(r.json()["id"])
check("scan completed", scan1["status"] == "completed", scan1.get("error_message") or "")
check("CONFIRMED BOLA found", scan1["confirmed_count"] >= 1,
      f"confirmed={scan1['confirmed_count']} potential={scan1['potential_count']}")

# ---- scan secure target ----
print("== scan (secure) ==")
r = C.post(f"{BASE}/scans", json={"target_id": sec_tid, "name": "E2E secure"})
scan2 = wait_done(r.json()["id"])
check("secure scan completed", scan2["status"] == "completed")
check("no false positives on secure API",
      scan2["confirmed_count"] == 0 and scan2["potential_count"] == 0,
      f"confirmed={scan2['confirmed_count']} potential={scan2['potential_count']}")
check("blocked count >= 1", scan2["blocked_count"] >= 1)

# ---- findings ----
print("== findings ==")
fnd = [f for f in C.get(f"{BASE}/findings").json() if f["target_id"] == vuln_tid]
check("findings exist for vulnerable target", len(fnd) >= 1, f"count={len(fnd)}")
if fnd:
    f = fnd[0]
    for k in ("name", "severity", "path", "requester_name", "owner_name", "http_status",
              "technical_explanation", "potential_impact", "remediation"):
        check(f"  finding field {k}", f.get(k) not in (None, ""))
    check("  severity in scale",
          f["severity"] in ("Critical", "High", "Medium", "Low", "Informational"))
    check("  evidence masked (no full token)", "mock-token-alice-3f8a9c" not in json.dumps(f))

# ---- matrix ----
print("== matrix ==")
m = C.get(f"{BASE}/matrix/{scan1['id']}").json()
check("matrix has rows x cols", len(m["accounts"]) >= 2 and len(m["endpoints"]) >= 1)
classes = {c["classification"] for c in m["cells"]}
check("matrix shows confirmed bola cell", "CONFIRMED_BOLA" in classes, str(classes))
check("matrix has owner cell", "OWNER" in classes)

# ---- dashboard ----
print("== dashboard ==")
d = C.get(f"{BASE}/dashboard/stats").json()
check("dashboard totals", d["total_scans"] >= 2 and d["endpoints_tested"] >= 2)
check("dashboard confirmed > 0", d["confirmed_vulnerabilities"] >= 1)
check("severity chart buckets", len(d["severity_chart"]) >= 1)

# ---- rescan + verification ----
print("== rescan + verification ==")
r = C.post(f"{BASE}/scans/{scan1['id']}/rescan")
check("rescan accepted", r.status_code == 201, r.text[:200])
if r.status_code == 201:
    scan3 = wait_done(r.json()["id"])
    check("rescan completed", scan3["status"] == "completed")
    v = C.get(f"{BASE}/scans/{scan3['id']}/verification").json()
    check("verification compares with previous", v["previous_scan_id"] == scan1["id"])
    states = {c["state"] for c in v["comparisons"]}
    check("comparisons produced", len(v["comparisons"]) >= 1, str(states))
    check("still_vulnerable detected", "still_vulnerable" in states, str(v.get("summary")))

# ---- PDF report ----
print("== pdf report ==")
r = C.get(f"{BASE}/reports/{scan1['id']}/pdf")
check("pdf 200", r.status_code == 200)
check("pdf content-type", r.headers.get("content-type", "").startswith("application/pdf"))
check("pdf bytes", r.content[:4] == b"%PDF" and len(r.content) > 2000, f"{len(r.content)} bytes")
check("pdf has no raw token", b"mock-token-alice-3f8a9c" not in r.content)

# ---- cleanup: remove e2e data so the UI starts fresh ----
print("== cleanup ==")
for tid in (vuln_tid, sec_tid):
    r = C.delete(f"{BASE}/targets/{tid}")
    check(f"delete target {tid}", r.status_code in (200, 204), r.text[:120])

print()
if failures:
    print(f"E2E FAILURES ({len(failures)}):")
    for f in failures:
        print(" -", f)
    sys.exit(1)
print("E2E: ALL CHECKS PASSED")
