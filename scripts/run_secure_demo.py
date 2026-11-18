"""Run a scan against the Secure Mock target and print results."""
import httpx, time

BASE = "http://127.0.0.1:8000/api"
C = httpx.Client(timeout=30)

# Start scan on target id=2 (Secure Mock)
r = C.post(f"{BASE}/scans", json={"target_id": 2, "name": "Secure Mock demo scan"})
assert r.status_code == 201, r.text
scan = r.json()
scan_id = scan["id"]
print(f"Scan #{scan_id} started...")

# Poll until done
for _ in range(40):
    s = C.get(f"{BASE}/scans/{scan_id}").json()
    if s["status"] in ("completed", "failed"):
        break
    time.sleep(0.5)

print(f"Status: {s['status']}")
print(f"Confirmed BOLA:   {s['confirmed_count']}")
print(f"Potential BOLA:   {s['potential_count']}")
print(f"Blocked (safe):   {s['blocked_count']}")
print(f"Authorized:       {s['authorized_count']}")
print(f"Inconclusive:     {s['inconclusive_count']}")
print()

if s["status"] == "completed":
    for r in s.get("results", []):
        print(f"  {r['requester_name']} -> {r['owner_name']} (res {r['resource_id']}): "
              f"{r['classification']} (HTTP {r['cross_status']})")
    print()
    if s["confirmed_count"] == 0 and s["potential_count"] == 0:
        print(">>> All access denied or properly blocked. This endpoint is SECURE. <<<")
