"""Add a contact-only endpoint to the Vulnerable Mock target and scan it -> High."""
import httpx, time

BASE = "http://127.0.0.1:8000/api"
C = httpx.Client(timeout=30)
TID = 1  # Vulnerable Mock API

# find Alice's account id on target 1
accts = C.get(f"{BASE}/targets/{TID}/accounts").json()
alice = next(a for a in accts if a["name"].lower() == "alice")
print("Alice account id:", alice["id"])

# add the contact endpoint (resource 101, owned by Alice)
r = C.post(f"{BASE}/targets/{TID}/endpoints", json={
    "name": "Contact (insecure, no SSN/card)",
    "path_template": "/v1/insecure/contacts/{resource_id}",
    "method": "GET",
    "resource_id": "101",
    "owner_account_id": alice["id"],
    "expected_access": "owner_only",
    "notes": "Leaks email/phone/address only -> High severity",
})
print("endpoint create:", r.status_code, r.json().get("id"))

# start a scan limited to just this new endpoint
ep_id = r.json()["id"]
s = C.post(f"{BASE}/scans", json={"target_id": TID, "name": "High-severity demo", "endpoint_ids": [ep_id]}).json()
sid = s["id"]
print(f"scan #{sid} started")

for _ in range(60):
    sc = C.get(f"{BASE}/scans/{sid}").json()
    if sc["status"] in ("completed", "failed"):
        break
    time.sleep(0.5)

print("status:", sc["status"], "| confirmed:", sc["confirmed_count"], "| potential:", sc["potential_count"])

# show severities of findings from this scan
fnd = [f for f in C.get(f"{BASE}/findings").json() if f["scan_id"] == sid]
for f in fnd:
    cats = f.get("exposed_categories")
    print(f"  {f['requester_name']}->{f['owner_name']} res{f['resource_id']}: "
          f"{f['classification']} | severity={f['severity']} | categories={cats}")
