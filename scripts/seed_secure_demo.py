"""Seed a 'Secure Mock' target for demo purposes."""
import httpx

BASE = "http://127.0.0.1:8000/api"
C = httpx.Client(timeout=15)

# Create secure target
r = C.post(f"{BASE}/targets", json={
    "name": "Secure Mock (Safe API)",
    "base_url": "http://127.0.0.1:8012",
    "authorization_confirmed": True,
    "allow_localhost": True,
    "notes": "Demonstrates properly secured endpoints - returns 403 on unauthorized access",
})
tid = r.json()["id"]
print(f"Target created: id={tid}")

# Add accounts
alice = C.post(f"{BASE}/targets/{tid}/accounts", json={
    "name": "Alice",
    "token": "mock-token-alice-3f8a9c",
    "home_resource_id": "101",
    "description": "Owner of resource 101",
}).json()
bob = C.post(f"{BASE}/targets/{tid}/accounts", json={
    "name": "Bob",
    "token": "mock-token-bob-77d1e0",
    "home_resource_id": "202",
    "description": "Owner of resource 202",
}).json()
print(f"Accounts: Alice id={alice['id']}, Bob id={bob['id']}")

# Endpoint: /v1/profiles/{resource_id} - checks ownership on secure server
ep = C.post(f"{BASE}/targets/{tid}/endpoints", json={
    "name": "Profile by ID (ownership enforced)",
    "path_template": "/v1/profiles/{resource_id}",
    "method": "GET",
    "resource_id": "101",
    "owner_account_id": alice["id"],
    "expected_access": "owner_only",
    "notes": "Secure server returns 403 when non-owner tries access",
}).json()
print(f"Endpoint created: id={ep['id']}")

print("Done! Go to New Scan and select 'Secure Mock (Safe API)' to test.")
