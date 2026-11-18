import httpx

d = httpx.get("http://127.0.0.1:8000/api/dashboard/stats", timeout=10).json()
print("Severity distribution (open findings):")
for b in d["severity_chart"]:
    if b["count"] > 0:
        print(f"  {b['severity']}: {b['count']}")
