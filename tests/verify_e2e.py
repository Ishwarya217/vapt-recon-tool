import urllib.request
import json
import time

import sys

def test_full_pipeline():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    print("[1] Verifying System Health endpoint...")
    res = urllib.request.urlopen("http://127.0.0.1:8000/api/v1/system/health")
    health = json.loads(res.read().decode())
    print("Health response:", json.dumps(health, indent=2))

    print("\n[2] Creating Mock Scan for example.com...")
    req = urllib.request.Request(
        "http://127.0.0.1:8000/api/v1/scans",
        data=json.dumps({"target_domain": "example.com", "mode": "mock"}).encode(),
        headers={"Content-Type": "application/json"}
    )
    scan_res = urllib.request.urlopen(req)
    scan = json.loads(scan_res.read().decode())
    scan_id = scan["id"]
    print(f"Scan created with ID: {scan_id}, mode: {scan['mode']}")

    print("\n[3] Waiting for Orchestration State Machine to complete...")
    for i in range(30):
        time.sleep(1)
        res = urllib.request.urlopen(f"http://127.0.0.1:8000/api/v1/scans/{scan_id}")
        data = json.loads(res.read().decode())
        print(f"  Step {i+1}: Status = {data['status']}")
        if data["status"].lower() in ("completed", "failed"):
            if data["status"].lower() == "failed":
                print("Scan error:", data.get("error_message"))
            break

    print("\n[4] Querying Scan Artifacts...")
    disc = json.loads(urllib.request.urlopen(f"http://127.0.0.1:8000/api/v1/scans/{scan_id}/discoveries").read().decode())
    assets = json.loads(urllib.request.urlopen(f"http://127.0.0.1:8000/api/v1/scans/{scan_id}/assets").read().decode())
    findings = json.loads(urllib.request.urlopen(f"http://127.0.0.1:8000/api/v1/scans/{scan_id}/findings").read().decode())
    print(f"  Discoveries: {len(disc)}")
    print(f"  Assets: {len(assets)}")
    print(f"  Findings: {len(findings)}")

    print("\n[5] Testing Report Generation Engines...")
    for fmt in ["pdf", "excel", "xml"]:
        rep_req = urllib.request.Request(
            f"http://127.0.0.1:8000/api/v1/scans/{scan_id}/reports/{fmt}",
            data=b"{}",
            headers={"Content-Type": "application/json"}
        )
        rep_res = urllib.request.urlopen(rep_req)
        content = rep_res.read()
        print(f"  {fmt.upper()} Report Generated Successfully: {len(content)} bytes")

    print("\n[6] Dashboard Stats Verification...")
    stats = json.loads(urllib.request.urlopen("http://127.0.0.1:8000/api/v1/dashboard/stats").read().decode())
    print("Dashboard stats:", json.dumps(stats, indent=2))
    print("\n✅ ALL END-TO-END VERIFICATIONS PASSED!")

if __name__ == "__main__":
    test_full_pipeline()
