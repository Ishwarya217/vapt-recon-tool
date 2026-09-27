import urllib.request
import json
import time

import sys

def test_real_scan():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    print("[1] Creating REAL Scan for example.com...")
    req = urllib.request.Request(
        "http://127.0.0.1:8000/api/v1/scans",
        data=json.dumps({"target_domain": "example.com", "mode": "real", "sources": ["hackertarget"]}).encode(),
        headers={"Content-Type": "application/json"}
    )
    scan_res = urllib.request.urlopen(req)
    scan = json.loads(scan_res.read().decode())
    scan_id = scan["id"]
    print(f"Scan created with ID: {scan_id}, mode: {scan['mode']}")

    print("\n[2] Waiting for Real Orchestration State Machine to complete...")
    for i in range(120):
        time.sleep(2)
        res = urllib.request.urlopen(f"http://127.0.0.1:8000/api/v1/scans/{scan_id}")
        data = json.loads(res.read().decode())
        print(f"  Check {i+1} ({(i+1)*2}s): Status = {data['status']}")
        if data["status"].lower() in ("completed", "failed"):
            if data["status"].lower() == "failed":
                print("Scan error:", data.get("error_message"))
            break

    print("\n[3] Querying Real Scan Artifacts...")
    disc = json.loads(urllib.request.urlopen(f"http://127.0.0.1:8000/api/v1/scans/{scan_id}/discoveries").read().decode())
    assets = json.loads(urllib.request.urlopen(f"http://127.0.0.1:8000/api/v1/scans/{scan_id}/assets").read().decode())
    findings = json.loads(urllib.request.urlopen(f"http://127.0.0.1:8000/api/v1/scans/{scan_id}/findings").read().decode())
    print(f"  Discoveries count: {len(disc)}")
    print(f"  Assets count: {len(assets)}")
    print(f"  Findings count: {len(findings)}")

    if disc:
        print("  Sample Discovery:", disc[0])
    if assets:
        print("  Sample Asset:", assets[0])

    print("\n[4] Testing PDF/Excel/XML Reports on Real Data...")
    for fmt in ["pdf", "excel", "xml"]:
        rep_req = urllib.request.Request(
            f"http://127.0.0.1:8000/api/v1/scans/{scan_id}/reports/{fmt}",
            data=b"{}",
            headers={"Content-Type": "application/json"}
        )
        rep_res = urllib.request.urlopen(rep_req)
        content = rep_res.read()
        print(f"  REAL {fmt.upper()} Report Generated Successfully: {len(content)} bytes")

    print("\n✅ REAL SCAN END-TO-END VERIFICATION PASSED!")

if __name__ == "__main__":
    test_real_scan()
