import urllib.request
import json
import re

def main():
    print("=== LIVE SERVER INTEGRATION TEST (http://127.0.0.1:5000) ===")
    
    # 1. Fetch HTML
    html = urllib.request.urlopen("http://127.0.0.1:5000/").read().decode("utf-8")
    assert "aiRiskGaugeContainer" in html, "Missing aiRiskGaugeContainer in index.html"
    assert "aiRiskGaugeSvg" in html, "Missing aiRiskGaugeSvg in index.html"
    assert "326.7" in html, "Missing 326.7 in index.html"
    print("[PASS] 1. index.html contains AI Risk Gauge SVG markup.")

    # 2. Get CSRF token via /api/session
    session_data = json.loads(urllib.request.urlopen("http://127.0.0.1:5000/api/session").read().decode("utf-8"))
    token = session_data.get("csrf", "")
    print(f"[PASS] 2. Obtained CSRF token: {token[:8]}... (len={len(token)})")

    # 3. Test POST /api/scan with ai_hybrid=True
    req = urllib.request.Request(
        "http://127.0.0.1:5000/api/scan",
        data=json.dumps({"target": "http://127.0.0.1:3000", "ai_hybrid": True}).encode("utf-8"),
        headers={"Content-Type": "application/json", "Origin": "http://127.0.0.1:5000", "X-CSRF-Token": token}
    )
    res = urllib.request.urlopen(req)
    data = json.loads(res.read().decode("utf-8"))
    assert "ai_gauge" in data, "Missing ai_gauge in scan response"
    gauge = data["ai_gauge"]
    print(f"[PASS] 3. POST /api/scan (Hybrid ON): ai_gauge = {gauge}")
    assert "risk_percent" in gauge and "findings" in gauge and "total" in gauge, "ai_gauge keys missing"
    assert isinstance(gauge["risk_percent"], int)
    assert 0 <= gauge["risk_percent"] <= 100

    # 4. Test POST /api/scan with ai_hybrid=False
    req_nohybrid = urllib.request.Request(
        "http://127.0.0.1:5000/api/scan",
        data=json.dumps({"target": "http://127.0.0.1:3000", "ai_hybrid": False}).encode("utf-8"),
        headers={"Content-Type": "application/json", "Origin": "http://127.0.0.1:5000", "X-CSRF-Token": token}
    )
    res_nohybrid = urllib.request.urlopen(req_nohybrid)
    data_nohybrid = json.loads(res_nohybrid.read().decode("utf-8"))
    assert "ai_gauge" not in data_nohybrid or data_nohybrid["ai_gauge"] is None, "ai_gauge should be omitted or null when Hybrid OFF"
    print("[PASS] 4. POST /api/scan (Hybrid OFF): ai_gauge is correctly omitted/null.")

    # 5. Test GET /api/report (JSON) and GET /api/report.html
    # Scan with hybrid again to ensure REPORT has gauge
    urllib.request.urlopen(req)
    rep_json = json.loads(urllib.request.urlopen("http://127.0.0.1:5000/api/report").read().decode("utf-8"))
    assert "ai_gauge" in rep_json, "Missing ai_gauge in /api/report JSON"
    print(f"[PASS] 5a. GET /api/report (JSON): ai_gauge = {rep_json['ai_gauge']}")

    rep_html = urllib.request.urlopen("http://127.0.0.1:5000/api/report.html").read().decode("utf-8")
    assert "AI Risk Gauge" in rep_html, "Missing AI Risk Gauge in /api/report.html"
    print("[PASS] 5b. GET /api/report.html: contains visual AI Risk Gauge.")

    print("\nALL LIVE INTEGRATION TESTS PASSED 100%!")

if __name__ == "__main__":
    main()
