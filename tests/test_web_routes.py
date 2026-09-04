"""Web-app route tests — Windows BAM/DAM Artifact Analyzer.

Builds a REAL temp directory containing a real, spec-conformant `.reg`
file (real FILETIME bytes via struct.pack) that triggers a finding, POSTs
it as target_path to /scan/run, and exercises every downstream page.
"""
import os
import shutil
import struct
import tempfile
from datetime import datetime, timezone

TEST_SID = "S-1-5-21-1111111111-2222222222-3333333333-1001"


def _real_filetime_bytes(dt=None):
    if dt is None:
        dt = datetime.now(timezone.utc)
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    ticks = int((dt - epoch).total_seconds() * 10_000_000)
    return struct.pack("<Q", ticks)


def _build_reg_file(tmpdir):
    raw_bytes = _real_filetime_bytes()
    hex_str = ",".join(f"{b:02x}" for b in raw_bytes)
    exe_path = r"\Device\HarddiskVolume3\Users\bob\AppData\Local\Temp\evil.exe"
    escaped = exe_path.replace("\\", "\\\\")
    text = (
        "Windows Registry Editor Version 5.00\r\n\r\n"
        f"[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\{TEST_SID}]\r\n"
        f'"{escaped}"=hex:{hex_str}\r\n'
    )
    reg_path = os.path.join(tmpdir, "bam_export.reg")
    with open(reg_path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return reg_path


def test_full_scan_alert_incident_workflow(registered_client):
    tmpdir = tempfile.mkdtemp()
    try:
        reg_path = _build_reg_file(tmpdir)

        # Run a real scan against the real temp .reg file we just built.
        resp = registered_client.post("/scan/run", data={"target_path": reg_path}, follow_redirects=True)
        assert resp.status_code == 200
        assert b"Scan complete" in resp.data

        # Logs page should show at least one scan
        resp = registered_client.get("/logs")
        assert reg_path.encode() in resp.data

        # Alerts page should load and, given a medium+ finding, should have data
        resp = registered_client.get("/alerts")
        assert resp.status_code == 200

        # Analytics JSON endpoint returns real aggregated data
        resp = registered_client.get("/analytics/data")
        assert resp.status_code == 200
        assert resp.is_json

        # Reports CSV export works
        resp = registered_client.get("/reports/export.csv")
        assert resp.status_code == 200
        assert resp.headers["Content-Type"].startswith("text/csv")
        assert b"WBD-001" in resp.data
    finally:
        shutil.rmtree(tmpdir)


def test_scan_run_rejects_missing_path(registered_client):
    resp = registered_client.post("/scan/run", data={"target_path": "/this/path/does/not/exist"}, follow_redirects=True)
    assert resp.status_code == 200
    assert b"Scan failed" in resp.data


def test_settings_page_round_trip(registered_client):
    resp = registered_client.post("/settings", data={
        "default_scan_path": "/tmp/bam_export.reg",
        "scan_depth_limit": "3",
        "exclude_paths": "",
        "alert_on_severity": "medium",
    }, follow_redirects=True)
    assert b"Settings saved" in resp.data

    resp = registered_client.get("/settings")
    assert b"/tmp/bam_export.reg" in resp.data


def test_all_nav_pages_load(registered_client):
    for path in ["/", "/logs", "/alerts", "/incidents", "/analytics", "/reports", "/settings"]:
        resp = registered_client.get(path)
        assert resp.status_code == 200, f"{path} failed with {resp.status_code}"


def test_404_page(registered_client):
    resp = registered_client.get("/this-page-does-not-exist")
    assert resp.status_code == 404
