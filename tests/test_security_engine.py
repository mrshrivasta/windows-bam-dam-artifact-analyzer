"""Tests for the Security Engine and Detection Rules — Windows BAM/DAM
Artifact Analyzer.

Two layers:
1. Rule-level unit tests against synthetic context dicts (fast, isolated).
2. Genuine engine-level tests that build a REAL, spec-conformant `.reg`
   file as actual text (with a real `Windows Registry Editor Version 5.00`
   header, a real bam/dam State\\UserSettings\\{SID} section, and real
   "value"=hex:.. lines whose bytes encode a real little-endian FILETIME
   computed with struct.pack), write it to a real temp file, and run the
   actual ScanEngine against it — no mocking of parsing logic.
"""
import os
import shutil
import struct
import sys
import tempfile
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.security_engine import ScanEngine, filetime_to_datetime
from app.detection_rules import (
    rule_suspicious_execution_directory,
    rule_removable_device_path,
    rule_duplicate_basename_multiple_paths,
    rule_zeroed_timestamp,
    rule_extension_spoofing,
    rule_unrelated_reg_content,
)

REG_HEADER = "Windows Registry Editor Version 5.00\r\n"
TEST_SID = "S-1-5-21-1111111111-2222222222-3333333333-1001"


def real_filetime_bytes(dt=None):
    """Compute REAL little-endian FILETIME bytes for a given UTC datetime
    (default: now) using struct.pack, exactly as Windows would encode it."""
    if dt is None:
        dt = datetime.now(timezone.utc)
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    delta = dt - epoch
    ticks = int(delta.total_seconds() * 10_000_000)
    return struct.pack("<Q", ticks)


def hex_line(value_name, raw_bytes):
    """Build a real `.reg` hex value line: "name"=hex:xx,xx,xx,..."""
    hex_str = ",".join(f"{b:02x}" for b in raw_bytes)
    escaped_name = value_name.replace("\\", "\\\\")
    return f'"{escaped_name}"=hex:{hex_str}'


def build_reg_text(entries, sid=TEST_SID, service="bam"):
    """entries: list of (exe_path, raw_bytes) tuples."""
    lines = [REG_HEADER, "", f"[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\{service}\\State\\UserSettings\\{sid}]"]
    for exe_path, raw_bytes in entries:
        lines.append(hex_line(exe_path, raw_bytes))
    return "\r\n".join(lines) + "\r\n"


def write_reg_file(text, tmpdir, name="export.reg"):
    path = os.path.join(tmpdir, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


# ---------------------------------------------------------------------
# Rule-level unit tests (synthetic context dicts)
# ---------------------------------------------------------------------

def test_rule_suspicious_execution_directory_hits_temp():
    ctx = {"exe_path": r"\Device\HarddiskVolume3\Users\bob\AppData\Local\Temp\evil.exe"}
    result = rule_suspicious_execution_directory(ctx)
    assert result is not None
    assert result["rule_id"] == "WBD-001"


def test_rule_suspicious_execution_directory_misses_program_files():
    ctx = {"exe_path": r"\Device\HarddiskVolume3\Program Files\Vendor\App\app.exe"}
    assert rule_suspicious_execution_directory(ctx) is None


def test_rule_removable_device_path_hits_cdrom():
    ctx = {"exe_path": r"\Device\CdRom0\setup.exe"}
    result = rule_removable_device_path(ctx)
    assert result is not None
    assert result["rule_id"] == "WBD-002"


def test_rule_removable_device_path_misses_users_tree():
    ctx = {"exe_path": r"\Device\HarddiskVolume3\Users\bob\Desktop\notes.exe"}
    assert rule_removable_device_path(ctx) is None


def test_rule_duplicate_basename_multiple_paths():
    ctx = {
        "exe_path": r"\Device\HarddiskVolume3\Users\bob\Downloads\tool.exe",
        "duplicate_paths": {
            r"\Device\HarddiskVolume3\Users\bob\Downloads\tool.exe",
            r"\Device\HarddiskVolume3\Users\alice\Desktop\tool.exe",
        },
    }
    result = rule_duplicate_basename_multiple_paths(ctx)
    assert result is not None
    assert result["rule_id"] == "WBD-003"


def test_rule_duplicate_basename_single_path_no_finding():
    ctx = {
        "exe_path": r"\Device\HarddiskVolume3\Users\bob\Downloads\tool.exe",
        "duplicate_paths": {r"\Device\HarddiskVolume3\Users\bob\Downloads\tool.exe"},
    }
    assert rule_duplicate_basename_multiple_paths(ctx) is None


def test_rule_zeroed_timestamp():
    ctx = {"exe_path": r"\Device\HarddiskVolume3\Windows\System32\cmd.exe", "filetime_int": 0}
    result = rule_zeroed_timestamp(ctx)
    assert result is not None
    assert result["rule_id"] == "WBD-004"


def test_rule_zeroed_timestamp_nonzero_no_finding():
    ctx = {"exe_path": r"\Device\HarddiskVolume3\Windows\System32\cmd.exe", "filetime_int": 132900000000000000}
    assert rule_zeroed_timestamp(ctx) is None


def test_rule_extension_spoofing_hits_double_extension():
    ctx = {"exe_path": r"\Device\HarddiskVolume3\Users\bob\Downloads\invoice.pdf.exe"}
    result = rule_extension_spoofing(ctx)
    assert result is not None
    assert result["rule_id"] == "WBD-005"


def test_rule_extension_spoofing_misses_normal_exe():
    ctx = {"exe_path": r"\Device\HarddiskVolume3\Windows\System32\notepad.exe"}
    assert rule_extension_spoofing(ctx) is None


def test_rule_unrelated_reg_content():
    ctx = {"source_file": "export.reg", "section_path": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Unrelated"}
    result = rule_unrelated_reg_content(ctx)
    assert result is not None
    assert result["rule_id"] == "WBD-006"


def test_filetime_to_datetime_zero_is_none():
    assert filetime_to_datetime(0) is None


def test_filetime_to_datetime_roundtrip():
    dt = datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
    raw = real_filetime_bytes(dt)
    ticks = struct.unpack("<Q", raw)[0]
    decoded = filetime_to_datetime(ticks)
    assert abs((decoded - dt).total_seconds()) < 1


# ---------------------------------------------------------------------
# Engine-level tests against a REAL, spec-conformant .reg file on disk
# ---------------------------------------------------------------------

def test_engine_parses_real_reg_and_flags_suspicious_directory():
    tmpdir = tempfile.mkdtemp()
    try:
        raw_bytes = real_filetime_bytes(datetime(2024, 3, 1, tzinfo=timezone.utc))
        exe_path = r"\Device\HarddiskVolume3\Users\bob\AppData\Local\Temp\evil.exe"
        text = build_reg_text([(exe_path, raw_bytes)])
        reg_path = write_reg_file(text, tmpdir)

        engine = ScanEngine(reg_path)
        result = engine.run()

        assert result["files_scanned"] == 1
        assert result["errors_count"] == 0
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "WBD-001" in rule_ids
        finding = next(f for f in result["findings"] if f["rule_id"] == "WBD-001")
        assert finding["file_path"] == reg_path
        assert exe_path in finding["permissions_octal"]
    finally:
        shutil.rmtree(tmpdir)


def test_engine_parses_directory_of_reg_files():
    tmpdir = tempfile.mkdtemp()
    try:
        raw_bytes = real_filetime_bytes()
        exe_path = r"\Device\HarddiskVolume2\Windows\System32\svchost.exe"
        text = build_reg_text([(exe_path, raw_bytes)])
        write_reg_file(text, tmpdir, name="bam_export.reg")

        engine = ScanEngine(tmpdir)
        result = engine.run()

        assert result["files_scanned"] == 1
        assert result["dirs_scanned"] >= 1
    finally:
        shutil.rmtree(tmpdir)


def test_engine_detects_zeroed_timestamp():
    tmpdir = tempfile.mkdtemp()
    try:
        raw_bytes = b"\x00" * 8
        exe_path = r"\Device\HarddiskVolume3\Windows\System32\cmd.exe"
        text = build_reg_text([(exe_path, raw_bytes)])
        reg_path = write_reg_file(text, tmpdir)

        engine = ScanEngine(reg_path)
        result = engine.run()
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "WBD-004" in rule_ids
    finally:
        shutil.rmtree(tmpdir)


def test_engine_detects_extension_spoofing():
    tmpdir = tempfile.mkdtemp()
    try:
        raw_bytes = real_filetime_bytes()
        exe_path = r"\Device\HarddiskVolume3\Users\bob\Downloads\report.pdf.exe"
        text = build_reg_text([(exe_path, raw_bytes)])
        reg_path = write_reg_file(text, tmpdir)

        engine = ScanEngine(reg_path)
        result = engine.run()
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "WBD-005" in rule_ids
    finally:
        shutil.rmtree(tmpdir)


def test_engine_detects_duplicate_basename_across_sids():
    tmpdir = tempfile.mkdtemp()
    try:
        raw_bytes = real_filetime_bytes()
        entries_bam = [(r"\Device\HarddiskVolume3\Users\bob\Downloads\tool.exe", raw_bytes)]
        text_bam = build_reg_text(entries_bam, sid=TEST_SID, service="bam")

        other_sid = "S-1-5-21-9999999999-8888888888-7777777777-1002"
        entries_dam = [(r"\Device\HarddiskVolume3\Users\alice\Desktop\tool.exe", raw_bytes)]
        text_dam = build_reg_text(entries_dam, sid=other_sid, service="dam")

        write_reg_file(text_bam, tmpdir, name="bam.reg")
        write_reg_file(text_dam, tmpdir, name="dam.reg")

        engine = ScanEngine(tmpdir)
        result = engine.run()

        assert result["files_scanned"] == 2
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "WBD-003" in rule_ids
    finally:
        shutil.rmtree(tmpdir)


def test_engine_detects_removable_device_path():
    tmpdir = tempfile.mkdtemp()
    try:
        raw_bytes = real_filetime_bytes()
        exe_path = r"\Device\CdRom0\autorun.exe"
        text = build_reg_text([(exe_path, raw_bytes)])
        reg_path = write_reg_file(text, tmpdir)

        engine = ScanEngine(reg_path)
        result = engine.run()
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "WBD-002" in rule_ids
    finally:
        shutil.rmtree(tmpdir)


def test_engine_reports_unrelated_reg_content():
    tmpdir = tempfile.mkdtemp()
    try:
        text = (
            REG_HEADER + "\r\n"
            '[HKEY_LOCAL_MACHINE\\SOFTWARE\\SomeUnrelatedApp]\r\n'
            '"Version"="1.0"\r\n'
        )
        reg_path = write_reg_file(text, tmpdir)

        engine = ScanEngine(reg_path)
        result = engine.run()
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "WBD-006" in rule_ids
        assert result["files_scanned"] == 0
    finally:
        shutil.rmtree(tmpdir)


def test_engine_handles_multiline_hex_continuation():
    tmpdir = tempfile.mkdtemp()
    try:
        raw_bytes = real_filetime_bytes() + b"\x01\x02\x03\x04\x05\x06\x07\x08"
        hex_str = ",".join(f"{b:02x}" for b in raw_bytes)
        # Split hex bytes across multiple physical lines with trailing backslashes,
        # exactly as `reg export` does for long values.
        parts = hex_str.split(",")
        mid = len(parts) // 2
        line1 = ",".join(parts[:mid]) + ",\\"
        line2 = "  " + ",".join(parts[mid:])
        exe_path = r"\Device\HarddiskVolume3\Windows\System32\longvalue.exe"
        escaped = exe_path.replace("\\", "\\\\")
        text = (
            REG_HEADER + "\r\n"
            f"[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\{TEST_SID}]\r\n"
            f'"{escaped}"=hex:{line1}\r\n'
            f"{line2}\r\n"
        )
        reg_path = write_reg_file(text, tmpdir)

        engine = ScanEngine(reg_path)
        result = engine.run()
        assert result["files_scanned"] == 1
        assert result["errors_count"] == 0
    finally:
        shutil.rmtree(tmpdir)


def test_engine_malformed_entry_counts_as_error_not_crash():
    tmpdir = tempfile.mkdtemp()
    try:
        text = (
            REG_HEADER + "\r\n"
            f"[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\{TEST_SID}]\r\n"
            '"\\\\Device\\\\HarddiskVolume3\\\\bad.exe"=hex:zz,zz\r\n'
        )
        reg_path = write_reg_file(text, tmpdir)

        engine = ScanEngine(reg_path)
        result = engine.run()
        assert result["errors_count"] >= 1
        assert result["files_scanned"] == 0
    finally:
        shutil.rmtree(tmpdir)


def test_engine_empty_directory_no_crash():
    tmpdir = tempfile.mkdtemp()
    try:
        engine = ScanEngine(tmpdir)
        result = engine.run()
        assert result["files_scanned"] == 0
        assert result["findings"] == []
    finally:
        shutil.rmtree(tmpdir)


def test_engine_nonexistent_path_no_crash():
    engine = ScanEngine("/nonexistent/path/for/testing/wbd")
    result = engine.run()
    assert result["files_scanned"] == 0
    assert isinstance(result["findings"], list)
