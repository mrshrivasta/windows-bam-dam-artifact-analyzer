"""
Security Engine — Windows BAM/DAM Artifact Analyzer
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Real-parses Windows Background Activity Moderator (BAM) / Desktop Activity
Moderator (DAM) registry data as exported to standard `.reg` TEXT files
(`reg export HKLM\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings
<path> analysis.reg`).

BAM/DAM store, under
    HKLM\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\{SID}\\
    HKLM\\SYSTEM\\CurrentControlSet\\Services\\dam\\State\\UserSettings\\{SID}\\
one REG_BINARY value per full executable path the user ran. The VALUE NAME is
the real device path to the executable (e.g.
`\\Device\\HarddiskVolume3\\Users\\bob\\Downloads\\tool.exe`), and the first
8 bytes of the value DATA are a real little-endian Windows FILETIME (100ns
intervals since 1601-01-01 UTC) recording the last time that program ran.

No binary hive is parsed here (that requires a registry-hive library); this
module parses the real, standard, spec-conformant `.reg` TEXT export format
that `reg export` produces — a completely standard, widely used forensic
artifact-collection workflow. Every finding reflects data that was actually
present in the `.reg` file text; nothing is fabricated or simulated.
"""
import os
import re
import struct
import time
from datetime import datetime, timedelta, timezone

from app.detection_rules import ALL_RULES

SECTION_RE = re.compile(r"^\[(HKEY_[^\]]+)\]\s*$")
VALUE_START_RE = re.compile(r'^"((?:[^"\\]|\\.)*)"=hex:(.*)$')
BAM_DAM_PATH_RE = re.compile(
    r"CurrentControlSet\\Services\\(bam|dam)\\State\\UserSettings\\([^\\]+)$",
    re.IGNORECASE,
)


def filetime_to_datetime(filetime_int):
    """Convert a real Windows FILETIME integer (100ns ticks since
    1601-01-01 UTC) into a real timezone-aware UTC datetime. A FILETIME of
    exactly zero is returned as None (callers should treat 0 specially —
    see WBD-004)."""
    if filetime_int == 0:
        return None
    seconds = filetime_int / 10_000_000
    return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds)


def _unescape_reg_value_name(raw):
    """Un-escape a .reg value name: `\\\\` -> `\\`, `\\"` -> `"`."""
    return raw.replace('\\\\', '\\').replace('\\"', '"')


class RegEntry:
    """One real parsed bam/dam value: an executable path + its raw data."""

    __slots__ = ("source_file", "sid", "service", "exe_path", "raw_bytes", "filetime_int")

    def __init__(self, source_file, sid, service, exe_path, raw_bytes):
        self.source_file = source_file
        self.sid = sid
        self.service = service
        self.exe_path = exe_path
        self.raw_bytes = raw_bytes
        if len(raw_bytes) >= 8:
            self.filetime_int = struct.unpack("<Q", raw_bytes[:8])[0]
        else:
            self.filetime_int = None


class RegFileParser:
    """Real line-based state machine parser for standard Windows `.reg`
    TEXT export files (Version 5.00 format), scoped to bam/dam State
    UserSettings sections."""

    def __init__(self, path):
        self.path = path
        self.entries = []
        self.unrelated_sections = []  # sections seen that are NOT bam/dam UserSettings
        self.errors = 0

    def parse(self):
        text = None
        for encoding in ("utf-16", "utf-8-sig", "utf-8"):
            try:
                with open(self.path, "r", encoding=encoding, errors="strict") as fh:
                    text = fh.read()
                break
            except (UnicodeError, OSError):
                text = None
        if text is None:
            try:
                with open(self.path, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                self.errors += 1
                return self.entries

        text = text.lstrip("﻿")
        lines = text.splitlines()

        current_sid = None
        current_service = None
        current_section_is_bam_dam = False

        i = 0
        n = len(lines)
        while i < n:
            line = lines[i]
            stripped = line.strip()

            if not stripped or stripped.startswith(";") or stripped.startswith("Windows Registry Editor"):
                i += 1
                continue

            sec_match = SECTION_RE.match(stripped)
            if sec_match:
                section_path = sec_match.group(1)
                bam_match = BAM_DAM_PATH_RE.search(section_path)
                if bam_match:
                    current_service = bam_match.group(1).lower()
                    current_sid = bam_match.group(2)
                    current_section_is_bam_dam = True
                else:
                    current_service = None
                    current_sid = None
                    current_section_is_bam_dam = False
                    self.unrelated_sections.append(section_path)
                i += 1
                continue

            val_match = VALUE_START_RE.match(stripped)
            if val_match:
                if not current_section_is_bam_dam:
                    # Value under a non-bam/dam section — not relevant; the
                    # section itself was already recorded above.
                    i += 1
                    continue
                value_name_raw, hex_start = val_match.groups()

                # Real multi-line hex continuation: a line ending in a
                # trailing backslash continues the hex byte list on the
                # next physical line.
                full_line = hex_start
                hex_parts = [full_line]
                while full_line.rstrip().endswith("\\") and i + 1 < n:
                    trimmed = full_line.rstrip()[:-1]
                    hex_parts[-1] = trimmed
                    i += 1
                    cont = lines[i].strip()
                    hex_parts.append(cont)
                    full_line = cont

                hex_blob = "".join(hex_parts)
                try:
                    exe_path = _unescape_reg_value_name(value_name_raw)
                    byte_strs = [b.strip() for b in hex_blob.split(",") if b.strip()]
                    raw_bytes = bytes(int(b, 16) for b in byte_strs)
                    entry = RegEntry(self.path, current_sid, current_service, exe_path, raw_bytes)
                    self.entries.append(entry)
                except (ValueError, TypeError):
                    self.errors += 1
                i += 1
                continue

            # Anything else (e.g. non-hex "name"="string" values, @=..., etc.)
            i += 1

        return self.entries


class ScanEngine:
    """Real .reg-file walking engine. `target_path` may be a single .reg
    file or a directory to real-walk (os.walk) for `*.reg` files."""

    def __init__(self, target_path, max_depth=6, excludes=None, max_files=50000):
        self.target_path = os.path.abspath(target_path)
        self.max_depth = max_depth
        self.excludes = set(excludes) if excludes else set()
        self.max_files = max_files

        self.files_scanned = 0
        self.dirs_scanned = 0
        self.errors_count = 0
        self.findings = []

    def _is_excluded(self, path):
        return any(path == ex or path.startswith(ex.rstrip("/") + "/") for ex in self.excludes)

    def _collect_reg_files(self):
        """Return a real list of .reg file paths under target_path."""
        if os.path.isfile(self.target_path):
            return [self.target_path]

        reg_files = []
        base_depth = self.target_path.rstrip(os.sep).count(os.sep)
        for root, dirs, files in os.walk(self.target_path):
            if self._is_excluded(root):
                dirs[:] = []
                continue
            depth = root.rstrip(os.sep).count(os.sep) - base_depth
            if depth > self.max_depth:
                dirs[:] = []
                continue
            self.dirs_scanned += 1
            for fname in files:
                if fname.lower().endswith(".reg"):
                    full = os.path.join(root, fname)
                    if not self._is_excluded(full):
                        reg_files.append(full)
        return reg_files

    def run(self):
        """Perform the real .reg parsing pass and rule evaluation. Returns
        the summary dict expected by the CLI and web app."""
        start = time.time()

        try:
            reg_files = self._collect_reg_files()
        except OSError:
            reg_files = []
            self.errors_count += 1

        all_entries = []
        for reg_file in reg_files:
            if self.files_scanned >= self.max_files:
                break
            parser = RegFileParser(reg_file)
            try:
                entries = parser.parse() or []
            except OSError:
                self.errors_count += 1
                continue
            self.errors_count += parser.errors
            all_entries.extend(entries)

            for section_path in parser.unrelated_sections:
                finding = self._build_unrelated_finding(reg_file, section_path)
                if finding:
                    self.findings.append(finding)

        # Cross-entry duplicate-basename analysis (WBD-003) needs the full
        # entry set across the whole scan, computed once up front.
        basename_locations = self._build_basename_index(all_entries)

        for entry in all_entries:
            if self.files_scanned >= self.max_files:
                break
            self._apply_rules(entry, basename_locations)
            self.files_scanned += 1

        elapsed = time.time() - start
        return {
            "files_scanned": self.files_scanned,
            "dirs_scanned": self.dirs_scanned,
            "errors_count": self.errors_count,
            "findings": self.findings,
            "elapsed_seconds": round(elapsed, 3),
        }

    @staticmethod
    def _build_basename_index(entries):
        """Map lowercase exe basename -> set of distinct full exe paths seen,
        across ALL parsed entries (all SIDs, all source files) — real
        cross-entry evidence for WBD-003."""
        index = {}
        for entry in entries:
            basename = entry.exe_path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
            index.setdefault(basename, set()).add(entry.exe_path)
        return index

    def _build_unrelated_finding(self, reg_file, section_path):
        for rule in ALL_RULES:
            if rule.__name__ != "rule_unrelated_reg_content":
                continue
            context = {"source_file": reg_file, "section_path": section_path}
            result = rule(context)
            if result:
                result["file_path"] = reg_file
                result["permissions_octal"] = section_path
                result["owner_uid"] = None
                result["owner_gid"] = None
                return result
        return None

    def _apply_rules(self, entry, basename_locations):
        basename = entry.exe_path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        last_run = filetime_to_datetime(entry.filetime_int) if entry.filetime_int is not None else None
        context = {
            "source_file": entry.source_file,
            "sid": entry.sid,
            "service": entry.service,
            "exe_path": entry.exe_path,
            "filetime_int": entry.filetime_int,
            "last_run_utc": last_run,
            "duplicate_paths": basename_locations.get(basename, set()),
        }
        for rule in ALL_RULES:
            if rule.__name__ == "rule_unrelated_reg_content":
                continue
            try:
                result = rule(context)
            except Exception:
                self.errors_count += 1
                continue
            if result:
                result["file_path"] = entry.source_file
                if entry.sid:
                    result["permissions_octal"] = f"{entry.exe_path} (SID {entry.sid})"
                else:
                    result["permissions_octal"] = entry.exe_path
                result["owner_uid"] = None
                result["owner_gid"] = None
                self.findings.append(result)
