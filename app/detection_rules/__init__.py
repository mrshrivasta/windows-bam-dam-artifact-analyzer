"""
Detection Rules — Windows BAM/DAM Artifact Analyzer
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Each rule inspects a REAL parsed BAM/DAM entry `context` dict (built by
app.security_engine.ScanEngine from an actual `.reg` export) and returns a
Finding dict if the condition is met. Rules are intentionally conservative
and documented so results can be independently cross-checked against other
Windows execution artifacts (Prefetch, Shimcache/AppCompatCache, Amcache,
UserAssist, SRUM).

Context dict shape (per bam/dam value entry):
    {
        "source_file": str,          # path to the .reg file this came from
        "sid": str | None,           # user SID the entry was recorded under
        "service": "bam" | "dam" | None,
        "exe_path": str,             # real parsed executable path (value name)
        "filetime_int": int | None,  # raw little-endian FILETIME (100ns ticks)
        "last_run_utc": datetime | None,  # decoded UTC datetime, or None if zero
        "duplicate_paths": set[str], # every distinct full path sharing this basename
    }

Context dict shape for unrelated-content notes:
    {"source_file": str, "section_path": str}
"""
import ntpath
import re

# Severity scale used consistently across the whole project
SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"
SEVERITY_INFO = "informational"

SUSPICIOUS_DIR_MARKERS = (
    "\\appdata\\local\\temp\\",
    "\\users\\public\\",
    "\\programdata\\",
    "\\windows\\temp\\",
)

_REMOVABLE_MEDIA_DEVICE_RE = re.compile(r"\\device\\(floppy|cdrom)", re.IGNORECASE)
_HARDDISKVOLUME_RE = re.compile(r"^\\device\\harddiskvolume\d+\\", re.IGNORECASE)
_KNOWN_SYSTEM_TREE_MARKERS = ("\\users\\", "\\windows\\", "\\program files\\", "\\program files (x86)\\", "\\programdata\\")

DOUBLE_EXT_RE = re.compile(
    r"\.(pdf|doc|docx|xls|xlsx|txt|jpg|jpeg|png|gif|zip|rar)\.(exe|scr|bat|cmd|com|pif|vbs|js)$",
    re.IGNORECASE,
)


def _lowered(path):
    return (path or "").lower().replace("/", "\\")


def rule_suspicious_execution_directory(context):
    """WBD-001: The real parsed executable path is located in a directory
    commonly abused for staging/executing malicious payloads (Temp,
    Public, ProgramData, Windows\\Temp). Corroborates or contradicts
    Prefetch/Shimcache evidence for the same binary — a classic forensic
    triage signal for post-exploitation or dropper activity."""
    exe_path = context.get("exe_path", "")
    lowered = _lowered(exe_path)
    for marker in SUSPICIOUS_DIR_MARKERS:
        if marker in lowered:
            return {
                "rule_id": "WBD-001",
                "rule_name": "Execution From Suspicious Directory",
                "severity": SEVERITY_MEDIUM,
                "description": (
                    f"BAM/DAM recorded execution of '{exe_path}', located in a "
                    f"directory commonly used to stage or run malicious payloads. "
                    f"Cross-reference with Prefetch/Shimcache/Amcache for this binary."
                ),
            }
    return None


def rule_removable_device_path(context):
    """WBD-002: The real parsed executable path references a device-path
    segment consistent with removable media (floppy/CD-ROM device nodes,
    or a HarddiskVolume path pattern outside standard Users/Windows/Program
    Files trees, which frequently corresponds to a distinct volume such as
    a USB stick). Best-effort heuristic — always confirm against the
    SYSTEM\\MountedDevices or Setupapi.dev.log for the true volume type."""
    exe_path = context.get("exe_path", "")
    is_removable = False
    if _REMOVABLE_MEDIA_DEVICE_RE.search(exe_path):
        is_removable = True
    elif _HARDDISKVOLUME_RE.match(exe_path):
        lowered = _lowered(exe_path)
        if not any(marker in lowered for marker in _KNOWN_SYSTEM_TREE_MARKERS):
            is_removable = True

    if is_removable:
        return {
            "rule_id": "WBD-002",
            "rule_name": "Possible Removable-Media Execution",
            "severity": SEVERITY_MEDIUM,
            "description": (
                f"BAM/DAM entry '{exe_path}' has a device-path pattern "
                f"consistent with removable/external media execution "
                f"(best-effort heuristic — verify against MountedDevices "
                f"or Setupapi logs)."
            ),
        }
    return None


def rule_duplicate_basename_multiple_paths(context):
    """WBD-003: The same executable file NAME was run from two or more
    distinct full paths (potentially across different user SIDs), computed
    across the whole scan. Real evidence of a binary being copied/staged to
    multiple locations — common in lateral movement and persistence."""
    duplicate_paths = context.get("duplicate_paths") or set()
    if len(duplicate_paths) >= 2:
        exe_path = context.get("exe_path", "")
        basename = ntpath.basename(exe_path)
        other_paths = sorted(p for p in duplicate_paths if p != exe_path)
        return {
            "rule_id": "WBD-003",
            "rule_name": "Same Binary Executed From Multiple Locations",
            "severity": SEVERITY_LOW,
            "description": (
                f"'{basename}' was executed from {len(duplicate_paths)} distinct "
                f"full paths recorded in BAM/DAM, including '{exe_path}' and "
                f"{', '.join(repr(p) for p in other_paths)}."
            ),
        }
    return None


def rule_zeroed_timestamp(context):
    """WBD-004: The real parsed last-execution FILETIME is exactly zero.
    Anomalous: a legitimate BAM/DAM entry should carry a non-zero last-run
    time. A zeroed timestamp can indicate a corrupted/truncated hive export,
    manual tampering, or an artifact-wiping tool."""
    filetime_int = context.get("filetime_int")
    if filetime_int == 0:
        exe_path = context.get("exe_path", "")
        return {
            "rule_id": "WBD-004",
            "rule_name": "Zeroed Last-Execution Timestamp",
            "severity": SEVERITY_LOW,
            "description": (
                f"BAM/DAM entry for '{exe_path}' has a last-execution FILETIME "
                f"of exactly zero — anomalous for a real execution record; "
                f"possible tampering, truncation, or corrupted export."
            ),
        }
    return None


def rule_extension_spoofing(context):
    """WBD-005: The real parsed executable path has a double-extension /
    extension-spoofing pattern such as `.pdf.exe`, `.doc.scr`, `.jpg.exe`
    — a classic technique used to disguise an executable as a benign
    document or image so a user double-clicks it in a file listing that
    truncates or hides the true extension."""
    exe_path = context.get("exe_path", "")
    basename = ntpath.basename(exe_path)
    if DOUBLE_EXT_RE.search(basename):
        return {
            "rule_id": "WBD-005",
            "rule_name": "Disguised Executable (Extension Spoofing)",
            "severity": SEVERITY_MEDIUM,
            "description": (
                f"BAM/DAM recorded execution of '{exe_path}', whose filename "
                f"'{basename}' uses a double/spoofed extension pattern often "
                f"used to disguise executables as documents or images."
            ),
        }
    return None


def rule_unrelated_reg_content(context):
    """WBD-006: A section inside the supplied `.reg` export did NOT match
    the expected bam/dam \\State\\UserSettings\\{SID} key path. Reported as
    an informational parse-note (not an error) so an analyst knows part of
    the export was outside scope, rather than the scan silently ignoring it."""
    section_path = context.get("section_path", "")
    source_file = context.get("source_file", "")
    return {
        "rule_id": "WBD-006",
        "rule_name": "Unrelated Registry Content In Export",
        "severity": SEVERITY_INFO,
        "description": (
            f"'{source_file}' contains a registry section '[{section_path}]' "
            f"that is not a bam/dam State\\UserSettings\\{{SID}} key — parsed "
            f"as informational context, not a BAM/DAM execution record."
        ),
    }


ALL_RULES = [
    rule_suspicious_execution_directory,
    rule_removable_device_path,
    rule_duplicate_basename_multiple_paths,
    rule_zeroed_timestamp,
    rule_extension_spoofing,
    rule_unrelated_reg_content,
]
