#!/usr/bin/env python3
"""
Windows BAM/DAM Artifact Analyzer — Command Line Interface
Developed by Karanam Shrivasta
GitHub: https://github.com/mrshrivasta | LinkedIn: https://www.linkedin.com/in/karanam-shrivasta

DISCLAIMER: Real-parses a `.reg` export of the BAM/DAM State\\UserSettings
registry key. Only analyze systems/media/exports you own or are explicitly
authorized to investigate. Provided AS IS, no warranty. See README.md for
the full disclaimer.

Usage:
    reg export "HKLM\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings" bam_export.reg
    python3 cli/main.py scan bam_export.reg
    python3 cli/main.py scan ./reg_exports_dir --json
    python3 cli/main.py scan bam_export.reg --csv findings.csv
    python3 cli/main.py rules
"""
import argparse
import csv
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.security_engine import ScanEngine
from app.detection_rules import ALL_RULES

BANNER = """\
==============================================================
 Windows BAM/DAM Artifact Analyzer (CLI)
 Developed by Karanam Shrivasta
 GitHub:   https://github.com/mrshrivasta
 LinkedIn: https://www.linkedin.com/in/karanam-shrivasta
 DISCLAIMER: Authorized use only. Provided AS IS, no warranty.
==============================================================\
"""

SEVERITY_COLOR = {
    "critical": "\033[95m",
    "high": "\033[91m",
    "medium": "\033[93m",
    "low": "\033[92m",
    "informational": "\033[96m",
}
RESET = "\033[0m"


def cmd_scan(args):
    print(BANNER)
    print(f"Scanning: {args.path}  (max depth {args.depth}, max entries {args.max_files})\n")

    engine = ScanEngine(
        args.path,
        max_depth=args.depth,
        excludes=args.exclude.split(",") if args.exclude else None,
        max_files=args.max_files,
    )
    result = engine.run()

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print(f"BAM/DAM entries parsed : {result['files_scanned']}")
        print(f"Directories walked     : {result['dirs_scanned']}")
        print(f"Errors                 : {result['errors_count']}")
        print(f"Elapsed                : {result['elapsed_seconds']}s")
        print(f"Findings               : {len(result['findings'])}\n")

        for f in result["findings"]:
            color = SEVERITY_COLOR.get(f["severity"], "")
            print(f"{color}[{f['severity'].upper():13}]{RESET} {f['rule_id']} {f['rule_name']}")
            print(f"           source .reg : {f['file_path']}")
            print(f"           exe / SID   : {f['permissions_octal']}")
            print(f"           {f['description']}\n")

    if args.csv:
        with open(args.csv, "w", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["rule_id", "rule_name", "severity", "source_reg_file", "exe_path_or_sid", "description"])
            for f in result["findings"]:
                writer.writerow([f["rule_id"], f["rule_name"], f["severity"], f["file_path"], f["permissions_octal"], f["description"]])
        print(f"CSV report written to {args.csv}")

    if result["findings"]:
        sys.exit(1)  # non-zero exit for CI/DFIR pipelines when findings exist
    sys.exit(0)


def cmd_rules(args):
    print(BANNER)
    print("Detection rules:\n")
    for rule in ALL_RULES:
        doc = (rule.__doc__ or "").strip().split("\n")[0]
        print(f" - {rule.__name__}: {doc}")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="wbd-cli",
        description="Windows BAM/DAM Artifact Analyzer — real .reg export parser for BAM/DAM execution artifacts (by Karanam Shrivasta).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Scan a real .reg file or a directory of .reg files")
    scan_p.add_argument("path", help="Path to a .reg file, or a directory to walk for *.reg files")
    scan_p.add_argument("--depth", type=int, default=6, help="Max directory recursion depth when scanning a directory (default 6)")
    scan_p.add_argument("--max-files", type=int, default=20000, dest="max_files", help="Safety cap on BAM/DAM entries parsed")
    scan_p.add_argument("--exclude", type=str, default="", help="Comma-separated directory paths to exclude")
    scan_p.add_argument("--json", action="store_true", help="Output raw JSON")
    scan_p.add_argument("--csv", type=str, default=None, help="Write findings to a CSV file")
    scan_p.set_defaults(func=cmd_scan)

    rules_p = sub.add_parser("rules", help="List all detection rules")
    rules_p.set_defaults(func=cmd_rules)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
