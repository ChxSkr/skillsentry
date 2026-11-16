"""SkillSentry 命令行入口。"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .report import render_json, render_sarif, render_text
from .rules import SEVERITY_ORDER, Severity
from .scanner import scan

_FAIL_LEVELS = ["never", "low", "medium", "high", "critical"]
_FORMATS = ["text", "json", "sarif"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="skillsentry",
        description="Static supply-chain risk scanner for AI agent skill packages.",
    )
    parser.add_argument("--version", action="version",
                        version=f"skillsentry {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="scan a skill directory")
    p_scan.add_argument("path", help="skill directory to scan")
    p_scan.add_argument("--format", choices=_FORMATS, default="text",
                        help="output format (default: text)")
    p_scan.add_argument(
        "--fail-on", choices=_FAIL_LEVELS, default="high",
        help="exit 1 when verdict severity reaches this level (default: high)")
    p_scan.add_argument(
        "-e", "--exclude", action="append", default=[],
        metavar="GLOB",
        help="skip files matching glob (relative path or basename); repeatable")

    args = parser.parse_args(argv)

    if args.command == "scan":
        result = scan(args.path, exclude=tuple(args.exclude))

        if args.format == "json":
            print(render_json(result))
        elif args.format == "sarif":
            print(render_sarif(result))
        else:
            print(render_text(result))

        verdict = result.verdict
        if args.fail_on == "never" or verdict == "clean":
            return 0
        threshold = Severity(args.fail_on)
        if verdict == "clean":
            return 0
        # clean 已处理；将 verdict 映射到 Severity 比较
        try:
            v = Severity(verdict)
        except ValueError:
            return 0
        return 1 if SEVERITY_ORDER[v] >= SEVERITY_ORDER[threshold] else 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
