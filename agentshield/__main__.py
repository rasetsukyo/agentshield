"""CLI entry point for AgentShield Core (MIT)."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from . import __version__
from .models import SEVERITY_ORDER
from .report_export import export_reports, render_terminal
from .scanner import run_scan


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="agentshield",
        description="Zero-dependency AI coding agent, MCP config, and prompt-injection security auditor (OWASP Agentic AI Top 10).",
    )
    p.add_argument("--version", action="version", version=f"AgentShield {__version__}")

    sub = p.add_subparsers(dest="command")
    scan = sub.add_parser("scan", help="Scan a repository and/or local workstation for AI agent and MCP security risks.")
    for target in (p, scan):
        target.add_argument("--path", default=".", help="Target repository or workspace directory (default: current directory)")
        target.add_argument("--no-home", action="store_true", help="Scan only --path (skip user home MCP/IDE configs; ideal for CI)")
        target.add_argument("--redact", action="store_true", help="Mask hostnames, usernames, home paths, and IPs for safe sharing")
        target.add_argument("--format", default="terminal", help="Comma-separated output formats: terminal,json,md,all")
        target.add_argument("--out-dir", default=".", help="Directory for exported report files")
        target.add_argument("--prefix", default="agentshield-report", help="Output filename prefix")
        target.add_argument(
            "--fail-on",
            choices=["critical", "high", "medium", "low"],
            default=None,
            help="Exit with code 2 if any FAIL/WARN check meets or exceeds this severity (useful in CI)",
        )
        target.add_argument("--no-color", action="store_true", help="Disable ANSI colors in terminal output")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    report = run_scan(
        target_path=args.path,
        scan_home=not args.no_home,
        redact=args.redact,
    )

    formats = {f.strip().lower() for f in args.format.split(",") if f.strip()}
    pro_only = formats & {"pdf", "docx", "html"}
    if pro_only:
        print(
            f"[AgentShield] Note: {', '.join(sorted(pro_only)).upper()} executive exports are part of AgentShield Pro: "
            "https://rasetsukyo.gumroad.com/l/agentshield",
            file=sys.stderr,
        )

    if "terminal" in formats or not (formats & {"json", "md", "all"}):
        use_color = sys.stdout.isatty() and not args.no_color
        print(render_terminal(report, color=use_color))

    file_formats = formats & {"json", "md", "all"}
    if file_formats:
        written = export_reports(
            report,
            out_dir=Path(args.out_dir),
            formats=file_formats,
            prefix=args.prefix,
        )
        for kind, path in written.items():
            print(f"[AgentShield] Wrote {kind.upper()}: {path}")

    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on.upper()]
        for c in report.checks:
            if c.status in ("FAIL", "WARN") and SEVERITY_ORDER.get(c.severity, 99) <= threshold:
                return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
