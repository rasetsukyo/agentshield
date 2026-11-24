"""Terminal, Markdown, and JSON export helpers for AgentShield Core (MIT)."""

from __future__ import annotations

import json
from pathlib import Path

from .models import ScanReport


ANSI = {
    "PASS": "\033[1;32mPASS\033[0m",
    "WARN": "\033[1;33mWARN\033[0m",
    "FAIL": "\033[1;31mFAIL\033[0m",
    "SKIP": "\033[1;36mSKIP\033[0m",
    "BOLD": "\033[1m",
    "DIM": "\033[2m",
    "RESET": "\033[0m",
}


def render_terminal(report: ScanReport, color: bool = True) -> str:
    b = ANSI["BOLD"] if color else ""
    d = ANSI["DIM"] if color else ""
    r = ANSI["RESET"] if color else ""
    lines = [
        f"{b}AgentShield v{report.tool_version}{r} | OWASP Agentic AI & MCP Security Audit",
        f"{d}Host: {report.hostname} | Target: {report.target_path} | UTC: {report.generated_at}{r}",
        f"{b}Score: {report.score}/100 (Grade {report.grade}){r} | "
        f"PASS: {report.counts['PASS']}  WARN: {report.counts['WARN']}  FAIL: {report.counts['FAIL']}  SKIP: {report.counts['SKIP']}",
        "-" * 78,
    ]
    for c in report.checks:
        st = ANSI[c.status] if color and c.status in ANSI else c.status
        lines.append(f"[{st}] {c.check_id} ({c.owasp_ref}, {c.severity:<8}) {c.title}")
        lines.append(f"       {c.summary}")
        for ev in c.evidence[:3]:
            lines.append(f"       {d}- {ev}{r}")
        if c.remediation and c.status != "PASS":
            lines.append(f"       Fix: {c.remediation}")
    lines.append("-" * 78)
    lines.append("Need white-label OWASP PDF/DOCX reports, --diff tracking & hardened MCP templates?")
    lines.append("AgentShield Pro ($39 one-time): https://rasetsukyo.gumroad.com/l/agentshield")
    return "\n".join(lines)


def render_markdown(report: ScanReport) -> str:
    lines = [
        "# AgentShield OWASP Agentic AI Security Audit",
        "",
        f"- **Score:** {report.score}/100 (Grade {report.grade})",
        f"- **Host:** `{report.hostname}`",
        f"- **Target:** `{report.target_path}`",
        f"- **Generated (UTC):** `{report.generated_at}`",
        f"- **Summary:** {report.counts['PASS']} PASS, {report.counts['WARN']} WARN, {report.counts['FAIL']} FAIL, {report.counts['SKIP']} SKIP",
        "",
        "## Findings",
        "",
        "| ID | OWASP | Severity | Status | Control | Summary |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
    ]
    for c in report.checks:
        lines.append(f"| {c.check_id} | {c.owasp_ref} | {c.severity} | **{c.status}** | {c.title} | {c.summary} |")
    lines.append("")
    for c in report.checks:
        if c.status == "PASS" and not c.evidence:
            continue
        lines.append(f"### {c.check_id}: {c.title} ({c.status})")
        lines.append(c.summary)
        for ev in c.evidence[:8]:
            lines.append(f"- `{ev}`")
        if c.remediation and c.status != "PASS":
            lines.append(f"- **Remediation:** {c.remediation}")
        lines.append("")
    return "\n".join(lines)


def export_reports(
    report: ScanReport,
    out_dir: Path,
    formats: set[str],
    prefix: str = "agentshield-report",
) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}

    if "json" in formats or "all" in formats:
        p = out_dir / f"{prefix}.json"
        p.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        written["json"] = p

    if "md" in formats or "all" in formats:
        p = out_dir / f"{prefix}.md"
        p.write_text(render_markdown(report), encoding="utf-8")
        written["md"] = p

    return written
