"""Core read-only security checks for AI coding agents, MCP configs, and repos.

All 14 checks use Python 3.10+ stdlib only, never modify files, and always mask
any detected secret literals before recording evidence.
"""

from __future__ import annotations

import getpass
import json
import os
from pathlib import Path
import platform
import re
import socket
import stat
import subprocess
from typing import Any

from . import __version__
from .models import CheckResult, ScanReport, redact_report, utc_now_iso


# Standard client MCP configuration locations
HOME_MCP_CANDIDATES = [
    ".gemini/config/mcp_config.json",
    ".gemini/settings.json",
    ".config/Claude/claude_desktop_config.json",
    "Library/Application Support/Claude/claude_desktop_config.json",
    ".cursor/mcp.json",
    ".codeium/windsurf/mcp_config.json",
    ".vscode/mcp.json",
    ".claude.json",
    ".claude/settings.json",
]

REPO_MCP_CANDIDATES = [
    ".mcp.json",
    "mcp.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    ".gemini/config/mcp_config.json",
    ".gemini/settings.json",
    ".claude/settings.json",
    ".claude/settings.local.json",
]

# Instruction / skill / rules files targeted by indirect prompt injection
INSTRUCTION_FILENAMES = {
    "AGENTS.md",
    "CLAUDE.md",
    "GEMINI.md",
    "SKILL.md",
    ".cursorrules",
    ".windsurfrules",
    ".clinerules",
    "copilot-instructions.md",
}

SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
    ".next",
    "target",
    ".cache",
}

# High-confidence secret token regexes (values are always masked in output)
SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("OpenAI API key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("GitHub classic PAT", re.compile(r"\bghp_[A-Za-z0-9]{20,}\b")),
    ("GitHub fine-grained PAT", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Stripe live secret", re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b")),
    ("Private key header", re.compile(r"-----BEGIN (?:OPENSSH|RSA|EC|DSA|PGP) PRIVATE KEY-----")),
]

SENSITIVE_ENV_KEY_RE = re.compile(
    r"(?:API_KEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE_KEY|ACCESS_KEY|AUTH)",
    re.IGNORECASE,
)

# High-impact MCP server types that should enforce explicit least-privilege restrictions
RISKY_MCP_KEYWORDS = {
    "gmail": "email send/delete",
    "workspace": "email/drive/calendar mutations",
    "google-workspace": "email/drive/calendar mutations",
    "slack": "channel/DM posting",
    "github": "repo write/merge/delete",
    "filesystem": "host filesystem access",
    "shell": "arbitrary shell execution",
    "bash": "arbitrary shell execution",
    "terminal": "arbitrary shell execution",
    "postgres": "database write/drop",
    "mysql": "database write/drop",
    "sqlite": "database write/drop",
    "aws": "cloud infrastructure mutations",
    "stripe": "billing/refund mutations",
    "ssh": "remote host execution",
}

SAFE_GUARDRAIL_HINTS = (
    "WORKSPACE_FEATURE_OVERRIDES",
    "READ_ONLY",
    "READONLY",
    "--read-only",
    "--readonly",
    "DENY",
    "DISABLE",
    "ALLOWLIST",
    "BLOCK",
    ":off",
)

# Invisible Unicode & Trojan Source bidi control codepoints
def _is_hidden_unicode(ch: str) -> str | None:
    cp = ord(ch)
    if 0xE0000 <= cp <= 0xE007F:
        return f"Unicode Tag U+{cp:05X}"
    if cp in (0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x2060):
        return f"Zero-width U+{cp:04X}"
    if 0x202A <= cp <= 0x202E or 0x2066 <= cp <= 0x2069:
        return f"Bidi override U+{cp:04X}"
    return None


PROMPT_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Instruction override phrase", re.compile(r"ignore (?:all )?(?:previous|prior|above) instructions", re.I)),
    ("System prompt override", re.compile(r"(?:disregard|override|bypass) (?:the )?system prompt", re.I)),
    ("Stealth directive", re.compile(r"(?:do not|never) (?:tell|inform|alert|show) the user", re.I)),
    ("Silent exfiltration wording", re.compile(r"(?:silently|secretly|covertly) (?:send|post|upload|exfiltrate|transmit)", re.I)),
    ("Hidden HTML comment directive", re.compile(r"<!--[^>]*(?:ignore previous|curl\s|wget\s|http://|https://|exfiltrate|system prompt)[^>]*-->", re.I | re.S)),
]

RCE_EXFIL_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Piped remote shell execution", re.compile(r"\b(?:curl|wget)\b[^\n|]{0,160}\|\s*(?:ba)?sh\b", re.I)),
    ("Base64 decode to shell", re.compile(r"base64\s+(?:-d|--decode)[^\n|]{0,80}\|\s*(?:ba)?sh\b", re.I)),
    ("Reverse shell primitive", re.compile(r"(?:/dev/tcp/\S+|\bnc\s+[^\n]*-e\b|\bmkfifo\s+/tmp/)", re.I)),
    ("Exfil webhook endpoint", re.compile(r"https?://(?:webhook\.site|requestbin\.|pipedream\.net|[\w.-]+\.ngrok(?:-free)?\.app|discord(?:app)?\.com/api/webhooks/)", re.I)),
    ("Credential theft target", re.compile(r"(?:cat|curl|base64|cp)\s+[^\n]*(?:~/.ssh/id_|~/.aws/credentials|/etc/shadow)", re.I)),
]

YOLO_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("dangerously-skip-permissions", re.compile(r"dangerously[-_]?skip[-_]?permissions", re.I)),
    ("yoloMode enabled", re.compile(r'"yoloMode"\s*:\s*true', re.I)),
    ("autoApprove enabled", re.compile(r'"autoApprove"\s*:\s*true', re.I)),
    ("Wildcard alwaysAllow", re.compile(r'"alwaysAllow"\s*:\s*\[\s*"\*"\s*\]', re.I)),
    ("Unrestricted shell allow", re.compile(r'"allow"\s*:\s*\[[^\]]*"Bash\(\*\)"', re.I)),
]

LOCAL_AI_PORTS: dict[int, str] = {
    11434: "Ollama LLM API",
    3000: "Open WebUI / local dev app",
    8080: "Open WebUI / LLM gateway",
    8000: "vLLM / FastAPI model server",
    1234: "LM Studio local server",
    8188: "ComfyUI generation server",
    8888: "Jupyter Notebook / Lab",
    9222: "Chrome / CDP Remote Debugging",
}


def _mask_secret(val: str) -> str:
    if len(val) <= 8:
        return "***"
    return f"{val[:4]}...{val[-2:]} (len={len(val)})"


def _read_text(path: Path, max_bytes: int = 512_000) -> str | None:
    try:
        if not path.is_file() or path.stat().st_size > max_bytes:
            return None
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None


def _parse_json(path: Path) -> dict[str, Any] | None:
    txt = _read_text(path)
    if not txt:
        return None
    try:
        obj = json.loads(txt)
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        return None


def _discover_mcp_files(target_path: Path, home_dir: Path | None) -> list[Path]:
    found: list[Path] = []
    seen: set[Path] = set()
    candidates: list[Path] = [target_path / rel for rel in REPO_MCP_CANDIDATES]
    if home_dir:
        candidates.extend(home_dir / rel for rel in HOME_MCP_CANDIDATES)
    for p in candidates:
        try:
            rp = p.resolve()
        except OSError:
            continue
        if rp not in seen and rp.is_file():
            seen.add(rp)
            found.append(rp)
    return found


def _extract_mcp_servers(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    servers: dict[str, dict[str, Any]] = {}
    for key in ("mcpServers", "servers"):
        block = data.get(key)
        if isinstance(block, dict):
            for name, cfg in block.items():
                if isinstance(cfg, dict):
                    servers[str(name)] = cfg
    return servers


def _discover_instruction_files(target_path: Path, home_dir: Path | None) -> list[Path]:
    files: list[Path] = []
    seen: set[Path] = set()

    def add_if_file(p: Path) -> None:
        try:
            rp = p.resolve()
        except OSError:
            return
        if rp not in seen and rp.is_file():
            seen.add(rp)
            files.append(rp)

    # Walk target repo (bounded depth/dirs)
    if target_path.is_dir():
        for root, dirs, filenames in os.walk(target_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            root_p = Path(root)
            for fn in filenames:
                fp = root_p / fn
                if (
                    fn in INSTRUCTION_FILENAMES
                    or ".cursor/rules" in str(root_p)
                    or fn.endswith(".mdc")
                ):
                    add_if_file(fp)

    # Check top-level user global agent instruction files (avoid scanning giant built-in dirs)
    if home_dir and home_dir.is_dir():
        for rel in (
            "AGENTS.md",
            "CLAUDE.md",
            ".gemini/GEMINI.md",
            ".gemini/magi-system.md",
            ".claude/CLAUDE.md",
            ".cursorrules",
        ):
            add_if_file(home_dir / rel)
        skills_dir = home_dir / ".gemini" / "skills"
        if skills_dir.is_dir():
            for p in skills_dir.rglob("SKILL.md"):
                add_if_file(p)
    return files


def _check_as001_mcp_inventory(mcp_files: list[Path]) -> tuple[CheckResult, list[tuple[Path, str, dict[str, Any]]]]:
    discovered: list[tuple[Path, str, dict[str, Any]]] = []
    evidence: list[str] = []
    for fp in mcp_files:
        data = _parse_json(fp)
        if not data:
            continue
        servers = _extract_mcp_servers(data)
        for name, cfg in servers.items():
            discovered.append((fp, name, cfg))
            cmd = cfg.get("command") or cfg.get("url") or cfg.get("serverUrl") or "unknown"
            evidence.append(f"{fp}: server '{name}' -> {cmd}")

    if not discovered:
        return (
            CheckResult(
                check_id="AS-001",
                owasp_ref="OWASP ASI02",
                domain="MCP & Tool Governance",
                title="MCP Server Inventory & Visibility",
                status="PASS",
                severity="INFO",
                summary="No active MCP server configurations found in scanned scope.",
                evidence=["0 MCP servers detected across standard client and repo paths."],
            ),
            discovered,
        )

    return (
        CheckResult(
            check_id="AS-001",
            owasp_ref="OWASP ASI02",
            domain="MCP & Tool Governance",
            title="MCP Server Inventory & Visibility",
            status="PASS",
            severity="INFO",
            summary=f"Inventoried {len(discovered)} MCP server(s) across {len(mcp_files)} config file(s).",
            evidence=evidence[:15],
        ),
        discovered,
    )


def _check_as002_destructive_mcp(servers: list[tuple[Path, str, dict[str, Any]]]) -> CheckResult:
    if not servers:
        return CheckResult(
            check_id="AS-002",
            owasp_ref="OWASP ASI02",
            domain="MCP & Tool Governance",
            title="Least-Privilege Guardrails on High-Impact MCP Tools",
            status="PASS",
            severity="HIGH",
            summary="No MCP servers configured; zero destructive MCP tool exposure.",
        )

    unrestricted: list[str] = []
    protected: list[str] = []
    for fp, name, cfg in servers:
        blob = json.dumps(cfg)
        blob_low = f"{name} {blob}".lower()
        matched_risk = None
        for kw, desc in RISKY_MCP_KEYWORDS.items():
            if kw in blob_low:
                matched_risk = (kw, desc)
                break
        if not matched_risk:
            continue

        # Check for filesystem root exposure or missing guardrails
        args_str = " ".join(str(a) for a in cfg.get("args", [])) if isinstance(cfg.get("args"), list) else ""
        has_guardrail = any(h.lower() in blob.lower() for h in SAFE_GUARDRAIL_HINTS)
        root_fs_danger = matched_risk[0] == "filesystem" and (
            re.search(r"(?:^|\s)/(?:\s|$)", args_str) or str(Path.home()) in args_str
        )

        if root_fs_danger:
            unrestricted.append(f"{name} ({fp.name}): filesystem MCP scoped broadly ({args_str[:80]})")
        elif not has_guardrail:
            unrestricted.append(
                f"{name} ({fp.name}): high-impact {matched_risk[1]} server with no explicit read-only or destructive-tool blocklist"
            )
        else:
            protected.append(f"{name} ({fp.name}): explicit guardrail/override detected")

    if unrestricted:
        return CheckResult(
            check_id="AS-002",
            owasp_ref="OWASP ASI02",
            domain="MCP & Tool Governance",
            title="Least-Privilege Guardrails on High-Impact MCP Tools",
            status="FAIL" if len(unrestricted) >= 2 else "WARN",
            severity="HIGH",
            summary=f"{len(unrestricted)} high-impact MCP server(s) lack explicit least-privilege guardrails.",
            evidence=unrestricted[:10] + protected[:5],
            remediation="Restrict high-impact MCP servers using explicit feature overrides (for example WORKSPACE_FEATURE_OVERRIDES blocking send/delete/trash), --read-only flags, or tightly scoped workspace paths.",
        )

    return CheckResult(
        check_id="AS-002",
        owasp_ref="OWASP ASI02",
        domain="MCP & Tool Governance",
        title="Least-Privilege Guardrails on High-Impact MCP Tools",
        status="PASS",
        severity="HIGH",
        summary="All detected high-impact MCP servers enforce explicit least-privilege guardrails.",
        evidence=protected[:10] or ["No unrestricted high-impact MCP servers found."],
    )


def _check_as003_mcp_secrets(mcp_files: list[Path]) -> CheckResult:
    findings: list[str] = []
    for fp in mcp_files:
        data = _parse_json(fp)
        if not data:
            continue
        servers = _extract_mcp_servers(data)
        for name, cfg in servers.items():
            # Inspect env dict
            env_map = cfg.get("env")
            if isinstance(env_map, dict):
                for k, v in env_map.items():
                    if not isinstance(v, str) or not v.strip():
                        continue
                    v_clean = v.strip()
                    if v_clean.startswith("${") or v_clean.startswith("$"):
                        continue
                    hit_label = None
                    for label, pat in SECRET_PATTERNS:
                        if pat.search(v_clean):
                            hit_label = label
                            break
                    if not hit_label and SENSITIVE_ENV_KEY_RE.search(k) and len(v_clean) >= 12:
                        hit_label = f"Plaintext env credential ({k})"
                    if hit_label:
                        findings.append(f"{fp}: server '{name}' env {k} -> {hit_label} [{_mask_secret(v_clean)}]")
            # Inspect args/headers for hardcoded tokens
            raw = json.dumps({k: v for k, v in cfg.items() if k != "env"})
            for label, pat in SECRET_PATTERNS:
                for m in pat.finditer(raw):
                    findings.append(f"{fp}: server '{name}' args/headers -> {label} [{_mask_secret(m.group(0))}]")

    if findings:
        return CheckResult(
            check_id="AS-003",
            owasp_ref="OWASP ASI03",
            domain="Secrets & Identity Isolation",
            title="Hardcoded Secrets in MCP Configurations",
            status="FAIL",
            severity="CRITICAL",
            summary=f"Detected {len(findings)} hardcoded secret/token value(s) in MCP configuration files.",
            evidence=findings[:12],
            remediation="Remove literal API keys from MCP JSON configs; load secrets via OS keyring, secret manager, or environment variable references (${ENV_VAR}).",
        )
    return CheckResult(
        check_id="AS-003",
        owasp_ref="OWASP ASI03",
        domain="Secrets & Identity Isolation",
        title="Hardcoded Secrets in MCP Configurations",
        status="PASS",
        severity="CRITICAL",
        summary="No hardcoded API keys or plaintext tokens found in MCP config files.",
        evidence=[f"Scanned {len(mcp_files)} MCP config file(s)."],
    )


def _check_as004_config_perms(mcp_files: list[Path], target_path: Path) -> CheckResult:
    if os.name == "nt":
        return CheckResult(
            check_id="AS-004",
            owasp_ref="OWASP ASI03",
            domain="Secrets & Identity Isolation",
            title="Strict Permissions (0600) on Agent Configs & .env Files",
            status="SKIP",
            severity="MEDIUM",
            summary="POSIX mode checks skipped on Windows.",
        )

    targets = list(mcp_files)
    env_file = target_path / ".env"
    if env_file.is_file():
        targets.append(env_file.resolve())

    if not targets:
        return CheckResult(
            check_id="AS-004",
            owasp_ref="OWASP ASI03",
            domain="Secrets & Identity Isolation",
            title="Strict Permissions (0600) on Agent Configs & .env Files",
            status="PASS",
            severity="MEDIUM",
            summary="No sensitive MCP config or .env files present to check.",
        )

    loose: list[str] = []
    ok: list[str] = []
    for fp in targets:
        try:
            mode = stat.S_IMODE(fp.stat().st_mode)
        except OSError:
            continue
        if mode & 0o077:
            loose.append(f"{fp}: mode {oct(mode)} (group/other accessible; expected 0600)")
        else:
            ok.append(f"{fp}: mode {oct(mode)}")

    if loose:
        return CheckResult(
            check_id="AS-004",
            owasp_ref="OWASP ASI03",
            domain="Secrets & Identity Isolation",
            title="Strict Permissions (0600) on Agent Configs & .env Files",
            status="WARN",
            severity="MEDIUM",
            summary=f"{len(loose)} agent config or .env file(s) have group/world-readable permissions.",
            evidence=loose[:10] + ok[:5],
            remediation="Lock down permissions with 'chmod 600 <file>' on all MCP configs and .env files.",
        )
    return CheckResult(
        check_id="AS-004",
        owasp_ref="OWASP ASI03",
        domain="Secrets & Identity Isolation",
        title="Strict Permissions (0600) on Agent Configs & .env Files",
        status="PASS",
        severity="MEDIUM",
        summary=f"All {len(ok)} checked agent config/.env file(s) enforce strict owner-only permissions.",
        evidence=ok[:10],
    )


def _check_as005_supply_chain(servers: list[tuple[Path, str, dict[str, Any]]]) -> CheckResult:
    if not servers:
        return CheckResult(
            check_id="AS-005",
            owasp_ref="OWASP ASI04",
            domain="Supply Chain & Remote Endpoints",
            title="Pinned MCP Versions & Encrypted Transport",
            status="PASS",
            severity="HIGH",
            summary="No MCP servers configured.",
        )

    issues: list[str] = []
    for fp, name, cfg in servers:
        cmd = str(cfg.get("command", "")).strip()
        args = [str(a) for a in cfg.get("args", [])] if isinstance(cfg.get("args"), list) else []
        url = str(cfg.get("url") or cfg.get("serverUrl") or "").strip()

        if os.path.basename(cmd) in ("npx", "uvx", "pnpx", "bunx"):
            pkg_args = [a for a in args if not a.startswith("-")]
            for pkg in pkg_args[:1]:
                # Scoped package @scope/pkg@1.2.3 has '@' after '/'
                pinned = bool(re.search(r"@\d+\.\d+", pkg) or "==" in pkg or "@sha256:" in pkg)
                if not pinned:
                    issues.append(f"{name} ({fp.name}): unpinned dynamic runner '{cmd} {' '.join(args[:3])}'")
        if os.path.basename(cmd) == "docker" and "run" in args:
            if any(a.endswith(":latest") for a in args):
                issues.append(f"{name} ({fp.name}): Docker MCP server uses mutable ':latest' tag")
        if url.startswith("http://") and not re.match(r"^http://(?:127\.0\.0\.1|localhost|\[::1\])(?::\d+)?", url):
            issues.append(f"{name} ({fp.name}): unencrypted remote HTTP MCP endpoint ({url})")

    if issues:
        return CheckResult(
            check_id="AS-005",
            owasp_ref="OWASP ASI04",
            domain="Supply Chain & Remote Endpoints",
            title="Pinned MCP Versions & Encrypted Transport",
            status="FAIL" if any("unencrypted remote HTTP" in i for i in issues) else "WARN",
            severity="HIGH",
            summary=f"Found {len(issues)} MCP supply-chain or transport weakness(es).",
            evidence=issues[:10],
            remediation="Pin npx/uvx MCP packages to exact version numbers (or build locally from verified source) and require HTTPS for any non-localhost MCP server.",
        )
    return CheckResult(
        check_id="AS-005",
        owasp_ref="OWASP ASI04",
        domain="Supply Chain & Remote Endpoints",
        title="Pinned MCP Versions & Encrypted Transport",
        status="PASS",
        severity="HIGH",
        summary="All configured MCP servers use local/pinned artifacts and encrypted or loopback transport.",
    )


def _check_as006_invisible_unicode(instruction_files: list[Path]) -> CheckResult:
    hits: list[str] = []
    for fp in instruction_files:
        txt = _read_text(fp)
        if not txt:
            continue
        file_hits: dict[str, int] = {}
        for idx, ch in enumerate(txt):
            # Ignore leading UTF-8 BOM at position 0
            if idx == 0 and ord(ch) == 0xFEFF:
                continue
            label = _is_hidden_unicode(ch)
            if label:
                file_hits[label] = file_hits.get(label, 0) + 1
        if file_hits:
            summary_str = ", ".join(f"{k} x{v}" for k, v in list(file_hits.items())[:4])
            hits.append(f"{fp}: {summary_str}")

    if hits:
        return CheckResult(
            check_id="AS-006",
            owasp_ref="OWASP ASI01",
            domain="Prompt Injection & Skill Integrity",
            title="Invisible Unicode & Bidi Smuggling in Agent Rules/Skills",
            status="FAIL",
            severity="CRITICAL",
            summary=f"Detected hidden Unicode or Bidi control characters in {len(hits)} agent instruction file(s).",
            evidence=hits[:12],
            remediation="Inspect the flagged files with 'cat -v' or a hex viewer and strip all Unicode Tag (U+E0000-E007F), zero-width, and Bidi override characters before letting any AI agent read them.",
        )
    return CheckResult(
        check_id="AS-006",
        owasp_ref="OWASP ASI01",
        domain="Prompt Injection & Skill Integrity",
        title="Invisible Unicode & Bidi Smuggling in Agent Rules/Skills",
        status="PASS",
        severity="CRITICAL",
        summary=f"No invisible Unicode smuggling or Trojan Source Bidi characters found across {len(instruction_files)} instruction/skill file(s).",
    )


def _check_as007_prompt_injection(instruction_files: list[Path]) -> CheckResult:
    hits: list[str] = []
    for fp in instruction_files:
        txt = _read_text(fp)
        if not txt:
            continue
        for label, pat in PROMPT_INJECTION_PATTERNS:
            m = pat.search(txt)
            if m:
                snippet = re.sub(r"\s+", " ", m.group(0))[:90]
                hits.append(f"{fp}: {label} -> \"{snippet}\"")

    if hits:
        return CheckResult(
            check_id="AS-007",
            owasp_ref="OWASP ASI01",
            domain="Prompt Injection & Skill Integrity",
            title="Indirect Prompt-Injection Directives in Rules/Skills",
            status="FAIL",
            severity="HIGH",
            summary=f"Flagged {len(hits)} prompt-injection or stealth override pattern(s) in agent instruction files.",
            evidence=hits[:12],
            remediation="Review and remove adversarial override or stealth directives from repo AGENTS.md, .cursorrules, and SKILL.md files before opening in an AI IDE.",
        )
    return CheckResult(
        check_id="AS-007",
        owasp_ref="OWASP ASI01",
        domain="Prompt Injection & Skill Integrity",
        title="Indirect Prompt-Injection Directives in Rules/Skills",
        status="PASS",
        severity="HIGH",
        summary=f"No adversarial prompt-injection override directives detected across {len(instruction_files)} instruction/skill file(s).",
    )


def _check_as008_rce_exfil_sinks(instruction_files: list[Path], mcp_files: list[Path]) -> CheckResult:
    hits: list[str] = []
    for fp in instruction_files + mcp_files:
        txt = _read_text(fp)
        if not txt:
            continue
        for label, pat in RCE_EXFIL_PATTERNS:
            m = pat.search(txt)
            if m:
                snippet = re.sub(r"\s+", " ", m.group(0))[:90]
                hits.append(f"{fp}: {label} -> \"{snippet}\"")

    if hits:
        return CheckResult(
            check_id="AS-008",
            owasp_ref="OWASP ASI05",
            domain="Prompt Injection & Skill Integrity",
            title="Shell RCE & Data Exfiltration Sinks in Skills/Configs",
            status="FAIL",
            severity="CRITICAL",
            summary=f"Detected {len(hits)} dangerous RCE or exfiltration pattern(s) in agent instructions/configs.",
            evidence=hits[:12],
            remediation="Do not run untrusted skills or rules that pipe remote downloads to sh/bash, read private keys, or post to external webhooks.",
        )
    return CheckResult(
        check_id="AS-008",
        owasp_ref="OWASP ASI05",
        domain="Prompt Injection & Skill Integrity",
        title="Shell RCE & Data Exfiltration Sinks in Skills/Configs",
        status="PASS",
        severity="CRITICAL",
        summary="No remote-shell RCE or webhook exfiltration sinks found in agent rules or configs.",
    )


def _check_as009_yolo_settings(target_path: Path, home_dir: Path | None) -> CheckResult:
    candidates = [
        target_path / ".claude/settings.json",
        target_path / ".claude/settings.local.json",
        target_path / ".cursor/settings.json",
        target_path / ".vscode/settings.json",
        target_path / ".gemini/settings.json",
    ]
    if home_dir:
        candidates.extend(
            [
                home_dir / ".claude/settings.json",
                home_dir / ".gemini/settings.json",
                home_dir / ".config/Code/User/settings.json",
                home_dir / ".config/Cursor/User/settings.json",
            ]
        )

    hits: list[str] = []
    checked = 0
    for fp in candidates:
        txt = _read_text(fp)
        if not txt:
            continue
        checked += 1
        for label, pat in YOLO_PATTERNS:
            if pat.search(txt):
                hits.append(f"{fp}: {label}")

    if hits:
        return CheckResult(
            check_id="AS-009",
            owasp_ref="OWASP ASI05",
            domain="Runtime Execution Guardrails",
            title="Auto-Approve & Unrestricted YOLO Execution Flags",
            status="FAIL",
            severity="HIGH",
            summary=f"Detected {len(hits)} unrestricted auto-approval / YOLO execution setting(s).",
            evidence=hits[:10],
            remediation="Disable global yoloMode/autoApprove and replace wildcard Bash(*) permissions with explicit read-only command allowlists.",
        )
    return CheckResult(
        check_id="AS-009",
        owasp_ref="OWASP ASI05",
        domain="Runtime Execution Guardrails",
        title="Auto-Approve & Unrestricted YOLO Execution Flags",
        status="PASS",
        severity="HIGH",
        summary=f"No unrestricted YOLO / auto-approve flags detected across {checked} checked agent settings file(s).",
    )


def _list_listening_tcp() -> list[tuple[str, int, str]]:
    """Return list of (bind_addr, port, process_hint) from ss or /proc/net/tcp."""
    rows: list[tuple[str, int, str]] = []
    try:
        proc = subprocess.run(
            ["ss", "-tlnp"],
            capture_output=True,
            text=True,
            timeout=4,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout:
            for line in proc.stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) < 4:
                    continue
                local = parts[3]
                if ":" not in local:
                    continue
                addr, port_s = local.rsplit(":", 1)
                addr = addr.strip("[]")
                try:
                    port = int(port_s)
                except ValueError:
                    continue
                proc_hint = parts[5] if len(parts) >= 6 else ""
                rows.append((addr, port, proc_hint))
            return rows
    except (OSError, subprocess.SubprocessError):
        pass

    # Fallback: Linux /proc/net/tcp
    tcp_path = Path("/proc/net/tcp")
    if tcp_path.is_file():
        for line in (_read_text(tcp_path) or "").splitlines()[1:]:
            parts = line.split()
            if len(parts) < 4 or parts[3] != "0A":  # 0A = LISTEN
                continue
            hex_ip, hex_port = parts[1].split(":")
            port = int(hex_port, 16)
            ip_bytes = bytes.fromhex(hex_ip)[::-1]
            addr = ".".join(str(b) for b in ip_bytes)
            rows.append((addr, port, ""))
    return rows


def _check_as010_exposed_ai_ports(scan_home: bool = True) -> CheckResult:
    if not scan_home:
        return CheckResult(
            check_id="AS-010",
            owasp_ref="OWASP ASI07",
            domain="Runtime Execution Guardrails",
            title="Exposed Local LLM, Agent & Browser Debug Ports",
            status="SKIP",
            severity="CRITICAL",
            summary="Host socket scan skipped in repository-only (--no-home) mode.",
        )
    listeners = _list_listening_tcp()
    exposed: list[str] = []
    loopback: list[str] = []

    for addr, port, proc_hint in listeners:
        if port not in LOCAL_AI_PORTS:
            continue
        svc = LOCAL_AI_PORTS[port]
        is_wild = addr in ("0.0.0.0", "*", "::", "")
        label = f"{addr}:{port} ({svc})" + (f" {proc_hint[:45]}" if proc_hint else "")
        if is_wild:
            exposed.append(f"EXPOSED ON ALL INTERFACES: {label}")
        else:
            loopback.append(f"Loopback only (safe): {label}")

    if exposed:
        return CheckResult(
            check_id="AS-010",
            owasp_ref="OWASP ASI07",
            domain="Runtime Execution Guardrails",
            title="Exposed Local LLM, Agent & Browser Debug Ports",
            status="FAIL",
            severity="CRITICAL",
            summary=f"{len(exposed)} local AI/LLM or browser debug port(s) are exposed on all network interfaces (0.0.0.0 / ::).",
            evidence=exposed[:10] + loopback[:5],
            remediation="Bind Ollama (OLLAMA_HOST=127.0.0.1:11434), Open WebUI, vLLM, Jupyter, and Chrome CDP strictly to 127.0.0.1 and verify host firewall rules.",
        )

    if loopback:
        return CheckResult(
            check_id="AS-010",
            owasp_ref="OWASP ASI07",
            domain="Runtime Execution Guardrails",
            title="Exposed Local LLM, Agent & Browser Debug Ports",
            status="PASS",
            severity="CRITICAL",
            summary=f"{len(loopback)} local AI/debug port(s) detected and all are strictly bound to loopback (127.0.0.1).",
            evidence=loopback[:10],
        )

    return CheckResult(
        check_id="AS-010",
        owasp_ref="OWASP ASI07",
        domain="Runtime Execution Guardrails",
        title="Exposed Local LLM, Agent & Browser Debug Ports",
        status="PASS",
        severity="CRITICAL",
        summary="No exposed local LLM, agent, or browser remote-debugging ports detected.",
    )


def _check_as011_repo_env_secrets(target_path: Path) -> CheckResult:
    issues: list[str] = []

    # Check if .env is tracked in git
    if (target_path / ".git").exists():
        try:
            proc = subprocess.run(
                ["git", "-C", str(target_path), "ls-files"],
                capture_output=True,
                text=True,
                timeout=4,
                check=False,
            )
            if proc.returncode == 0:
                tracked = proc.stdout.splitlines()
                for rel in tracked:
                    base = os.path.basename(rel)
                    if base == ".env" or base.startswith(".env.") and not base.endswith(".example"):
                        issues.append(f"Tracked secret env file in git: {rel}")
        except (OSError, subprocess.SubprocessError):
            pass

    # Scan small text config/env files in target_path (depth <= 2) for hardcoded AI/cloud keys
    scanned_files = 0
    for root, dirs, filenames in os.walk(target_path):
        rel_root = Path(root).relative_to(target_path)
        if len(rel_root.parts) > 2:
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fn in filenames:
            if fn.endswith((".png", ".jpg", ".pdf", ".docx", ".zip", ".lock", ".pyc")):
                continue
            fp = Path(root) / fn
            txt = _read_text(fp, max_bytes=128_000)
            if not txt:
                continue
            scanned_files += 1
            for label, pat in SECRET_PATTERNS:
                m = pat.search(txt)
                if m:
                    # Skip our own regex definition strings in scanner/test files when clearly placeholder
                    matched_val = m.group(0)
                    if "EXAMPLE" in matched_val.upper() or "DUMMY" in matched_val.upper():
                        continue
                    issues.append(f"{fp.relative_to(target_path)}: {label} [{_mask_secret(matched_val)}]")
                    break

    if issues:
        return CheckResult(
            check_id="AS-011",
            owasp_ref="OWASP ASI03",
            domain="Secrets & Identity Isolation",
            title="Repository Secret Leakage & Tracked .env Files",
            status="FAIL",
            severity="CRITICAL",
            summary=f"Found {len(issues)} secret or tracked .env exposure(s) in target workspace.",
            evidence=issues[:12],
            remediation="Remove tracked .env files with 'git rm --cached .env', add '.env*' to .gitignore, and rotate any exposed API keys immediately.",
        )
    return CheckResult(
        check_id="AS-011",
        owasp_ref="OWASP ASI03",
        domain="Secrets & Identity Isolation",
        title="Repository Secret Leakage & Tracked .env Files",
        status="PASS",
        severity="CRITICAL",
        summary=f"No tracked .env files or hardcoded API keys found across {scanned_files} scanned workspace file(s).",
    )


def _check_as012_workspace_hooks(target_path: Path) -> CheckResult:
    hook_candidates = [
        target_path / ".claude/settings.json",
        target_path / ".claude/settings.local.json",
        target_path / ".gemini/settings.json",
        target_path / ".cursor/hooks.json",
    ]
    hits: list[str] = []
    for fp in hook_candidates:
        data = _parse_json(fp)
        if not data:
            continue
        if "hooks" in data and data["hooks"]:
            hits.append(f"{fp.relative_to(target_path)}: defines workspace-level agent hooks ({len(data['hooks'])} trigger(s))")

    # Also check .claude/hooks or .gemini/hooks directories
    for rel in (".claude/hooks", ".gemini/hooks", ".cursor/hooks"):
        d = target_path / rel
        if d.is_dir():
            scripts = [p.name for p in d.iterdir() if p.is_file()]
            if scripts:
                hits.append(f"{rel}/: contains executable hook scripts ({', '.join(scripts[:5])})")

    if hits:
        return CheckResult(
            check_id="AS-012",
            owasp_ref="OWASP ASI04",
            domain="Runtime Execution Guardrails",
            title="Untrusted Workspace-Level Agent Hooks",
            status="WARN",
            severity="HIGH",
            summary=f"Workspace defines {len(hits)} auto-executed agent hook configuration(s) that trigger on repo activity.",
            evidence=hits[:10],
            remediation="Audit every workspace-level hook script before trusting a cloned repository; disable automatic repo hooks in untrusted directories.",
        )
    return CheckResult(
        check_id="AS-012",
        owasp_ref="OWASP ASI04",
        domain="Runtime Execution Guardrails",
        title="Untrusted Workspace-Level Agent Hooks",
        status="PASS",
        severity="HIGH",
        summary="No workspace-level auto-executing agent hooks detected in target directory.",
    )


def _check_as013_workspace_credentials(target_path: Path) -> CheckResult:
    sensitive_names = {
        "id_rsa",
        "id_ed25519",
        "id_ecdsa",
        ".npmrc",
        ".pypirc",
        "kubeconfig",
        "credentials.json",
        "service-account.json",
    }
    found: list[str] = []
    if target_path.is_dir():
        for root, dirs, filenames in os.walk(target_path):
            rel_root = Path(root).relative_to(target_path)
            if len(rel_root.parts) > 2:
                dirs[:] = []
                continue
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fn in filenames:
                if fn in sensitive_names or fn.endswith((".pem", ".key", ".p12")):
                    fp = Path(root) / fn
                    found.append(str(fp.relative_to(target_path)))

    if found:
        return CheckResult(
            check_id="AS-013",
            owasp_ref="OWASP ASI06",
            domain="Secrets & Identity Isolation",
            title="Private Keys & Auth Artifacts Inside Agent Workspace",
            status="WARN",
            severity="HIGH",
            summary=f"Found {len(found)} private key or auth artifact(s) directly inside the agent-readable workspace.",
            evidence=found[:10],
            remediation="Move SSH keys, PEM certificates, kubeconfigs, and service-account JSON files outside coding workspaces and add them to agent ignore rules (.cursorignore / .geminiignore).",
        )
    return CheckResult(
        check_id="AS-013",
        owasp_ref="OWASP ASI06",
        domain="Secrets & Identity Isolation",
        title="Private Keys & Auth Artifacts Inside Agent Workspace",
        status="PASS",
        severity="HIGH",
        summary="No private keys, PEM files, or cloud credential bundles found inside target workspace.",
    )


def _check_as014_guardrail_baseline(target_path: Path, home_dir: Path | None) -> CheckResult:
    ignore_files = [
        ".cursorignore",
        ".geminiignore",
        ".claudeignore",
        ".aiignore",
        "SECURITY.md",
        ".agentshield.json",
    ]
    found: list[str] = []
    for name in ignore_files:
        if (target_path / name).is_file():
            found.append(name)

    if home_dir:
        for rel in ("AGENTS.md", ".gemini/GEMINI.md", ".claude/CLAUDE.md"):
            txt = _read_text(home_dir / rel)
            if txt and any(w in txt.lower() for w in ("deny-by-default", "do not", "never", "guardrail", "backup")):
                found.append(f"~/{rel} (policy rules)")

    if found:
        return CheckResult(
            check_id="AS-014",
            owasp_ref="OWASP ASI08",
            domain="MCP & Tool Governance",
            title="Agent Ignore Rules & Guardrail Policy Baseline",
            status="PASS",
            severity="LOW",
            summary=f"Detected {len(found)} agent ignore/policy guardrail file(s).",
            evidence=found[:10],
        )
    return CheckResult(
        check_id="AS-014",
        owasp_ref="OWASP ASI08",
        domain="MCP & Tool Governance",
        title="Agent Ignore Rules & Guardrail Policy Baseline",
        status="WARN",
        severity="LOW",
        summary="No agent ignore file (.cursorignore / .claudeignore / .geminiignore) or SECURITY.md baseline found in workspace.",
        remediation="Add a .aiignore / .cursorignore / .geminiignore file excluding .env*, *.pem, *.key, and secrets/ directories from AI agent context indexing.",
    )


def run_scan(
    target_path: str | Path = ".",
    scan_home: bool = True,
    redact: bool = False,
) -> ScanReport:
    """Execute all 14 read-only AgentShield checks and return a ScanReport."""
    target = Path(target_path).expanduser().resolve()
    home = Path.home().resolve() if scan_home else None

    mcp_files = _discover_mcp_files(target, home)
    instruction_files = _discover_instruction_files(target, home)

    c001, servers = _check_as001_mcp_inventory(mcp_files)
    checks = [
        c001,
        _check_as002_destructive_mcp(servers),
        _check_as003_mcp_secrets(mcp_files),
        _check_as004_config_perms(mcp_files, target),
        _check_as005_supply_chain(servers),
        _check_as006_invisible_unicode(instruction_files),
        _check_as007_prompt_injection(instruction_files),
        _check_as008_rce_exfil_sinks(instruction_files, mcp_files),
        _check_as009_yolo_settings(target, home),
        _check_as010_exposed_ai_ports(scan_home=scan_home),
        _check_as011_repo_env_secrets(target),
        _check_as012_workspace_hooks(target),
        _check_as013_workspace_credentials(target),
        _check_as014_guardrail_baseline(target, home),
    ]

    report = ScanReport(
        tool_version=__version__,
        generated_at=utc_now_iso(),
        target_path=str(target),
        scanned_home=scan_home,
        hostname=socket.gethostname(),
        platform_info=f"{platform.system()} {platform.release()} ({platform.machine()})",
        redacted=False,
        checks=checks,
        metadata={
            "mcp_config_files": len(mcp_files),
            "mcp_servers": len(servers),
            "instruction_files": len(instruction_files),
        },
    )

    if redact:
        report = redact_report(report, str(Path.home().resolve()), getpass.getuser())
    return report
