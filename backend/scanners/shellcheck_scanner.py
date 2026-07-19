# =========================================================
# SHELLCHECK ADAPTER — shell script analysis (.sh, entrypoints)
# Catches unquoted expansions, unsafe rm/globbing, `curl | bash`,
# word-splitting bugs — issues no other scanner in the set covers.
# =========================================================

import json
import os

from backend.scanners.base import is_available, make_finding, run_command

TOOL = "shellcheck"

SEVERITY_MAP = {
    "error": "HIGH",
    "warning": "MEDIUM",
    "info": "LOW",
    "style": "LOW",
}

_SHELL_EXTS = (".sh", ".bash", ".ksh", ".dash")
# Shebang hints for extensionless scripts (entrypoint, run, …). zsh is
# excluded because shellcheck cannot analyse it.
_SHEBANG_HINTS = ("/bash", "/sh", "/dash", "/ksh", "env bash", "env sh", "env dash", "env ksh")


def available() -> bool:
    return is_available(TOOL)


def _shell_scripts(workspace_dir: str) -> list:
    scripts = []
    for root, _dirs, files in os.walk(workspace_dir):
        for name in files:
            if name.lower().endswith(_SHELL_EXTS):
                scripts.append(os.path.join(root, name))
                continue
            if "." not in name:  # extensionless — sniff the shebang
                path = os.path.join(root, name)
                try:
                    with open(path, "r", errors="ignore") as fh:
                        first = fh.readline(200)
                except OSError:
                    continue
                if first.startswith("#!") and "zsh" not in first and any(h in first for h in _SHEBANG_HINTS):
                    scripts.append(path)
    return scripts


def parse_report(report: list, workspace_dir: str) -> list:
    findings = []
    for issue in report or []:
        code = issue.get("code")
        rule = f"SC{code}" if code is not None else "shellcheck"
        filepath = issue.get("file", "")
        if workspace_dir and filepath:
            filepath = os.path.relpath(filepath, workspace_dir)
        findings.append(make_finding(
            tool=TOOL,
            rule_id=rule,
            severity=SEVERITY_MAP.get(issue.get("level", ""), "LOW"),
            file=filepath,
            line=issue.get("line", 0),
            title=issue.get("message", "Shell script issue"),
            detail="Shell script quality/security issue (shellcheck).",
            guideline=f"https://www.shellcheck.net/wiki/SC{code}" if code is not None else None,
        ))
    return findings


def scan(workspace_dir: str) -> list:
    scripts = _shell_scripts(workspace_dir)
    if not scripts:
        return []
    result = run_command([TOOL, "-f", "json", *scripts])
    if not result.stdout.strip():
        return []
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []
    return parse_report(report, workspace_dir)
