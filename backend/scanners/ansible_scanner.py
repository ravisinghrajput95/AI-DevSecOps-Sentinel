# =========================================================
# ANSIBLE SECURITY GUARD (built-in, dependency-free)
# The other scanners cover Terraform/K8s/Docker/CI but not
# Ansible, so risky playbook tasks — disabling the firewall,
# flushing iptables, world-writable perms, piping a download
# into a shell — slipped through (a documented false negative).
# This is a targeted, low-false-positive pattern check over
# Ansible playbook tasks; not a full ansible-lint (which would
# drag in ansible-core), just the clear security regressions.
# =========================================================

import os
import re

from backend.scanners.base import find_files, make_finding

TOOL = "ansible-guard"

# (pattern, rule_id, severity, title)
_RISKS = [
    (re.compile(r"\bufw\s+disable\b", re.I),
     "ANSIBLE-FIREWALL-DISABLED", "HIGH", "Task disables the UFW firewall"),
    (re.compile(r"\bsystemctl\s+(?:stop|disable)\s+firewalld\b", re.I),
     "ANSIBLE-FIREWALL-DISABLED", "HIGH", "Task stops/disables firewalld"),
    (re.compile(r"\biptables\s+-F\b"),
     "ANSIBLE-FIREWALL-FLUSHED", "HIGH", "Task flushes all iptables rules"),
    (re.compile(r"\bsetenforce\s+0\b"),
     "ANSIBLE-SELINUX-DISABLED", "HIGH", "Task disables SELinux enforcement"),
    (re.compile(r"\bchmod\s+(?:-R\s+)?0?777\b"),
     "ANSIBLE-WORLD-WRITABLE", "HIGH", "Task sets world-writable (777) permissions"),
    (re.compile(r"\brm\s+-rf\s+/(?:\s|\*|$)"),
     "ANSIBLE-DESTRUCTIVE-RM", "CRITICAL", "Task runs a destructive rm -rf on '/'"),
    (re.compile(r"\bcurl\b[^\n|]*\|\s*(?:sudo\s+)?(?:bash|sh)\b", re.I),
     "ANSIBLE-CURL-PIPE-SHELL", "HIGH", "Task pipes a downloaded script into a shell"),
]

_K8S = re.compile(r"^apiVersion\s*:", re.M)
_K8S_KIND = re.compile(r"^kind\s*:", re.M)
_ANSIBLE_MARK = re.compile(r"^\s*-?\s*hosts\s*:|^\s*tasks\s*:|^\s*become\s*:", re.M)


def available() -> bool:
    return True  # pure-Python; always available


def _is_ansible(text: str) -> bool:
    if _K8S.search(text) and _K8S_KIND.search(text):
        return False  # a Kubernetes manifest, not an Ansible playbook
    return bool(_ANSIBLE_MARK.search(text) or "ansible.builtin" in text)


def scan(workspace_dir: str) -> list:
    findings = []
    for path in find_files(workspace_dir,
                           lambda n: n.lower().endswith((".yml", ".yaml"))):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
        except Exception:
            continue
        if not _is_ansible(text):
            continue
        rel = os.path.relpath(path, workspace_dir)
        for lineno, line in enumerate(text.splitlines(), start=1):
            for pattern, rule_id, sev, title in _RISKS:
                if pattern.search(line):
                    findings.append(make_finding(
                        tool=TOOL, rule_id=rule_id, severity=sev,
                        file=rel, line=lineno, title=title,
                        evidence=line.strip()[:200],
                        detail="Ansible playbook task performs a security-"
                               "weakening or destructive operation."))
    return findings
