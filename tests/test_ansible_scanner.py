# Lightweight Ansible security guard (fixes FA-06: firewall-disable /
# destructive shell tasks were missed). Targeted, low-false-positive.
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.scanners import ansible_scanner as al
from backend import scanners

_PLAYBOOK = """- hosts: all
  become: yes
  tasks:
    - name: add key
      shell: echo "AKIAIOSFODNN7EXAMPLE" >> /root/.aws/credentials
    - name: open firewall
      shell: ufw disable
    - name: loosen perms
      shell: chmod -R 777 /var/www
"""

_K8S = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      containers:
        - name: web
          command: ["ufw", "disable"]
"""


def _ws(files):
    d = tempfile.mkdtemp()
    for name, content in files.items():
        with open(os.path.join(d, name), "w") as f:
            f.write(content)
    return d


def test_flags_firewall_disable_and_world_writable():
    fs = al.scan(_ws({"playbook.yml": _PLAYBOOK}))
    rules = {f["rule_id"] for f in fs}
    assert "ANSIBLE-FIREWALL-DISABLED" in rules
    assert "ANSIBLE-WORLD-WRITABLE" in rules
    fw = next(f for f in fs if f["rule_id"] == "ANSIBLE-FIREWALL-DISABLED")
    assert fw["severity"] == "HIGH" and "ufw disable" in fw["evidence"]


def test_kubernetes_manifest_not_scanned_as_ansible():
    # k8s YAML has apiVersion+kind — must NOT be treated as an Ansible play
    # even though it contains "ufw disable".
    fs = al.scan(_ws({"deploy.yaml": _K8S}))
    assert fs == []


def test_non_ansible_yaml_ignored():
    fs = al.scan(_ws({"config.yml": "database:\n  host: db\n  port: 5432\n"}))
    assert fs == []


def test_registered_as_11th_scanner():
    assert al in scanners.SCANNERS
    assert al.available() is True
    status = scanners.scanner_status()
    assert status.get("ansible-guard") is True
    assert len(scanners.SCANNERS) == 11
