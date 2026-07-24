# actionlint should lint a standalone workflow YAML (uploaded outside
# .github/workflows/), not only files under that path (fixes FA-05).
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.scanners import actionlint_scanner as al

_WORKFLOW = """name: ci
on: [pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.pull_request.title }}"
"""


def _ws(files):
    d = tempfile.mkdtemp()
    for rel, content in files.items():
        p = os.path.join(d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(content)
    return d


def test_standalone_workflow_is_detected():
    ws = _ws({"ci.yml": _WORKFLOW})
    files = al._workflow_files(ws)
    assert any(f.endswith("ci.yml") for f in files)


def test_non_workflow_yaml_ignored():
    ws = _ws({"config.yml": "database:\n  host: localhost\n  port: 5432\n"})
    assert al._workflow_files(ws) == []


def test_workflow_in_github_dir_still_detected():
    ws = _ws({".github/workflows/ci.yml": _WORKFLOW})
    files = al._workflow_files(ws)
    assert any("ci.yml" in f for f in files)


def test_looks_like_workflow_helper():
    ws = _ws({"a.yml": _WORKFLOW, "b.yml": "just: data\n"})
    assert al._looks_like_workflow(os.path.join(ws, "a.yml")) is True
    assert al._looks_like_workflow(os.path.join(ws, "b.yml")) is False
