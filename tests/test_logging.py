import json
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import logging_setup


def _reconfigure(monkeypatch, **env):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    logging_setup._configured = False
    logging_setup.configure_logging()


def test_json_format_is_parseable_with_request_id(monkeypatch, capsys):
    _reconfigure(monkeypatch, LOG_FORMAT="json", LOG_LEVEL="INFO")
    logging_setup.set_request_id("abc123")
    logging_setup.get_logger("test").info("hello world=%s", 42)

    line = capsys.readouterr().out.strip().splitlines()[-1]
    rec = json.loads(line)  # must be valid JSON
    assert rec["level"] == "INFO"
    assert rec["logger"] == "test"
    assert rec["msg"] == "hello world=42"
    assert rec["request_id"] == "abc123"
    assert rec["ts"].endswith("Z")


def test_request_id_defaults_and_isolates(monkeypatch, capsys):
    _reconfigure(monkeypatch, LOG_FORMAT="json")
    logging_setup.set_request_id("")  # falsy → sentinel
    logging_setup.get_logger("t").warning("no id here")
    rec = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert rec["request_id"] == "-"
    assert rec["level"] == "WARNING"


def test_text_format_includes_request_id(monkeypatch, capsys):
    _reconfigure(monkeypatch, LOG_FORMAT="text")
    logging_setup.set_request_id("req-xyz")
    logging_setup.get_logger("t").error("boom")
    out = capsys.readouterr().out.strip().splitlines()[-1]
    assert "[req-xyz]" in out
    assert "ERROR" in out and "boom" in out


def test_level_filtering_respects_env(monkeypatch, capsys):
    _reconfigure(monkeypatch, LOG_FORMAT="json", LOG_LEVEL="WARNING")
    log = logging_setup.get_logger("t")
    log.info("should be suppressed")
    log.warning("should appear")
    out = capsys.readouterr().out
    assert "should be suppressed" not in out
    assert "should appear" in out


def test_exception_logging_includes_traceback(monkeypatch, capsys):
    _reconfigure(monkeypatch, LOG_FORMAT="json")
    try:
        raise ValueError("kaboom")
    except ValueError:
        logging_setup.get_logger("t").exception("caught it")
    rec = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert "exc" in rec and "ValueError: kaboom" in rec["exc"]


def teardown_module(_module):
    # Restore default config so other test modules aren't affected
    logging_setup._configured = False
    for k in ("LOG_FORMAT", "LOG_LEVEL"):
        os.environ.pop(k, None)
    logging.getLogger().handlers.clear()
