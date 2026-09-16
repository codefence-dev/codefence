"""SQLite history tests."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

import codefence as cf


@pytest.fixture
def isolated_history(tmp_path, monkeypatch):
    """Redirect history DB to a temp dir for each test."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    yield tmp_path
    # cleanup not needed; tmp_path auto-removes


def test_history_path_uses_xdg(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    p = cf._history_path()
    assert str(tmp_path) in str(p)
    assert p.name == "history.db"


def test_record_and_query_scan(isolated_history, all_rules):
    src = 'API_KEY = "sk-abcdef1234567890"\n'
    findings = cf.scan_source(src, cf.Language.PYTHON, all_rules,
                              path="x.py")
    evidence = {
        "scan_id": "abc123",
        "timestamp": "2026-09-16T00:00:00+00:00",
        "tool_version": "1.0.0",
        "files_scanned": 1,
        "duration_ms": 2,
        "findings_count": len(findings),
        "by_severity": {"critical": 1},
        "rules_hash": "r",
        "policy_hash": "",
        "baseline_hash": "",
        "commit_sha": "deadbeef",
        "result_hash": "x",
    }
    cf._record_scan(evidence, findings)
    conn = cf._open_history_db()
    assert conn is not None
    rows = conn.execute("SELECT scan_id FROM scans").fetchall()
    assert rows == [("abc123",)]
    conn.close()


def test_no_history_env_blocks(isolated_history, monkeypatch, all_rules):
    monkeypatch.setenv("CODEFENCE_NO_HISTORY", "1")
    src = 'API_KEY = "sk-abcdef1234567890"\n'
    findings = cf.scan_source(src, cf.Language.PYTHON, all_rules,
                              path="x.py")
    evidence = {
        "scan_id": "abc123",
        "timestamp": "2026-09-16T00:00:00+00:00",
        "tool_version": "1.0.0",
        "files_scanned": 1,
        "duration_ms": 1,
        "findings_count": len(findings),
        "by_severity": {"critical": 1},
        "rules_hash": "r", "policy_hash": "", "baseline_hash": "",
        "commit_sha": "", "result_hash": "x",
    }
    cf._record_scan(evidence, findings)
    conn = cf._open_history_db()
    rows = conn.execute("SELECT COUNT(*) FROM scans").fetchone()
    assert rows[0] == 0
    conn.close()
