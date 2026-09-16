"""Policy loading and application tests."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import codefence as cf


def write_policy(tmp_path: Path, data: dict) -> Path:
    p = tmp_path / "policy.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


def test_policy_valid_minimal(tmp_path):
    p = write_policy(tmp_path, {
        "schema": "codefence/policy-v1",
        "overrides": {"R001": "warn"},
    })
    data = cf._load_policy(p)
    assert data["schema"] == "codefence/policy-v1"


def test_policy_invalid_schema(tmp_path):
    p = write_policy(tmp_path, {"schema": "wrong"})
    with pytest.raises(ValueError):
        cf._load_policy(p)


def test_policy_invalid_action(tmp_path):
    p = write_policy(tmp_path, {
        "schema": "codefence/policy-v1",
        "overrides": {"R001": "danger"},
    })
    with pytest.raises(ValueError):
        cf._load_policy(p)


def test_policy_org_id_required(tmp_path):
    p = write_policy(tmp_path, {
        "schema": "codefence/policy-v1",
        "rules": [{
            "id": "NOTORG-1", "name": "x",
            "languages": ["python"], "severity": "high",
            "category": "c", "description": "x",
            "detection": "regex", "patterns": ["a"],
            "message": "m", "remediation": "r",
        }],
    })
    with pytest.raises(ValueError):
        cf._load_policy(p)


def test_policy_pattern_too_long(tmp_path):
    p = write_policy(tmp_path, {
        "schema": "codefence/policy-v1",
        "rules": [{
            "id": "ORG-001", "name": "x",
            "languages": ["python"], "severity": "high",
            "category": "c", "description": "x",
            "detection": "regex", "patterns": ["a" * 600],
            "message": "m", "remediation": "r",
        }],
    })
    with pytest.raises(ValueError):
        cf._load_policy(p)


def test_policy_apply_override(tmp_path, all_rules):
    p = write_policy(tmp_path, {
        "schema": "codefence/policy-v1",
        "overrides": {"R001": "allow"},
    })
    data = cf._load_policy(p)
    new_rules = cf._apply_policy(all_rules, data)
    r001 = next(r for r in new_rules if r.id == "R001")
    assert r001.action == "allow"


def test_policy_apply_adds_org_rules(tmp_path, all_rules):
    p = write_policy(tmp_path, {
        "schema": "codefence/policy-v1",
        "rules": [{
            "id": "ORG-002", "name": "no console.log",
            "languages": ["javascript"], "severity": "medium",
            "category": "org-policy", "description": "x",
            "detection": "regex", "patterns": [r"console\.log\("],
            "message": "m", "remediation": "r", "action": "warn",
        }],
    })
    data = cf._load_policy(p)
    new_rules = cf._apply_policy(all_rules, data)
    ids = [r.id for r in new_rules]
    assert "ORG-002" in ids
