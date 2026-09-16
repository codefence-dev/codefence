"""End-to-end integration tests using a real git repository."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import codefence as cf


GIT_ENV = {
    "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
    "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
}


def _run(args, cwd, check=False):
    e = os.environ.copy()
    e.update(GIT_ENV)
    return subprocess.run(
        args, cwd=cwd, capture_output=True, text=True,
        env=e, check=check,
    )


def _run_cf(args, cwd):
    """Run codefence via subprocess in the given directory."""
    root = Path(__file__).resolve().parent.parent
    e = os.environ.copy()
    e.update(GIT_ENV)
    return subprocess.run(
        [sys.executable, str(root / "codefence.py"),
         *args,
         "--rules", str(root / "rules.json")],
        cwd=cwd, capture_output=True, text=True, env=e,
    )


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "r"
    r.mkdir()
    _run(["git", "init", "-q"], cwd=r, check=True)
    _run(["git", "commit", "-q", "--allow-empty", "-m", "init"],
         cwd=r, check=True)
    return r


@pytest.fixture
def hook_env():
    """Env override so the installed hook can find codefence.py in tests."""
    root = Path(__file__).resolve().parent.parent
    return {
        "CODEFENCE_CMD": f"{sys.executable} {root / 'codefence.py'}",
        "CODEFENCE_RULES": str(root / "rules.json"),
    }


# ---------------------------------------------------------------------------
# 1. Git hook blocks a bad commit
# ---------------------------------------------------------------------------

def test_git_hook_blocks_bad_commit(repo, hook_env):
    # install hook
    p = _run_cf(["init-hook"], cwd=repo)
    assert p.returncode == 0, p.stderr
    assert (repo / ".git" / "hooks" / "pre-commit").is_file()

    # stage a bad file
    (repo / "bad.py").write_text(
        'API_KEY = "sk-abcdef1234567890"\n', encoding="utf-8",
    )
    _run(["git", "add", "bad.py"], cwd=repo, check=True)

    # commit should trigger the hook, which calls codefence --staged
    e = os.environ.copy()
    e.update(GIT_ENV)
    e.update(hook_env)
    result = subprocess.run(
        ["git", "commit", "-m", "bad"], cwd=repo,
        capture_output=True, text=True, env=e,
    )
    # hook exits 1 -> commit blocked
    assert result.returncode != 0


def test_git_hook_allows_clean_commit(repo, hook_env):
    # install hook
    _run_cf(["init-hook"], cwd=repo)

    # stage a clean file
    (repo / "ok.py").write_text(
        "def add(a, b):\n    return a + b\n", encoding="utf-8",
    )
    _run(["git", "add", "ok.py"], cwd=repo, check=True)

    e = os.environ.copy()
    e.update(GIT_ENV)
    e.update(hook_env)
    result = subprocess.run(
        ["git", "commit", "-m", "ok"], cwd=repo,
        capture_output=True, text=True, env=e,
    )
    # hook passes -> commit allowed
    assert result.returncode == 0, result.stderr


# ---------------------------------------------------------------------------
# 2. Baseline + diff in a real repo
# ---------------------------------------------------------------------------

def test_baseline_then_new_finding_only(repo):
    # baseline with one bad file already committed
    (repo / "old_bad.py").write_text(
        'API_KEY = "sk-abcdef1234567890"\n', encoding="utf-8",
    )
    _run(["git", "add", "old_bad.py"], cwd=repo, check=True)
    _run(["git", "commit", "-m", "old", "--no-verify"], cwd=repo,
         check=True)

    # create baseline
    p = _run_cf(["baseline"], cwd=repo)
    assert p.returncode == 0, p.stderr
    assert (repo / ".codefence" / "baseline.json").is_file()

    # stage a NEW bad file
    (repo / "new_bad.py").write_text(
        'password = "supersecret123"\n', encoding="utf-8",
    )
    _run(["git", "add", "new_bad.py"], cwd=repo, check=True)

    # --staged --diff should only report the new finding
    p = _run_cf(["--staged", "--diff"], cwd=repo)
    assert p.returncode == 1, (p.returncode, p.stdout, p.stderr)
    assert "new_bad.py" in p.stdout
    # old file should be suppressed
    assert "old_bad.py" not in p.stdout
    assert "existing finding(s) suppressed" in p.stdout


# ---------------------------------------------------------------------------
# 3. Policy overrides and ORG rules
# ---------------------------------------------------------------------------

def test_policy_overrides_and_org_rule(repo):
    policy = repo / "policy.json"
    policy.write_text(json.dumps({
        "schema": "codefence/policy-v1",
        "overrides": {"R024": "allow"},
        "rules": [{
            "id": "ORG-001", "name": "no console.log",
            "languages": ["javascript"], "severity": "medium",
            "category": "org-policy", "description": "x",
            "detection": "regex",
            "patterns": [r"console\.log\("],
            "message": "console.log is not allowed.",
            "remediation": "use the logger",
            "action": "warn",
        }],
    }), encoding="utf-8")

    # R024 case: unused import - should be suppressed by allow override
    (repo / "u.py").write_text("import sys\nx = 1\n", encoding="utf-8")
    p = _run_cf(["--policy", str(policy), "u.py"], cwd=repo)
    assert p.returncode == 0, (p.stdout, p.stderr)
    assert "R024" not in p.stdout

    # ORG-001 with action warn: shown but exit 0
    (repo / "f.js").write_text('console.log("x");\n', encoding="utf-8")
    p = _run_cf(["--policy", str(policy), "f.js"], cwd=repo)
    assert p.returncode == 0, (p.stdout, p.stderr)
    assert "ORG-001" in p.stdout


# ---------------------------------------------------------------------------
# 4. SARIF structure is fully valid
# ---------------------------------------------------------------------------

def test_sarif_full_schema(repo):
    (repo / "bad.py").write_text(
        'API_KEY = "sk-abcdef1234567890"\n', encoding="utf-8",
    )
    p = _run_cf(["--format", "sarif", "bad.py"], cwd=repo)
    assert p.returncode == 1
    data = json.loads(p.stdout)

    # top-level
    assert data["version"] == "2.1.0"
    assert "$schema" in data
    assert isinstance(data["runs"], list)
    assert len(data["runs"]) == 1

    run = data["runs"][0]
    # driver
    driver = run["tool"]["driver"]
    assert driver["name"] == "codefence"
    assert driver["version"] == "1.0.0"
    assert isinstance(driver["rules"], list)
    assert len(driver["rules"]) >= 1

    # rule shape
    rule = driver["rules"][0]
    assert "id" in rule
    assert "shortDescription" in rule
    assert "defaultConfiguration" in rule

    # results shape
    assert len(run["results"]) >= 1
    result = run["results"][0]
    assert "ruleId" in result
    assert "message" in result
    assert "locations" in result
    assert "partialFingerprints" in result
    assert "codefence/v1" in result["partialFingerprints"]

    region = result["locations"][0]["physicalLocation"]["region"]
    assert "startLine" in region
    assert "startColumn" in region


# ---------------------------------------------------------------------------
# 5. init command in fresh repo
# ---------------------------------------------------------------------------

def test_init_creates_config_and_hook(repo):
    p = _run_cf(["init"], cwd=repo)
    assert p.returncode == 0, p.stderr
    assert (repo / ".codefence" / "config.json").is_file()
    assert (repo / ".git" / "hooks" / "pre-commit").is_file()

    # idempotent
    p2 = _run_cf(["init"], cwd=repo)
    assert p2.returncode == 0
    assert "already installed" in p2.stdout or "skip" in p2.stdout


# ---------------------------------------------------------------------------
# 6. Exit codes
# ---------------------------------------------------------------------------

def test_exit_code_zero_on_clean(repo):
    (repo / "ok.py").write_text("x = 1\n", encoding="utf-8")
    p = _run_cf(["ok.py"], cwd=repo)
    assert p.returncode == 0


def test_exit_code_one_on_finding(repo):
    (repo / "bad.py").write_text(
        'API_KEY = "sk-abcdef1234567890"\n', encoding="utf-8",
    )
    p = _run_cf(["bad.py"], cwd=repo)
    assert p.returncode == 1
