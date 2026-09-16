"""Shared fixtures for CodeFence tests."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import codefence as cf  # noqa: E402


@pytest.fixture(scope="session")
def root() -> Path:
    return ROOT


@pytest.fixture(scope="session")
def rules_path(root: Path) -> Path:
    return root / "rules.json"


@pytest.fixture(scope="session")
def all_rules(rules_path: Path) -> list:
    return cf.load_rules(rules_path)


@pytest.fixture
def tmp_py(tmp_path: Path):
    """Helper: write a temporary Python file and return its path."""
    def _make(content: str, name: str = "sample.py") -> Path:
        p = tmp_path / name
        p.write_text(content, encoding="utf-8")
        return p
    return _make


@pytest.fixture
def tmp_js(tmp_path: Path):
    """Helper: write a temporary JavaScript file and return its path."""
    def _make(content: str, name: str = "sample.js") -> Path:
        p = tmp_path / name
        p.write_text(content, encoding="utf-8")
        return p
    return _make


@pytest.fixture
def tmp_git_repo(tmp_path: Path):
    """Helper: create a fresh git repo with an initial empty commit."""
    import subprocess
    repo = tmp_path / "repo"
    repo.mkdir()
    env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
    import os
    e = os.environ.copy()
    e.update(env)
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True, env=e)
    subprocess.run(["git", "commit", "-q", "--allow-empty", "-m", "init"],
                   cwd=repo, check=True, env=e)
    return repo
