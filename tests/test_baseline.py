"""Baseline and fingerprint tests."""
from __future__ import annotations

from pathlib import Path

import codefence as cf


def test_fingerprint_stable_across_line_shifts(all_rules):
    p1 = Path("/tmp/f1.py")
    p2 = Path("/tmp/f2.py")
    src = 'API_KEY = "sk-abcdef1234567890"\n'
    f1 = cf.scan_source(src, cf.Language.PYTHON, all_rules, path=str(p1))
    f2 = cf.scan_source(src, cf.Language.PYTHON, all_rules, path=str(p2))
    # Same rule, same snippet, different path -> different fingerprint
    assert cf._finding_fingerprint(f1[0]) != cf._finding_fingerprint(f2[0])
    # Same path + same snippet -> same fingerprint
    f3 = cf.scan_source(src, cf.Language.PYTHON, all_rules, path=str(p1))
    assert cf._finding_fingerprint(f1[0]) == cf._finding_fingerprint(f3[0])


def test_filter_new_findings(all_rules):
    src = 'API_KEY = "sk-abcdef1234567890"\n'
    findings = cf.scan_source(src, cf.Language.PYTHON, all_rules,
                              path="/tmp/x.py")
    fps = {cf._finding_fingerprint(f) for f in findings}
    assert cf._filter_new_findings(findings, fps) == []
    assert len(cf._filter_new_findings(findings, set())) == len(findings)


def test_save_and_load_baseline(tmp_path, all_rules):
    src = 'API_KEY = "sk-abcdef1234567890"\n'
    findings = cf.scan_source(src, cf.Language.PYTHON, all_rules,
                              path="/tmp/x.py")
    bpath = tmp_path / ".codefence" / "baseline.json"
    cf._save_baseline(bpath, findings)
    loaded = cf._load_baseline(bpath)
    assert loaded is not None
    assert len(loaded) == len(findings)


def test_load_baseline_missing(tmp_path):
    assert cf._load_baseline(tmp_path / "nope.json") is None


def test_load_baseline_corrupt(tmp_path):
    p = tmp_path / "b.json"
    p.write_text("garbage", encoding="utf-8")
    assert cf._load_baseline(p) is None
