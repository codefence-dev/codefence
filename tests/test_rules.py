"""Rule tests: each rule must fire on bad code and stay silent on good."""
from __future__ import annotations

import pytest

import codefence as cf


def find(findings, rule_id):
    return [f for f in findings if f.id == rule_id]


# ---------------------------------------------------------------------------
# R001 — hardcoded secrets
# ---------------------------------------------------------------------------

def test_r001_fires_on_hardcoded_key(tmp_py, all_rules):
    p = tmp_py('API_KEY = "sk-abcdef1234567890"\n')
    findings = cf.scan_file(p, all_rules)
    assert find(findings, "R001")


def test_r001_clean(tmp_py, all_rules):
    p = tmp_py('import os\nAPI_KEY = os.environ["API_KEY"]\n')
    findings = cf.scan_file(p, all_rules)
    assert not find(findings, "R001")


# ---------------------------------------------------------------------------
# R002 — SQL injection via concatenation
# ---------------------------------------------------------------------------

def test_r002_concat(tmp_py, all_rules):
    p = tmp_py(
        'cursor.execute("SELECT * FROM t WHERE id = " + uid)\n'
    )
    findings = cf.scan_file(p, all_rules)
    assert find(findings, "R002")


def test_r002_fstring(tmp_py, all_rules):
    p = tmp_py('cursor.execute(f"SELECT * FROM t WHERE id = {uid}")\n')
    findings = cf.scan_file(p, all_rules)
    assert find(findings, "R002")


def test_r002_clean(tmp_py, all_rules):
    p = tmp_py('cursor.execute("SELECT * FROM t WHERE id = ?", (uid,))\n')
    findings = cf.scan_file(p, all_rules)
    assert not find(findings, "R002")


# ---------------------------------------------------------------------------
# R003 — eval/exec
# ---------------------------------------------------------------------------

def test_r003_eval(tmp_py, all_rules):
    p = tmp_py("result = eval(user_input)\n")
    findings = cf.scan_file(p, all_rules)
    assert find(findings, "R003")


def test_r003_literal_eval_clean(tmp_py, all_rules):
    p = tmp_py(
        "import ast\nresult = ast.literal_eval(user_input)\n"
    )
    findings = cf.scan_file(p, all_rules)
    assert not find(findings, "R003")


# ---------------------------------------------------------------------------
# R004 — shell=True
# ---------------------------------------------------------------------------

def test_r004_shell_true(tmp_py, all_rules):
    p = tmp_py(
        "import subprocess\n"
        'subprocess.run("ls " + name, shell=True)\n'
    )
    findings = cf.scan_file(p, all_rules)
    assert find(findings, "R004")


def test_r004_clean(tmp_py, all_rules):
    p = tmp_py(
        "import subprocess\n"
        'subprocess.run(["ls", name], shell=False)\n'
    )
    findings = cf.scan_file(p, all_rules)
    assert not find(findings, "R004")


# ---------------------------------------------------------------------------
# R005 — innerHTML (JS)
# ---------------------------------------------------------------------------

def test_r005_innerhtml(tmp_js, all_rules):
    p = tmp_js('el.innerHTML = data;\n')
    findings = cf.scan_file(p, all_rules)
    assert find(findings, "R005")


def test_r005_clean(tmp_js, all_rules):
    p = tmp_js('el.textContent = data;\n')
    findings = cf.scan_file(p, all_rules)
    assert not find(findings, "R005")


# ---------------------------------------------------------------------------
# R006 — missing auth
# ---------------------------------------------------------------------------

def test_r006_admin_without_auth(tmp_py, all_rules):
    p = tmp_py(
        '@app.get("/admin/users")\n'
        "def list_users():\n"
        "    return []\n"
    )
    findings = cf.scan_file(p, all_rules)
    assert find(findings, "R006")


def test_r006_clean(tmp_py, all_rules):
    p = tmp_py(
        '@app.get("/admin/users")\n'
        "@login_required\n"
        "def list_users():\n"
        "    return []\n"
    )
    findings = cf.scan_file(p, all_rules)
    assert not find(findings, "R006")


# ---------------------------------------------------------------------------
# R007 — CORS
# ---------------------------------------------------------------------------

def test_r007_cors_star(tmp_py, all_rules):
    p = tmp_py('allow_origins = ["*"]\n')
    findings = cf.scan_file(p, all_rules)
    assert find(findings, "R007")


# ---------------------------------------------------------------------------
# R008 — insecure random
# ---------------------------------------------------------------------------

def test_r008_random_token(tmp_py, all_rules):
    p = tmp_py(
        "import random\n"
        "token = random.randint(1000, 9999)\n"
    )
    findings = cf.scan_file(p, all_rules)
    assert find(findings, "R008")


def test_r008_clean(tmp_py, all_rules):
    p = tmp_py(
        "import secrets\n"
        "token = secrets.token_urlsafe(32)\n"
    )
    findings = cf.scan_file(p, all_rules)
    assert not find(findings, "R008")


# ---------------------------------------------------------------------------
# R009 — disabled TLS
# ---------------------------------------------------------------------------

def test_r009_verify_false(tmp_py, all_rules):
    p = tmp_py('requests.get("https://x", verify=False)\n')
    findings = cf.scan_file(p, all_rules)
    assert find(findings, "R009")


# ---------------------------------------------------------------------------
# R010 — path traversal
# ---------------------------------------------------------------------------

def test_r010_open_join(tmp_py, all_rules):
    p = tmp_py(
        "import os\n"
        'open(os.path.join("/srv", user_path))\n'
    )
    findings = cf.scan_file(p, all_rules)
    assert find(findings, "R010")


def test_r010_clean(tmp_py, all_rules):
    p = tmp_py('open("/srv/static/logo.png")\n')
    findings = cf.scan_file(p, all_rules)
    assert not find(findings, "R010")


# ---------------------------------------------------------------------------
# R011 — DB creds
# ---------------------------------------------------------------------------

def test_r011_hardcoded_db(tmp_py, all_rules):
    p = tmp_py(
        'DB = "postgres://admin:secretpw@db.local:5432/prod"\n'
    )
    findings = cf.scan_file(p, all_rules)
    assert find(findings, "R011")


# ---------------------------------------------------------------------------
# R012 — broad except
# ---------------------------------------------------------------------------

def test_r012_bare_except(tmp_py, all_rules):
    p = tmp_py(
        "try:\n"
        "    risky()\n"
        "except:\n"
        "    pass\n"
    )
    findings = cf.scan_file(p, all_rules)
    assert find(findings, "R012")


def test_r012_clean(tmp_py, all_rules):
    p = tmp_py(
        "try:\n"
        "    risky()\n"
        "except ValueError:\n"
        "    print('x')\n"
    )
    findings = cf.scan_file(p, all_rules)
    assert not find(findings, "R012")


# ---------------------------------------------------------------------------
# R013 — mutable defaults
# ---------------------------------------------------------------------------

def test_r013_list_default(tmp_py, all_rules):
    p = tmp_py("def add(item, items=[]):\n    return items\n")
    findings = cf.scan_file(p, all_rules)
    assert find(findings, "R013")


def test_r013_clean(tmp_py, all_rules):
    p = tmp_py("def add(item, items=None):\n    return items\n")
    findings = cf.scan_file(p, all_rules)
    assert not find(findings, "R013")


# ---------------------------------------------------------------------------
# R014 — prototype pollution (JS)
# ---------------------------------------------------------------------------

def test_r014_proto(tmp_js, all_rules):
    p = tmp_js('obj.__proto__ = evil;\n')
    findings = cf.scan_file(p, all_rules)
    assert find(findings, "R014")


# ---------------------------------------------------------------------------
# R015 — missing rate limit
# ---------------------------------------------------------------------------

def test_r015_login_no_limiter(tmp_py, all_rules):
    p = tmp_py(
        '@app.post("/login")\n'
        "def login():\n"
        '    return "ok"\n'
    )
    findings = cf.scan_file(p, all_rules)
    assert find(findings, "R015")


# ---------------------------------------------------------------------------
# R016 — weak hash
# ---------------------------------------------------------------------------

def test_r016_md5(tmp_py, all_rules):
    p = tmp_py(
        "import hashlib\n"
        'hashlib.md5(password.encode()).hexdigest()\n'
    )
    findings = cf.scan_file(p, all_rules)
    assert find(findings, "R016")


# ---------------------------------------------------------------------------
# R017 — debug mode
# ---------------------------------------------------------------------------

def test_r017_debug_true(tmp_py, all_rules):
    p = tmp_py("app.run(debug=True)\n")
    findings = cf.scan_file(p, all_rules)
    assert find(findings, "R017")


# ---------------------------------------------------------------------------
# R018 — open redirect
# ---------------------------------------------------------------------------

def test_r018_open_redirect(tmp_py, all_rules):
    p = tmp_py(
        "from flask import redirect, request\n"
        'return redirect(request.args.get("next"))\n'
    )
    findings = cf.scan_file(p, all_rules)
    assert find(findings, "R018")


# ---------------------------------------------------------------------------
# R019 — unsafe deserialization
# ---------------------------------------------------------------------------

def test_r019_pickle_loads(tmp_py, all_rules):
    p = tmp_py(
        "import pickle\n"
        "data = pickle.loads(payload)\n"
    )
    findings = cf.scan_file(p, all_rules)
    assert find(findings, "R019")


# ---------------------------------------------------------------------------
# R020 — JWT without exp
# ---------------------------------------------------------------------------

def test_r020_jwt_no_exp(tmp_py, all_rules):
    p = tmp_py(
        "import jwt\n"
        'jwt.encode({"sub": uid}, "k", algorithm="HS256")\n'
    )
    findings = cf.scan_file(p, all_rules)
    assert find(findings, "R020")


# ---------------------------------------------------------------------------
# R021 — missing helmet (JS)
# ---------------------------------------------------------------------------

def test_r021_no_helmet(tmp_js, all_rules):
    p = tmp_js(
        "const express = require('express');\n"
        "const app = express();\n"
    )
    findings = cf.scan_file(p, all_rules)
    assert find(findings, "R021")


# ---------------------------------------------------------------------------
# R022 — race condition
# ---------------------------------------------------------------------------

def test_r022_toctou(tmp_py, all_rules):
    p = tmp_py(
        "import os\n"
        "def w(path, data):\n"
        "    if not os.path.exists(path):\n"
        '        with open(path, "w") as f:\n'
        "            f.write(data)\n"
    )
    findings = cf.scan_file(p, all_rules)
    assert find(findings, "R022")


# ---------------------------------------------------------------------------
# R023 — logging sensitive
# ---------------------------------------------------------------------------

def test_r023_log_password(tmp_py, all_rules):
    p = tmp_py(
        "import logging\n"
        'logger = logging.getLogger(__name__)\n'
        'logger.info("password is %s", password)\n'
    )
    findings = cf.scan_file(p, all_rules)
    assert find(findings, "R023")


# ---------------------------------------------------------------------------
# R024 — unused imports
# ---------------------------------------------------------------------------

def test_r024_unused(tmp_py, all_rules):
    p = tmp_py("import os\nimport sys\nprint(os.name)\n")
    findings = cf.scan_file(p, all_rules)
    assert find(findings, "R024")


def test_r024_future_clean(tmp_py, all_rules):
    p = tmp_py(
        "from __future__ import annotations\n"
        "def f() -> int:\n"
        "    return 1\n"
    )
    findings = cf.scan_file(p, all_rules)
    assert not find(findings, "R024")


# ---------------------------------------------------------------------------
# R025 — promise rejection (JS)
# ---------------------------------------------------------------------------

def test_r025_then_no_catch(tmp_js, all_rules):
    p = tmp_js("fetch(url).then(r => r.json());\n")
    findings = cf.scan_file(p, all_rules)
    assert find(findings, "R025")


def test_r025_with_catch_clean(tmp_js, all_rules):
    p = tmp_js("fetch(url).then(r => r.json()).catch(handle);\n")
    findings = cf.scan_file(p, all_rules)
    assert not find(findings, "R025")


# ---------------------------------------------------------------------------
# R026 — HTTP no timeout
# ---------------------------------------------------------------------------

def test_r026_no_timeout(tmp_py, all_rules):
    p = tmp_py('import requests\nrequests.get("https://x")\n')
    findings = cf.scan_file(p, all_rules)
    assert find(findings, "R026")


def test_r026_with_timeout_clean(tmp_py, all_rules):
    p = tmp_py('import requests\nrequests.get("https://x", timeout=5)\n')
    findings = cf.scan_file(p, all_rules)
    assert not find(findings, "R026")


# ---------------------------------------------------------------------------
# R027 — naive datetime
# ---------------------------------------------------------------------------

def test_r027_naive_datetime_security(tmp_py, all_rules):
    p = tmp_py(
        "from datetime import datetime, timedelta\n"
        "exp = datetime.now() + timedelta(hours=1)\n"
    )
    findings = cf.scan_file(p, all_rules)
    assert find(findings, "R027")


def test_r027_filename_clean(tmp_py, all_rules):
    p = tmp_py(
        "from datetime import datetime\n"
        'filename = datetime.now().strftime("%Y%m%d")\n'
    )
    findings = cf.scan_file(p, all_rules)
    assert not find(findings, "R027")


# ---------------------------------------------------------------------------
# R028 — env fallback secret
# ---------------------------------------------------------------------------

def test_r028_env_fallback(tmp_py, all_rules):
    p = tmp_py(
        "import os\n"
        'SECRET = os.environ.get("JWT_SECRET_KEY", "CHANGE-ME")\n'
    )
    findings = cf.scan_file(p, all_rules)
    assert find(findings, "R028")


def test_r028_clean(tmp_py, all_rules):
    p = tmp_py(
        "import os\n"
        'SECRET = os.environ["JWT_SECRET_KEY"]\n'
    )
    findings = cf.scan_file(p, all_rules)
    assert not find(findings, "R028")


# ---------------------------------------------------------------------------
# R030 — typosquatting
# ---------------------------------------------------------------------------

def test_r030_typosquat(tmp_py, all_rules):
    p = tmp_py("import reqeusts\n")
    findings = cf.scan_file(p, all_rules)
    assert find(findings, "R030")


def test_r030_real_package_clean(tmp_py, all_rules):
    p = tmp_py("import requests\n")
    findings = cf.scan_file(p, all_rules)
    assert not find(findings, "R030")


# ---------------------------------------------------------------------------
# R031 — TODO in code
# ---------------------------------------------------------------------------

def test_r031_todo(tmp_py, all_rules):
    p = tmp_py("# TODO: fix this\nx = 1\n")
    findings = cf.scan_file(p, all_rules)
    assert find(findings, "R031")


def test_r031_normal_comment_clean(tmp_py, all_rules):
    p = tmp_py("# This is a normal comment\nx = 1\n")
    findings = cf.scan_file(p, all_rules)
    assert not find(findings, "R031")


# ---------------------------------------------------------------------------
# Extra edge cases
# ---------------------------------------------------------------------------

def test_bom_in_python_file(tmp_py, all_rules):
    """UTF-8 BOM must not hide findings in the first line."""
    p = tmp_py('\ufeffAPI_KEY = "sk-abcdef1234567890"\n')
    findings = cf.scan_file(p, all_rules)
    assert find(findings, "R001")


def test_empty_file(tmp_py, all_rules):
    p = tmp_py("")
    findings = cf.scan_file(p, all_rules)
    assert findings == []


def test_crlf_line_endings(tmp_py, all_rules):
    p = tmp_py('API_KEY = "sk-abcdef1234567890"\r\n')
    findings = cf.scan_file(p, all_rules)
    assert find(findings, "R001")


def test_noqa_suppresses_all(tmp_py, all_rules):
    p = tmp_py('API_KEY = "sk-abcdef1234567890"  # noqa\n')
    findings = cf.scan_file(p, all_rules)
    assert not find(findings, "R001")


def test_noqa_specific_rule(tmp_py, all_rules):
    p = tmp_py('API_KEY = "sk-abcdef1234567890"  # noqa: R001\n')
    findings = cf.scan_file(p, all_rules)
    assert not find(findings, "R001")


def test_noqa_wrong_rule_does_not_suppress(tmp_py, all_rules):
    p = tmp_py('API_KEY = "sk-abcdef1234567890"  # noqa: R002\n')
    findings = cf.scan_file(p, all_rules)
    assert find(findings, "R001")


def test_noqa_javascript(tmp_js, all_rules):
    p = tmp_js('el.innerHTML = data;  // noqa: R005\n')
    findings = cf.scan_file(p, all_rules)
    assert not find(findings, "R005")


def test_fingerprint_distinguishes_lines(all_rules):
    """Same rule, same snippet, different lines = distinct fingerprints."""
    src = (
        "import subprocess\n"
        "def a(x):\n"
        "    subprocess.run(x, shell=True)\n"
        "\n"
        "def b(y):\n"
        "    subprocess.run(y, shell=True)\n"
    )
    findings = cf.scan_source(src, cf.Language.PYTHON, all_rules,
                              path="/tmp/x.py")
    r004 = find(findings, "R004")
    assert len(r004) == 2
    fps = {cf._finding_fingerprint(f) for f in r004}
    assert len(fps) == 2
