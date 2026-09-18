# Detection Methodology

This document explains how CodeFence detects issues, what it can and
cannot find, and where its known limitations are. It is intended for
technical reviewers and security-conscious buyers.

---

## 1. Purpose and Scope

CodeFence is a **pattern-based sanity checker**. It runs a curated set
of rules over Python and JavaScript source files and reports matches.

It is:

- Fast, offline, deterministic, and zero-dependency
- A first-pass filter before commit
- Honest about what it can and cannot do

It is **not**:

- A security audit
- A Semgrep or CodeQL replacement
- A substitute for professional security review
- A guarantee that a clean scan means secure code

---

## 2. Detection Mechanism

CodeFence uses three detection methods.

| Method | Used for | Strength | Weakness |
|---|---|---|---|
| Regular expression | Literal patterns (secrets, config strings, insecure defaults) | Fast, simple, deterministic | Cannot understand syntax or scope |
| Python AST | Structural analysis of Python code | Understands Python structure | Only what is written; no dataflow |
| JavaScript lexer | Token-level analysis of JavaScript | Handles JS without a full parser | Token-level only; no full AST |

All three are **local, deterministic, and single-file**. No dataflow
analysis. No taint tracking. No interprocedural analysis. No call
graph. No type inference.

---

## 3. What CodeFence Does NOT Detect

This is the most important section of this document.

- **No dataflow.** If user input flows through three function calls and
  reaches a SQL query, CodeFence cannot trace it. It detects the
  pattern only when the concatenation is syntactically present in one
  expression.
- **No interprocedural analysis.** Calls across files or functions are
  not followed.
- **No taint tracking.** CodeFence does not know which values are
  user-controlled.
- **No configuration awareness.** If `verify=False` is intentional
  (e.g. internal service), CodeFence still reports it. Use `# noqa` or
  a policy override to suppress it.
- **No framework-specific semantics.** Flask, Django, Express, FastAPI,
  NestJS - CodeFence treats route decorators and middleware by pattern,
  not by framework semantics.
- **No cross-language analysis.** Each file is scanned independently; a
  Python file calling a JavaScript service is not analyzed jointly.
- **No fix verification.** A "typical fix" example is provided, but
  CodeFence does not verify that applying it removes the issue or does
  not introduce new issues.

---

## 4. Test Methodology

The 30 rules have been developed and validated against:

- **Synthetic test cases** - at least 2 per rule (one vulnerable, one
  clean)
- **Real-world files** from AI-generated projects (ChatGPT, Claude,
  DeepSeek, and Grok outputs)
- **Adversarial edge cases** - empty files, UTF-8 BOM, CRLF line
  endings, mixed line endings, deeply nested code, very long single
  lines, binary content with a `.py` extension
- **Integration tests** - git hook, baseline, policy, history, and
  SARIF schema validation

Test counts at the time of this release:

- 88 automated tests pass
- Self-scan on CodeFence's own source produces zero findings
- Zero false positives on the clean sample corpus included with the
  product (`samples/clean_example.py`, `samples/clean_example.js`)
- Zero false negatives on the synthetic corpus for the patterns each
  rule is designed to detect

These numbers describe the test set. They do **not** describe
real-world performance on arbitrary code. See Sections 6 and 7 for
known false positive and false negative scenarios.

---

## 5. Per-Rule Samples

### R001 - Hardcoded API keys / secrets

Vulnerable:
    API_KEY = "sk-abcdef1234567890"

Clean:
    API_KEY = os.environ["API_KEY"]

Limitation: obfuscated or encoded secrets are not detected.

### R002 - SQL injection via string concatenation (Python)

Vulnerable:
    cursor.execute("SELECT * FROM t WHERE id = " + uid)
    cursor.execute(f"SELECT * FROM t WHERE id = {uid}")

Clean:
    cursor.execute("SELECT * FROM t WHERE id = ?", (uid,))

Limitation: Fires on any string concatenation passed to execute.
Does not fire when the query is built in a separate function.

### R003 - eval() / exec() on untrusted input (Python)

Vulnerable:
    result = eval(user_input)
    exec(code_from_request)

Clean:
    import ast
    result = ast.literal_eval(user_input)

Limitation: Fires on any eval or exec call with a non-constant
argument, including cases where input is provably safe.

### R004 - Command injection via shell=True (Python)

Vulnerable:
    subprocess.run("ls " + name, shell=True)
    os.system(f"ping {host}")

Clean:
    subprocess.run(["ls", name], shell=False)

Limitation: Fires on every shell=True and every os.system call. Use
`# noqa: R004` for known-safe cases.

### R005 - innerHTML with unsanitized data (JavaScript)

Vulnerable:
    el.innerHTML = userInput;
    document.write(data);

Clean:
    el.textContent = userInput;
    el.innerHTML = DOMPurify.sanitize(userInput);

Limitation: Does not distinguish sanitized from unsanitized data at
the token level.

### R006 - Missing authentication on endpoints

Vulnerable:
    @app.get("/admin/users")
    def list_users(): ...

Clean:
    @app.get("/admin/users")
    @login_required
    def list_users(): ...

Limitation: Heuristic. Fires only on paths containing admin, manage,
internal, private, or superuser. Does not know about custom auth
middleware. Confidence: medium.

### R007 - Overly permissive CORS (*)

Vulnerable:
    allow_origins = ["*"]
    app.use(cors());

Clean:
    allow_origins = ["https://app.example.com"]
    app.use(cors({ origin: "https://app.example.com" }));

Limitation: Fires on cors() with no arguments. Use `# noqa: R007` if
the application intentionally exposes a public API.

### R008 - Insecure random for security tokens (Python)

Vulnerable:
    token = random.randint(1000, 9999)

Clean:
    import secrets
    token = secrets.token_urlsafe(32)

Limitation: Only fires when the assignment target name contains a
security-related token (token, secret, session, password, key, nonce,
otp, salt, csrf, auth).

### R009 - Disabled TLS/SSL verification

Vulnerable:
    requests.get(url, verify=False)
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"

Clean:
    requests.get(url)

Limitation: Fires on the pattern. Does not distinguish between
intentional internal-only traffic and external traffic.

### R010 - Path traversal

Vulnerable:
    open(os.path.join(BASE, user_path))
    fs.readFileSync(path.join(BASE, req.query.file))

Clean:
    full = os.path.realpath(os.path.join(BASE, user_path))
    if not full.startswith(os.path.realpath(BASE)):
        raise ValueError("path traversal")
    open(full)

Limitation: Heuristic. Fires on any open call whose path is built from
os.path.join with a non-literal second argument. Confidence: medium.

### R011 - Hardcoded database credentials

Vulnerable:
    DATABASE_URL = "postgres://admin:s3cr3t@db.local:5432/prod"
    const db = "mysql://root:pass@localhost/app"

Clean:
    DATABASE_URL = os.environ["DATABASE_URL"]
    const db = process.env.DATABASE_URL;

Limitation: Fires on URLs matching common schemes (postgres, mysql,
mongodb, redis, amqp). Does not detect credentials passed as separate
variables.

### R012 - Broad except: pass (Python)

Vulnerable:
    try:
        risky()
    except:
        pass

Clean:
    try:
        risky()
    except SpecificError as e:
        logger.warning("risky failed: %s", e)

Limitation: Fires on bare except and except Exception with only pass
in the body. A try/except that silently logs to a black hole without
pass is not flagged.

### R013 - Mutable default arguments (Python)

Vulnerable:
    def add(item, items=[]):
        items.append(item)

Clean:
    def add(item, items=None):
        items = items if items is not None else []
        items.append(item)

Limitation: Only list, dict, set literals, and common constructor
calls (list(), dict(), set(), OrderedDict(), defaultdict()) are
detected as mutable defaults.

### R014 - Prototype pollution (JavaScript)

Vulnerable:
    obj[key] = value;          // key from user input
    Object.assign(target, userInput);
    target.__proto__ = userInput;

Clean:
    if (key === "__proto__" || key === "constructor") throw new Error();
    Object.assign(target, sanitize(userInput));

Limitation: Fires on __proto__ assignment. Dynamic bracket assignment
is not flagged unless the key is provably __proto__ in the same
expression.

### R015 - Missing rate limiting on public endpoints

Vulnerable:
    @app.post("/login")
    def login(): ...

Clean:
    @limiter.limit("5/minute")
    @app.post("/login")
    def login(): ...

Limitation: Heuristic. Fires only on paths containing login, signin,
register, signup, forgot, reset, auth, token, or otp. Confidence: low.

### R016 - MD5/SHA1 for password hashing

Vulnerable:
    hashlib.md5(password.encode()).hexdigest()
    crypto.createHash('md5').update(pwd).digest('hex')

Clean:
    bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    await bcrypt.hash(pwd, 12)

Limitation: Fires on md5 and sha1 usage. If used for non-password
purposes (e.g. file integrity checks), the rule still fires. Use
`# noqa: R016` for known-safe cases.

### R017 - Debug mode left enabled

Vulnerable:
    app.run(debug=True)
    DEBUG = True

Clean:
    app.run(debug=os.environ.get("DEBUG") == "1")
    DEBUG = os.environ.get("DEBUG") == "1"

Limitation: Fires on literal True assignment to a debug flag.
Does not detect debug mode set at runtime via environment variables.

### R018 - Open redirect

Vulnerable:
    return redirect(request.args.get("next"))
    res.redirect(req.query.next);

Clean:
    nxt = request.args.get("next", "/")
    if not nxt.startswith("/"):
        nxt = "/"
    return redirect(nxt)

Limitation: Heuristic. Fires on redirect calls whose target comes from
request.args, request.params, or request.query. Confidence: medium.

### R019 - Unsafe deserialization

Vulnerable:
    data = pickle.loads(payload)
    config = yaml.load(text)

Clean:
    data = json.loads(payload)
    config = yaml.safe_load(text)

Limitation: Fires on pickle.load/loads, yaml.load (without safe_load),
dill.load, and marshal.load. Does not detect custom deserialization
libraries.

### R020 - Never-expiring tokens / JWT

Vulnerable:
    jwt.encode({"sub": uid}, key, algorithm="HS256")
    jwt.sign(payload, key);

Clean:
    jwt.encode({"sub": uid, "exp": now + 3600}, key, algorithm="HS256")
    jwt.sign(payload, key, { expiresIn: '1h' });

Limitation: Fires only when the JWT payload dict/object is a literal
visible in the same call. Dynamic payloads are not analyzed.
Confidence: medium.

### R021 - Missing security headers (Express)

Vulnerable:
    const app = express();

Clean:
    const app = express();
    app.use(helmet());

Limitation: Fires when Express is imported and helmet is not imported
in the same file. Does not detect other header middleware.

### R022 - Race conditions in async code

Vulnerable:
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(data)

Clean:
    try:
        with open(path, "x") as f:
            f.write(data)
    except FileExistsError:
        pass

Limitation: Heuristic. Fires on the check-then-act pattern on files.
Does not detect race conditions on shared in-memory state.
Confidence: low.

### R023 - Logging sensitive data

Vulnerable:
    logger.info("user login: %s / %s", user, password)
    console.log('token', token);

Clean:
    logger.info("user login: %s", user)

Limitation: Fires when the word password, token, secret, or apikey
appears as an argument to a common logging function. Does not
understand variable contents, so a variable named `token` that
actually holds a public value will still fire.

### R024 - Unused imports / dead code (Python)

Vulnerable:
    import os
    import sys

    print(os.name)

Clean:
    import os

    print(os.name)

Limitation: Fires on unused Python imports. `from __future__ import`
statements are ignored (they are compiler directives). Star imports
(`from x import *`) are not analyzed. Dynamic imports (importlib) are
not analyzed.

### R025 - Promise rejection ignored (JavaScript)

Vulnerable:
    fetch(url).then(r => r.json());

Clean:
    fetch(url).then(r => r.json()).catch(handleError);

Limitation: Fires on .then() chains without .catch(). Await inside
try/catch is not flagged.

### R026 - HTTP request without timeout

Vulnerable:
    requests.get("https://api.example.com")
    requests.post("https://api.example.com", json={})

Clean:
    requests.get("https://api.example.com", timeout=10)

Limitation: Fires on requests methods without a timeout keyword
argument. Does not detect the use of a Session object with a default
timeout configured elsewhere.

### R027 - Naive datetime (no timezone)

Vulnerable:
    exp = datetime.now() + timedelta(hours=1)
    token_expiry = datetime.now()
    stamp = datetime.utcnow()

Clean:
    exp = datetime.now(timezone.utc) + timedelta(hours=1)
    stamp = datetime.now(timezone.utc)

Limitation: Context-aware. Only fires when the result is assigned to a
security-related name (exp, expire, expiry, token, session, auth, jwt,
nonce, salt, otp, csrf) or used inside a security-named function.
A datetime.now() assigned to a filename or log variable does not fire.

### R028 - Env var with hardcoded fallback secret

Vulnerable:
    SECRET = os.environ.get("JWT_SECRET_KEY", "CHANGE-ME")
    const KEY = process.env.API_KEY || "dev-key";

Clean:
    SECRET = os.environ["JWT_SECRET_KEY"]

Limitation: Fires when the environment variable name contains a
security-related token. If the fallback is an empty string, it is not
flagged. If the fallback is loaded from a config file, it is not
detected.

*Note on numbering: R029 is intentionally absent from v1.0. It is a
planned rule for hallucinated package imports, deferred to a future
release pending a curated data source.*

### R030 - Typosquatted package imports

Vulnerable:
    import reqeusts
    from panadas import DataFrame

Clean:
    import requests
    from pandas import DataFrame

Limitation: Uses a fixed list of common typosquats for a small number
of popular packages (requests, numpy, pandas, django, express, lodash).
A typosquat targeting a less-common package is not detected.

### R031 - TODO / FIXME / HACK in new code

Vulnerable:
    # TODO: handle edge case
    // FIXME: this is broken

Clean:
    # normal comment

Limitation: Fires on the words TODO, FIXME, HACK, and XXX in comments.
A TODO written without one of these markers (e.g. `# later:` ) is not
detected.


---

## 6. Known False Positive Scenarios

The following scenarios may produce false positives. If any of these
apply to your project, use `# noqa: RXXX` on the line, or a policy
override in `.codefence/policy.json`.

1. **`shell=True` with a hardcoded command.** If the command is a
   constant string and no user input is involved, the pattern is still
   flagged. Example: `subprocess.run("ls", shell=True)`.
2. **`verify=False` for internal traffic.** If the destination is a
   service on a private network with a self-signed certificate, the
   rule still fires.
3. **`random` for non-security purposes.** If the random value is
   assigned to a variable named `token` but is used for a test fixture,
   the rule fires.
4. **`datetime.now()` in a security context for local logging.** If the
   variable is named `token_expiry` but is only used in a debug log,
   the rule fires.
5. **Admin routes protected by global middleware.** If authentication
   is applied globally rather than per-route, R006 may fire on routes
   that are actually protected.
6. **`console.log` or `print()` used in a CLI tool.** Not flagged by
   default (no such rule), but policy-as-code can add it.

---

## 7. Known False Negative Scenarios

The following scenarios will not be detected by CodeFence.

1. **User input flowing through multiple functions** into a dangerous
   sink (no dataflow / no taint tracking).
2. **Secrets loaded from files outside the scanned tree** (e.g. a
   `.env` file loaded at runtime).
3. **Dynamic SQL built via `str.format()` with a variable template.**
4. **Indirect `eval` via `__import__("builtins").eval`.**
5. **Obfuscated or encoded secrets** (base64, hex, split strings).
6. **Custom framework patterns** that do not match the rule's
   heuristic vocabulary.
7. **Race conditions on in-memory shared state** (only filesystem
   check-then-act is detected).
8. **Package supply chain attacks via legitimate-looking names**
   (unless they happen to match the typosquat list).

---

## 8. Responsible Use

CodeFence is a **first-pass filter**, not a replacement for:

- Manual code review
- Dedicated SAST tools (Semgrep, CodeQL, Bandit, ESLint security)
- Dependency scanners (Snyk, Dependabot, Trivy)
- Professional security audits

A clean scan means "no pattern in the current rule set matched." It
does **not** mean the code is secure.

If you find a missed vulnerability or a false positive that is not
documented here, that is useful information. See `SECURITY.md` for how
to report it.

---

## 9. Rule Sources and References

Each rule in `rules.json` carries one or more CWE references. Where
applicable, the following resources informed the detection logic:

- OWASP Top 10 (2021)
- CWE (Common Weakness Enumeration)
- Real-world AI-generated code samples from ChatGPT, Claude, Grok, and
  DeepSeek
- Community knowledge from the open-source security tooling ecosystem
  (Semgrep, Bandit, ESLint security plugins)

No proprietary data, no external service, and no network call is used
at any point.

---

*End of Detection Methodology.*
