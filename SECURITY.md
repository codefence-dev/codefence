# Security Model — CodeFence

This document describes, honestly and completely, what this tool can
and cannot do with respect to security. It is written for users and
security reviewers.

## What this tool is

CodeFence is a **pattern-based sanity checker**. It reads source
files, runs pre-compiled regular expressions and a bounded AST walk,
and reports findings. It is a *helper*, not a security guarantee.

## Threat model

### What the tool does NOT do

- It does **not** execute the scanned code.
- It does **not** import user modules.
- It does **not** make network connections.
- It does **not** send telemetry or data anywhere.
- It does **not** write into user source files.
- It does **not** create or modify anything outside:
  - stdout, or the file passed to `--output`
  - (optionally, if `--cache` is enabled) `~/.cache/codefence/`
  - (optionally, if `--history` is enabled) `~/.local/share/codefence/`

### Attack surfaces and how they are handled

1. **Malicious `rules.json`**
   - Schema is validated on load: rule IDs must match `R###`, severity
     and language values must be from the allowed sets, regex patterns
     are compiled eagerly and rejected on error.
   - Per-pattern length is capped (`MAX_REGEX_PATTERN_LEN` = 500).
   - Per-rule pattern count is capped (`MAX_REGEX_PATTERNS_PER_RULE` = 20).
   - Every regex call is run line-by-line, with a hard per-call timeout
     (`REGEX_TIMEOUT_SEC` = 0.5 s) and per-line cap
     (`MAX_REGEX_LINE_LEN` = 8192 chars). This bounds catastrophic
     backtracking (ReDoS).

2. **Malicious source file**
   - File size is capped by `--max-size` (default 2 MiB).
   - Files are read as text with `errors="replace"`.
   - Python files are parsed by CPython's own `ast.parse`. The AST
     parser is memory-safe in supported Python versions.
   - JavaScript files are tokenized by our own lexer, written in pure
     Python. It never executes input.

3. **Cache poisoning (only when `--cache` is used)**
   - Cache directory is created with mode `0o700`.
   - Cache files are created with mode `0o600` via `mkstemp` +
     `os.replace` (atomic).
   - Cache entries are keyed by SHA-256 of (version, language, rules
     fingerprint, file content). A modified file produces a different
     key.
   - On load, the cache file is checked: must be a regular file (no
     symlinks), JSON must parse, and each finding must validate. Any
     failure results in a silent cache miss and a fresh scan.
   - Cache never contains executable content; it is plain JSON.

4. **History database (only when `--history` is used)**
   - SQLite database at `~/.local/share/codefence/history.db`.
   - Directory mode `0o700`, file mode `0o600`.
   - Contains: scan timestamp, tool version, file count, finding
     counts, rule IDs, file paths, line numbers, and message text.
   - Contains **no source code** and **no secret values**. Only
     metadata about scans.
   - Disable with `--history` omitted (default) or with
     `CODEFENCE_NO_HISTORY=1` in the environment.
   - Delete the directory at any time to clear history.

5. **Distribution tampering**
   - Published package includes `CHECKSUMS.txt` with SHA-256 of every
     shipped file. Users are advised to verify after download.

## Platform limitations and safe fallbacks

- **Signal-based regex timeout.** On Unix-like systems and the main
  thread, CodeFence enforces a hard 0.5-second timeout on every
  regex call. On platforms where signals are unavailable (Windows)
  or when running in a non-main thread (e.g. an async worker), the
  timeout cannot be enforced by the OS. In that case CodeFence:
  1. Prints a one-time warning to stderr.
  2. Falls back to a strict input cap of 1024 characters per regex
     call.
  3. Continues the scan; results may be less complete on very long
     lines.
  This behavior is intentional: silent failure of ReDoS protection
  would be worse than a visible warning.

- **Baseline fingerprint includes line and column.** A finding's
  fingerprint is derived from rule ID, file path, line, column, and
  normalized snippet text. This means:
  - Two findings of the same rule on different lines are distinct
    (correct behavior — no collision).
  - If code shifts up or down within a file (e.g. after adding
    lines above), existing findings may appear as "new" in
    `--diff`. This is intentional: catching new instances of a
    dangerous pattern matters more than avoiding re-reporting a
    shifted one.
  - To suppress a known false positive permanently, use
    `# noqa: RXXX` on that line, which is not affected by line
    shifts.

- **Policy self-modification.** A pull request can modify
  `.codefence/policy.json` in the same commit as the code it
  affects. This allows a PR to weaken its own gate. CodeFence
  prints a warning when the policy or config file is staged in the
  current commit, but does not block. Review policy changes
  carefully in code review.

## Supply chain

This tool has **zero third-party dependencies**. It only uses modules
from the Python standard library (`argparse`, `ast`, `hashlib`, `html`,
`json`, `os`, `re`, `signal`, `stat`, `sys`, `tempfile`, `time`,
`dataclasses`, `datetime`, `enum`, `pathlib`, `typing`,
`unicodedata`).

There is no `pip install`, no `npm install`, no vendored code, no
build step, and no runtime download.

## Reporting a security issue

This is a one-time, as-is product. There is no official support
channel. If you find a vulnerability you believe is worth sharing,
please publish it responsibly — the maintainers do not operate a
private disclosure inbox.

## Honest limitations

- A clean scan **does not mean the code is secure**.
- The tool detects a curated set of dangerous **patterns**, not
  vulnerabilities in general.
- The tool does not perform dataflow or taint analysis.
- False positives and false negatives are inherent to the approach.
- Do not rely on this tool as the only security check before shipping
  code. It is designed to be a fast, offline, first-pass filter.

## License of the security model

This document is provided for transparency. It is not a warranty.
See `TERMS_OF_USE.md` for the legal terms.
