# Changelog

All notable changes to CodeFence.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.9] — 2026-09-18

### Added
- Pro tier license system with offline HMAC-SHA256 verification
- License source priority: `CODEFENCE_LICENSE_KEY` env var, then
  `~/.codefence/license.key`
- `tools/gen_license.py` seller-side key generation tool (not shipped)
- README: Free vs Pro feature table with activation instructions

### Changed
- Pro features are now gated when no valid license is present:
  - `--staged`, `--diff`, `--policy`, `--evidence`, `--history`
  - `--format sarif`, `--format html`
  - Subcommands: `init`, `init-hook`, `uninstall-hook`, `init-github`,
    `baseline`, `policy`, `history`, `stats`, `explain`
- Payment methods: removed USDC, added SOL
- Free tier message shows clear upgrade path when Pro features are used

### Fixed
- Integration tests use an autouse Pro license fixture

[1.0.9]: https://github.com/codefence-dev/codefence/releases/tag/v1.0.9

## [1.0.8] — 2026-09-18

### Added
- `report_cli_gate`: three-state compact output for `--staged` and git hooks
  - `commit blocked` when blocking findings are present
  - `commit allowed (warning)` when only warn-action findings are present
  - `commit passed` when clean
- `--verbose` flag for direct scans to show code snippets and fix examples
- `--quiet` short output: one-line header + one-line summary
- Footer with tool version, offline note, and honest scope statement in HTML

### Changed
- CLI: replaced banner box with a single-line header
- CLI: replaced bottom summary box with a one-line severity summary
- CLI: snippet and fix diff are now opt-in via `--verbose` (default compact)
- HTML: replaced 5-card dashboard with a horizontal severity summary line
- HTML: severity card left border reduced from 4px to 2px
- HTML: fix panels use neutral diff styling (`-` muted red, `+` muted green)
  instead of a blue "after" block
- HTML: card radius from 12px to 8px, softer shadows
- HTML: typography and spacing tuned for readability

### Fixed
- HTML: multi-line diff rendering in fix panels (newlines were being collapsed)
- Tests: SARIF test now reads tool version dynamically instead of hardcoding 1.0.0

### Internal
- Renamed test-only references from legacy product name to CodeFence

[1.0.8]: https://github.com/codefence-dev/codefence/releases/tag/v1.0.8

## [1.0.0] — 2026-09-16

### Added
- Initial public release.
- Offline, single-file CLI scanner for AI-generated Python and
  JavaScript source code.
- 28 pattern rules across secrets, injection, cryptography,
  authentication, configuration, quality, and reliability.
- Four output formats: colored CLI, JSON, HTML (dark/light theme),
  SARIF 2.1.0.
- Support for `.py`, `.js`, `.mjs`, `.cjs` input files.
- Config file (`--config`), glob include/exclude (`--include`,
  `--exclude`), and severity threshold (`--severity`).
- Optional local cache (`--cache`), off by default, mode 0o600.
- Strict `rules.json` schema validation and ReDoS mitigation
  (line-by-line regex with per-call timeout).
- Friendly welcome screen on zero-argument invocation and a full
  `--help` reference.
- JSON and SARIF outputs are pure on stdout (no banners), suitable
  for CI/CD and agent pipelines.

### Security
- Zero network calls. Zero telemetry.
- Zero third-party dependencies (Python standard library only).
- Cache path is not user-overridable via environment variables.
- `CHECKSUMS.txt` shipped for verification.

### Known limitations
- Autofix is intentionally not provided.
- No TypeScript support.
- No interprocedural or dataflow analysis.
- Clean scan does not mean the code is secure.

[1.0.0]: https://example.invalid/codefence/releases/v1.0.0

### Added during pre-release preparation (Day 12)
- `SECURITY.md` — transparent threat model and design rationale.
- `NOTICE.md` — statement on source availability (source-readable, not
  open source).
- `LICENSE.txt` — Custom Source-Available EULA with machine-use and
  redistribution restrictions.
- `TERMS_OF_USE.md` — Terms of Use with explicit scope, payment, and
  no-support clauses.
- `REFUND_POLICY.md` — Refund policy preserving EU/UK statutory
  consumer rights.
- `README.md` — full user-facing documentation, honest about scope
  and limitations.
- `tools/make_checksums.py` — internal helper for generating
  `CHECKSUMS.txt`.
- Copyright header in `codefence.py`.
- `fix_before` / `fix_after` fields per rule (typical fix examples).
- CLI fix blocks and HTML fix blocks with Copy button.
- HTML dark/light theme toggle with system-preference detection.
- Friendly welcome screen on zero-argument invocation.
- Comprehensive `--help` reference.
- `--config`, `--include`, `--exclude` flags for flexible scanning.
- ReDoS mitigation: line-by-line regex with per-call timeout.
- Strict `rules.json` schema validation.
- Optional cache (opt-in, mode 0o600, keyed by SHA-256).

### Changed
- Default excludes expanded to cover common build/cache directories.
- `--severity` accepts `info` for full verbosity.

### Fixed
- Removed duplicate `debug=True` pattern in R017.
- R024 no longer flags `from __future__ import annotations`.
- R027 is now context-aware (only fires in security-relevant contexts).
- Empty target list produces a clear message instead of silent output.

### Added (post-consultation, Days 14-28)
- `codefence init` — one-command setup (config + hook)
- `codefence init-hook` / `uninstall-hook` — git pre-commit integration
- `codefence init-github` — GitHub Actions workflow installer
- `codefence baseline` — snapshot current findings to .codefence/baseline.json
- `--staged` — scan only git-staged files
- `--diff` — report only new findings since baseline
- `--no-baseline` — ignore baseline even with --diff
- `--policy FILE` — policy-as-code with ORG-* rules and allow/warn/block
- `codefence policy validate FILE` — schema validation for policy files
- `--evidence FILE` — deterministic evidence JSON
  (result_hash, rules_hash, policy_hash, baseline_hash, commit_sha, scan_id)
- `--history` — record scans in SQLite at ~/.local/share/codefence/history.db
- `codefence history` — recent scans table
- `codefence stats` — summary statistics
- `codefence explain RXXX` — structured rule explanation
- `# noqa` / `# noqa: R001,R002` inline suppression
- `CODEFENCE_CMD` / `CODEFENCE_RULES` env overrides for the hook
- `CODEFENCE_NO_HISTORY=1` env to disable history
- Two AI-specific rules: R030 (typosquatted imports), R031 (TODO/FIXME/HACK)
- Rule versioning + fingerprints (rule_version, fingerprint)
- SARIF partialFingerprints with `codefence/v1` key
- Auto-discovery of `.codefence/config.json`
- `pyproject.toml` (PEP 621), pip-installable as `codefence`
- Console scripts: `cfence` and `codefence`
- LICENSE_FAQ.md
- 80 tests (unit + integration), pytest suite
- Internal docs: NAMING_DUE_DILIGENCE.md

### Changed (post-consultation)
- Renamed product from "AI Code Sanitizer" to "CodeFence"
- Product definition: "A tiny offline policy gate for code."
- Acquisition tagline: "Check AI-generated code before it reaches Git."
- README rewritten (no forbidden phrases, no geographic identity)
- LICENSE_FAQ.md added for source-available clarity
- SECURITY.md updated (history DB, path corrections)
- `--help` USAGE line now shows `cfence [OPTIONS] PATH...`
- Default `action` for all rules: `block`

### Removed (from earlier v1.0 plan)
- Watch mode (deferred)
- VS Code extension (deferred to v1.1)
- R029 hallucinated packages (deferred to v1.1)
- R032 prompt-context secrets (deferred to v1.1)
- Team tier pricing (deferred to v1.1)

### Fixed
- R024 no longer flags `from __future__ import annotations`
- R027 context-aware (only fires in security-relevant contexts)
- R017 duplicate pattern removed
- R022 expanded to detect both TOCTOU directions
- Hook env override (CODEFENCE_CMD) for testing and custom installs

### Security
- ReDoS mitigation: line-by-line regex, per-call timeout
- rules.json schema validation (strict)
- Cache mode 0o600, dir 0o700
- History DB mode 0o600, dir 0o700
- Symlink rejection in cache
- Atomic writes (mkstemp + os.replace)
- noqa directives parsed safely (regex, no eval)
