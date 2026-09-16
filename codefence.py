#!/usr/bin/env python3
# Copyright (c) 2026 CodeFence. All rights reserved.
# Licensed under the CodeFence End User License Agreement.
# See LICENSE.txt for terms. Source is provided for auditability.
# Redistribution and resale are prohibited.
"""
CodeFence - Offline AI Code Sanity Check
Version 1.0.0

A single-file, zero-dependency, offline CLI that scans AI-generated
code for selected dangerous patterns before commit.

This is a pattern-based sanity check. It is NOT a security audit and
does NOT replace professional security review.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import html as _html
import json
import os
import re
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Callable, Iterable, Iterator, Sequence


# =============================================================================
# [SECTION] Constants
# =============================================================================

TOOL_NAME = "codefence"
TOOL_VERSION = "1.0.0"
RULES_SCHEMA = "codefence/rules-v1"
DEFAULT_MAX_SIZE = 2 * 1024 * 1024
DEFAULT_RULES_FILENAME = "rules.json"

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_INTERNAL = 3

# Security limits (see SECURITY.md)
MAX_REGEX_PATTERN_LEN = 500
MAX_REGEX_PATTERNS_PER_RULE = 20
MAX_REGEX_LINE_LEN = 8192
REGEX_TIMEOUT_SEC = 0.5
NO_SIGNAL_MAX_REGEX_INPUT = 1024  # strict cap when signal is unavailable
_NO_SIGNAL_WARNED = False

_DEBUG_HANDLERS = False  # set True to see handler exceptions


# =============================================================================
# [SECTION] Enums
# =============================================================================

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def severity_rank(value: Severity) -> int:
    return _SEVERITY_RANK[value]


class Language(str, Enum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"


class Detection(str, Enum):
    REGEX = "regex"
    AST = "ast"
    LEXICAL = "lexical"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# =============================================================================
# [SECTION] Data model (frozen, immutable, hashable)
# =============================================================================

class TokenKind(str, Enum):
    IDENT = "ident"
    KEYWORD = "keyword"
    STRING = "string"
    TEMPLATE = "template"
    NUMBER = "number"
    REGEX = "regex"
    PUNCT = "punct"


@dataclass(frozen=True, slots=True)
class Token:
    kind: TokenKind
    value: str
    line: int
    column: int


@dataclass(frozen=True, slots=True)
class Finding:
    id: str
    rule_name: str
    severity: Severity
    category: str
    file: str
    line: int
    column: int
    snippet: str
    message: str
    remediation: str
    language: Language
    confidence: Confidence
    fix_before: str = ""
    fix_after: str = ""
    action: str = "block"

    def sort_key(self) -> tuple[str, int, int, str]:
        return (self.file, self.line, self.column, self.id)


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    name: str
    languages: tuple[Language, ...]
    severity: Severity
    category: str
    description: str
    detection: Detection
    message: str
    remediation: str
    references: tuple[str, ...]
    confidence: Confidence
    enabled: bool
    patterns: tuple[re.Pattern[str], ...] = ()
    handler: str = ""
    fix_before: str = ""
    fix_after: str = ""
    action: str = "block"
    rule_version: str = "1"
    fingerprint: str = ""


@dataclass(frozen=True, slots=True)
class ScanContext:
    path: str
    language: Language
    source: str
    lines: tuple[str, ...]
    ast_tree: ast.AST | None = None
    js_tokens: tuple[Token, ...] = ()


# =============================================================================
# [SECTION] Rule handler registry (populated incrementally)
# =============================================================================

RuleHandler = Callable[[ScanContext, Rule], Iterable[Finding]]

RULE_HANDLERS: dict[str, RuleHandler] = {}


def register_handler(name: str) -> Callable[[RuleHandler], RuleHandler]:
    """Decorator to register an AST/lexical rule handler by name."""
    def deco(fn: RuleHandler) -> RuleHandler:
        RULE_HANDLERS[name] = fn
        return fn
    return deco


# =============================================================================
# [SECTION] Rule loading (pure)
# =============================================================================

def load_rules(path: Path) -> list[Rule]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    schema = raw.get("schema")
    if schema != RULES_SCHEMA:
        raise ValueError(f"Unsupported rules schema: {schema!r}")
    entries = raw.get("rules", [])
    if not isinstance(entries, list):
        raise ValueError("rules.json: 'rules' must be a list")
    return [_build_rule(e) for e in entries]


VALID_ACTIONS = frozenset({"allow", "warn", "block"})


def _validate_action(value, rid: str) -> str:
    if value is None:
        return "block"
    if not isinstance(value, str):
        raise ValueError(f"rule {rid}: action must be a string")
    low = value.lower()
    if low not in VALID_ACTIONS:
        raise ValueError(
            f"rule {rid}: action must be one of {sorted(VALID_ACTIONS)}, "
            f"got {value!r}"
        )
    return low


def _build_rule(entry: dict) -> Rule:
    if not isinstance(entry, dict):
        raise ValueError(f"rule entry must be an object, got {type(entry).__name__}")
    rid = entry.get("id")
    if not isinstance(rid, str) or not re.match(r"^(R[0-9]{3}|ORG-[0-9]{3,})$", rid):
        raise ValueError(
            f"rule id must match R### or ORG-###, got {rid!r}"
        )
    detection_str = entry.get("detection")
    try:
        detection = Detection(detection_str)
    except ValueError:
        raise ValueError(f"rule {rid}: invalid detection {detection_str!r}")

    patterns: tuple[re.Pattern[str], ...] = ()
    if detection == Detection.REGEX:
        raw_patterns = entry.get("patterns", [])
        if not isinstance(raw_patterns, list):
            raise ValueError(f"rule {rid}: patterns must be a list")
        if len(raw_patterns) > MAX_REGEX_PATTERNS_PER_RULE:
            raise ValueError(
                f"rule {rid}: too many patterns "
                f"({len(raw_patterns)} > {MAX_REGEX_PATTERNS_PER_RULE})"
            )
        compiled: list[re.Pattern[str]] = []
        for i, pat in enumerate(raw_patterns):
            if not isinstance(pat, str):
                raise ValueError(f"rule {rid}: pattern {i} must be a string")
            if len(pat) > MAX_REGEX_PATTERN_LEN:
                raise ValueError(
                    f"rule {rid}: pattern {i} too long "
                    f"({len(pat)} > {MAX_REGEX_PATTERN_LEN})"
                )
            try:
                compiled.append(re.compile(pat))
            except re.error as e:
                raise ValueError(f"rule {rid}: pattern {i} invalid regex: {e}")
        patterns = tuple(compiled)

    try:
        languages = tuple(Language(x) for x in entry["languages"])
    except (KeyError, TypeError, ValueError) as e:
        raise ValueError(f"rule {rid}: invalid languages: {e}")
    try:
        severity = Severity(entry["severity"])
    except (KeyError, ValueError) as e:
        raise ValueError(f"rule {rid}: invalid severity: {e}")
    try:
        confidence = Confidence(entry.get("confidence", "medium"))
    except ValueError as e:
        raise ValueError(f"rule {rid}: invalid confidence: {e}")

    return Rule(
        id=rid,
        name=str(entry.get("name", "")),
        languages=languages,
        severity=severity,
        category=str(entry.get("category", "")),
        description=str(entry.get("description", "")),
        detection=detection,
        message=str(entry.get("message", "")),
        remediation=str(entry.get("remediation", "")),
        references=tuple(str(x) for x in entry.get("references", [])),
        confidence=confidence,
        enabled=bool(entry.get("enabled", True)),
        patterns=patterns,
        handler=str(entry.get("handler", "") or ""),
        fix_before=str(entry.get("fix_before", "")),
        fix_after=str(entry.get("fix_after", "")),
        action=_validate_action(entry.get("action", "block"), rid),
        rule_version=str(entry.get("rule_version", "1")),
        fingerprint=str(entry.get("fingerprint", "")),
    )


# =============================================================================
# [SECTION] Python AST helpers
# =============================================================================

def _node_line(node: ast.AST) -> int:
    return int(getattr(node, "lineno", 0) or 0)


def _node_col(node: ast.AST) -> int:
    return int(getattr(node, "col_offset", 0) or 0) + 1


def _make_finding(ctx: ScanContext, rule: Rule, node: ast.AST,
                  message: str | None = None) -> Finding:
    line = _node_line(node)
    if 1 <= line <= len(ctx.lines):
        snippet = ctx.lines[line - 1].strip()
    else:
        snippet = ""
    if len(snippet) > 200:
        snippet = snippet[:197] + "..."
    return Finding(
        id=rule.id,
        rule_name=rule.name,
        severity=rule.severity,
        category=rule.category,
        file=ctx.path,
        line=line,
        column=_node_col(node),
        snippet=snippet,
        message=message or rule.message,
        remediation=rule.remediation,
        language=ctx.language,
        confidence=rule.confidence,
        fix_before=rule.fix_before,
        fix_after=rule.fix_after,
        action=rule.action,
    )


def _walk(tree: ast.AST) -> Iterable[ast.AST]:
    yield from ast.walk(tree)


def _attr_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _attr_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def _is_string_constant(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


SECURITY_TOKEN_NAMES = (
    "token", "secret", "session", "password", "passwd", "pwd",
    "key", "nonce", "otp", "salt", "csrf", "auth",
)


def _looks_security_related(name: str) -> bool:
    low = name.lower()
    return any(tok in low for tok in SECURITY_TOKEN_NAMES)


# =============================================================================
# [SECTION] Python rule handlers
# =============================================================================

@register_handler("check_sql_injection_python")
def check_sql_injection_python(ctx: ScanContext, rule: Rule) -> Iterable[Finding]:
    if ctx.ast_tree is None:
        return
    execute_methods = {"execute", "executemany", "executescript"}
    for node in _walk(ctx.ast_tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr not in execute_methods:
            continue
        if not node.args:
            continue
        if _is_dangerous_sql(node.args[0]):
            yield _make_finding(ctx, rule, node)


def _is_dangerous_sql(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp):
        if isinstance(node.op, ast.Add):
            return _is_string_constant(node.left) or _is_string_constant(node.right)
        if isinstance(node.op, ast.Mod):
            return _is_string_constant(node.left)
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            return _is_string_constant(node.func.value)
    return False


@register_handler("check_eval_exec_python")
def check_eval_exec_python(ctx: ScanContext, rule: Rule) -> Iterable[Finding]:
    if ctx.ast_tree is None:
        return
    dangerous = {"eval", "exec"}
    for node in _walk(ctx.ast_tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Name):
            continue
        if node.func.id not in dangerous:
            continue
        if not node.args:
            continue
        first = node.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, (int, float)):
            continue
        yield _make_finding(ctx, rule, node)


@register_handler("check_shell_true_python")
def check_shell_true_python(ctx: ScanContext, rule: Rule) -> Iterable[Finding]:
    if ctx.ast_tree is None:
        return
    shell_funcs = {
        "subprocess.run", "subprocess.call", "subprocess.Popen",
        "subprocess.check_call", "subprocess.check_output",
    }
    always_shell = {"os.system", "os.popen"}
    for node in _walk(ctx.ast_tree):
        if not isinstance(node, ast.Call):
            continue
        name = _attr_name(node.func)
        if name in shell_funcs:
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) \
                        and kw.value.value is True:
                    yield _make_finding(ctx, rule, node)
                    break
        elif name in always_shell:
            yield _make_finding(ctx, rule, node)


@register_handler("check_random_python")
def check_random_python(ctx: ScanContext, rule: Rule) -> Iterable[Finding]:
    if ctx.ast_tree is None:
        return
    random_attrs = {
        "random", "randint", "randrange", "choice", "choices",
        "sample", "uniform", "getrandbits", "shuffle",
    }
    for node in _walk(ctx.ast_tree):
        if not isinstance(node, ast.Assign):
            continue
        value = node.value
        if not (isinstance(value, ast.Call)
                and isinstance(value.func, ast.Attribute)
                and value.func.attr in random_attrs
                and isinstance(value.func.value, ast.Name)
                and value.func.value.id == "random"):
            continue
        names: list[str] = []
        for tgt in node.targets:
            if isinstance(tgt, ast.Name):
                names.append(tgt.id)
            elif isinstance(tgt, ast.Attribute):
                names.append(tgt.attr)
        if any(_looks_security_related(n) for n in names):
            yield _make_finding(ctx, rule, node)


@register_handler("check_except_pass_python")
def check_except_pass_python(ctx: ScanContext, rule: Rule) -> Iterable[Finding]:
    if ctx.ast_tree is None:
        return
    for node in _walk(ctx.ast_tree):
        if not isinstance(node, ast.Try):
            continue
        for handler in node.handlers:
            if not _is_broad_except(handler.type):
                continue
            if _is_silent_body(handler.body):
                yield _make_finding(ctx, rule, handler)


def _is_broad_except(exc_type: ast.AST | None) -> bool:
    if exc_type is None:
        return True
    if isinstance(exc_type, ast.Name):
        return exc_type.id in {"Exception", "BaseException"}
    if isinstance(exc_type, ast.Tuple):
        return any(
            isinstance(e, ast.Name) and e.id in {"Exception", "BaseException"}
            for e in exc_type.elts
        )
    return False


def _is_silent_body(body: list[ast.stmt]) -> bool:
    if not body:
        return False
    meaningful = [s for s in body
                  if not (isinstance(s, ast.Expr)
                          and isinstance(s.value, ast.Constant)
                          and isinstance(s.value.value, str))]
    if len(meaningful) != 1:
        return False
    return isinstance(meaningful[0], ast.Pass)


# =============================================================================
# [SECTION] Python additional rule handlers (Day 4)
# =============================================================================

MUTABLE_DEFAULT_TYPES = (ast.List, ast.Dict, ast.Set)
MUTABLE_DEFAULT_CALLS = {"list", "dict", "set", "bytearray", "OrderedDict", "defaultdict"}


@register_handler("check_mutable_defaults_python")
def check_mutable_defaults_python(ctx: ScanContext, rule: Rule) -> Iterable[Finding]:
    if ctx.ast_tree is None:
        return
    for node in _walk(ctx.ast_tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        defaults = list(node.args.defaults)
        defaults.extend(d for d in node.args.kw_defaults if d is not None)
        for default in defaults:
            if _is_mutable_default(default):
                yield _make_finding(
                    ctx, rule, node,
                    f"Function '{node.name}' has a mutable default argument.",
                )
                break


def _is_mutable_default(node: ast.AST) -> bool:
    if isinstance(node, MUTABLE_DEFAULT_TYPES):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        if node.func.id in MUTABLE_DEFAULT_CALLS:
            return True
    return False


@register_handler("check_unused_imports_python")
def check_unused_imports_python(ctx: ScanContext, rule: Rule) -> Iterable[Finding]:
    if ctx.ast_tree is None:
        return
    tree = ctx.ast_tree
    imported: dict[str, ast.AST] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    key = alias.asname
                elif "." in alias.name:
                    key = alias.name.split(".")[0]
                else:
                    key = alias.name
                imported.setdefault(key, node)
        elif isinstance(node, ast.ImportFrom):
            # Skip compiler directives (from __future__ import ...)
            if node.module == "__future__":
                continue
            for alias in node.names:
                if alias.name == "*":
                    continue
                key = alias.asname or alias.name
                imported.setdefault(key, node)
    if not imported:
        return
    used: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            used.add(node.id)
        elif isinstance(node, ast.Attribute):
            root: ast.AST = node
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name):
                used.add(root.id)
    for name, node in imported.items():
        if name not in used:
            yield _make_finding(ctx, rule, node, f"Unused import: {name}")


ROUTE_METHODS = {"get", "post", "put", "delete", "patch", "route", "options", "head"}

AUTH_DECORATOR_TOKENS = (
    "login_required", "requires_auth", "auth_required", "jwt_required",
    "requires_login", "authenticated", "protected", "token_required",
    "requires_authentication", "requires_token",
)

ADMIN_PATH_HINTS = ("admin", "manage", "internal", "private", "superuser")

LOGIN_PATH_HINTS = ("login", "signin", "register", "signup", "forgot", "reset", "auth", "token", "otp")


def _decorator_call_name(deco: ast.AST) -> str:
    target = deco.func if isinstance(deco, ast.Call) else deco
    return _attr_name(target) or ""


@register_handler("check_missing_auth")
def check_missing_auth(ctx: ScanContext, rule: Rule) -> Iterable[Finding]:
    if ctx.language == Language.JAVASCRIPT:
        yield from check_missing_auth_js(ctx, rule)
        return
    if ctx.ast_tree is None:
        return
    for node in _walk(ctx.ast_tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        route_path: str | None = None
        has_auth = False
        for deco in node.decorator_list:
            name = _decorator_call_name(deco)
            last = name.split(".")[-1] if name else ""
            if last in ROUTE_METHODS and isinstance(deco, ast.Call) \
                    and deco.args and _is_string_constant(deco.args[0]):
                route_path = deco.args[0].value  # type: ignore[union-attr]
            if any(tok in name.lower() for tok in AUTH_DECORATOR_TOKENS):
                has_auth = True
        if route_path is None or has_auth:
            continue
        if any(h in route_path.lower() for h in ADMIN_PATH_HINTS):
            yield _make_finding(
                ctx, rule, node,
                f"Route '{route_path}' has no visible authentication.",
            )


@register_handler("check_missing_rate_limit")
def check_missing_rate_limit(ctx: ScanContext, rule: Rule) -> Iterable[Finding]:
    if ctx.language == Language.JAVASCRIPT:
        yield from check_missing_rate_limit_js(ctx, rule)
        return
    if ctx.ast_tree is None:
        return
    for node in _walk(ctx.ast_tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        route_path: str | None = None
        has_limiter = False
        for deco in node.decorator_list:
            name = _decorator_call_name(deco)
            last = name.split(".")[-1] if name else ""
            if last in ROUTE_METHODS and isinstance(deco, ast.Call) \
                    and deco.args and _is_string_constant(deco.args[0]):
                route_path = deco.args[0].value  # type: ignore[union-attr]
            if any(tok in name.lower() for tok in ("limit", "throttle", "ratelimit")):
                has_limiter = True
        if route_path is None or has_limiter:
            continue
        if any(t in route_path.lower() for t in LOGIN_PATH_HINTS):
            yield _make_finding(
                ctx, rule, node,
                f"Endpoint '{route_path}' has no visible rate limiting.",
            )


@register_handler("check_open_redirect")
def check_open_redirect(ctx: ScanContext, rule: Rule) -> Iterable[Finding]:
    if ctx.language == Language.JAVASCRIPT:
        yield from check_open_redirect_js(ctx, rule)
        return
    if ctx.ast_tree is None:
        return
    for node in _walk(ctx.ast_tree):
        if not isinstance(node, ast.Call):
            continue
        name = _attr_name(node.func) or ""
        if not name.endswith("redirect"):
            continue
        if not node.args:
            continue
        arg = node.args[0]
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            continue
        if _is_user_input_access(arg):
            yield _make_finding(ctx, rule, node)


def _is_user_input_access(node: ast.AST) -> bool:
    if isinstance(node, ast.Call):
        name = _attr_name(node.func) or ""
        low = name.lower()
        if name.startswith("request."):
            return True
        if "query" in low or "param" in low or "get_param" in low:
            return True
    if isinstance(node, ast.Subscript):
        name = _attr_name(node.value) or ""
        if name.startswith("request."):
            return True
    return False


@register_handler("check_jwt_no_exp")
def check_jwt_no_exp(ctx: ScanContext, rule: Rule) -> Iterable[Finding]:
    if ctx.language == Language.JAVASCRIPT:
        yield from check_jwt_no_exp_js(ctx, rule)
        return
    if ctx.ast_tree is None:
        return
    for node in _walk(ctx.ast_tree):
        if not isinstance(node, ast.Call):
            continue
        name = _attr_name(node.func) or ""
        if not name.endswith("jwt.encode"):
            continue
        if not node.args:
            continue
        payload = node.args[0]
        if not isinstance(payload, ast.Dict):
            continue
        keys = [
            k.value for k in payload.keys
            if isinstance(k, ast.Constant) and isinstance(k.value, str)
        ]
        if "exp" not in keys and "expires" not in keys and "iat" not in keys:
            yield _make_finding(ctx, rule, node)


@register_handler("check_race_conditions")
def check_race_conditions(ctx: ScanContext, rule: Rule) -> Iterable[Finding]:
    if ctx.language != Language.PYTHON:
        return
    if ctx.ast_tree is None:
        return
    for fn in _walk(ctx.ast_tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for i, stmt in enumerate(fn.body):
            if not isinstance(stmt, ast.If):
                continue
            if not _cond_is_exists_check(stmt.test):
                continue
            is_negated = _cond_is_negated(stmt.test)
            if is_negated:
                # Pattern 1: if not exists(x): open(x, "w") ...
                for sub in ast.walk(stmt):
                    if isinstance(sub, ast.Call) and _is_write_open(sub):
                        yield _make_finding(ctx, rule, sub)
                        break
            else:
                # Pattern 2: if exists(x): return / raise / continue
                #            open(x, "w")   # after the guard
                if not _body_is_early_exit(stmt.body):
                    continue
                for later in fn.body[i + 1:]:
                    fire = None
                    for sub in ast.walk(later):
                        if isinstance(sub, ast.Call) and _is_write_open(sub):
                            fire = sub
                            break
                    if fire is not None:
                        yield _make_finding(ctx, rule, fire)
                        break


def _cond_is_negated(test: ast.AST) -> bool:
    return isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not)


def _body_is_early_exit(body: list) -> bool:
    if not body:
        return False
    if len(body) == 1 and isinstance(body[0], (ast.Return, ast.Raise,
                                                ast.Continue, ast.Break)):
        return True
    return False


def _cond_is_exists_check(test: ast.AST) -> bool:
    for n in ast.walk(test):
        if isinstance(n, ast.Call):
            name = _attr_name(n.func) or ""
            if name.endswith("exists") or name.endswith("isfile") or name.endswith("isdir"):
                return True
    return False


def _is_write_open(node: ast.Call) -> bool:
    name = _attr_name(node.func) or ""
    if name not in ("open", "io.open"):
        return False
    if len(node.args) >= 2:
        mode = node.args[1]
        if isinstance(mode, ast.Constant) and isinstance(mode.value, str):
            return any(c in mode.value for c in ("w", "a", "x", "+"))
    for kw in node.keywords:
        if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
            return any(c in str(kw.value.value) for c in ("w", "a", "x", "+"))
    return False


@register_handler("check_path_traversal")
def check_path_traversal(ctx: ScanContext, rule: Rule) -> Iterable[Finding]:
    if ctx.language != Language.PYTHON:
        return
    if ctx.ast_tree is None:
        return
    for node in _walk(ctx.ast_tree):
        if not isinstance(node, ast.Call):
            continue
        name = _attr_name(node.func) or ""
        if name not in ("open", "io.open"):
            continue
        if not node.args:
            continue
        if _looks_path_traversable(node.args[0]):
            yield _make_finding(ctx, rule, node)


def _looks_path_traversable(arg: ast.AST) -> bool:
    if isinstance(arg, ast.Call):
        name = _attr_name(arg.func) or ""
        if name.endswith("path.join"):
            for a in arg.args[1:]:
                if isinstance(a, (ast.Name, ast.Attribute, ast.Subscript)):
                    return True
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
        if isinstance(arg.left, (ast.Name, ast.Attribute, ast.Subscript)):
            return True
        if isinstance(arg.right, (ast.Name, ast.Attribute, ast.Subscript)):
            return True
    return False


# =============================================================================
# [SECTION] JavaScript lexer
# =============================================================================

JS_KEYWORDS = frozenset({
    "break", "case", "catch", "class", "const", "continue", "debugger",
    "default", "delete", "do", "else", "export", "extends", "finally",
    "for", "function", "if", "import", "in", "instanceof", "let", "new",
    "return", "super", "switch", "this", "throw", "try", "typeof", "var",
    "void", "while", "with", "yield", "async", "await", "of", "static",
    "get", "set",
})

JS_PUNCT_3 = ("===", "!==", "**=", "<<=", ">>=", ">>>", "&&=", "||=", "??=", "...")
JS_PUNCT_2 = ("=>", "==", "!=", "<=", ">=", "&&", "||", "??", "?.",
              "++", "--", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=",
              "**", "<<", ">>")
JS_PUNCT_1 = tuple("+-*/%=<>!&|^~?:;,.(){}[]")


def tokenize_js(source: str) -> list[Token]:
    """Minimal JS lexer. Comments skipped. Template literals treated as a
    single token (contents not analyzed). Regex vs division resolved via
    previous-token heuristic."""
    tokens: list[Token] = []
    i = 0
    line = 1
    col = 1
    n = len(source)

    def advance(k: int = 1) -> None:
        nonlocal i, line, col
        for _ in range(k):
            if i >= n:
                return
            if source[i] == "\n":
                line += 1
                col = 1
            else:
                col += 1
            i += 1

    def prev_meaningful() -> Token | None:
        return tokens[-1] if tokens else None

    def regex_context() -> bool:
        prev = prev_meaningful()
        if prev is None:
            return True
        if prev.kind in (TokenKind.IDENT, TokenKind.NUMBER, TokenKind.STRING,
                         TokenKind.TEMPLATE, TokenKind.REGEX):
            return False
        if prev.kind == TokenKind.KEYWORD:
            return prev.value not in ("this", "super", "true", "false",
                                       "null", "undefined")
        if prev.kind == TokenKind.PUNCT:
            return prev.value not in (")", "]", "}")
        return True

    while i < n:
        c = source[i]

        if c in " \t\r\n":
            advance()
            continue

        if c == "/" and i + 1 < n and source[i + 1] == "/":
            while i < n and source[i] != "\n":
                advance()
            continue

        if c == "/" and i + 1 < n and source[i + 1] == "*":
            advance(2)
            while i + 1 < n and not (source[i] == "*" and source[i + 1] == "/"):
                advance()
            if i + 1 < n:
                advance(2)
            continue

        start_line, start_col = line, col

        if c in ("'", '"'):
            quote = c
            buf = [c]
            advance()
            while i < n and source[i] != quote:
                if source[i] == "\\" and i + 1 < n:
                    buf.append(source[i]); advance()
                    buf.append(source[i]); advance()
                elif source[i] == "\n":
                    break
                else:
                    buf.append(source[i]); advance()
            if i < n and source[i] == quote:
                buf.append(quote); advance()
            tokens.append(Token(TokenKind.STRING, "".join(buf),
                                start_line, start_col))
            continue

        if c == "`":
            buf = [c]
            advance()
            while i < n and source[i] != "`":
                if source[i] == "\\" and i + 1 < n:
                    buf.append(source[i]); advance()
                    buf.append(source[i]); advance()
                else:
                    buf.append(source[i]); advance()
            if i < n and source[i] == "`":
                buf.append("`"); advance()
            tokens.append(Token(TokenKind.TEMPLATE, "".join(buf),
                                start_line, start_col))
            continue

        if c.isalpha() or c == "_" or c == "$":
            buf = [c]; advance()
            while i < n and (source[i].isalnum() or source[i] in "_$"):
                buf.append(source[i]); advance()
            word = "".join(buf)
            kind = TokenKind.KEYWORD if word in JS_KEYWORDS else TokenKind.IDENT
            tokens.append(Token(kind, word, start_line, start_col))
            continue

        if c.isdigit() or (c == "." and i + 1 < n and source[i + 1].isdigit()):
            buf = [c]; advance()
            while i < n and (source[i].isalnum() or source[i] in "._"):
                buf.append(source[i]); advance()
            tokens.append(Token(TokenKind.NUMBER, "".join(buf),
                                start_line, start_col))
            continue

        if c == "/" and regex_context():
            buf = [c]; advance()
            while i < n and source[i] != "/":
                if source[i] == "\\" and i + 1 < n:
                    buf.append(source[i]); advance()
                    buf.append(source[i]); advance()
                elif source[i] == "\n":
                    break
                else:
                    buf.append(source[i]); advance()
            if i < n and source[i] == "/":
                buf.append("/"); advance()
                while i < n and source[i].isalpha():
                    buf.append(source[i]); advance()
            tokens.append(Token(TokenKind.REGEX, "".join(buf),
                                start_line, start_col))
            continue

        matched = False
        for length, table in ((3, JS_PUNCT_3), (2, JS_PUNCT_2), (1, JS_PUNCT_1)):
            chunk = source[i:i + length]
            if len(chunk) == length and chunk in table:
                tokens.append(Token(TokenKind.PUNCT, chunk,
                                    start_line, start_col))
                advance(length)
                matched = True
                break
        if matched:
            continue

        advance()

    return tokens


# =============================================================================
# [SECTION] JavaScript rule handlers (Day 6)
# =============================================================================

def _js_finding(ctx: ScanContext, rule: Rule, token: Token,
                message: str | None = None) -> Finding:
    line = token.line
    if 1 <= line <= len(ctx.lines):
        snippet = ctx.lines[line - 1].strip()
    else:
        snippet = ""
    if len(snippet) > 200:
        snippet = snippet[:197] + "..."
    return Finding(
        id=rule.id,
        rule_name=rule.name,
        severity=rule.severity,
        category=rule.category,
        file=ctx.path,
        line=line,
        column=token.column,
        snippet=snippet,
        message=message or rule.message,
        remediation=rule.remediation,
        language=ctx.language,
        confidence=rule.confidence,
        fix_before=rule.fix_before,
        fix_after=rule.fix_after,
        action=rule.action,
    )


def _js_next(toks: tuple[Token, ...], i: int, offset: int) -> Token | None:
    j = i + offset
    if 0 <= j < len(toks):
        return toks[j]
    return None


@register_handler("check_innerhtml_js")
def check_innerhtml_js(ctx: ScanContext, rule: Rule) -> Iterable[Finding]:
    if ctx.language != Language.JAVASCRIPT:
        return
    toks = ctx.js_tokens
    for i, t in enumerate(toks):
        if t.kind == TokenKind.IDENT and t.value == "innerHTML":
            n1 = _js_next(toks, i, 1)
            n2 = _js_next(toks, i, 2)
            if (n1 and n2 and n1.kind == TokenKind.PUNCT and n1.value == "="
                    and n2.kind != TokenKind.STRING):
                yield _js_finding(ctx, rule, t)
        if t.kind == TokenKind.IDENT and t.value == "document":
            n1 = _js_next(toks, i, 1)
            n2 = _js_next(toks, i, 2)
            if (n1 and n2 and n1.kind == TokenKind.PUNCT and n1.value == "."
                    and n2.kind == TokenKind.IDENT and n2.value == "write"):
                yield _js_finding(ctx, rule, t)


@register_handler("check_prototype_pollution_js")
def check_prototype_pollution_js(ctx: ScanContext, rule: Rule) -> Iterable[Finding]:
    if ctx.language != Language.JAVASCRIPT:
        return
    for t in ctx.js_tokens:
        if t.kind == TokenKind.IDENT and t.value == "__proto__":
            yield _js_finding(ctx, rule, t)


@register_handler("check_missing_helmet_js")
def check_missing_helmet_js(ctx: ScanContext, rule: Rule) -> Iterable[Finding]:
    if ctx.language != Language.JAVASCRIPT:
        return
    toks = ctx.js_tokens
    has_express = False
    has_helmet = False
    express_tok: Token | None = None
    for i, t in enumerate(toks):
        if t.kind != TokenKind.STRING:
            continue
        if t.value in ("'express'", '"express"'):
            has_express = True
            if express_tok is None:
                express_tok = t
        if t.value in ("'helmet'", '"helmet"'):
            has_helmet = True
    if has_express and not has_helmet and express_tok is not None:
        yield _js_finding(ctx, rule, express_tok)


@register_handler("check_promise_rejection_js")
def check_promise_rejection_js(ctx: ScanContext, rule: Rule) -> Iterable[Finding]:
    if ctx.language != Language.JAVASCRIPT:
        return
    toks = ctx.js_tokens
    n = len(toks)
    for i, t in enumerate(toks):
        if t.kind != TokenKind.PUNCT or t.value != ".":
            continue
        nxt = _js_next(toks, i, 1)
        if not (nxt and nxt.kind == TokenKind.IDENT and nxt.value == "then"):
            continue
        # Look ahead until ';' or EOF for a .catch on the same chain
        has_catch = False
        j = i + 1
        depth = 0
        while j < n:
            tk = toks[j]
            if tk.kind == TokenKind.PUNCT:
                if tk.value in ("(", "[", "{"):
                    depth += 1
                elif tk.value in (")", "]", "}"):
                    if depth > 0:
                        depth -= 1
                elif tk.value == ";" and depth == 0:
                    break
                elif tk.value == "." and depth == 0:
                    nx = _js_next(toks, j, 1)
                    if nx and nx.kind in (TokenKind.IDENT, TokenKind.KEYWORD) and nx.value == "catch":
                        has_catch = True
                        break
            j += 1
        if not has_catch:
            yield _js_finding(ctx, rule, nxt,
                              "Promise .then() without .catch() in the same chain.")


# =============================================================================
# [SECTION] JS extensions to shared heuristic rules
# =============================================================================

JS_AUTH_TOKENS = (
    "auth", "authenticate", "authorize", "requireAuth", "ensureAuth",
    "isAuthenticated", "verifyToken", "passport",
)

JS_RATE_TOKENS = (
    "rateLimit", "rateLimiter", "limiter", "throttle", "slowDown",
    "expressRateLimit",
)

JS_LOGIN_HINTS = ("login", "signin", "register", "signup", "forgot",
                  "reset", "auth", "token", "otp")

JS_ADMIN_HINTS = ("admin", "manage", "internal", "private", "superuser")


def _js_route_targets(toks: tuple[Token, ...]) -> list[tuple[Token, str]]:
    """Return (route_token, path) for patterns:
       app.get('/path', ...), router.post('/x', ...), app.route('/y')"""
    routes: list[tuple[Token, str]] = []
    methods = {"get", "post", "put", "delete", "patch", "options", "head", "route"}
    for i, t in enumerate(toks):
        if t.kind != TokenKind.PUNCT or t.value != ".":
            continue
        n1 = _js_next(toks, i, 1)
        n2 = _js_next(toks, i, 2)
        n3 = _js_next(toks, i, 3)
        if not (n1 and n2 and n3):
            continue
        if n1.kind not in (TokenKind.IDENT, TokenKind.KEYWORD) or n1.value not in methods:
            continue
        if n2.kind != TokenKind.PUNCT or n2.value != "(":
            continue
        if n3.kind != TokenKind.STRING:
            continue
        raw = n3.value
        if raw[:1] in ("'", '"'):
            raw = raw[1:]
        if raw[-1:] in ("'", '"'):
            raw = raw[:-1]
        if not raw.startswith("/"):
            continue
        routes.append((n3, raw))
    return routes


def _js_has_nearby_auth(toks: tuple[Token, ...], start_idx: int,
                        tokens_of_interest: tuple[str, ...],
                        span: int = 200) -> bool:
    end = min(len(toks), start_idx + span)
    for k in range(start_idx, end):
        tk = toks[k]
        if tk.kind in (TokenKind.IDENT, TokenKind.STRING):
            low = tk.value.lower()
            if any(tok.lower() in low for tok in tokens_of_interest):
                return True
    return False


def _find_token_index(toks: tuple[Token, ...], target: Token) -> int:
    for i, tk in enumerate(toks):
        if tk is target:
            return i
    return 0


def check_missing_auth_js(ctx: ScanContext, rule: Rule) -> Iterable[Finding]:
    if ctx.language != Language.JAVASCRIPT:
        return
    toks = ctx.js_tokens
    for tok, path in _js_route_targets(toks):
        if not any(h in path.lower() for h in JS_ADMIN_HINTS):
            continue
        idx = _find_token_index(toks, tok)
        if not _js_has_nearby_auth(toks, idx, JS_AUTH_TOKENS):
            yield _js_finding(ctx, rule, tok,
                              f"Route '{path}' has no visible authentication.")


def check_missing_rate_limit_js(ctx: ScanContext, rule: Rule) -> Iterable[Finding]:
    if ctx.language != Language.JAVASCRIPT:
        return
    toks = ctx.js_tokens
    for tok, path in _js_route_targets(toks):
        if not any(h in path.lower() for h in JS_LOGIN_HINTS):
            continue
        idx = _find_token_index(toks, tok)
        if not _js_has_nearby_auth(toks, idx, JS_RATE_TOKENS):
            yield _js_finding(ctx, rule, tok,
                              f"Endpoint '{path}' has no visible rate limiting.")


def check_open_redirect_js(ctx: ScanContext, rule: Rule) -> Iterable[Finding]:
    if ctx.language != Language.JAVASCRIPT:
        return
    toks = ctx.js_tokens
    for i, t in enumerate(toks):
        if t.kind != TokenKind.PUNCT or t.value != ".":
            continue
        n1 = _js_next(toks, i, 1)
        if not (n1 and n1.kind == TokenKind.IDENT and n1.value == "redirect"):
            continue
        n2 = _js_next(toks, i, 2)
        n3 = _js_next(toks, i, 3)
        if not (n2 and n3 and n2.value == "("):
            continue
        if n3.kind == TokenKind.STRING:
            continue
        # check if user-controlled (req.query / req.params)
        seg = toks[i:i + 12]
        joined = "".join(tk.value for tk in seg)
        if "req.query" in joined or "req.params" in joined or "req.body" in joined:
            yield _js_finding(ctx, rule, n1)


def check_jwt_no_exp_js(ctx: ScanContext, rule: Rule) -> Iterable[Finding]:
    if ctx.language != Language.JAVASCRIPT:
        return
    toks = ctx.js_tokens
    for i, t in enumerate(toks):
        if t.kind != TokenKind.IDENT:
            continue
        if t.value not in ("sign", "encode"):
            continue
        if t.kind not in (TokenKind.IDENT, TokenKind.KEYWORD):
            continue
        prev = _js_next(toks, i, -1)
        if not (prev and prev.kind == TokenKind.PUNCT and prev.value == "."):
            continue
        # Only flag if there is a jwt-ish receiver within previous 4 tokens
        back = toks[max(0, i - 4):i]
        if not any(tk.kind == TokenKind.IDENT and "jwt" in tk.value.lower()
                   for tk in back):
            continue
        # Look ahead to matching ) and check for expiresIn / exp
        j = i + 1
        depth = 0
        has_exp = False
        while j < len(toks):
            tk = toks[j]
            if tk.kind == TokenKind.PUNCT:
                if tk.value == "(":
                    depth += 1
                elif tk.value == ")":
                    if depth == 0:
                        break
                    depth -= 1
            if tk.kind == TokenKind.IDENT and tk.value in ("expiresIn", "exp"):
                has_exp = True
                break
            j += 1
        if not has_exp:
            yield _js_finding(ctx, rule, t,
                              "JWT signed without expiration (expiresIn/exp).")


# =============================================================================
# [SECTION] Python additional rule handlers (Day 7)
# =============================================================================

REQUESTS_METHODS = frozenset({
    "get", "post", "put", "delete", "patch", "head", "options", "request",
})


@register_handler("check_requests_no_timeout_python")
def check_requests_no_timeout_python(ctx: ScanContext, rule: Rule) -> Iterable[Finding]:
    if ctx.language != Language.PYTHON or ctx.ast_tree is None:
        return
    for node in _walk(ctx.ast_tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr not in REQUESTS_METHODS:
            continue
        base = node.func.value
        if not (isinstance(base, ast.Name) and base.id == "requests"):
            continue
        has_timeout = any(kw.arg == "timeout" for kw in node.keywords)
        if not has_timeout:
            yield _make_finding(ctx, rule, node)


DATETIME_METHODS = frozenset({
    "now", "utcnow", "fromtimestamp", "fromordinal",
})


@register_handler("check_datetime_no_tz_python")
def check_datetime_no_tz_python(ctx: ScanContext, rule: Rule) -> Iterable[Finding]:
    if ctx.language != Language.PYTHON or ctx.ast_tree is None:
        return
    for node in _walk(ctx.ast_tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr not in DATETIME_METHODS:
            continue
        base = node.func.value
        is_datetime = False
        if isinstance(base, ast.Attribute) and base.attr == "datetime":
            if isinstance(base.value, ast.Name) and base.value.id == "datetime":
                is_datetime = True
        elif isinstance(base, ast.Name) and base.id == "datetime":
            is_datetime = True
        if not is_datetime:
            continue
        if node.func.attr == "utcnow":
            yield _make_finding(
                ctx, rule, node,
                "datetime.utcnow() returns a naive datetime (deprecated in 3.12).",
            )
            continue
        if node.func.attr == "fromordinal":
            yield _make_finding(ctx, rule, node)
            continue
        has_tz_kw = any(kw.arg == "tz" for kw in node.keywords)
        positional_count = len(node.args)
        if node.func.attr == "fromtimestamp":
            has_tz_pos = positional_count >= 2
        else:  # now
            has_tz_pos = positional_count >= 1
        if has_tz_kw or has_tz_pos:
            continue
        # Context check: only fire when the result is likely security-related.
        if _datetime_call_in_security_context(node, ctx.ast_tree):
            yield _make_finding(ctx, rule, node)


DATETIME_SECURITY_TOKENS = (
    "exp", "expire", "expiry", "expires", "issued", "issue",
    "iat", "token", "session", "auth", "jwt", "nonce", "salt",
    "otp", "csrf", "reset", "sign",
)

DATETIME_SECURITY_FUNCS = (
    "login", "register", "authenticate", "signin", "signup",
    "create_token", "issue_token", "make_token", "generate_token",
    "new_session", "create_session", "reset_password",
)


def _datetime_call_in_security_context(node: ast.AST,
                                        tree: ast.AST | None) -> bool:
    """Return True if the datetime call's result is assigned to a
    security-related name, or if the call is inside a security-named
    function. Parents are found via a reverse walk over the tree."""
    if tree is None:
        return False
    parents: dict[int, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[id(child)] = parent

    target_names: list[str] = []
    cursor: ast.AST = node
    security_func_found = False
    for _ in range(20):  # bounded depth
        parent = parents.get(id(cursor))
        if parent is None:
            break
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
            fname = parent.name.lower()
            if any(tok in fname for tok in DATETIME_SECURITY_FUNCS):
                security_func_found = True
            break  # stop at function boundary
        if isinstance(parent, ast.Assign):
            for tgt in parent.targets:
                if isinstance(tgt, ast.Name):
                    target_names.append(tgt.id)
                elif isinstance(tgt, ast.Attribute):
                    target_names.append(tgt.attr)
        if isinstance(parent, ast.AnnAssign) and isinstance(parent.target,
                                                            ast.Name):
            target_names.append(parent.target.id)
        if isinstance(parent, ast.keyword):
            # e.g. jwt.encode(..., exp=datetime.now()) -> kw.arg == "exp"
            if parent.arg:
                target_names.append(parent.arg)
        cursor = parent

    if security_func_found:
        return True
    for name in target_names:
        low = name.lower()
        if any(tok in low for tok in DATETIME_SECURITY_TOKENS):
            return True
    return False


@register_handler("check_env_fallback_secret")
def check_env_fallback_secret(ctx: ScanContext, rule: Rule) -> Iterable[Finding]:
    if ctx.language == Language.PYTHON:
        yield from _check_env_fallback_python(ctx, rule)
    elif ctx.language == Language.JAVASCRIPT:
        yield from _check_env_fallback_js(ctx, rule)


ENV_GET_FUNCS = frozenset({
    "getenv", "get", "os.environ.get", "environ.get",
})


def _name_looks_secret(name: str) -> bool:
    low = name.lower()
    return any(tok in low for tok in (
        "secret", "key", "token", "password", "passwd", "pwd",
        "apikey", "api_key", "auth", "session", "salt", "nonce",
        "csrf", "jwt",
    ))


def _string_literal(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _check_env_fallback_python(ctx: ScanContext,
                                rule: Rule) -> Iterable[Finding]:
    if ctx.ast_tree is None:
        return
    for node in _walk(ctx.ast_tree):
        if not isinstance(node, ast.Call):
            continue
        name = _attr_name(node.func) or ""
        if name not in ("os.environ.get", "os.getenv", "environ.get"):
            continue
        if len(node.args) < 2:
            continue
        env_name = _string_literal(node.args[0])
        if env_name is None or not _name_looks_secret(env_name):
            continue
        fallback = _string_literal(node.args[1])
        if fallback is None:
            continue
        if fallback.strip() == "" or fallback.strip().lower() in (
            "none", "null", "undefined",
        ):
            continue
        yield _make_finding(
            ctx, rule, node,
            f"Env var '{env_name}' has a hardcoded fallback secret.",
        )


def _check_env_fallback_js(ctx: ScanContext,
                            rule: Rule) -> Iterable[Finding]:
    toks = ctx.js_tokens
    n = len(toks)
    for i, t in enumerate(toks):
        if t.kind != TokenKind.IDENT or t.value != "process":
            continue
        n1 = _js_next(toks, i, 1)
        n2 = _js_next(toks, i, 2)
        n3 = _js_next(toks, i, 3)
        if not (n1 and n2 and n3):
            continue
        if not (n1.kind == TokenKind.PUNCT and n1.value == "."
                and n2.kind == TokenKind.IDENT and n2.value == "env"
                and n3.kind == TokenKind.PUNCT and n3.value == "."):
            continue
        env_tok = _js_next(toks, i, 4)
        if not (env_tok and env_tok.kind == TokenKind.IDENT):
            continue
        if not _name_looks_secret(env_tok.value):
            continue
        # Look ahead for || "fallback"  or  ?? "fallback"
        j = i + 5
        while j < n:
            tk = toks[j]
            if tk.kind == TokenKind.PUNCT and tk.value in ("||", "??"):
                fallback = _js_next(toks, j, 1)
                if fallback and fallback.kind == TokenKind.STRING:
                    inner = fallback.value.strip("\"'")
                    if inner.strip():
                        yield _js_finding(
                            ctx, rule, env_tok,
                            f"Env var '{env_tok.value}' has a hardcoded "
                            f"fallback secret.",
                        )
                break
            if tk.kind == TokenKind.PUNCT and tk.value in (";", ",", ")"):
                break
            j += 1


# =============================================================================
# [SECTION] Secure cache (opt-in, off by default)
# =============================================================================

CACHE_DIR_NAME = "codefence"
CACHE_VERSION = "v1"


def _cache_root() -> Path:
    base = os.environ.get("XDG_CACHE_HOME")
    if base:
        root = Path(base) / CACHE_DIR_NAME
    else:
        root = Path.home() / ".cache" / CACHE_DIR_NAME
    return root / CACHE_VERSION


def _ensure_cache_dir() -> Path:
    root = _cache_root()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(root, 0o700)
    except OSError:
        pass
    return root


def _cache_key(source: str, language: Language,
               rules_fingerprint: str) -> str:
    h = hashlib.sha256()
    h.update(CACHE_VERSION.encode("ascii"))
    h.update(b"\x00")
    h.update(language.value.encode("ascii"))
    h.update(b"\x00")
    h.update(rules_fingerprint.encode("ascii"))
    h.update(b"\x00")
    h.update(source.encode("utf-8", errors="replace"))
    return h.hexdigest()


def _rules_fingerprint(rules_path: Path) -> str:
    try:
        data = rules_path.read_bytes()
    except OSError:
        return "0" * 64
    return hashlib.sha256(data).hexdigest()


def _finding_to_dict(f: Finding) -> dict:
    return {
        "id": f.id,
        "rule_name": f.rule_name,
        "severity": f.severity.value,
        "category": f.category,
        "file": f.file,
        "line": f.line,
        "column": f.column,
        "snippet": f.snippet,
        "message": f.message,
        "remediation": f.remediation,
        "language": f.language.value,
        "confidence": f.confidence.value,
    }


def _dict_to_finding(d: dict) -> Finding | None:
    try:
        return Finding(
            id=str(d["id"]),
            rule_name=str(d["rule_name"]),
            severity=Severity(d["severity"]),
            category=str(d["category"]),
            file=str(d["file"]),
            line=int(d["line"]),
            column=int(d["column"]),
            snippet=str(d["snippet"]),
            message=str(d["message"]),
            remediation=str(d["remediation"]),
            language=Language(d["language"]),
            confidence=Confidence(d["confidence"]),
        )
    except (KeyError, TypeError, ValueError):
        return None


def cache_load(source: str, language: Language, rules_fp: str) -> list[Finding] | None:
    """Return cached findings, or None on miss/corruption."""
    try:
        key = _cache_key(source, language, rules_fp)
        f = _cache_root() / f"{key}.json"
        if not f.is_file():
            return None
        # Reject symlinks and non-regular files
        st = f.lstat()
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            return None
        data = json.loads(f.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return None
        if data.get("version") != CACHE_VERSION:
            return None
        items = data.get("findings", [])
        if not isinstance(items, list):
            return None
        out: list[Finding] = []
        for item in items:
            fnd = _dict_to_finding(item)
            if fnd is None:
                return None
            out.append(fnd)
        return out
    except (OSError, ValueError, json.JSONDecodeError):
        return None


def cache_store(source: str, language: Language, rules_fp: str,
                findings: Sequence[Finding]) -> None:
    try:
        root = _ensure_cache_dir()
        key = _cache_key(source, language, rules_fp)
        target = root / f"{key}.json"
        payload = {
            "version": CACHE_VERSION,
            "language": language.value,
            "rules_fingerprint": rules_fp,
            "findings": [_finding_to_dict(f) for f in findings],
        }
        text = json.dumps(payload, ensure_ascii=False)
        fd, tmp_path = tempfile.mkstemp(
            prefix=".tmp-", dir=str(root), suffix=".json"
        )
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fp:
                fp.write(text)
            os.replace(tmp_path, target)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
    except (OSError, ValueError):
        # Cache is best-effort; never fail the scan because of cache
        return


# =============================================================================
# [SECTION] Source helpers
# =============================================================================

def _try_parse_python(source: str) -> tuple[ast.AST | None, str | None]:
    """Return (tree, error_message). Never raises."""
    try:
        return ast.parse(source), None
    except SyntaxError as e:
        where = f"line {e.lineno}, column {e.offset}" if e.lineno else "unknown"
        return None, f"Python syntax error at {where}: {e.msg}"
    except ValueError as e:
        return None, f"Python parse error: {e}"


def _parse_python(source: str) -> ast.AST | None:
    tree, _err = _try_parse_python(source)
    return tree


def _make_meta_finding(path: str, language: Language, message: str) -> Finding:
    """Synthetic finding used when a file could not be scanned at all."""
    return Finding(
        id="R000",
        rule_name="File not scanned",
        severity=Severity.INFO,
        category="meta",
        file=path,
        line=1,
        column=1,
        snippet="",
        message=message,
        remediation="Fix the issue above and re-run the scanner.",
        language=language,
        confidence=Confidence.HIGH,
    )


def _line_col(source: str, offset: int) -> tuple[int, int]:
    line = source.count("\n", 0, offset) + 1
    last_nl = source.rfind("\n", 0, offset)
    column = offset - last_nl
    return line, column


def _snippet(source: str, start: int, end: int, radius: int = 60) -> str:
    a = max(0, start - radius)
    b = min(len(source), end + radius)
    text = source[a:b].replace("\n", " ").replace("\r", " ").replace("\t", " ")
    return " ".join(text.split())


# =============================================================================
# [SECTION] Core scan API (pure, testable)
# =============================================================================

_NOQA_RE = re.compile(
    r"(?:#|//)\s*noqa(?:\s*:\s*([A-Za-z0-9_,\s-]+))?",
    re.IGNORECASE,
)


def _parse_noqa_directives(lines: Sequence[str]) -> dict[int, set[str] | None]:
    """Return {line_no: set_of_rule_ids or None}.

    None means "suppress all rules on this line."
    A set of rule IDs means "suppress only these rules on this line."
    """
    directives: dict[int, set[str] | None] = {}
    for i, line in enumerate(lines, 1):
        m = _NOQA_RE.search(line)
        if not m:
            continue
        rules_part = m.group(1)
        if not rules_part:
            directives[i] = None
            continue
        ids = {tok.strip().upper()
               for tok in re.split(r"[,\s]+", rules_part)
               if tok.strip()}
        if not ids:
            directives[i] = None
        else:
            directives[i] = ids
    return directives


def _apply_noqa(findings: Iterable[Finding],
                directives: dict[int, set[str] | None]) -> list[Finding]:
    out: list[Finding] = []
    for f in findings:
        d = directives.get(f.line, "missing")
        if d == "missing":
            out.append(f)
            continue
        if d is None:
            continue
        if f.id.upper() in d:
            continue
        out.append(f)
    return out


def _dedupe_findings(findings: Iterable[Finding]) -> list[Finding]:
    """One finding per (rule_id, file, line) - drops duplicate matches
    produced when multiple patterns of the same rule hit the same line."""
    seen: set[tuple[str, str, int]] = set()
    out: list[Finding] = []
    for f in sorted(findings, key=Finding.sort_key):
        key = (f.id, f.file, f.line)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def scan_source(
    source: str,
    language: Language,
    rules: Sequence[Rule],
    path: str = "<memory>",
) -> list[Finding]:
    # Defensive BOM strip for direct API callers.
    if source.startswith("\ufeff"):
        source = source[1:]
    js_tokens: tuple[Token, ...] = ()
    ast_tree: ast.AST | None = None
    parse_error: str | None = None
    if language == Language.PYTHON:
        ast_tree, parse_error = _try_parse_python(source)
    elif language == Language.JAVASCRIPT:
        js_tokens = tuple(tokenize_js(source))
    ctx = ScanContext(
        path=path,
        language=language,
        source=source,
        lines=tuple(source.splitlines()),
        ast_tree=ast_tree,
        js_tokens=js_tokens,
    )
    findings: list[Finding] = []
    if parse_error is not None:
        findings.append(_make_meta_finding(path, language, parse_error))
        return findings
    for rule in rules:
        if not rule.enabled:
            continue
        if language not in rule.languages:
            continue
        if rule.detection == Detection.REGEX:
            findings.extend(_run_regex_rule(rule, ctx))
        elif rule.detection in (Detection.AST, Detection.LEXICAL):
            handler = RULE_HANDLERS.get(rule.handler)
            if handler is None:
                continue
            try:
                findings.extend(handler(ctx, rule))
            except Exception as _e:
                if _DEBUG_HANDLERS:
                    import traceback
                    print(f"[handler-error] {rule.id} "
                          f"{rule.handler}: {_e!r}", file=sys.stderr)
                    traceback.print_exc()
                continue
    directives = _parse_noqa_directives(ctx.lines)
    if directives:
        findings = _apply_noqa(findings, directives)
    return _dedupe_findings(findings)


class _RegexTimeout(Exception):
    pass


def _regex_timeout_handler(signum, frame):
    raise _RegexTimeout()


def _safe_regex_matches(pattern: "re.Pattern[str]", text: str) -> list:
    """Run pattern.finditer(text) with a hard timeout when possible.

    On platforms or threads where signal-based timeouts are unavailable
    (Windows, non-main threads), fall back to a strict input cap and
    emit a one-time warning. The regex still runs, but on at most
    NO_SIGNAL_MAX_REGEX_INPUT characters.
    """
    global _NO_SIGNAL_WARNED
    try:
        import signal as _signal
        prev = _signal.signal(_signal.SIGALRM, _regex_timeout_handler)
        _signal.setitimer(_signal.ITIMER_REAL, REGEX_TIMEOUT_SEC)
    except (ImportError, ValueError, AttributeError, OSError):
        # Signal-based timeout unavailable. Apply strict input cap.
        if not _NO_SIGNAL_WARNED:
            print(
                "[codefence] warning: signal-based regex timeout is not "
                "available on this platform or thread; using strict input "
                "cap instead. Regex results may be less complete on very "
                "long lines.",
                file=sys.stderr,
            )
            _NO_SIGNAL_WARNED = True
        capped = text[:NO_SIGNAL_MAX_REGEX_INPUT]
        return list(pattern.finditer(capped))
    try:
        return list(pattern.finditer(text))
    except _RegexTimeout:
        return []
    finally:
        try:
            _signal.setitimer(_signal.ITIMER_REAL, 0)
            _signal.signal(_signal.SIGALRM, prev)
        except Exception:  # noqa: R012
            pass


def _run_regex_rule(rule: Rule, ctx: ScanContext) -> Iterator[Finding]:
    """Scan line-by-line so a single regex call can never touch more than
    one line of source (bounds catastrophic backtracking) and enforce a
    hard per-call timeout on top of that."""
    for pattern in rule.patterns:
        for line_no, raw_line in enumerate(ctx.lines, 1):
            line = raw_line if len(raw_line) <= MAX_REGEX_LINE_LEN \
                else raw_line[:MAX_REGEX_LINE_LEN]
            for match in _safe_regex_matches(pattern, line):
                column = match.start() + 1
                snippet = line.strip()
                if len(snippet) > 200:
                    snippet = snippet[:197] + "..."
                yield Finding(
                    id=rule.id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    category=rule.category,
                    file=ctx.path,
                    line=line_no,
                    column=column,
                    snippet=snippet,
                    message=rule.message,
                    remediation=rule.remediation,
                    language=ctx.language,
                    confidence=rule.confidence,
                    fix_before=rule.fix_before,
                    fix_after=rule.fix_after,
                    action=rule.action,
                )


def _display_path(path: str) -> str:
    """Return a path relative to CWD when possible, otherwise the original."""
    try:
        p = Path(path).resolve()
        cwd = Path.cwd().resolve()
        rel = p.relative_to(cwd)
        return str(rel) if str(rel) != "." else "."
    except (ValueError, OSError):
        return path


def scan_file(
    path: Path,
    rules: Sequence[Rule],
    max_size: int = DEFAULT_MAX_SIZE,
    use_cache: bool = False,
    rules_fingerprint: str = "",
) -> list[Finding]:
    language = _detect_language(path)
    if language is None:
        return []
    display = _display_path(str(path))
    try:
        size = path.stat().st_size
        if size > max_size:
            return [_make_meta_finding(
                display, language,
                f"File skipped: size {size} bytes exceeds limit {max_size} bytes.",
            )]
        # utf-8-sig auto-strips a leading BOM if present.
        source = path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError as e:
        return [_make_meta_finding(
            display, language, f"File skipped: {e}",
        )]
    if use_cache:
        cached = cache_load(source, language, rules_fingerprint)
        if cached is not None:
            # Patch path in cached findings (in case file moved)
            return [
                Finding(
                    id=f.id, rule_name=f.rule_name, severity=f.severity,
                    category=f.category, file=display, line=f.line,
                    column=f.column, snippet=f.snippet, message=f.message,
                    remediation=f.remediation, language=f.language,
                    confidence=f.confidence,
                )
                for f in cached
            ]
    findings = scan_source(source, language, rules, path=display)
    if use_cache:
        cache_store(source, language, rules_fingerprint, findings)
    return findings


def _detect_language(path: Path) -> Language | None:
    suffix = path.suffix.lower()
    if suffix == ".py":
        return Language.PYTHON
    if suffix in (".js", ".mjs", ".cjs"):
        return Language.JAVASCRIPT
    return None


# =============================================================================
# [SECTION] Reporters
# =============================================================================

_ANSI = {
    Severity.CRITICAL: "\033[1;31m",
    Severity.HIGH: "\033[31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[90m",
    Severity.INFO: "\033[36m",
}
_ANSI_RESET = "\033[0m"


def _color_enabled(force_no_color: bool) -> bool:
    if force_no_color:
        return False
    if os.environ.get("NO_COLOR"):
        return False
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


# --- Visual tokens (Unicode safe on modern terminals) ---
_BOX_TL = "\u256d"   # rounded corner top-left
_BOX_TR = "\u256e"
_BOX_BL = "\u2570"
_BOX_BR = "\u256f"
_BOX_H  = "\u2500"
_BOX_V  = "\u2502"
_BOX_BAR = "\u258e"  # left bar accent

_ICON_FINDING = "\u2716"    # heavy multiply (finding)
_ICON_ARROW = "\u21b3"      # arrow for remediation
_ICON_CLOCK = "\u23f1"      # stopwatch
_ICON_DOT = "\u25cf"        # filled circle
_ICON_CHECK = "\u2714"      # check mark for clean

_SEV_LABEL = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
    Severity.INFO: "INFO",
}


def _c(text: str, sev: Severity, use_color: bool) -> str:
    if not use_color or sev not in _ANSI:
        return text
    return f"{_ANSI[sev]}{text}{_ANSI_RESET}"


import unicodedata as _unicodedata

_WIDE_RANGES = (
    (0x1100, 0x115F), (0x2E80, 0x303E), (0x3041, 0x33FF),
    (0x3400, 0x4DBF), (0x4E00, 0x9FFF), (0xA000, 0xA4CF),
    (0xAC00, 0xD7A3), (0xF900, 0xFAFF), (0xFE30, 0xFE4F),
    (0xFF00, 0xFF60), (0xFFE0, 0xFFE6),
    (0x1F300, 0x1F64F), (0x1F900, 0x1F9FF),
)


def _char_width(ch: str) -> int:
    code = ord(ch)
    for lo, hi in _WIDE_RANGES:
        if lo <= code <= hi:
            return 2
    if _unicodedata.east_asian_width(ch) in ("W", "F"):
        return 2
    return 1


def _visible_width(text: str) -> int:
    import re as _re
    plain = _re.sub(r"\x1b\[[0-9;]*m", "", text)
    return sum(_char_width(c) for c in plain)


def _pad_visible(text: str, width: int) -> str:
    w = _visible_width(text)
    pad = max(0, width - w)
    return text + " " * pad


def _hr(width: int = 64, char: str = _BOX_H) -> str:
    return char * width


def _box_top(width: int) -> str:
    return _BOX_TL + _BOX_H * (width - 2) + _BOX_TR


def _box_bot(width: int) -> str:
    return _BOX_BL + _BOX_H * (width - 2) + _BOX_BR


def _box_row(text: str, width: int) -> str:
    return f"{_BOX_V} {_pad_visible(text, width - 3)}{_BOX_V}"


def report_cli(findings: Sequence[Finding],
               files_scanned: int,
               duration_ms: int,
               use_color: bool,
               quiet: bool = False) -> str:
    W = 64
    out: list[str] = []

    # --- Header box ---
    brand = _c("CodeFence", Severity.INFO, use_color)
    ver = f"v{TOOL_VERSION}"
    line1 = f"  {brand}  {_c('\u00b7', Severity.LOW, use_color)}  {ver}"
    line2 = "  Pattern-based sanity check \u00b7 not a security audit"
    out.append(_box_top(W))
    out.append(_box_row(line1, W))
    out.append(_box_row(line2, W))
    out.append(_box_bot(W))
    out.append("")

    if quiet:
        # quiet: only summary
        summary = _summary_counts(findings)
        out.append(f"  Scanned {files_scanned} file(s) in {duration_ms} ms")
        out.append(_format_summary_inline(summary, use_color))
        return "\n".join(out)

    # --- Scan info ---
    clock = _c(_ICON_CLOCK, Severity.INFO, use_color)
    plural = "file" if files_scanned == 1 else "files"
    out.append(
        f"  {clock}  Scanned {files_scanned} {plural} "
        f"\u00b7 {duration_ms} ms"
    )
    out.append("")

    if not findings:
        if files_scanned == 0:
            warn = _c("No files matched.", Severity.MEDIUM, use_color)
            out.append(f"  {warn}")
            out.append(
                "  Check your paths, --include, and --exclude options."
            )
        else:
            check = _c(_ICON_CHECK, Severity.INFO, use_color)
            out.append(
                f"  {check}  {_c('No findings.', Severity.LOW, use_color)}"
            )
        out.append("")
        out.append(_summary_box(findings, W, use_color))
        return "\n".join(out)

    # --- Group by severity, ordered ---
    order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
             Severity.LOW, Severity.INFO]
    groups: dict[Severity, list[Finding]] = {s: [] for s in order}
    for f in findings:
        groups[f.severity].append(f)

    for sev in order:
        bucket = groups[sev]
        if not bucket:
            continue
        label = _SEV_LABEL[sev]
        count = len(bucket)
        count_word = "finding" if count == 1 else "findings"
        header = (f"  {_c(_BOX_BAR, sev, use_color)}"
                  f"{_c(label, sev, use_color)}  "
                  f"{_c(str(count), sev, use_color)} {count_word}")
        out.append(header)
        out.append("  " + _hr(W - 2))
        for f in bucket:
            mark = _c(_ICON_FINDING, sev, use_color)
            rid = _c(f.id, sev, use_color)
            out.append(f"  {mark}  {rid}  {f.rule_name}")
            out.append(f"     {_c(f.file, Severity.LOW, use_color)}:"
                       f"{f.line}:{f.column}")
            out.append(f"     {f.message}")
            if f.snippet:
                snip = f.snippet
                if len(snip) > 100:
                    snip = snip[:97] + "..."
                out.append(f"     {_c('>', Severity.LOW, use_color)} {snip}")
            if f.remediation:
                out.append(f"     {_c(_ICON_ARROW, Severity.INFO, use_color)}"
                           f"  {_c(f.remediation, Severity.LOW, use_color)}")
            if f.fix_before or f.fix_after:
                out.append("")
                out.append(f"     {_c('Typical fix:', Severity.INFO, use_color)}")
                for line in f.fix_before.split("\n"):
                    prefix = _c("  - ", Severity.CRITICAL, use_color)
                    out.append(f"     {prefix}{line}")
                for line in f.fix_after.split("\n"):
                    prefix = _c("  + ", Severity.INFO, use_color)
                    out.append(f"     {prefix}{line}")
            out.append("")

    out.append(_summary_box(findings, W, use_color))
    return "\n".join(out)


def _summary_box(findings: Sequence[Finding], width: int,
                 use_color: bool) -> str:
    counts = _summary_counts(findings)
    out: list[str] = []
    title = _c(" Summary ", Severity.INFO, use_color)
    dash_len = width - 4 - len(" Summary ")
    top = (f"  {_BOX_TL}{_BOX_H} {title}{_BOX_H * dash_len}"
           f"{_BOX_TR}")
    out.append(top)
    # two rows: critical/high  and  medium/low (+ info if present)
    def cell(sev: Severity, count: int) -> str:
        dot = _c(_ICON_DOT, sev, use_color)
        name = _SEV_LABEL[sev].lower()
        num = _c(f"{count:>3}", sev, use_color)
        return f"{dot}  {name:<9} {num}"
    has_info = counts.get("info", 0) > 0
    row1 = f"  {cell(Severity.CRITICAL, counts.get('critical', 0))}" \
           f"     {cell(Severity.HIGH, counts.get('high', 0))}"
    row2 = f"  {cell(Severity.MEDIUM, counts.get('medium', 0))}" \
           f"     {cell(Severity.LOW, counts.get('low', 0))}"
    out.append(f"  {_BOX_V} {_pad_visible(row1[2:], width - 4)}{_BOX_V}")
    out.append(f"  {_BOX_V} {_pad_visible(row2[2:], width - 4)}{_BOX_V}")
    if has_info:
        row3 = f"  {cell(Severity.INFO, counts.get('info', 0))}"
        out.append(f"  {_BOX_V} {_pad_visible(row3[2:], width - 4)}{_BOX_V}")
    out.append(f"  {_box_bot(width - 2)}")
    return "\n".join(out)


def _format_summary_inline(counts: dict[str, int],
                           use_color: bool) -> str:
    parts = []
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                Severity.LOW, Severity.INFO):
        n = counts.get(sev.value, 0)
        if n == 0 and sev == Severity.INFO:
            continue
        parts.append(f"{_c(sev.value, sev, use_color)}={n}")
    return "Findings: " + ", ".join(parts)


def _summary_counts(findings: Sequence[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    return counts


def report_json(findings: Sequence[Finding],
                files_scanned: int,
                duration_ms: int) -> str:
    payload = {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "scan": {
            "files": files_scanned,
            "duration_ms": duration_ms,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
        "findings": [
            {
                "id": f.id,
                "rule_name": f.rule_name,
                "severity": f.severity.value,
                "category": f.category,
                "file": f.file,
                "line": f.line,
                "column": f.column,
                "snippet": f.snippet,
                "message": f.message,
                "remediation": f.remediation,
                "language": f.language.value,
                "confidence": f.confidence.value,
                "fix_before": f.fix_before,
                "fix_after": f.fix_after,
            }
            for f in findings
        ],
        "summary": _summary_counts(findings),
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


SEVERITY_TO_SARIF = {
    Severity.CRITICAL: ("error", "9.0"),
    Severity.HIGH: ("error", "7.5"),
    Severity.MEDIUM: ("warning", "5.0"),
    Severity.LOW: ("note", "3.0"),
    Severity.INFO: ("note", "0.0"),
}


def report_sarif(rules: Sequence[Rule],
                 findings: Sequence[Finding]) -> str:
    used_rule_ids = {f.id for f in findings}
    sarif_rules = []
    for r in rules:
        if r.id not in used_rule_ids and r.id != "R000":
            continue
        level, score = SEVERITY_TO_SARIF.get(r.severity, ("warning", "0.0"))
        rule_props = {
            "security-severity": score,
            "tags": [r.category] if r.category else [],
            "codefence/rule_version": r.rule_version,
        }
        if r.fingerprint:
            rule_props["codefence/rule_fingerprint"] = r.fingerprint
        sarif_rules.append({
            "id": r.id,
            "name": r.name,
            "shortDescription": {"text": r.name},
            "fullDescription": {"text": r.description},
            "defaultConfiguration": {"level": level},
            "helpUri": "https://github.com/codefence",
            "properties": rule_props,
        })
    if "R000" in used_rule_ids:
        sarif_rules.append({
            "id": "R000",
            "name": "File not scanned",
            "shortDescription": {"text": "File not scanned"},
            "defaultConfiguration": {"level": "note"},
        })

    results = []
    for f in findings:
        level, _score = SEVERITY_TO_SARIF.get(f.severity, ("warning", "0.0"))
        fp = _finding_fingerprint(f)
        results.append({
            "ruleId": f.id,
            "level": level,
            "message": {"text": f.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    "region": {
                        "startLine": max(1, f.line),
                        "startColumn": max(1, f.column),
                        "snippet": {"text": f.snippet or ""},
                    },
                },
            }],
            "partialFingerprints": {
                "codefence/v1": fp,
            },
            "properties": {
                "confidence": f.confidence.value,
                "remediation": f.remediation,
            },
        })

    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "version": TOOL_VERSION,
                    "informationUri": "https://github.com/codefence",
                    "rules": sarif_rules,
                },
            },
            "results": results,
        }],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


_HTML_CSS = """
:root{
  --bg:#f6f8fb;--card:#ffffff;--fg:#1a1f2e;--muted:#64748b;
  --border:#e2e8f0;--code-bg:#0f172a;--code-fg:#e2e8f0;
  --crit:#dc2626;--high:#ea580c;--med:#d97706;--low:#64748b;--info:#0891b2;
  --shadow:0 1px 3px rgba(15,23,42,.08),0 1px 2px rgba(15,23,42,.04);
}
[data-theme="dark"]{
  --bg:#0b1020;--card:#131a2e;--fg:#e8ecf5;--muted:#94a3b8;
  --border:#1f2a44;--code-bg:#050912;--code-fg:#cbd5e1;
  --crit:#f87171;--high:#fb923c;--med:#fbbf24;--low:#94a3b8;--info:#22d3ee;
  --shadow:0 1px 3px rgba(0,0,0,.4),0 1px 2px rgba(0,0,0,.3);
}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{
  padding:32px 20px 60px;font-family:-apple-system,BlinkMacSystemFont,
  "Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
  background:var(--bg);color:var(--fg);line-height:1.5;
  transition:background .2s,color .2s;
}
.container{max-width:960px;margin:0 auto}
header{margin-bottom:24px;display:flex;justify-content:space-between;
       align-items:flex-start;gap:16px;flex-wrap:wrap}
h1{margin:0 0 4px;font-size:26px;font-weight:700;letter-spacing:-.02em}
.tagline{color:var(--muted);font-size:14px;margin:0}
.meta{color:var(--muted);font-size:13px;margin-top:8px}
button.theme-btn{
  padding:6px 11px;border:1px solid var(--border);background:var(--card);
  color:var(--fg);border-radius:8px;cursor:pointer;font-size:12px;
  font-weight:500;box-shadow:var(--shadow);transition:transform .15s;
  white-space:nowrap;flex-shrink:0;
}
button.theme-btn:hover{transform:translateY(-1px)}
.dashboard{
  display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));
  gap:12px;margin-bottom:24px;
}
.stat{
  background:var(--card);border:1px solid var(--border);border-radius:12px;
  padding:16px 18px;box-shadow:var(--shadow);
}
.stat .label{font-size:11px;font-weight:600;text-transform:uppercase;
             letter-spacing:.08em;color:var(--muted);margin-bottom:4px}
.stat .value{font-size:28px;font-weight:700;letter-spacing:-.03em;line-height:1}
.stat.crit .value{color:var(--crit)}
.stat.high .value{color:var(--high)}
.stat.med .value{color:var(--med)}
.stat.low .value{color:var(--low)}
.stat.info .value{color:var(--info)}
.stat.total .value{color:var(--fg)}
h2.section{
  font-size:13px;font-weight:700;text-transform:uppercase;
  letter-spacing:.1em;color:var(--muted);margin:28px 0 12px;
  display:flex;align-items:center;gap:10px;
}
h2.section::after{
  content:"";flex:1;height:1px;background:var(--border);
}
.card{
  background:var(--card);border:1px solid var(--border);border-radius:12px;
  padding:16px 18px;margin-bottom:10px;box-shadow:var(--shadow);
  border-left:4px solid var(--border);
}
.card.critical{border-left-color:var(--crit)}
.card.high{border-left-color:var(--high)}
.card.medium{border-left-color:var(--med)}
.card.low{border-left-color:var(--low)}
.card.info{border-left-color:var(--info)}
.card-head{display:flex;align-items:center;gap:10px;margin-bottom:8px;
           flex-wrap:wrap}
.badge{
  display:inline-block;padding:3px 9px;border-radius:999px;
  font-size:11px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;
}
.badge.critical{background:var(--crit);color:#fff}
.badge.high{background:var(--high);color:#fff}
.badge.medium{background:var(--med);color:#fff}
.badge.low{background:var(--low);color:#fff}
.badge.info{background:var(--info);color:#fff}
.rule-id{font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace;
         font-size:12px;font-weight:700;color:var(--muted);
         padding:3px 7px;background:var(--bg);border-radius:6px}
.rule-name{font-weight:600;font-size:15px}
.location{
  font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace;
  font-size:12px;color:var(--muted);margin-bottom:8px;
  word-break:break-all;
}
.message{font-size:14px;margin-bottom:10px}
pre.snippet{
  background:var(--code-bg);color:var(--code-fg);
  padding:10px 12px;border-radius:8px;overflow-x:auto;
  font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace;
  font-size:12.5px;line-height:1.5;margin:0 0 8px;white-space:pre-wrap;
  word-break:break-word;
}
.remediation{
  font-size:13px;color:var(--muted);
  padding:8px 12px;background:var(--bg);border-radius:8px;
  border-left:3px solid var(--info);
  margin-bottom:10px;
}
.remediation strong{color:var(--fg);font-weight:600}
.fix-example{
  margin-top:10px;
  background:var(--bg);
  border:1px solid var(--border);
  border-radius:8px;
  padding:10px 12px;
}
.fix-title{
  font-size:11px;font-weight:700;text-transform:uppercase;
  letter-spacing:.08em;color:var(--muted);margin-bottom:8px;
}
pre.fix-before,pre.fix-after{
  margin:0 0 6px;
  padding:8px 10px;
  border-radius:6px;
  font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace;
  font-size:12.5px;line-height:1.5;
  white-space:pre-wrap;word-break:break-word;
}
pre.fix-before{
  background:rgba(220,38,38,.08);
  color:var(--fg);
  border-left:3px solid var(--crit);
}
pre.fix-after{
  background:rgba(8,145,178,.10);
  color:var(--fg);
  border-left:3px solid var(--info);
  margin-bottom:0;
}
pre.fix-before .ln,pre.fix-after .ln{
  color:var(--muted);
  font-weight:700;
  user-select:none;
}
.fix-after-wrap{
  position:relative;
  padding-top:30px;
}
.copy-btn{
  position:absolute;
  top:0;right:0;
  display:inline-flex;align-items:center;gap:5px;
  padding:4px 10px;
  font-size:11px;font-weight:600;
  border:1px solid var(--border);
  background:var(--card);
  color:var(--fg);
  border-radius:6px;
  cursor:pointer;
  opacity:.95;
  transition:opacity .15s,transform .15s,background .15s;
}
.copy-btn:hover{opacity:1;transform:translateY(-1px)}
.copy-btn:active{transform:translateY(0)}
.copy-btn.copied{
  background:var(--info);color:#fff;border-color:var(--info);
}
.copy-btn .copy-icon{font-size:13px;line-height:1}
@media (max-width:600px){
  .fix-after-wrap{padding-top:28px}
  .copy-btn{padding:5px 9px;font-size:11px}
}
.empty{
  text-align:center;padding:60px 20px;color:var(--muted);
  background:var(--card);border:1px dashed var(--border);border-radius:12px;
}
.empty .icon{font-size:48px;margin-bottom:12px;display:block}
footer{
  margin-top:40px;text-align:center;color:var(--muted);font-size:12px;
  padding-top:20px;border-top:1px solid var(--border);
}
@media (max-width:600px){
  body{padding:20px 14px 40px}
  h1{font-size:22px}
  .stat .value{font-size:22px}
}
"""

_HTML_JS = r"""
(function(){
  var root = document.documentElement;
  var btn = document.getElementById('theme');
  var saved = null;
  try { saved = localStorage.getItem('ai-sanitizer-theme'); } catch(e) {}
  if (!saved) {
    saved = (window.matchMedia &&
             window.matchMedia('(prefers-color-scheme: dark)').matches)
      ? 'dark' : 'light';
  }
  root.setAttribute('data-theme', saved);

  function updateLabel() {
    btn.textContent = root.getAttribute('data-theme') === 'dark'
      ? 'Light mode' : 'Dark mode';
  }
  updateLabel();

  btn.addEventListener('click', function() {
    var cur = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    root.setAttribute('data-theme', cur);
    try { localStorage.setItem('ai-sanitizer-theme', cur); } catch(e) {}
    updateLabel();
  });

  function getPlainFix(el) {
    var text = el.innerText || el.textContent || '';
    return text.replace(/^\+ ?/gm, '').trim();
  }

  function fallbackCopy(text) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.top = '-1000px';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); } catch(e) {}
    document.body.removeChild(ta);
  }

  function markCopied(btn) {
    var t = btn.querySelector('.copy-text');
    var old = t ? t.textContent : '';
    btn.classList.add('copied');
    if (t) { t.textContent = 'Copied'; }
    setTimeout(function() {
      btn.classList.remove('copied');
      if (t) { t.textContent = old || 'Copy'; }
    }, 1400);
  }

  document.querySelectorAll('.copy-btn').forEach(function(btn) {
    btn.addEventListener('click', function() {
      var id = btn.getAttribute('data-target');
      var el = document.getElementById(id);
      if (!el) return;
      var text = getPlainFix(el);
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(function() {
          markCopied(btn);
        }).catch(function() {
          fallbackCopy(text); markCopied(btn);
        });
      } else {
        fallbackCopy(text); markCopied(btn);
      }
    });
  });
})();
"""


def report_html(findings: Sequence[Finding],
                files_scanned: int,
                duration_ms: int) -> str:
    esc = _html.escape
    counts = _summary_counts(findings)
    total = len([f for f in findings if f.severity != Severity.INFO])

    def stat(cls: str, label: str, value: int) -> str:
        return (
            f'<div class="stat {cls}">'
            f'<div class="label">{esc(label)}</div>'
            f'<div class="value">{value}</div>'
            f'</div>'
        )

    dashboard = (
        stat("total", "Total", total)
        + stat("crit", "Critical", counts.get("critical", 0))
        + stat("high", "High", counts.get("high", 0))
        + stat("med", "Medium", counts.get("medium", 0))
        + stat("low", "Low", counts.get("low", 0))
        + (stat("info", "Info", counts.get("info", 0))
           if counts.get("info", 0) else "")
    )

    if not findings:
        body = (
            '<div class="empty">'
            '<span class="icon">\u2714</span>'
            '<strong>No findings.</strong><br>'
            'The scanned file(s) look clean according to the active rules.'
            '</div>'
        )
    else:
        # group by severity
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                 Severity.LOW, Severity.INFO]
        labels = {
            Severity.CRITICAL: "Critical",
            Severity.HIGH: "High",
            Severity.MEDIUM: "Medium",
            Severity.LOW: "Low",
            Severity.INFO: "Info",
        }
        sections: list[str] = []
        for sev in order:
            bucket = [f for f in findings if f.severity == sev]
            if not bucket:
                continue
            plural = "finding" if len(bucket) == 1 else "findings"
            sections.append(
                f'<h2 class="section">{esc(labels[sev])} '
                f'&middot; {len(bucket)} {plural}</h2>'
            )
            for f in bucket:
                snippet = (
                    f'<pre class="snippet">{esc(f.snippet)}</pre>'
                    if f.snippet else ""
                )
                rem = (
                    f'<div class="remediation">'
                    f'<strong>Fix:</strong> {esc(f.remediation)}</div>'
                    if f.remediation else ""
                )
                fix_block = ""
                if f.fix_before or f.fix_after:
                    # Unique id for the copy target
                    safe_id = f"fix-{f.id}-{f.line}-{f.column}".replace(
                        ".", "_")
                    parts = ['<div class="fix-example">',
                             '<div class="fix-title">Typical fix</div>']
                    if f.fix_before:
                        parts.append('<pre class="fix-before">')
                        for ln in f.fix_before.split("\n"):
                            parts.append(f'<span class="ln">- </span>'
                                         f'{esc(ln)}')
                        parts.append('</pre>')
                    if f.fix_after:
                        parts.append(
                            '<div class="fix-after-wrap">'
                            '<button type="button" class="copy-btn" '
                            f'data-target="{safe_id}" '
                            'aria-label="Copy fix">'
                            '<span class="copy-icon">&#x2398;</span>'
                            '<span class="copy-text">Copy</span>'
                            '</button>'
                            f'<pre class="fix-after" id="{safe_id}">'
                        )
                        for ln in f.fix_after.split("\n"):
                            parts.append(f'<span class="ln">+ </span>'
                                         f'{esc(ln)}')
                        parts.append('</pre>')
                        parts.append('</div>')
                    parts.append('</div>')
                    fix_block = "".join(parts)
                sections.append(
                    f'<div class="card {f.severity.value}">'
                    f'<div class="card-head">'
                    f'<span class="badge {f.severity.value}">'
                    f'{esc(f.severity.value)}</span>'
                    f'<span class="rule-id">{esc(f.id)}</span>'
                    f'<span class="rule-name">{esc(f.rule_name)}</span>'
                    f'</div>'
                    f'<div class="location">{esc(f.file)}:{f.line}:{f.column}'
                    f'</div>'
                    f'<div class="message">{esc(f.message)}</div>'
                    f'{snippet}'
                    f'{rem}'
                    f'{fix_block}'
                    f'</div>'
                )
        body = "\n".join(sections)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    plural = "file" if files_scanned == 1 else "files"
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
        "<title>CodeFence Report</title>\n"
        f"<style>{_HTML_CSS}</style>\n"
        "</head>\n"
        "<body>\n"
        '<div class="container">\n'
        "<header>\n"
        "<div>\n"
        "<h1>CodeFence Report</h1>\n"
        '<p class="tagline">Pattern-based sanity check '
        "&middot; not a security audit</p>\n"
        f'<p class="meta">Scanned {files_scanned} {plural} '
        f'in {duration_ms} ms &middot; {esc(timestamp)}</p>\n'
        "</div>\n"
        '<button id="theme" class="theme-btn">Toggle theme</button>\n'
        "</header>\n"
        f'<div class="dashboard">{dashboard}</div>\n'
        f"{body}\n"
        "<footer>\n"
        f"Generated by {esc(TOOL_NAME)} v{esc(TOOL_VERSION)} "
        "&middot; Offline &middot; Zero network calls\n"
        "</footer>\n"
        "</div>\n"
        f"<script>{_HTML_JS}</script>\n"
        "</body>\n</html>\n"
    )


# =============================================================================
# [SECTION] CLI
# =============================================================================

BASELINE_DIR = ".codefence"
BASELINE_FILE = "baseline.json"
BASELINE_VERSION = "v1"
CONFIG_FILE = "config.json"

DEFAULT_CONFIG_CONTENT = {
    "schema": "codefence/config-v1",
    "format": "cli",
    "severity": "low",
    "include": ["*.py", "*.js", "*.mjs", "*.cjs"],
    "exclude": ["node_modules", ".git", "venv", ".venv", "__pycache__",
                "dist", "build", ".tox"],
    "max_size": 2097152,
    "cache": False,
}


def _finding_fingerprint(f: Finding) -> str:
    """Stable identity for a finding.

    v3: includes line number and column. Two findings with the same
    rule but on different lines are now distinct, which prevents
    baseline collision when a file contains the same dangerous
    pattern multiple times.

    Trade-off: if code shifts up or down within a file, existing
    findings may appear as "new" in --diff. This is intentional —
    catching new instances of a dangerous pattern matters more than
    avoiding re-reporting a shifted one. Use `# noqa: RXXX` for
    one-off suppressions.
    """
    h = hashlib.sha256()
    h.update(b"codefence-fp-v3\x00")
    h.update(f.id.encode("utf-8"))
    h.update(b"\x00")
    h.update(f.file.encode("utf-8"))
    h.update(b"\x00")
    h.update(str(f.line).encode("ascii"))
    h.update(b"\x00")
    h.update(str(f.column).encode("ascii"))
    h.update(b"\x00")
    snippet = (f.snippet or "").strip().lower()
    h.update(snippet.encode("utf-8"))
    return h.hexdigest()


def _baseline_path(git_root: Path | None = None) -> Path:
    root = git_root or _find_git_root() or Path.cwd()
    return root / BASELINE_DIR / BASELINE_FILE


def _load_baseline(path: Path) -> set[str] | None:
    """Return set of fingerprints, or None if missing/invalid."""
    try:
        if not path.is_file():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return None
        if data.get("version") != BASELINE_VERSION:
            return None
        items = data.get("findings", [])
        if not isinstance(items, list):
            return None
        out: set[str] = set()
        for item in items:
            fp = item.get("fingerprint") if isinstance(item, dict) else None
            if isinstance(fp, str):
                out.add(fp)
        return out
    except (OSError, ValueError, json.JSONDecodeError):
        return None


def _save_baseline(path: Path, findings: Sequence[Finding]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    items = []
    seen: set[str] = set()
    for f in findings:
        fp = _finding_fingerprint(f)
        if fp in seen:
            continue
        seen.add(fp)
        items.append({
            "fingerprint": fp,
            "rule": f.id,
            "file": f.file,
            "line": f.line,
        })
    payload = {
        "version": BASELINE_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "tool_version": TOOL_VERSION,
        "findings": items,
    }
    text = json.dumps(payload, indent=2, ensure_ascii=False)
    fd, tmp_path = tempfile.mkstemp(prefix=".tmp-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fp:
            fp.write(text)
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _filter_new_findings(findings: Sequence[Finding],
                         baseline: set[str]) -> list[Finding]:
    return [f for f in findings if _finding_fingerprint(f) not in baseline]


HISTORY_DIR = "codefence"
HISTORY_FILE = "history.db"
HISTORY_VERSION = 1


def _history_path() -> Path:
    base = os.environ.get("XDG_DATA_HOME")
    if base:
        root = Path(base) / HISTORY_DIR
    else:
        root = Path.home() / ".local" / "share" / HISTORY_DIR
    return root / HISTORY_FILE


def _history_disabled() -> bool:
    val = os.environ.get("CODEFENCE_NO_HISTORY", "").strip().lower()
    return val in ("1", "true", "yes", "on")


def _open_history_db() -> sqlite3.Connection | None:
    try:
        path = _history_path()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(path.parent, 0o700)
        except OSError:
            pass
        conn = sqlite3.connect(str(path))
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        _ensure_schema(conn)
        return conn
    except (sqlite3.Error, OSError):
        return None


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            scan_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            tool_version TEXT NOT NULL,
            files_scanned INTEGER NOT NULL,
            duration_ms INTEGER NOT NULL,
            findings_count INTEGER NOT NULL,
            critical_count INTEGER NOT NULL,
            high_count INTEGER NOT NULL,
            medium_count INTEGER NOT NULL,
            low_count INTEGER NOT NULL,
            rules_hash TEXT NOT NULL,
            policy_hash TEXT NOT NULL,
            baseline_hash TEXT NOT NULL,
            commit_sha TEXT NOT NULL,
            result_hash TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            file TEXT NOT NULL,
            line INTEGER NOT NULL,
            column_no INTEGER NOT NULL,
            severity TEXT NOT NULL,
            action TEXT NOT NULL,
            message TEXT NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_findings_rule "
        "ON findings(rule_id)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_scans_ts "
        "ON scans(timestamp)"
    )
    conn.execute(
        "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
        ("schema_version", str(HISTORY_VERSION)),
    )
    conn.commit()


def _record_scan(evidence: dict,
                 findings: Sequence[Finding]) -> None:
    if _history_disabled():
        return
    conn = _open_history_db()
    if conn is None:
        return
    try:
        sev = evidence.get("by_severity", {}) or {}
        conn.execute(
            """INSERT OR REPLACE INTO scans(
                scan_id, timestamp, tool_version, files_scanned,
                duration_ms, findings_count,
                critical_count, high_count, medium_count, low_count,
                rules_hash, policy_hash, baseline_hash,
                commit_sha, result_hash
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                evidence["scan_id"],
                evidence["timestamp"],
                evidence["tool_version"],
                evidence["files_scanned"],
                evidence["duration_ms"],
                evidence["findings_count"],
                int(sev.get("critical", 0)),
                int(sev.get("high", 0)),
                int(sev.get("medium", 0)),
                int(sev.get("low", 0)),
                evidence["rules_hash"],
                evidence["policy_hash"],
                evidence["baseline_hash"],
                evidence["commit_sha"],
                evidence["result_hash"],
            ),
        )
        for f in findings:
            conn.execute(
                """INSERT INTO findings(
                    scan_id, rule_id, file, line, column_no,
                    severity, action, message
                ) VALUES (?,?,?,?,?,?,?,?)""",
                (
                    evidence["scan_id"],
                    f.id,
                    f.file,
                    f.line,
                    f.column,
                    f.severity.value,
                    getattr(f, "action", "block"),
                    f.message,
                ),
            )
        conn.commit()
    except (sqlite3.Error, OSError, KeyError, TypeError):
        pass
    finally:
        try:
            conn.close()
        except sqlite3.Error:
            pass


def _hash_file(path: Path) -> str:
    try:
        data = path.read_bytes()
    except OSError:
        return ""
    return hashlib.sha256(data).hexdigest()


def _hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _compute_result_hash(findings: Sequence[Finding]) -> str:
    """Deterministic hash of the finding set, order-independent."""
    items = []
    for f in findings:
        items.append({
            "id": f.id,
            "file": f.file,
            "line": f.line,
            "column": f.column,
            "severity": f.severity.value,
            "action": getattr(f, "action", "block"),
            "snippet": f.snippet,
            "message": f.message,
        })
    items.sort(key=lambda x: (
        x["id"], x["file"], x["line"], x["column"], x["message"],
    ))
    canonical = json.dumps(items, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _git_commit_sha() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True, text=True, check=False,
        )
    except (FileNotFoundError, OSError):
        return ""
    if result.returncode != 0:
        return ""
    return result.stdout.strip()


def _build_evidence(findings: Sequence[Finding],
                    files_scanned: int,
                    duration_ms: int,
                    rules_path: Path,
                    policy_path: Path | None,
                    baseline_path: Path | None) -> dict:
    rules_hash = _hash_file(rules_path)
    policy_hash = _hash_file(policy_path) if policy_path else ""
    baseline_hash = _hash_file(baseline_path) if baseline_path else ""
    result_hash = _compute_result_hash(findings)
    commit_sha = _git_commit_sha()
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    return {
        "tool": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "scan_id": result_hash[:16],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "files_scanned": files_scanned,
        "duration_ms": duration_ms,
        "rules_hash": rules_hash,
        "policy_hash": policy_hash,
        "baseline_hash": baseline_hash,
        "commit_sha": commit_sha,
        "result_hash": result_hash,
        "findings_count": len(findings),
        "by_severity": counts,
    }


POLICY_SCHEMA = "codefence/policy-v1"


def _load_policy(path: Path) -> dict:
    """Load and validate a policy file. Raises ValueError on error."""
    if not path.is_file():
        raise ValueError(f"policy file not found: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("policy file must contain a JSON object")
    schema = data.get("schema")
    if schema != POLICY_SCHEMA:
        raise ValueError(
            f"unsupported policy schema: {schema!r} (expected {POLICY_SCHEMA!r})"
        )
    overrides = data.get("overrides", {})
    if not isinstance(overrides, dict):
        raise ValueError("policy 'overrides' must be an object")
    for rid, act in overrides.items():
        if not isinstance(rid, str):
            raise ValueError("override keys must be rule IDs (strings)")
        _validate_action(act, rid)
    extra = data.get("rules", [])
    if not isinstance(extra, list):
        raise ValueError("policy 'rules' must be a list")
    for i, entry in enumerate(extra):
        if not isinstance(entry, dict):
            raise ValueError(f"policy rule {i}: must be an object")
        rid = entry.get("id", "")
        if not isinstance(rid, str) or not rid.startswith("ORG-"):
            raise ValueError(
                f"policy rule {i}: id must start with 'ORG-', got {rid!r}"
            )
        det = entry.get("detection")
        if det not in ("regex", "ast", "lexical"):
            raise ValueError(
                f"policy rule {rid}: detection must be regex/ast/lexical"
            )
        if det == "regex":
            pats = entry.get("patterns", [])
            if not isinstance(pats, list) or not pats:
                raise ValueError(
                    f"policy rule {rid}: regex rules need a 'patterns' list"
                )
            for pat in pats:
                if not isinstance(pat, str):
                    raise ValueError(
                        f"policy rule {rid}: patterns must be strings"
                    )
                if len(pat) > MAX_REGEX_PATTERN_LEN:
                    raise ValueError(
                        f"policy rule {rid}: pattern too long "
                        f"({len(pat)} > {MAX_REGEX_PATTERN_LEN})"
                    )
                try:
                    re.compile(pat)
                except re.error as e:
                    raise ValueError(
                        f"policy rule {rid}: invalid regex: {e}"
                    )
    return data


def _apply_policy(rules: list[Rule], policy: dict) -> list[Rule]:
    """Return a new list of rules with policy overrides + extra rules."""
    overrides = policy.get("overrides", {}) or {}
    extra_entries = policy.get("rules", []) or []

    # Apply overrides to existing rules (action only)
    new_rules: list[Rule] = []
    for r in rules:
        new_action = overrides.get(r.id)
        if new_action and new_action != r.action:
            new_rules.append(Rule(
                id=r.id, name=r.name, languages=r.languages,
                severity=r.severity, category=r.category,
                description=r.description, detection=r.detection,
                message=r.message, remediation=r.remediation,
                references=r.references, confidence=r.confidence,
                enabled=r.enabled, patterns=r.patterns, handler=r.handler,
                fix_before=r.fix_before, fix_after=r.fix_after,
                action=new_action,
                rule_version=r.rule_version,
                fingerprint=r.fingerprint,
            ))
        else:
            new_rules.append(r)

    # Append extra rules
    for entry in extra_entries:
        new_rules.append(_build_rule(entry))

    return new_rules


_VALUE_FLAGS = {
    "--rules", "--policy", "--format", "--output", "--severity",
    "--max-size", "--include", "--exclude", "--config", "--evidence",
}


def _find_subcommand(argv: list[str]) -> tuple[int, str] | tuple[None, None]:
    """Find the first non-flag arg that matches a subcommand name,
    allowing flags (with values) to appear before it.
    Stops scanning as soon as a non-subcommand positional is seen."""
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in _VALUE_FLAGS:
            i += 2
            continue
        if a.startswith("--") and "=" in a:
            i += 1
            continue
        if a.startswith("-") and a != "-":
            i += 1
            continue
        # First non-flag positional
        if a in SUBCOMMANDS:
            return i, a
        return None, None
    return None, None


def _cmd_explain(argv: list[str]) -> int:
    """Print a structured explanation of a single rule."""
    if not argv:
        print("usage: codefence explain RXXX [--rules FILE]",
              file=sys.stderr)
        return EXIT_USAGE

    # Parse minimal: first positional = rule id, optional --rules FILE
    rid = None
    rules_path_arg = None
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--rules" and i + 1 < len(argv):
            rules_path_arg = argv[i + 1]
            i += 2
            continue
        if a.startswith("--rules="):
            rules_path_arg = a.split("=", 1)[1]
            i += 1
            continue
        if rid is None and not a.startswith("-"):
            rid = a
        i += 1

    if not rid:
        print("usage: codefence explain RXXX [--rules FILE]",
              file=sys.stderr)
        return EXIT_USAGE

    rules_path = Path(rules_path_arg) if rules_path_arg else _default_rules_path()
    if not rules_path.is_file():
        print(f"error: rules file not found: {rules_path}", file=sys.stderr)
        return EXIT_USAGE
    try:
        rules = load_rules(rules_path)
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print(f"error: failed to load rules: {e}", file=sys.stderr)
        return EXIT_INTERNAL

    rule = next((r for r in rules if r.id == rid), None)
    if rule is None:
        print(f"error: rule not found: {rid}", file=sys.stderr)
        return EXIT_USAGE

    W = 66
    out = []
    out.append("=" * W)
    out.append(f"RULE:        {rule.id} - {rule.name}")
    out.append(f"VERSION:     {rule.rule_version}")
    out.append(f"SEVERITY:    {rule.severity.value}")
    out.append(f"CATEGORY:    {rule.category}")
    out.append(f"CONFIDENCE:  {rule.confidence.value}")
    out.append(f"ACTION:      {rule.action}")
    out.append(f"LANGUAGES:   {', '.join(l.value for l in rule.languages)}")
    out.append(f"DETECTION:   {rule.detection.value}")
    out.append("=" * W)
    out.append("")
    if rule.description:
        out.append("DESCRIPTION")
        for line in _wrap(rule.description, W):
            out.append(f"  {line}")
        out.append("")
    if rule.message:
        out.append("MESSAGE")
        for line in _wrap(rule.message, W):
            out.append(f"  {line}")
        out.append("")
    if rule.fix_before or rule.fix_after:
        out.append("TYPICAL FIX")
        if rule.fix_before:
            out.append("  Bad:")
            for ln in rule.fix_before.split("\n"):
                out.append(f"    {ln}")
        if rule.fix_after:
            out.append("  Good:")
            for ln in rule.fix_after.split("\n"):
                out.append(f"    {ln}")
        out.append("")
    if rule.remediation:
        out.append("REMEDIATION")
        for line in _wrap(rule.remediation, W):
            out.append(f"  {line}")
        out.append("")
    if rule.references:
        out.append("REFERENCES")
        for ref in rule.references:
            out.append(f"  {ref}")
        out.append("")
    out.append("-" * W)
    out.append("To get a deeper explanation, paste this output into any AI chat.")
    out.append("-" * W)
    print("\n".join(out))
    return EXIT_OK


def _wrap(text: str, width: int) -> list[str]:
    """Simple word wrap without external dependencies."""
    words = text.split()
    lines: list[str] = []
    cur = ""
    for w in words:
        if not cur:
            cur = w
        elif len(cur) + 1 + len(w) <= width - 2:
            cur += " " + w
        else:
            lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    return lines or [""]


def _cmd_history(argv: list[str]) -> int:
    """Show recent scans from the local history database."""
    limit = 10
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--limit" and i + 1 < len(argv):
            try:
                limit = max(1, int(argv[i + 1]))
            except ValueError:
                print("error: --limit must be an integer", file=sys.stderr)
                return EXIT_USAGE
            i += 2
            continue
        if a.startswith("--limit="):
            try:
                limit = max(1, int(a.split("=", 1)[1]))
            except ValueError:
                print("error: --limit must be an integer", file=sys.stderr)
                return EXIT_USAGE
            i += 1
            continue
        i += 1

    conn = _open_history_db()
    if conn is None:
        print("error: could not open history database", file=sys.stderr)
        return EXIT_INTERNAL
    try:
        rows = conn.execute(
            """SELECT scan_id, timestamp, files_scanned, findings_count,
                      critical_count, high_count, medium_count, low_count,
                      commit_sha
               FROM scans
               ORDER BY timestamp DESC
               LIMIT ?""",
            (limit,),
        ).fetchall()
    except sqlite3.Error as e:
        conn.close()
        print(f"error: query failed: {e}", file=sys.stderr)
        return EXIT_INTERNAL
    conn.close()

    if not rows:
        print("No scans recorded. Run with --history to record.")
        return EXIT_OK

    W = 78
    print("=" * W)
    print(f"HISTORY - last {len(rows)} scan(s)")
    print(f"DB: {_history_path()}")
    print("=" * W)
    print(f"{'timestamp':<22s} {'scan_id':<10s} {'files':>5s} "
          f"{'find':>5s}  {'sev (C/H/M/L)':<20s} commit")
    print("-" * W)
    for r in rows:
        (sid, ts, files, fnd, c, h, m, l, csha) = r
        ts_short = ts[:19].replace("T", " ")
        sev = f"{c}/{h}/{m}/{l}"
        csha_short = (csha[:7] if csha else "-")
        print(f"{ts_short:<22s} {sid[:8]:<10s} {files:>5d} "
              f"{fnd:>5d}  {sev:<20s} {csha_short}")
    print("=" * W)
    return EXIT_OK


def _cmd_stats(argv: list[str]) -> int:
    """Print summary statistics across all recorded scans."""
    conn = _open_history_db()
    if conn is None:
        print("error: could not open history database", file=sys.stderr)
        return EXIT_INTERNAL
    try:
        total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        if total == 0:
            conn.close()
            print("No scans recorded. Run with --history to record.")
            return EXIT_OK
        first_ts = conn.execute(
            "SELECT MIN(timestamp) FROM scans"
        ).fetchone()[0]
        last_ts = conn.execute(
            "SELECT MAX(timestamp) FROM scans"
        ).fetchone()[0]
        total_findings = conn.execute(
            "SELECT COALESCE(SUM(findings_count), 0) FROM scans"
        ).fetchone()[0]
        top_rules = conn.execute(
            """SELECT rule_id, COUNT(*) AS n
               FROM findings
               GROUP BY rule_id
               ORDER BY n DESC, rule_id ASC
               LIMIT 5"""
        ).fetchall()
        top_sev = conn.execute(
            """SELECT severity, COUNT(*) AS n
               FROM findings
               GROUP BY severity
               ORDER BY n DESC"""
        ).fetchall()
    except sqlite3.Error as e:
        conn.close()
        print(f"error: query failed: {e}", file=sys.stderr)
        return EXIT_INTERNAL
    conn.close()

    W = 66
    print("=" * W)
    print("STATS")
    print(f"DB: {_history_path()}")
    print("=" * W)
    print(f"  Total scans:        {total}")
    print(f"  Total findings:     {total_findings}")
    print(f"  First scan:         {first_ts[:19].replace('T', ' ')}")
    print(f"  Last scan:          {last_ts[:19].replace('T', ' ')}")
    if total > 0:
        print(f"  Avg findings/scan:  {total_findings / total:.1f}")
    print()
    if top_rules:
        print("  Top rules by frequency:")
        for rid, n in top_rules:
            print(f"    {rid:<10s} {n}")
        print()
    if top_sev:
        print("  Severity distribution:")
        for sev, n in top_sev:
            print(f"    {sev:<10s} {n}")
    print("=" * W)
    return EXIT_OK


GITHUB_ACTION_PATH = ".github/workflows/codefence.yml"
GITHUB_ACTION_MARKER = "# Installed by: codefence init-github"

GITHUB_ACTION_CONTENT = """# Installed by: codefence init-github
# Uninstall: delete this file.
name: CodeFence

on:
  push:
    branches: [ "**" ]
  pull_request:
    branches: [ "**" ]

permissions:
  contents: read
  security-events: write

jobs:
  codefence:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Obtain CodeFence
        run: |
          set -e
          if pip install --quiet codefence 2>/dev/null; then
            echo "installed from PyPI"
            cp "$(python3 -c 'import codefence, os; print(os.path.dirname(codefence.__file__))')/codefence.py" ./codefence.py 2>/dev/null || true
          fi
          if [ ! -f codefence.py ]; then
            echo "falling back to standalone download"
            curl -fsSL -o codefence.py "https://raw.githubusercontent.com/OWNER/codefence/main/codefence.py"
            curl -fsSL -o rules.json  "https://raw.githubusercontent.com/OWNER/codefence/main/rules.json"
          fi

      - name: Run CodeFence
        run: |
          python3 codefence.py \
            --rules rules.json \
            --format sarif \
            --output results.sarif \
            --severity low \
            .
        continue-on-error: true

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
          category: codefence

      - name: Enforce result
        run: |
          python3 codefence.py --rules rules.json --severity medium .
"""


def _cmd_init_github(argv: list[str]) -> int:
    """Install a GitHub Actions workflow that runs CodeFence on every push/PR."""
    git_root = _find_git_root()
    if git_root is None:
        print("error: not in a git repository", file=sys.stderr)
        return EXIT_USAGE

    workflow_path = git_root / GITHUB_ACTION_PATH
    if workflow_path.exists():
        content = workflow_path.read_text(encoding="utf-8", errors="replace")
        if GITHUB_ACTION_MARKER in content:
            print(f"already installed: {workflow_path}")
            return EXIT_OK
        print(f"error: {workflow_path} already exists and was not created "
              f"by CodeFence; refusing to overwrite", file=sys.stderr)
        return EXIT_USAGE

    workflow_path.parent.mkdir(parents=True, exist_ok=True)
    workflow_path.write_text(GITHUB_ACTION_CONTENT, encoding="utf-8")
    print(f"installed: {workflow_path}")
    print()
    print("Next steps:")
    print("  1. Edit the workflow to replace OWNER with your GitHub username")
    print("     if you are not publishing to PyPI.")
    print("  2. Commit the file. CodeFence will run on the next push/PR.")
    return EXIT_OK


def _cmd_init(argv: list[str]) -> int:
    """One-command project setup: config + hook (optional: github, baseline)."""
    with_github = "--with-github" in argv
    with_baseline = "--with-baseline" in argv

    git_root = _find_git_root()
    if git_root is None:
        print("error: not in a git repository", file=sys.stderr)
        print("       run 'git init' first", file=sys.stderr)
        return EXIT_USAGE

    print(f"CodeFence setup in: {git_root}")
    print()

    # 1. Config file
    codefence_dir = git_root / BASELINE_DIR
    config_path = codefence_dir / CONFIG_FILE
    if config_path.exists():
        print(f"[skip] config already exists: {config_path}")
    else:
        codefence_dir.mkdir(parents=True, exist_ok=True)
        config_path.write_text(
            json.dumps(DEFAULT_CONFIG_CONTENT, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"[new]  config: {config_path}")

    # 2. Pre-commit hook
    rc = _cmd_init_hook([])
    if rc != EXIT_OK:
        return rc

    # 3. Optional: GitHub Action
    if with_github:
        rc = _cmd_init_github([])
        if rc != EXIT_OK:
            return rc

    # 4. Optional: baseline
    if with_baseline:
        rc = _cmd_baseline([])
        if rc != EXIT_OK:
            return rc

    print()
    print("Setup complete. Try:")
    print("  codefence --staged         # scan only what is staged")
    print("  codefence --staged --diff  # only NEW findings")
    print("  git commit                 # hook runs automatically")
    return EXIT_OK


def _cmd_policy(argv: list[str]) -> int:
    if not argv or argv[0] != "validate":
        print("usage: codefence policy validate FILE",
              file=sys.stderr)
        return EXIT_USAGE
    if len(argv) < 2:
        print("usage: codefence policy validate FILE",
              file=sys.stderr)
        return EXIT_USAGE
    path = Path(argv[1])
    try:
        data = _load_policy(path)
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_INTERNAL
    n_overrides = len(data.get("overrides", {}) or {})
    n_extra = len(data.get("rules", []) or [])
    print(f"policy valid: {path}")
    print(f"  overrides: {n_overrides}")
    print(f"  extra rules: {n_extra}")
    return EXIT_OK


SUBCOMMANDS = {
    "init-hook", "uninstall-hook", "init", "baseline",
    "check", "explain", "policy", "history", "stats",
    "init-github",
}

HOOK_MARKER = "# CodeFence pre-commit hook"
HOOK_BACKUP_SUFFIX = ".pre-codefence"
HOOK_CONTENT = """#!/bin/sh
# CodeFence pre-commit hook
# Installed by: codefence init-hook
# To uninstall: codefence uninstall-hook

# Environment override (optional):
#   CODEFENCE_CMD   - explicit command or path (e.g. "python3 /path/to/codefence.py")
#   CODEFENCE_RULES - explicit rules.json path

if [ -n "$CODEFENCE_CMD" ]; then
    CF="$CODEFENCE_CMD"
elif command -v cfence >/dev/null 2>&1; then
    CF=cfence
elif command -v codefence >/dev/null 2>&1; then
    CF=codefence
elif [ -f "./codefence.py" ]; then
    CF="python3 ./codefence.py"
elif [ -f "./cfence.py" ]; then
    CF="python3 ./cfence.py"
else
    echo "[codefence] executable not found in PATH or current directory"
    exit 0
fi

if [ -n "$CODEFENCE_RULES" ]; then
    RULES="$CODEFENCE_RULES"
elif [ -f "rules.json" ]; then
    RULES="rules.json"
else
    RULES="$(dirname "$0")/../../rules.json"
fi

$CF --rules "$RULES" --staged
exit $?
"""


def _find_git_root(start: Path | None = None) -> Path | None:
    p = (start or Path.cwd()).resolve()
    while True:
        if (p / ".git").is_dir():
            return p
        if p.parent == p:
            return None
        p = p.parent


def _get_staged_files() -> list[Path] | None:
    """Return list of staged file paths, or None if git unavailable/not a repo."""
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
            capture_output=True, text=True, check=False,
        )
    except (FileNotFoundError, OSError):
        return None
    if result.returncode != 0:
        return None
    return [Path(line.strip()) for line in result.stdout.splitlines()
            if line.strip()]


def _cmd_baseline(argv: list[str]) -> int:
    """Create .codefence/baseline.json from the current scan."""
    git_root = _find_git_root()
    if git_root is None:
        print("error: not in a git repository", file=sys.stderr)
        return EXIT_USAGE
    # Parse minimal argv for --rules / paths / etc, but keep it simple:
    parser = _build_argparser()
    args = parser.parse_args(argv)
    try:
        cfg = _merge_config(args)
    except SystemExit as e:
        print(str(e), file=sys.stderr)
        return EXIT_USAGE

    rules_path = Path(cfg.rules_file) if cfg.rules_file else _default_rules_path()
    if not rules_path.is_file():
        print(f"error: rules file not found: {rules_path}", file=sys.stderr)
        return EXIT_USAGE
    try:
        rules = load_rules(rules_path)
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print(f"error: failed to load rules: {e}", file=sys.stderr)
        return EXIT_INTERNAL

    targets = _collect_paths(args.paths, cfg.include, cfg.exclude)
    if not targets:
        targets = _collect_paths(["."], cfg.include, cfg.exclude)

    findings: list[Finding] = []
    for target in targets:
        findings.extend(scan_file(target, rules, cfg.max_size))
    findings.sort(key=Finding.sort_key)

    baseline_path = _baseline_path(git_root)
    _save_baseline(baseline_path, findings)
    print(f"baseline written: {baseline_path}")
    print(f"  {len(findings)} finding(s) recorded")
    return EXIT_OK


def _cmd_init_hook(argv: list[str]) -> int:
    git_root = _find_git_root()
    if git_root is None:
        print("error: not in a git repository", file=sys.stderr)
        return EXIT_USAGE
    hooks_dir = git_root / ".git" / "hooks"
    hooks_dir.mkdir(exist_ok=True)
    hook_path = hooks_dir / "pre-commit"

    if hook_path.exists():
        content = hook_path.read_text(encoding="utf-8", errors="replace")
        if HOOK_MARKER in content:
            print(f"already installed: {hook_path}")
            return EXIT_OK
        backup = Path(str(hook_path) + HOOK_BACKUP_SUFFIX)
        if not backup.exists():
            backup.write_text(content, encoding="utf-8")
            print(f"backed up existing hook to: {backup}")

    hook_path.write_text(HOOK_CONTENT, encoding="utf-8")
    try:
        os.chmod(hook_path, 0o755)
    except OSError:
        pass
    print(f"installed: {hook_path}")
    return EXIT_OK


def _cmd_uninstall_hook(argv: list[str]) -> int:
    git_root = _find_git_root()
    if git_root is None:
        print("error: not in a git repository", file=sys.stderr)
        return EXIT_USAGE
    hook_path = git_root / ".git" / "hooks" / "pre-commit"
    if not hook_path.exists():
        print("no pre-commit hook found")
        return EXIT_OK
    content = hook_path.read_text(encoding="utf-8", errors="replace")
    if HOOK_MARKER not in content:
        print("pre-commit hook exists but was not installed by CodeFence; "
              "refusing to remove", file=sys.stderr)
        return EXIT_USAGE
    backup = Path(str(hook_path) + HOOK_BACKUP_SUFFIX)
    if backup.exists():
        hook_path.write_text(backup.read_text(encoding="utf-8"),
                             encoding="utf-8")
        backup.unlink()
        print("restored previous pre-commit hook")
    else:
        hook_path.unlink()
        print("removed CodeFence pre-commit hook")
    return EXIT_OK


DEFAULT_EXCLUDES = (
    "node_modules", ".git", "venv", ".venv", "__pycache__",
    "dist", "build", ".tox", ".mypy_cache", ".pytest_cache",
    ".idea", ".vscode", "target", "vendor",
)

DEFAULT_INCLUDES = ("*.py", "*.js", "*.mjs", "*.cjs")


@dataclass(frozen=True, slots=True)
class ScanConfig:
    include: tuple[str, ...] = DEFAULT_INCLUDES
    exclude: tuple[str, ...] = DEFAULT_EXCLUDES
    max_size: int = DEFAULT_MAX_SIZE
    severity: str = "low"
    format: str = "cli"
    cache: bool = False
    rules_file: str | None = None


def _load_config_file(path: Path) -> dict:
    if not path.is_file():
        raise FileNotFoundError(f"config file not found: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("config file must contain a JSON object")
    return data


def _merge_config(args: argparse.Namespace) -> ScanConfig:
    """Priority: CLI args > config file > built-in defaults."""
    file_cfg: dict = {}
    config_source: Path | None = None
    if args.config:
        config_source = Path(args.config)
    else:
        git_root = _find_git_root()
        if git_root is not None:
            auto = git_root / BASELINE_DIR / CONFIG_FILE
            if auto.is_file():
                config_source = auto
    if config_source is not None:
        try:
            file_cfg = _load_config_file(config_source)
        except (OSError, ValueError, json.JSONDecodeError) as e:
            raise SystemExit(f"error: failed to load config: {e}")

    def pick(cli_value, key, default):
        if cli_value is not None:
            return cli_value
        if key in file_cfg:
            return file_cfg[key]
        return default

    include = pick(args.include, "include", DEFAULT_INCLUDES)
    exclude = pick(args.exclude, "exclude", DEFAULT_EXCLUDES)
    max_size = pick(args.max_size, "max_size", DEFAULT_MAX_SIZE)
    severity = pick(args.severity_cli, "severity", "low")
    fmt = pick(args.format_cli, "format", "cli")
    cache = pick(args.cache, "cache", False)
    rules_file = pick(args.rules, "rules", None)

    if isinstance(include, str):
        include = (include,)
    if isinstance(exclude, str):
        exclude = (exclude,)

    return ScanConfig(
        include=tuple(include),
        exclude=tuple(exclude),
        max_size=int(max_size),
        severity=str(severity),
        format=str(fmt),
        cache=bool(cache),
        rules_file=rules_file if rules_file else None,
    )


def _is_excluded(path: Path, excludes: Sequence[str]) -> bool:
    parts = set(path.parts)
    for ex in excludes:
        if ex in parts:
            return True
    return False


def _matches_include(path: Path, includes: Sequence[str]) -> bool:
    name = path.name
    for pat in includes:
        # simple glob: "*.py", "*.js", or exact
        if pat.startswith("*.") and name.endswith(pat[1:]):
            return True
        if pat == name:
            return True
    return False


def _build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Offline AI code sanity check (pattern-based).",
        add_help=False,
    )
    p.add_argument("-h", "--help", action="store_true", dest="show_help",
                   help="Show full help and exit.")
    p.add_argument("paths", nargs="*",
                   help="Files or directories to scan.")
    p.add_argument("--rules", default=None,
                   help="Path to rules.json.")

    p.add_argument("--max-size", type=int, default=None)
    p.add_argument("--format-cli", dest="format_cli", default=None,
                   choices=["cli", "json", "html", "sarif"])
    p.add_argument("--format", dest="format_cli", default=None,
                   choices=["cli", "json", "html", "sarif"])
    p.add_argument("--output", default=None,
                   help="Write report to file instead of stdout.")
    p.add_argument("--include", action="append", default=None,
                   help="Glob of files to include (repeatable).")
    p.add_argument("--exclude", action="append", default=None,
                   help="Directory or file name to exclude (repeatable).")
    p.add_argument("--config", default=None,
                   help="Path to a JSON config file.")
    p.add_argument("--cache", action="store_true", default=None,
                   help="Enable local cache (off by default).")
    p.add_argument("--staged", action="store_true", default=False,
                   help="Scan only files currently staged in git.")
    p.add_argument("--diff", action="store_true", default=False,
                   help="Report only findings NOT in the baseline.")
    p.add_argument("--no-baseline", action="store_true", default=False,
                   help="Ignore the baseline even if --diff is set.")
    p.add_argument("--policy", default=None,
                   help="Path to a policy JSON file.")
    p.add_argument("--evidence", default=None,
                   help="Write a deterministic evidence JSON file.")
    p.add_argument("--history", action="store_true", default=False,
                   help="Record this scan in the local history DB.")
    p.add_argument("--no-color", action="store_true",
                   help="Disable ANSI colors.")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="Only print summary.")
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    p.add_argument("--severity", dest="severity_cli", default=None,
                   choices=["critical", "high", "medium", "low", "info"])
    return p


def _default_rules_path() -> Path:
    return Path(__file__).resolve().parent / DEFAULT_RULES_FILENAME


def _collect_paths(paths: Sequence[str],
                   includes: Sequence[str] = DEFAULT_INCLUDES,
                   excludes: Sequence[str] = DEFAULT_EXCLUDES) -> list[Path]:
    out: list[Path] = []
    seen: set[str] = set()
    for raw in paths:
        p = Path(raw)
        if p.is_file():
            if _matches_include(p, includes):
                key = str(p)
                if key not in seen:
                    seen.add(key)
                    out.append(p)
            continue
        if not p.is_dir():
            continue
        for child in p.rglob("*"):
            if not child.is_file():
                continue
            if _is_excluded(child, excludes):
                continue
            if not _matches_include(child, includes):
                continue
            key = str(child)
            if key in seen:
                continue
            seen.add(key)
            out.append(child)
    return sorted(out)


def _print_welcome() -> None:
    use_color = _color_enabled(False)

    def c(text: str, sev: Severity = Severity.INFO) -> str:
        return _c(text, sev, use_color)

    W = 64
    out: list[str] = []
    out.append(_box_top(W))
    out.append(_box_row("", W))
    out.append(_box_row(
        f"   {c('CodeFence')}  {c(chr(0x00b7), Severity.LOW)}  "
        f"v{TOOL_VERSION}", W))
    out.append(_box_row("   Offline AI code sanity check", W))
    out.append(_box_row("", W))
    out.append(_box_bot(W))
    out.append("")
    out.append("  Pattern-based. Zero network calls. Python + JavaScript.")
    out.append("")
    out.append(f"  {c('QUICK START', Severity.LOW)}")
    out.append(f"    {TOOL_NAME}.py <file-or-directory>")
    out.append("")
    out.append(f"  {c('EXAMPLES', Severity.LOW)}")
    out.append(f"    {TOOL_NAME}.py src/")
    out.append(f"    {TOOL_NAME}.py --format json app.py")
    out.append(f"    {TOOL_NAME}.py --format html "
               f"--output report.html src/")
    out.append(f"    {TOOL_NAME}.py --severity high .")
    out.append("")
    out.append(f"  {c('COMMON OPTIONS', Severity.LOW)}")
    out.append("    --format {cli,json,html,sarif}   "
               "Output format (default: cli)")
    out.append("    --output FILE                    "
               "Write report to file")
    out.append("    --severity LEVEL                 "
               "Minimum severity (default: low)")
    out.append("    --include GLOB                   "
               "Files to include (repeatable)")
    out.append("    --exclude NAME                   "
               "Directory/file to skip (repeatable)")
    out.append("    -q, --quiet                      Summary only")
    out.append("")
    out.append(f"  Full help:  {TOOL_NAME}.py --help")
    out.append("")
    print("\n".join(out))


def _print_help() -> None:
    use_color = _color_enabled(False)

    def h(text: str) -> str:
        return _c(text, Severity.INFO, use_color)

    def s(text: str) -> str:
        return _c(text, Severity.LOW, use_color)

    blocks: list[str] = []
    blocks.append(f"{h('CodeFence')}  "
                  f"{s(chr(0x00b7))}  v{TOOL_VERSION}")
    blocks.append("Offline AI code sanity check. Pattern-based, "
                  "not a security audit.")
    blocks.append("")
    blocks.append(h("USAGE"))
    blocks.append(f"    cfence [OPTIONS] PATH...")
    blocks.append(f"    {TOOL_NAME}.py [OPTIONS] PATH...   (source checkout)")
    blocks.append("")
    blocks.append(h("DESCRIPTION"))
    blocks.append(
        "    Scans AI-generated Python and JavaScript source files for")
    blocks.append(
        "    selected dangerous patterns (hardcoded secrets, injection,")
    blocks.append(
        "    weak cryptography, unsafe config) before you commit.")
    blocks.append(
        "    Fully offline. Zero network calls. Zero telemetry.")
    blocks.append("")
    blocks.append(h("OUTPUT FORMATS"))
    blocks.append("    cli     Colored terminal report (default)")
    blocks.append("    json    Machine-readable JSON for automation")
    blocks.append("    html    Self-contained HTML report "
                  "(dark/light theme)")
    blocks.append("    sarif   SARIF 2.1.0 for GitHub Code Scanning")
    blocks.append("")
    blocks.append(h("OPTIONS"))
    options = [
        ("--format FORMAT",
         "Output format: cli, json, html, sarif (default: cli)"),
        ("--output FILE",
         "Write report to file instead of stdout"),
        ("--severity LEVEL",
         "Minimum severity to report: critical, high, medium, low, "
         "info (default: low)"),
        ("--include GLOB",
         "Glob of files to include (repeatable). "
         "Default: *.py *.js *.mjs *.cjs"),
        ("--exclude NAME",
         "Directory or file name to skip (repeatable). "
         "Default: node_modules, .git, venv, __pycache__, ..."),
        ("--config FILE",
         "Load options from a JSON config file"),
        ("--max-size BYTES",
         f"Skip files larger than N bytes (default: {DEFAULT_MAX_SIZE})"),
        ("--rules FILE",
         "Path to rules.json (default: sibling of this script)"),
        ("--cache",
         "Enable local cache (off by default)"),
        ("--no-color", "Disable ANSI colors"),
        ("-q, --quiet", "Print only the summary"),
        ("-h, --help", "Show this help and exit"),
        ("--version", "Print version and exit"),
    ]
    for flag, desc in options:
        blocks.append(f"    {flag:<24s} {desc}")
    blocks.append("")
    blocks.append(h("EXAMPLES"))
    examples = [
        f"{TOOL_NAME}.py app.py",
        f"{TOOL_NAME}.py src/",
        f"{TOOL_NAME}.py --format json --output report.json src/",
        f"{TOOL_NAME}.py --format sarif -o results.sarif .",
        f"{TOOL_NAME}.py --severity high --exclude tests .",
        f"{TOOL_NAME}.py --config sanitizer.json .",
    ]
    for ex in examples:
        blocks.append(f"    #")
        blocks.append(f"    {ex}")
    blocks.append("")
    blocks.append(h("EXIT CODES"))
    blocks.append("    0    No findings "
                  "(or all below the severity threshold)")
    blocks.append("    1    At least one finding at or above "
                  "the threshold")
    blocks.append("    2    Usage error (invalid arguments)")
    blocks.append("    3    Internal error")
    blocks.append("")
    blocks.append(h("USING IN CI/CD AND AGENT PIPELINES"))
    blocks.append("    - JSON and SARIF are pure on stdout "
                  "(no banner, no ANSI).")
    blocks.append("    - Exit codes are stable and documented above.")
    blocks.append("    - Safe for headless use: no stdin, no prompts.")
    blocks.append("    - Never performs network calls.")
    blocks.append("")
    print("\n".join(blocks))


def main(argv: Sequence[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    # No arguments at all → friendly welcome screen.
    if not argv:
        _print_welcome()
        return EXIT_OK

    # Subcommand dispatch (allows flags before subcommand)
    sub_idx, sub = _find_subcommand(argv)
    if sub is not None:
        rest = argv[:sub_idx] + argv[sub_idx + 1:]
        if sub == "init-hook":
            return _cmd_init_hook(rest)
        if sub == "uninstall-hook":
            return _cmd_uninstall_hook(rest)
        if sub == "baseline":
            return _cmd_baseline(rest)
        if sub == "policy":
            return _cmd_policy(rest)
        if sub == "explain":
            return _cmd_explain(rest)
        if sub == "history":
            return _cmd_history(rest)
        if sub == "stats":
            return _cmd_stats(rest)
        if sub == "init-github":
            return _cmd_init_github(rest)
        if sub == "init":
            return _cmd_init(rest)
        print(f"error: subcommand '{sub}' not implemented yet",
              file=sys.stderr)
        return EXIT_USAGE

    parser = _build_argparser()
    args = parser.parse_args(argv)

    if getattr(args, "show_help", False):
        _print_help()
        return EXIT_OK

    try:
        cfg = _merge_config(args)
    except SystemExit as e:
        print(str(e), file=sys.stderr)
        return EXIT_USAGE

    rules_path = Path(cfg.rules_file) if cfg.rules_file else _default_rules_path()
    if not rules_path.is_file():
        print(f"error: rules file not found: {rules_path}", file=sys.stderr)
        return EXIT_USAGE
    try:
        rules = load_rules(rules_path)
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print(f"error: failed to load rules: {e}", file=sys.stderr)
        return EXIT_INTERNAL

    # Apply --policy if provided
    if getattr(args, "policy", None):
        try:
            policy = _load_policy(Path(args.policy))
            rules = _apply_policy(rules, policy)
        except (OSError, ValueError, json.JSONDecodeError) as e:
            print(f"error: failed to load policy: {e}", file=sys.stderr)
            return EXIT_INTERNAL

    # If --staged, override targets with staged files from git
    if getattr(args, "staged", False):
        staged = _get_staged_files()
        if staged is None:
            print("error: --staged requires a git repository with git "
                  "installed", file=sys.stderr)
            return EXIT_USAGE
        if not staged:
            # No staged files: exit clean, print short message
            if cfg.format == "cli":
                print("No staged files.")
            return EXIT_OK
        # Warn if the policy or config file is itself being staged
        # in this commit — that allows a PR to weaken its own gate.
        staged_set = {str(t) for t in staged}
        watch_paths = []
        if getattr(args, "policy", None):
            watch_paths.append(Path(args.policy))
        git_root = _find_git_root()
        if git_root is not None:
            watch_paths.append(git_root / BASELINE_DIR / "policy.json")
            watch_paths.append(git_root / BASELINE_DIR / CONFIG_FILE)
        # Deduplicate watch paths (resolve to absolute)
        seen_wp: set[str] = set()
        unique_wp = []
        for wp in watch_paths:
            try:
                resolved = str(wp.resolve())
            except OSError:
                resolved = str(wp)
            if resolved in seen_wp:
                continue
            seen_wp.add(resolved)
            unique_wp.append(wp)
        for wp in unique_wp:
            try:
                rel = wp.relative_to(git_root) if git_root else wp
            except ValueError:
                rel = wp
            if str(rel) in staged_set or str(wp) in staged_set:
                print(
                    f"[codefence] warning: {rel} is staged in this "
                    f"commit. If this is a pull request, the change may "
                    f"weaken or bypass the gate. Review carefully before "
                    f"merging.",
                    file=sys.stderr,
                )
        targets = [t for t in staged
                   if _matches_include(t, cfg.include)
                   and not _is_excluded(t, cfg.exclude)]
    else:
        targets = _collect_paths(args.paths, cfg.include, cfg.exclude)
    # Note: empty targets still produces output (empty report),
    # so CI/CD pipelines always get valid JSON/SARIF.

    threshold = severity_rank(Severity(cfg.severity))
    started = time.perf_counter()
    all_findings: list[Finding] = []
    rules_fp = ""
    if cfg.cache:
        rules_fp = _rules_fingerprint(rules_path)
    for target in targets:
        all_findings.extend(scan_file(
            target, rules, cfg.max_size,
            use_cache=cfg.cache, rules_fingerprint=rules_fp,
        ))
    duration_ms = int((time.perf_counter() - started) * 1000)

    all_findings = [f for f in all_findings
                    if f.severity == Severity.INFO
                    or severity_rank(f.severity) <= threshold]
    all_findings.sort(key=Finding.sort_key)

    # --diff: filter to only new findings vs baseline
    if getattr(args, "diff", False) and not getattr(args, "no_baseline", False):
        baseline_path = _baseline_path()
        baseline_set = _load_baseline(baseline_path)
        if baseline_set is None:
            print(f"warning: baseline not found at {baseline_path}; "
                  f"run 'codefence baseline' first", file=sys.stderr)
            # Fall through: show all findings (safe default)
        else:
            before = len(all_findings)
            all_findings = _filter_new_findings(all_findings, baseline_set)
            suppressed = before - len(all_findings)
            if cfg.format == "cli":
                print(f"Baseline: {len(baseline_set)} finding(s) recorded; "
                      f"{suppressed} existing finding(s) suppressed.")
                print()

    # Apply action policy:
    #   allow -> remove finding entirely (not shown, not counted)
    #   warn  -> shown, but does NOT affect exit code
    #   block -> shown AND affects exit code
    allow_suppressed = 0
    if any(getattr(f, "action", "block") != "block" for f in all_findings):
        filtered = []
        for f in all_findings:
            act = getattr(f, "action", "block")
            if act == "allow":
                allow_suppressed += 1
                continue
            filtered.append(f)
        all_findings = filtered
    if allow_suppressed and cfg.format == "cli":
        print(f"Policy: {allow_suppressed} finding(s) suppressed by 'allow' rules.")
        print()

    fmt = cfg.format
    if fmt == "cli":
        use_color = _color_enabled(args.no_color)
        out = report_cli(all_findings, len(targets), duration_ms,
                         use_color, quiet=args.quiet)
    elif fmt == "json":
        out = report_json(all_findings, len(targets), duration_ms)
    elif fmt == "html":
        out = report_html(all_findings, len(targets), duration_ms)
    elif fmt == "sarif":
        out = report_sarif(rules, all_findings)
    else:
        print(f"error: unknown format {fmt!r}", file=sys.stderr)
        return EXIT_USAGE

    if args.output:
        try:
            Path(args.output).write_text(out, encoding="utf-8")
        except OSError as e:
            print(f"error: failed to write output: {e}", file=sys.stderr)
            return EXIT_INTERNAL
    else:
        print(out)

    # --evidence or --history: build evidence struct
    need_evidence = (getattr(args, "evidence", None)
                     or getattr(args, "history", False))
    if need_evidence:
        policy_path = Path(args.policy) if getattr(args, "policy", None) else None
        baseline_path = _baseline_path()
        if not baseline_path.is_file():
            baseline_path = None
        evidence = _build_evidence(
            findings=all_findings,
            files_scanned=len(targets),
            duration_ms=duration_ms,
            rules_path=rules_path,
            policy_path=policy_path,
            baseline_path=baseline_path,
        )
        if getattr(args, "history", False):
            _record_scan(evidence, all_findings)
            if cfg.format == "cli":
                print()
                print(f"History: scan {evidence['scan_id'][:8]} recorded.")
        if getattr(args, "evidence", None):
            try:
                Path(args.evidence).write_text(
                    json.dumps(evidence, indent=2, ensure_ascii=False),
                    encoding="utf-8",
                )
            except OSError as e:
                print(f"error: failed to write evidence: {e}",
                      file=sys.stderr)
                return EXIT_INTERNAL
            if cfg.format == "cli":
                print()
                print(f"Evidence written: {args.evidence}")
                print(f"  scan_id:     {evidence['scan_id']}")
                print(f"  result_hash: {evidence['result_hash'][:32]}...")

    if not all_findings:
        return EXIT_OK
    if any(
        f.severity in (Severity.CRITICAL, Severity.HIGH,
                       Severity.MEDIUM, Severity.LOW)
        and getattr(f, "action", "block") == "block"
        for f in all_findings
    ):
        return EXIT_FINDINGS
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
