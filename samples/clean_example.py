"""Example of clean, safe Python code.

This file shows patterns that CodeFence should NOT flag.
It is included as a reference for safe coding patterns.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from pathlib import Path


API_KEY = os.environ["API_KEY"]
JWT_SECRET = os.environ["JWT_SECRET_KEY"]


def hash_password(password: str, salt: bytes) -> bytes:
    """Use PBKDF2-HMAC-SHA256 for password hashing."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)


def verify_password(password: str, salt: bytes, expected: bytes) -> bool:
    candidate = hash_password(password, salt)
    return hmac.compare_digest(candidate, expected)


def new_session_token() -> str:
    """Use the secrets module for cryptographic tokens."""
    return secrets.token_urlsafe(32)


def read_user_file(base_dir: str, user_path: str) -> str:
    """Safely read a file under a fixed base directory."""
    base = Path(base_dir).resolve()
    target = (base / user_path).resolve()
    if not str(target).startswith(str(base)):
        raise ValueError("path traversal detected")
    return target.read_text(encoding="utf-8")


def safe_divide(a: float, b: float) -> float | None:
    try:
        return a / b
    except ZeroDivisionError:
        return None
