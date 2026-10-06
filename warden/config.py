"""Configuration classes. Read the environment at instantiation time so that
load_dotenv() in app.py has already run."""
from __future__ import annotations

import os
import secrets
import warnings


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be one of 1/true/yes/on or 0/false/no/off, got {raw!r}")


class Config:
    TESTING = False
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    WTF_CSRF_ENABLED = True
    MAX_CONTENT_LENGTH = 1_048_576  # the upload size limit of spec 7: a request over 1 MiB is answered 413
    # The commit form posts the CSV text percent-encoded, up to three bytes per byte of a 256 KiB file (786432),
    # so the non-file form memory limit is raised from Werkzeug's 500 kB default to the request limit (S4 finding O1).
    MAX_FORM_MEMORY_SIZE = 1_048_576
    SCAN_TARGET = "sample_repo"  # the default scan target of spec 6.9, relative to SCAN_BASE

    def __init__(self) -> None:
        self.SECRET_KEY: str = os.environ.get("SECRET_KEY") or self._dev_secret_key()
        # None means "use the SQLite default under the instance folder"; resolved in create_app().
        self.DATABASE_URL: str | None = os.environ.get("DATABASE_URL") or None
        self.SESSION_COOKIE_SECURE: bool = _env_bool("SESSION_COOKIE_SECURE", False)
        # None means the repository root (the folder holding app.py); resolved in create_app(). A scan
        # target must stay inside it (spec 6.9).
        self.SCAN_BASE: str | None = os.environ.get("WARDEN_SCAN_BASE") or None

    @staticmethod
    def _dev_secret_key() -> str:
        warnings.warn(
            "SECRET_KEY is not set. Using a random key; sessions will not survive a restart.",
            RuntimeWarning,
            stacklevel=2,
        )
        return secrets.token_hex(32)


class TestingConfig(Config):
    TESTING = True

    def __init__(self) -> None:
        # Deliberately does not call super().__init__(): tests never read the
        # environment, so they behave the same on every machine and never warn.
        self.SECRET_KEY = "test-only-key-not-a-secret"
        self.DATABASE_URL = "sqlite:///:memory:"
        self.SESSION_COOKIE_SECURE = False
        self.SCAN_BASE = None
