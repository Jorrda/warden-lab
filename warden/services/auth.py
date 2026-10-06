"""Sign-in rules (spec 6.1): password check, throttling and the auth audit rows.

Throttling is in memory, as spec section 3 states for the prototype (decision
D-049): LoginThrottle keeps a per-username counter with a lockout window, held
on the application object so each app instance (and each test) has its own.
Five consecutive failures lock the username for ten minutes, whether or not
it matches an account, so a locked-out response never reveals which usernames
exist, and an unknown username is checked against a dummy hash so the response
time does not reveal it either (S4 finding F1). A locked username is refused
before its password is checked. Every failed attempt writes an
auth.login_failed row: against the users row when
the username exists, else against the users table with entity_id null
(D-048). The response text is the same generic message either way.
The service commits: a route calls it and redirects.
"""
from __future__ import annotations

import math
import secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import select
from werkzeug.security import check_password_hash, generate_password_hash

from warden.extensions import db
from warden.models import User
from warden.services import audit
from warden.services.audit import Actor

MAX_FAILURES = 5
LOCKOUT = timedelta(minutes=10)
GENERIC_MESSAGE = "Invalid username or password."
USERNAME_MAX_LENGTH = 64
# Checked when the username matches no account, so both failure branches cost one scrypt
# computation; built once at import time with the same parameters as every stored hash.
DUMMY_HASH = generate_password_hash(secrets.token_urlsafe(16))


@dataclass
class Attempts:
    failures: int = 0
    last_failure_at: datetime | None = None
    locked_until: datetime | None = None


@dataclass
class LoginThrottle:
    """Per-username failure counter with a lockout window, in memory (spec section 3).

    One instance is shared by every request and app.run() serves them threaded, so each
    method holds the lock: without it a prune that iterates the dict can run while another
    request deletes from it. The lock is reentrant because record_failure calls prune.
    """

    max_failures: int = MAX_FAILURES
    window: timedelta = LOCKOUT
    attempts: dict[str, Attempts] = field(default_factory=dict)
    lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def locked_until(self, username: str, now: datetime) -> datetime | None:
        """The lock end when the username is locked at now, else None."""
        with self.lock:
            entry = self.attempts.get(username)
            if entry is None or entry.locked_until is None:
                return None
            if entry.locked_until > now:
                return entry.locked_until
            self.attempts.pop(username, None)
            return None

    def record_failure(self, username: str, now: datetime) -> Attempts:
        """Count one failure; the max_failures-th in a row starts a lock of one window."""
        with self.lock:
            self.prune(now)
            entry = self.attempts.setdefault(username, Attempts())
            entry.failures += 1
            entry.last_failure_at = now
            if entry.failures >= self.max_failures:
                entry.locked_until = now + self.window
                entry.failures = 0
            return entry

    def reset(self, username: str) -> None:
        with self.lock:
            self.attempts.pop(username, None)

    def prune(self, now: datetime) -> None:
        """Forget usernames whose last failure is older than one window and that are not locked; bounds the dict."""
        with self.lock:
            stale = [name for name, entry in list(self.attempts.items()) if (entry.locked_until is None or entry.locked_until <= now) and entry.last_failure_at is not None and now - entry.last_failure_at > self.window]
            for name in stale:
                self.attempts.pop(name, None)


@dataclass(frozen=True)
class LoginResult:
    """user is set on success; message is the flash text on failure."""

    user: User | None
    message: str | None

    @property
    def ok(self) -> bool:
        return self.user is not None


def lockout_message(locked_until: datetime, now: datetime) -> str:
    minutes = max(1, math.ceil((locked_until - now).total_seconds() / 60))
    unit = "minute" if minutes == 1 else "minutes"
    return f"Too many failed attempts. Try again in {minutes} {unit}."


def authenticate(username: str, password: str, *, throttle: LoginThrottle, now: datetime, actor: Actor) -> LoginResult:
    """Check the credentials under the lockout rule, write the audit row, commit."""
    key = username[:USERNAME_MAX_LENGTH]
    user = db.session.execute(select(User).where(User.username == username)).scalar_one_or_none()
    anonymous = Actor(None, actor.ip, actor.user_agent)

    def failed(reason: str, entry: Attempts | None, locked_until: datetime | None) -> LoginResult:
        payload: dict[str, object] = {"reason": reason, "failures": entry.failures if entry else 0, "locked_until": locked_until.isoformat() if locked_until else None}
        if user is None:
            payload["username"] = key
            audit.record("auth.login_failed", entity_type=User.__tablename__, actor=anonymous, after=payload, created_at=now)
        else:
            audit.record("auth.login_failed", user, actor=anonymous, after=payload, created_at=now)
        db.session.commit()
        return LoginResult(None, lockout_message(locked_until, now) if locked_until else GENERIC_MESSAGE)

    locked = throttle.locked_until(key, now)
    if locked is not None:
        return failed("locked", throttle.attempts.get(key), locked)
    password_ok = check_password_hash(user.password_hash if user is not None else DUMMY_HASH, password)
    if user is None or not password_ok:
        entry = throttle.record_failure(key, now)
        return failed("unknown_user" if user is None else "bad_password", entry, entry.locked_until)

    throttle.reset(key)
    user.last_login_at = now
    audit.record("auth.login", user, actor=Actor(user.id, actor.ip, actor.user_agent), after={"username": user.username, "role": user.role.value}, created_at=now)
    db.session.commit()
    return LoginResult(user, None)


def sign_out(user: User, *, now: datetime, actor: Actor) -> None:
    """Write the auth.logout row and commit; the route ends the session afterwards."""
    audit.record("auth.logout", user, actor=actor, after={"username": user.username}, created_at=now)
    db.session.commit()
