"""Login accounts for Warden itself (spec 4.1 users), 1:1 optional with people.

ON DELETE RESTRICT everywhere a user is referenced, so audit rows keep their
actor. AUDIT_EXCLUDE keeps the password hash and the throttling columns out
of audit payloads (warden/services/audit.py). failed_logins and locked_until
are reserved: v1 throttles in memory (spec section 3, decision D-049), so no
code writes or reads them.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from flask_login import UserMixin
from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from warden.extensions import db
from warden.models.enums import UserRole
from warden.models.types import UtcDateTime, enum_column


class User(UserMixin, db.Model):
    __tablename__ = "users"
    __table_args__ = {"comment": "Warden login accounts: the IT coordinator (admin) and managers (viewer)."}

    AUDIT_EXCLUDE = frozenset({"password_hash", "failed_logins", "locked_until"})

    id: Mapped[int] = mapped_column(primary_key=True)
    person_id: Mapped[int | None] = mapped_column(
        ForeignKey("people.id", ondelete="RESTRICT"), unique=True, comment="The person behind the account; null for a pure admin."
    )
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255), comment="Werkzeug scrypt hash, never the password.")
    role: Mapped[UserRole] = mapped_column(enum_column(UserRole, "user_role"), comment="admin mutates, viewer reads.")
    last_login_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    failed_logins: Mapped[int] = mapped_column(default=0, comment="Reserved; v1 throttles in memory and never writes it (D-049).")
    locked_until: Mapped[datetime | None] = mapped_column(UtcDateTime, comment="Reserved; v1 throttles in memory and never writes it (D-049).")

    person: Mapped[Optional["Person"]] = relationship(back_populates="user")
