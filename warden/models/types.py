"""Column types shared by every model."""
from __future__ import annotations

import enum
from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum
from sqlalchemy.engine import Dialect
from sqlalchemy.types import TypeDecorator


def utcnow() -> datetime:
    """The one place the application asks for the current time: aware UTC."""
    return datetime.now(timezone.utc)


class UtcDateTime(TypeDecorator[datetime]):
    """Timezone-aware UTC on every backend (CLAUDE.md 5, decision D-045).

    SQLite stores datetimes as text without an offset, so a plain
    DateTime(timezone=True) comes back naive. This decorator rejects naive
    values on write, converts every aware value to UTC before it is stored,
    and re-attaches UTC on read.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("naive datetime written to a UtcDateTime column; pass an aware UTC value")
        return value.astimezone(timezone.utc)

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


def enum_column(enum_class: type[enum.Enum], name: str) -> Enum:
    """A VARCHAR column holding the enum's values, with a CHECK constraint.

    native_enum=False keeps the DDL the same on SQLite and PostgreSQL;
    create_constraint=True writes the whitelist into the schema;
    validate_strings=True makes SQLAlchemy reject an unknown string before
    the database sees it; values_callable stores the member values (the
    lowercase strings of spec section 4.1), not the member names.
    """
    return Enum(
        enum_class,
        name=name,
        native_enum=False,
        create_constraint=True,
        validate_strings=True,
        values_callable=lambda cls: [member.value for member in cls],
    )
