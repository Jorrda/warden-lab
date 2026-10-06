"""The one audit helper (CLAUDE.md 2: every state-changing action writes a row).

record() adds an audit_events row to the session without committing, so it
joins the caller's transaction. snapshot() serialises a model row for the
before and after payloads, leaving out the columns the model's AUDIT_EXCLUDE
names (password hashes never reach the audit table). Actor carries who acted
and from where; a route builds it from current_user and request and passes it
into the service, so services never import Flask request objects (CLAUDE.md 5).
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import date, datetime, time, timezone
from enum import Enum
from typing import Any

from sqlalchemy import Select, func, inspect, select
from sqlalchemy.orm import selectinload

from warden.extensions import db
from warden.models.audit import AuditEvent
from warden.models.types import utcnow
from warden.models.user import User

TRAIL_LIMIT = 25
PAGE_SIZE = 100  # S14 rows per page (spec 6.8; spec 10 budgets thousands of rows)
ACTOR_SYSTEM = "system"  # the S14 actor filter value for rows with no actor (seed and CLI)
# Payload keys S14 masks for the viewer role: the username of a failed login for an unknown account is what the
# visitor typed into that field, which may be a password typed one field too high (phase 5 S8b review). The admin,
# who investigates failed logins, sees the value; the viewer sees the mask.
VIEWER_MASKED: dict[str, frozenset[str]] = {"auth.login_failed": frozenset({"username"})}
MASK = "********"


@dataclass(frozen=True)
class Actor:
    """Who performed a mutation and from where. user_id is None for the seed and for unauthenticated auth events."""

    user_id: int | None
    ip: str | None = None
    user_agent: str | None = None


def snapshot(instance: Any) -> dict[str, Any]:
    """Column values of a mapped row as JSON-ready data, minus AUDIT_EXCLUDE."""
    exclude = getattr(type(instance), "AUDIT_EXCLUDE", frozenset())
    mapper = inspect(type(instance))
    return {attr.key: _jsonable(getattr(instance, attr.key)) for attr in mapper.column_attrs if attr.key not in exclude}


def _jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def record(
    action: str,
    entity: Any = None,
    *,
    entity_type: str | None = None,
    actor: Actor | None = None,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
    created_at: datetime | None = None,
) -> AuditEvent:
    """Add one audit row to the current session, for entity (a flushed model row)
    or, when the event concerns no stored row (a failed login for an unknown
    username), for an explicit entity_type with entity_id left null (D-048).

    actor supplies the actor id, address and user agent; None means the system
    or the seed (all three null). created_at defaults to the current time; the
    seed passes its reference time so two runs with the same input produce
    identical rows.
    """
    entity_id: int | None = None
    if entity is not None:
        if not hasattr(entity, "id"):
            raise ValueError(
                f"{type(entity).__name__} has no single-column id; audit it through its parent row "
                "(scope links ride in the NHI's payload, decision D-039)"
            )
        if entity.id is None:
            raise ValueError("flush the session before recording an audit row; the entity has no id yet")
        entity_type, entity_id = entity.__tablename__, entity.id
    elif entity_type is None:
        raise ValueError("record() needs an entity row, or an entity_type for an event about no stored row")
    event = AuditEvent(
        actor_user_id=actor.user_id if actor else None,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        before=before,
        after=after,
        ip=actor.ip if actor else None,
        user_agent=actor.user_agent if actor else None,
        created_at=created_at or utcnow(),
    )
    db.session.add(event)
    return event


def masked_rows(event: AuditEvent, *, viewer: bool) -> list[tuple[str, Any, Any, bool]]:
    """The S14 expansion rows of an event; for the viewer, the values of the keys VIEWER_MASKED names are replaced by MASK."""
    rows = event.diff_rows()
    keys = VIEWER_MASKED.get(event.action) if viewer else None
    if not keys:
        return rows
    return [(key, MASK if key in keys and before is not None else before, MASK if key in keys and after is not None else after, differs) for key, before, after, differs in rows]


def trail(entity: Any, limit: int = TRAIL_LIMIT) -> list[AuditEvent]:
    """The newest audit rows about one entity row, with their actors, for the entity page (CLAUDE.md 5)."""
    statement = (
        select(AuditEvent)
        .where(AuditEvent.entity_type == entity.__tablename__, AuditEvent.entity_id == entity.id)
        .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
        .limit(limit)
        .options(selectinload(AuditEvent.actor))
    )
    return list(db.session.execute(statement).scalars())


@dataclass(frozen=True)
class LogQuery:
    """The S14 filters, parsed by the route: actor is "", "system" or a user id as text."""

    actor: str = ""
    action: str = ""
    entity_type: str = ""
    date_from: date | None = None
    date_to: date | None = None
    page: int = 1


@dataclass(frozen=True)
class LogPage:
    rows: list[AuditEvent]
    total: int
    page: int
    pages: int

    @property
    def first(self) -> int:
        return 0 if not self.rows else (self.page - 1) * PAGE_SIZE + 1

    @property
    def last(self) -> int:
        return 0 if not self.rows else (self.page - 1) * PAGE_SIZE + len(self.rows)


def _day_start(value: date) -> datetime:
    return datetime.combine(value, time.min, tzinfo=timezone.utc)


def _apply_filters(statement: Select, query: LogQuery) -> Select:
    if query.actor == ACTOR_SYSTEM:
        statement = statement.where(AuditEvent.actor_user_id.is_(None))
    elif query.actor.isdecimal():
        statement = statement.where(AuditEvent.actor_user_id == int(query.actor))
    if query.action:
        statement = statement.where(AuditEvent.action == query.action)
    if query.entity_type:
        statement = statement.where(AuditEvent.entity_type == query.entity_type)
    if query.date_from is not None:
        statement = statement.where(AuditEvent.created_at >= _day_start(query.date_from))
    if query.date_to is not None:
        # The whole UTC day, inclusive, with no date arithmetic: 9999-12-31 is a valid bound (S4 finding F3).
        statement = statement.where(AuditEvent.created_at <= datetime.combine(query.date_to, time.max, tzinfo=timezone.utc))
    return statement


def search(query: LogQuery) -> LogPage:
    """One page of the S14 log, newest first, with the total the filters match."""
    total = db.session.execute(_apply_filters(select(func.count(AuditEvent.id)), query)).scalar_one()
    pages = max(1, math.ceil(total / PAGE_SIZE))
    page = min(max(query.page, 1), pages)
    statement = (
        _apply_filters(select(AuditEvent), query)
        .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
        .offset((page - 1) * PAGE_SIZE)
        .limit(PAGE_SIZE)
        .options(selectinload(AuditEvent.actor))
    )
    return LogPage(rows=list(db.session.execute(statement).scalars()), total=total, page=page, pages=pages)


def actions() -> list[str]:
    """Every action code present in the log, for the S14 filter."""
    return list(db.session.execute(select(AuditEvent.action).distinct().order_by(AuditEvent.action)).scalars())


def entity_types() -> list[str]:
    return list(db.session.execute(select(AuditEvent.entity_type).distinct().order_by(AuditEvent.entity_type)).scalars())


def actors() -> list[User]:
    """Every login account, for the S14 actor filter (rows with no actor are "system")."""
    return list(db.session.execute(select(User).order_by(User.username)).scalars())
