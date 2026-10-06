"""The audit log (spec 4.1 audit_events). Written only through
warden/services/audit.py; every state-changing action writes a row.

ON DELETE RESTRICT on the actor: an event never loses its user. actor, before,
after, ip and user_agent are nullable because seed and CLI rows have no actor
and no request (decision D-039). entity_id is nullable for an event about no
stored row: a failed login for a username that matches no users row (D-048).
"""
from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any, Optional

from sqlalchemy import JSON, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from warden.extensions import db
from warden.models.types import UtcDateTime, utcnow

if TYPE_CHECKING:
    from warden.models.user import User


class AuditEvent(db.Model):
    __tablename__ = "audit_events"
    __table_args__ = (
        Index("ix_audit_events_entity", "entity_type", "entity_id"),
        Index("ix_audit_events_created_at", "created_at"),
        {"comment": "Append-only record of every mutation and auth event."},
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    actor_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), comment="Null for system and seed rows.")
    action: Mapped[str] = mapped_column(String(64), comment="Code such as nhi.create, person.mark_departed, seed.load.")
    entity_type: Mapped[str] = mapped_column(String(64), comment="The table name of the entity.")
    entity_id: Mapped[int | None] = mapped_column(comment="Null when the event concerns no stored row (a failed login for an unknown username).")
    before: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    after: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    ip: Mapped[str | None] = mapped_column(String(45), comment="Null outside a request.")
    user_agent: Mapped[str | None] = mapped_column(Text, comment="Null outside a request.")
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)

    actor: Mapped[Optional["User"]] = relationship()

    # Values the actor did not set: updated_at is stamped on every write, the two score copies
    # move with the rescore that follows a write (spec 5.2), and nhis_rescored is the count of
    # identities rescored with a person or system write, a consequence rather than a column.
    # The payload keeps them all; the trail names what the actor changed.
    IGNORED_IN_CHANGES = frozenset({"updated_at", "current_score", "current_band", "nhis_rescored"})

    def changed_fields(self) -> list[str]:
        """Keys whose value differs between before and after, for the entity page's trail."""
        if not self.before or not self.after:
            return []
        return [key for key, value in self.after.items() if self.before.get(key) != value and key not in self.IGNORED_IN_CHANGES]

    def diff_rows(self) -> list[tuple[str, Any, Any, bool]]:
        """Every key of before and after with both values and whether they differ, for the S14 expansion.

        A row about no change (a login, a batch recompute) has one payload, so
        every key reads as unchanged; keys are listed in after order, then the
        keys only before had."""
        before = self.before or {}
        after = self.after or {}
        keys = list(after) + [key for key in before if key not in after]
        both = bool(self.before) and bool(self.after)
        return [(key, before.get(key), after.get(key), both and before.get(key) != after.get(key)) for key in keys]
