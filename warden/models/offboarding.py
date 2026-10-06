"""Offboarding cases and their items (spec 4.1 offboarding_cases, offboarding_items).

ON DELETE: items cascade from their case, as the spec names; every other
foreign key is RESTRICT. justification and new_owner_id are nullable because
an item starts as pending; the two conditional rules (transfer needs a new
owner, keep needs a justification) are service-level checks in
warden/services/offboarding.py. The three user relationships name who opened,
closed and decided; they add no column.

At most one case per person is open at a time (phase 2 audit F12). The service
checks it before opening, and the partial unique index
uq_offboarding_cases_one_open_per_person backs the check in the schema: two requests
that pass the check at once cannot both insert an open row (phase 5 S8a
finding R09). SQLite has had partial indexes since 3.8.0 and PostgreSQL always
has; SQLAlchemy emits the WHERE clause from sqlite_where and postgresql_where.
"""
from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Optional

from sqlalchemy import ForeignKey, Index, Text, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from warden.extensions import db
from warden.models.enums import CaseStatus, Decision
from warden.models.types import UtcDateTime, enum_column, utcnow

if TYPE_CHECKING:
    from warden.models.nhi import Nhi
    from warden.models.person import Person
    from warden.models.user import User


class OffboardingCase(db.Model):
    __tablename__ = "offboarding_cases"
    __table_args__ = (
        Index(
            "uq_offboarding_cases_one_open_per_person",
            "person_id",
            unique=True,
            sqlite_where=text("status != 'closed'"),
            postgresql_where=text("status != 'closed'"),
        ),
        {"comment": "One review of a leaver's identities; at most one per person is open at a time."},
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    person_id: Mapped[int] = mapped_column(ForeignKey("people.id", ondelete="RESTRICT"), comment="The leaver; unique among the cases that are not closed (the partial unique index).")
    status: Mapped[CaseStatus] = mapped_column(
        enum_column(CaseStatus, "case_status"), default=CaseStatus.open, comment="open until the first decision, then in_progress, closed when no item is pending."
    )
    opened_by: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    opened_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    closed_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    closed_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    notes: Mapped[str] = mapped_column(Text, default="", comment="Reserved; v1 never writes it (phase 5 audit F05).")

    person: Mapped["Person"] = relationship(back_populates="offboarding_cases")
    items: Mapped[list["OffboardingItem"]] = relationship(back_populates="case", cascade="all, delete-orphan", order_by="OffboardingItem.id")
    opened_by_user: Mapped["User"] = relationship(foreign_keys=[opened_by])
    closed_by_user: Mapped[Optional["User"]] = relationship(foreign_keys=[closed_by])


class OffboardingItem(db.Model):
    __tablename__ = "offboarding_items"
    __table_args__ = (
        UniqueConstraint("case_id", "nhi_id", name="uq_offboarding_items_case_nhi"),
        {"comment": "One decision per identity in a case (the associative entity between cases and NHIs)."},
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("offboarding_cases.id", ondelete="CASCADE"))
    nhi_id: Mapped[int] = mapped_column(ForeignKey("nhis.id", ondelete="RESTRICT"))
    decision: Mapped[Decision] = mapped_column(enum_column(Decision, "offboarding_decision"), default=Decision.pending)
    new_owner_id: Mapped[int | None] = mapped_column(ForeignKey("people.id", ondelete="RESTRICT"), comment="Required when the decision is transfer.")
    justification: Mapped[str | None] = mapped_column(Text, comment="Required when the decision is keep.")
    decided_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    decided_at: Mapped[datetime | None] = mapped_column(UtcDateTime)

    case: Mapped["OffboardingCase"] = relationship(back_populates="items")
    nhi: Mapped["Nhi"] = relationship()
    new_owner: Mapped[Optional["Person"]] = relationship(foreign_keys=[new_owner_id])
    decided_by_user: Mapped[Optional["User"]] = relationship(foreign_keys=[decided_by])
