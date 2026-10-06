"""People: the humans who own NHIs (spec 4.1 people).

ON DELETE: every foreign key that points at people is RESTRICT. A person with
identities, a login or a case cannot be deleted, and no route deletes a person
in v1. passive_deletes on the relationships keeps the ORM from nulling or
deleting the children first, so the database rule is what decides. The CHECK
constraint keeps departed_at set exactly when the status is departed, so
"reactivate" must clear it (phase 3).
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import CheckConstraint, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from warden.extensions import db
from warden.models.enums import PersonStatus
from warden.models.types import UtcDateTime, enum_column, utcnow


class Person(db.Model):
    __tablename__ = "people"
    __table_args__ = (
        CheckConstraint(
            "(status = 'departed') = (departed_at IS NOT NULL)",
            name="ck_people_departed_at_matches_status",
        ),
        {"comment": "Employees and external contacts who can own non-human identities."},
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    full_name: Mapped[str] = mapped_column(String(120), comment="Display name.")
    email: Mapped[str] = mapped_column(String(254), unique=True, comment="Work email, unique; the importer matches owners by it.")
    department: Mapped[str] = mapped_column(String(64), comment="Department name from the seed list, free text.")
    job_title: Mapped[str] = mapped_column(String(80))
    status: Mapped[PersonStatus] = mapped_column(
        enum_column(PersonStatus, "person_status"),
        default=PersonStatus.active,
        comment="A departed owner makes every NHI they own an orphan candidate.",
    )
    departed_at: Mapped[datetime | None] = mapped_column(UtcDateTime, comment="Set when the status becomes departed; cleared on reactivate.")
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow, onupdate=utcnow)

    user: Mapped[Optional["User"]] = relationship(back_populates="person", uselist=False, passive_deletes="all")
    owned_nhis: Mapped[list["Nhi"]] = relationship(back_populates="owner", passive_deletes="all")
    offboarding_cases: Mapped[list["OffboardingCase"]] = relationship(back_populates="person", passive_deletes="all")
