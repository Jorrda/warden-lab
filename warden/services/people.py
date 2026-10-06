"""People rules (spec 6.4): edit, mark departed, reactivate. Every change writes
an audit row through warden.services.audit and commits. Mark departed and
reactivate rescore every identity the person owns (spec 5.2, trigger write)
before their audit row, which records how many were rescored; an edit of the
name, email, department or title changes nothing the engine reads, so it
writes no assessment (phase 4 audit F16). The offboarding case button is
phase 5's."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import select

from warden.extensions import db
from warden.models import Person, PersonStatus, RiskTrigger
from warden.services import audit, risk
from warden.services.audit import Actor


def email_taken(email: str, *, except_id: int | None = None) -> bool:
    statement = select(Person.id).where(Person.email == email)
    if except_id is not None:
        statement = statement.where(Person.id != except_id)
    return db.session.execute(statement).first() is not None


def update_person(person: Person, *, full_name: str, email: str, department: str, job_title: str, actor: Actor, now: datetime) -> Person:
    before = audit.snapshot(person)
    person.full_name = full_name
    person.email = email
    person.department = department
    person.job_title = job_title
    person.updated_at = now
    db.session.flush()
    audit.record("person.update", person, actor=actor, before=before, after=audit.snapshot(person), created_at=now)
    db.session.commit()
    return person


def mark_departed(person: Person, *, actor: Actor, now: datetime) -> int:
    """Set the status and departed_at; return how many identities the person owns."""
    if person.status == PersonStatus.departed:
        raise ValueError(f"{person.full_name} is already marked departed")
    before = audit.snapshot(person)
    person.status = PersonStatus.departed
    person.departed_at = now
    person.updated_at = now
    db.session.flush()
    rescored = risk.assess_many(person.owned_nhis, now=now, trigger=RiskTrigger.write)
    audit.record("person.mark_departed", person, actor=actor, before=before, after=_payload(person, rescored), created_at=now)
    db.session.commit()
    return len(rescored)


def reactivate(person: Person, *, actor: Actor, now: datetime) -> Person:
    """Set the status back to active and clear departed_at (the CHECK constraint requires both)."""
    if person.status == PersonStatus.active:
        raise ValueError(f"{person.full_name} is already active")
    before = audit.snapshot(person)
    person.status = PersonStatus.active
    person.departed_at = None
    person.updated_at = now
    db.session.flush()
    rescored = risk.assess_many(person.owned_nhis, now=now, trigger=RiskTrigger.write)
    audit.record("person.reactivate", person, actor=actor, before=before, after=_payload(person, rescored), created_at=now)
    db.session.commit()
    return person


def _payload(person: Person, rescored: list[object]) -> dict[str, object]:
    """The person's snapshot plus the number of identities rescored with it (0 when the person owns none)."""
    payload: dict[str, object] = audit.snapshot(person)
    payload["nhis_rescored"] = len(rescored)
    return payload
