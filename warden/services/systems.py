"""System rules (spec 6.5): edit. Writes an audit row and commits. A change of
criticality rescores every identity on the system (spec 5.2, trigger write:
criticality feeds the privilege factor; the ninth hook point, phase 3 review
B-1); a change of name, category or description writes no assessment."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import select

from warden.extensions import db
from warden.models import Criticality, RiskTrigger, System, SystemCategory
from warden.services import audit, risk
from warden.services.audit import Actor


def name_taken(name: str, *, except_id: int | None = None) -> bool:
    statement = select(System.id).where(System.name == name)
    if except_id is not None:
        statement = statement.where(System.id != except_id)
    return db.session.execute(statement).first() is not None


def update_system(system: System, *, name: str, category: SystemCategory, criticality: Criticality, description: str, actor: Actor, now: datetime) -> System:
    before = audit.snapshot(system)
    criticality_changed = system.criticality != criticality
    system.name = name
    system.category = category
    system.criticality = criticality
    system.description = description
    db.session.flush()
    after: dict[str, object] = audit.snapshot(system)
    if criticality_changed:
        after["nhis_rescored"] = len(risk.assess_many(system.nhis, now=now, trigger=RiskTrigger.write))
    audit.record("system.update", system, actor=actor, before=before, after=after, created_at=now)
    db.session.commit()
    return system
