"""Inventory rules (spec 6.3): create, edit, transfer owner, record rotation,
revoke, decommission, and the filtered list. Every mutation rescores the
identity through warden.services.risk (spec 5.2, trigger write), writes an
audit row through warden.services.audit whose after snapshot carries the new
score, and commits.

Status rules (spec 6.3 and 4.1): transfer and rotation apply to an active
identity; revoke moves active to revoked; decommission moves active or
revoked to decommissioned; revoked and decommissioned are final. Rotation
and transfer do not change the status (phase 0 plan 18.4).

create_nhi() and update_nhi() each commit, and the importer calls them once
per accepted row (phase 6 audit F20); add_nhi() and record_create() are
create_nhi() without the commit, for the scanner, which links a finding to
the new row before its first score. The attributes column is a plain JSON
type, so every write assigns a new dict, the return value of
validate_attributes(); nothing edits the loaded dict in place (phase 2 plan
section 16). Scopes are read-only in v1: no
phase 3 screen grants or removes nhi_scopes rows (phase 3 audit F03), and the
seeded AI agents hold grants on other systems, so a future picker must not
restrict a scope to the identity's own system (spec section 8).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import ScalarSelect, Select, case, func, or_, select
from sqlalchemy.orm import selectinload

from warden.extensions import db
from warden.models import (
    Environment,
    Nhi,
    NhiStatus,
    NhiType,
    Person,
    PersonStatus,
    PrivilegeLevel,
    RiskAssessment,
    RiskBand,
    RiskTrigger,
    StorageLocation,
    System,
    validate_attributes,
)
from warden.services import audit, risk
from warden.services.audit import Actor
from warden.services.risk_policy import FLAG_CODES  # the thirteen codes of spec 5.3, declared once with the policy

SORTS: tuple[str, ...] = ("score", "name", "last_used", "rotation_age")
OWNER_NONE = "none"
OWNER_DEPARTED = "departed"


class StatusError(ValueError):
    """The action is not allowed in the identity's current status."""


@dataclass(frozen=True)
class NhiFields:
    """Everything the create and edit form provides, already typed."""

    type: NhiType
    name: str
    system_id: int
    owner_id: int | None
    purpose: str
    environment: Environment
    privilege_level: PrivilegeLevel
    storage_location: StorageLocation
    created_at: datetime
    last_used_at: datetime | None
    last_rotated_at: datetime | None
    expires_at: datetime | None
    attributes: dict[str, Any]


@dataclass(frozen=True)
class ListQuery:
    """The S03 filters and sort, parsed by the route from the query string."""

    q: str = ""
    type: NhiType | None = None
    system_id: int | None = None
    owner: str = ""  # a person id as text, "none", "departed" or ""
    environment: Environment | None = None
    privilege: PrivilegeLevel | None = None
    storage: StorageLocation | None = None
    status: NhiStatus | None = None
    band: RiskBand | None = None
    flag: str = ""
    sort: str = "score"


@dataclass(frozen=True)
class ListRow:
    nhi: Nhi
    flags: list[str]


def latest_flags_subquery() -> ScalarSelect[Any]:
    return (
        select(RiskAssessment.flags)
        .where(RiskAssessment.nhi_id == Nhi.id)
        .order_by(RiskAssessment.computed_at.desc(), RiskAssessment.id.desc())
        .limit(1)
        .scalar_subquery()
    )


def like_pattern(term: str) -> str:
    """A LIKE pattern that matches the term literally: backslash, percent and underscore are escaped."""
    escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _apply_filters(statement: Select, query: ListQuery) -> Select:
    if query.q:
        pattern = like_pattern(query.q)
        statement = statement.where(or_(Nhi.name.ilike(pattern, escape="\\"), Nhi.purpose.ilike(pattern, escape="\\")))
    if query.type is not None:
        statement = statement.where(Nhi.type == query.type)
    if query.system_id is not None:
        statement = statement.where(Nhi.system_id == query.system_id)
    if query.owner == OWNER_NONE:
        statement = statement.where(Nhi.owner_id.is_(None))
    elif query.owner == OWNER_DEPARTED:
        statement = statement.where(Nhi.owner_id.in_(select(Person.id).where(Person.status == PersonStatus.departed)))
    elif query.owner.isdecimal():
        statement = statement.where(Nhi.owner_id == int(query.owner))
    if query.environment is not None:
        statement = statement.where(Nhi.environment == query.environment)
    if query.privilege is not None:
        statement = statement.where(Nhi.privilege_level == query.privilege)
    if query.storage is not None:
        statement = statement.where(Nhi.storage_location == query.storage)
    if query.status is not None:
        statement = statement.where(Nhi.status == query.status)
    if query.band is not None:
        statement = statement.where(Nhi.current_band == query.band)
    return statement


def _apply_sort(statement: Select, sort: str) -> Select:
    """Nulls are ordered with a CASE so the SQL runs on any SQLite (no NULLS LAST clause)."""
    if sort == "name":
        return statement.order_by(func.lower(Nhi.name), Nhi.id)
    if sort == "last_used":
        return statement.order_by(case((Nhi.last_used_at.is_(None), 1), else_=0), Nhi.last_used_at.desc(), Nhi.name)
    if sort == "rotation_age":
        # Oldest rotation first, never rotated first of all: the null column is the strongest
        # signal on a list sorted for review (phase 3 audit F26). The engine's rotation age
        # falls back to created_at for the factor (spec 5.1); NEVER_ROTATED is its own flag.
        return statement.order_by(case((Nhi.last_rotated_at.is_(None), 0), else_=1), Nhi.last_rotated_at.asc(), Nhi.name)
    return statement.order_by(case((Nhi.current_score.is_(None), 1), else_=0), Nhi.current_score.desc(), func.lower(Nhi.name), Nhi.id)


def detail_sort_key(nhi: Nhi) -> tuple[bool, int, str]:
    """The order the list query uses, for the rows a detail page already holds in memory:
    score descending, unscored last, then the name case-folded as _apply_sort's lower() folds it."""
    return (nhi.current_score is None, -(nhi.current_score or 0), nhi.name.lower())


def list_nhis(query: ListQuery) -> list[ListRow]:
    """The S03 rows: every filter in SQL, the flag filter over each row's latest assessment."""
    statement = select(Nhi, latest_flags_subquery().label("flags")).options(selectinload(Nhi.system), selectinload(Nhi.owner))
    statement = _apply_sort(_apply_filters(statement, query), query.sort)
    rows = [ListRow(nhi=nhi, flags=list(flags or [])) for nhi, flags in db.session.execute(statement).all()]
    if query.flag:
        rows = [row for row in rows if query.flag in row.flags]
    return rows


def count_all() -> int:
    return db.session.execute(select(func.count(Nhi.id))).scalar_one()


def name_taken(system_id: int, name: str, *, except_id: int | None = None) -> bool:
    statement = select(Nhi.id).where(Nhi.system_id == system_id, Nhi.name == name)
    if except_id is not None:
        statement = statement.where(Nhi.id != except_id)
    return db.session.execute(statement).first() is not None


def nhi_payload(nhi: Nhi) -> dict[str, Any]:
    payload = audit.snapshot(nhi)
    payload["scope_ids"] = sorted(link.scope_id for link in nhi.scope_links)
    return payload


def _same_day(stored: datetime | None, submitted: datetime | None) -> datetime | None:
    """Keep the stored instant when the form submitted the same calendar day (the form carries dates only)."""
    if stored is not None and submitted is not None and stored.date() == submitted.date():
        return stored
    return submitted


def _assign(nhi: Nhi, fields: NhiFields, now: datetime) -> None:
    nhi.type = fields.type
    nhi.name = fields.name
    nhi.system_id = fields.system_id
    nhi.owner_id = fields.owner_id
    nhi.purpose = fields.purpose
    nhi.environment = fields.environment
    nhi.privilege_level = fields.privilege_level
    nhi.storage_location = fields.storage_location
    nhi.created_at = _same_day(nhi.created_at, fields.created_at)
    nhi.last_used_at = _same_day(nhi.last_used_at, fields.last_used_at)
    nhi.last_rotated_at = _same_day(nhi.last_rotated_at, fields.last_rotated_at)
    nhi.expires_at = _same_day(nhi.expires_at, fields.expires_at)
    nhi.attributes = validate_attributes(fields.type, fields.attributes)
    nhi.updated_at = now


def add_nhi(fields: NhiFields, *, actor: Actor, now: datetime, fingerprint: str | None = None) -> Nhi:
    """Add a new identity to the session and flush it; no score, no audit row, no commit.

    The two-step shape lets the scanner link a finding to the new row between
    the flush and the score, so the first assessment sees the link (phase 6).
    The fingerprint is null for a hand-registered identity (decision D-029) and
    the finding's digest when the identity is created from a finding.
    """
    nhi = Nhi(status=NhiStatus.active, registered_by=actor.user_id, registered_at=now, fingerprint=fingerprint)
    _assign(nhi, fields, now)
    db.session.add(nhi)
    db.session.flush()
    return nhi


def record_create(nhi: Nhi, *, actor: Actor, now: datetime) -> Nhi:
    """Score a flushed new identity and write its nhi.create row; no commit."""
    risk.assess_nhi(nhi, now=now, trigger=RiskTrigger.write)
    audit.record("nhi.create", nhi, actor=actor, after=nhi_payload(nhi), created_at=now)
    return nhi


def create_nhi(fields: NhiFields, *, actor: Actor, now: datetime) -> Nhi:
    nhi = record_create(add_nhi(fields, actor=actor, now=now), actor=actor, now=now)
    db.session.commit()
    return nhi


def update_nhi(nhi: Nhi, fields: NhiFields, *, actor: Actor, now: datetime) -> Nhi:
    """Edit every form field, the type included; the scope links are left untouched."""
    before = nhi_payload(nhi)
    _assign(nhi, fields, now)
    db.session.flush()
    db.session.refresh(nhi, ["owner", "system"])  # the edit may have moved the two keys; score the rows they now name
    risk.assess_nhi(nhi, now=now, trigger=RiskTrigger.write)
    audit.record("nhi.update", nhi, actor=actor, before=before, after=nhi_payload(nhi), created_at=now)
    db.session.commit()
    return nhi


def _require_status(nhi: Nhi, allowed: tuple[NhiStatus, ...], action: str) -> None:
    if nhi.status not in allowed:
        raise StatusError(f"{nhi.name} is {nhi.status.value}; {action} applies only to an identity that is {' or '.join(s.value for s in allowed)}")


def transfer_owner(nhi: Nhi, new_owner: Person, *, actor: Actor, now: datetime) -> Nhi:
    _require_status(nhi, (NhiStatus.active,), "transfer")
    if new_owner.status != PersonStatus.active:
        raise ValueError(f"{new_owner.full_name} is departed and cannot receive an identity")
    before = nhi_payload(nhi)
    nhi.owner = new_owner
    nhi.updated_at = now
    db.session.flush()
    risk.assess_nhi(nhi, now=now, trigger=RiskTrigger.write)
    audit.record("nhi.transfer_owner", nhi, actor=actor, before=before, after=nhi_payload(nhi), created_at=now)
    db.session.commit()
    return nhi


def record_rotation(nhi: Nhi, *, actor: Actor, now: datetime) -> Nhi:
    _require_status(nhi, (NhiStatus.active,), "rotation")
    before = nhi_payload(nhi)
    nhi.last_rotated_at = now
    nhi.updated_at = now
    db.session.flush()
    risk.assess_nhi(nhi, now=now, trigger=RiskTrigger.write)
    audit.record("nhi.record_rotation", nhi, actor=actor, before=before, after=nhi_payload(nhi), created_at=now)
    db.session.commit()
    return nhi


def revoke(nhi: Nhi, *, actor: Actor, now: datetime) -> Nhi:
    _require_status(nhi, (NhiStatus.active,), "revoke")
    before = nhi_payload(nhi)
    nhi.status = NhiStatus.revoked
    nhi.updated_at = now
    db.session.flush()
    risk.assess_nhi(nhi, now=now, trigger=RiskTrigger.write)
    audit.record("nhi.revoke", nhi, actor=actor, before=before, after=nhi_payload(nhi), created_at=now)
    db.session.commit()
    return nhi


def decommission(nhi: Nhi, *, actor: Actor, now: datetime) -> Nhi:
    _require_status(nhi, (NhiStatus.active, NhiStatus.revoked), "decommission")
    before = nhi_payload(nhi)
    nhi.status = NhiStatus.decommissioned
    nhi.updated_at = now
    db.session.flush()
    risk.assess_nhi(nhi, now=now, trigger=RiskTrigger.write)
    audit.record("nhi.decommission", nhi, actor=actor, before=before, after=nhi_payload(nhi), created_at=now)
    db.session.commit()
    return nhi


def latest_assessment(nhi: Nhi) -> RiskAssessment | None:
    return nhi.assessments[0] if nhi.assessments else None


def systems_for_select() -> list[System]:
    return list(db.session.execute(select(System).order_by(System.name)).scalars())


def people_for_select(include: Person | None = None) -> list[Person]:
    """Active people, plus the current owner when departed so an edit does not lose it."""
    people = list(db.session.execute(select(Person).where(Person.status == PersonStatus.active).order_by(Person.full_name)).scalars())
    if include is not None and include not in people:
        people.append(include)
        people.sort(key=lambda person: person.full_name)
    return people


