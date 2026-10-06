"""Offboarding cases (spec 6.7, FR5): open a case for a departed person, decide
every identity on its checklist, close it with the score delta.

The checklist is every identity the leaver owns plus any identity whose
attributes.created_by_email is the leaver's email (spec 6.7), riskiest first.
A decision applies its effect to the identity in the same transaction as the
item update, the rescore (spec 5.2, trigger offboarding) and the audit rows:
rotate sets last_rotated_at and leaves the owner as they are, transfer sets the
owner to an active person, revoke sets the status to revoked, keep changes
nothing on the identity and needs a justification. Rotate, transfer and revoke
need an active identity, the phase 3 status rule; an identity that is revoked
or decommissioned before its case opens can only be kept. A decision can be
changed until the case closes, except revoke, which is final because the
identity is; saving the same decision again writes nothing (audit F14), and a
save that changes only the justification updates the item without touching
the identity. For a closed case the delta's second side is read at or before
the close, so a later recompute cannot move it. The case moves from open to in_progress on the first decision and
closes only when no item is pending; the close-time score delta is read from
the assessment history, the latest row at or before the case opened against
the latest row now, with no snapshot column (phase 2 audit F11). At most one
case per person is open at a time (phase 2 audit F12): the service checks it
and the partial unique index on offboarding_cases backs the check, so a
request whose check passed before another request's case was committed ends
in the same CaseError when its own flush meets the index (phase 5 S8a R09).
Two requests writing at the same instant meet SQLite's single-writer lock
instead: the second gets "database is locked" and the styled 500 page, a
property of every concurrent write on this prototype, recorded on the
technology page. A case is opened for a departed person only.

Audit rows: case.open on the case, case.decide on the item (its before and
after carry the identity's score copies, which the trail ignores), one
identity row with the phase 3 action code (nhi.record_rotation,
nhi.transfer_owner, nhi.revoke) when a decision changes the identity, and
case.close on the case with the score totals. Nothing here imports Flask
request objects (CLAUDE.md 5).
"""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import and_, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import selectinload

from warden.extensions import db
from warden.models import (
    AuditEvent,
    CaseStatus,
    Decision,
    Nhi,
    NhiStatus,
    OffboardingCase,
    OffboardingItem,
    Person,
    PersonStatus,
    RiskAssessment,
    RiskTrigger,
)
from warden.services import audit, risk
from warden.services.audit import TRAIL_LIMIT, Actor
from warden.services.inventory import detail_sort_key, nhi_payload

DECISIONS: tuple[Decision, ...] = (Decision.rotate, Decision.transfer, Decision.revoke, Decision.keep)
EFFECT_ACTIONS: dict[Decision, str] = {
    Decision.rotate: "nhi.record_rotation",
    Decision.transfer: "nhi.transfer_owner",
    Decision.revoke: "nhi.revoke",
}
NOT_CLOSED = "not_closed"  # the S12 filter the dashboard tile links to: open or in progress
STATUS_FILTERS: tuple[str, ...] = ("all", NOT_CLOSED, CaseStatus.open.value, CaseStatus.in_progress.value, CaseStatus.closed.value)


class CaseError(ValueError):
    """The action is not allowed for this case or item in its current state."""


@dataclass(frozen=True)
class CaseRow:
    """One S12 row: the case with its item and pending counts."""

    case: OffboardingCase
    items: int
    pending: int

    @property
    def decided(self) -> int:
        return self.items - self.pending


@dataclass(frozen=True)
class ItemScores:
    """An item with the identity's score when the case opened and its latest score."""

    item: OffboardingItem
    before: int | None
    after: int | None

    @property
    def delta(self) -> int | None:
        return None if self.before is None or self.after is None else self.after - self.before


@dataclass(frozen=True)
class CaseDelta:
    """The before and after totals over the case's identities (spec 6.7 close)."""

    rows: tuple[ItemScores, ...]
    before_total: int
    after_total: int
    counted: int

    @property
    def delta(self) -> int:
        return self.after_total - self.before_total


def open_case_for(person: Person) -> OffboardingCase | None:
    """The person's case that is not closed, if any (at most one by construction)."""
    statement = select(OffboardingCase).where(OffboardingCase.person_id == person.id, OffboardingCase.status != CaseStatus.closed)
    return db.session.execute(statement).scalars().first()


def people_for_open_case() -> list[Person]:
    """Departed people without an open case, the S12 picker (spec 6.7: pick a departed person)."""
    with_open_case = select(OffboardingCase.person_id).where(OffboardingCase.status != CaseStatus.closed)
    statement = select(Person).where(Person.status == PersonStatus.departed, Person.id.not_in(with_open_case)).order_by(Person.full_name)
    return list(db.session.execute(statement).scalars())


def checklist_identities(person: Person) -> list[Nhi]:
    """Every identity the person owns plus any whose created_by_email is theirs, riskiest first.

    The attribute clause is matched in Python over the loaded rows: one query at
    demo scale, and no column depends on SQLite's JSON functions (phase 2 audit F19).
    """
    email = person.email.strip().lower()
    statement = select(Nhi).order_by(Nhi.id)  # the filter and the sort read columns only; the S13 page loads its own relationships
    matched = [
        nhi
        for nhi in db.session.execute(statement).scalars()
        if nhi.owner_id == person.id or str(nhi.attributes.get("created_by_email") or "").strip().lower() == email
    ]
    return sorted(matched, key=detail_sort_key)


def listed_because(item: OffboardingItem) -> str:
    """Why the identity is on the checklist, as things stand now."""
    if item.nhi.owner_id == item.case.person_id:
        return "owned by the leaver"
    if str(item.nhi.attributes.get("created_by_email") or "").strip().lower() == item.case.person.email.strip().lower():
        return "created by the leaver"
    return "was owned by the leaver"


def _case_payload(case: OffboardingCase) -> dict[str, Any]:
    payload = audit.snapshot(case)
    payload["items"] = len(case.items)
    return payload


def _item_payload(item: OffboardingItem) -> dict[str, Any]:
    """The item's columns plus the identity's name and score copies; the trail ignores the copies."""
    payload = audit.snapshot(item)
    payload["nhi_name"] = item.nhi.name
    payload["current_score"] = item.nhi.current_score
    payload["current_band"] = None if item.nhi.current_band is None else item.nhi.current_band.value
    return payload


def open_case(person: Person, *, actor: Actor, now: datetime) -> OffboardingCase:
    """Open a case with one pending item per checklist identity; write case.open; commit.

    notes stays empty: the column is reserved in v1 (audit F05, the D-049 shape)."""
    if person.status != PersonStatus.departed:
        raise CaseError(f"{person.full_name} is active; an offboarding case is opened for a departed person")
    if open_case_for(person) is not None:
        raise CaseError(f"{person.full_name} already has an open offboarding case")
    identities = checklist_identities(person)  # queried before the case exists, so no autoflush sees a half-built row
    case = OffboardingCase(person=person, status=CaseStatus.open, opened_by=actor.user_id, opened_at=now)
    db.session.add(case)
    for nhi in identities:
        case.items.append(OffboardingItem(nhi=nhi, decision=Decision.pending))
    try:
        db.session.flush()
    except IntegrityError:
        # Two requests passed the check above at once; the partial unique index let one row in (phase 5 S8a R09).
        db.session.rollback()
        raise CaseError(f"{person.full_name} already has an open offboarding case") from None
    audit.record("case.open", case, actor=actor, after=_case_payload(case), created_at=now)
    db.session.commit()
    return case


def decide(
    item: OffboardingItem,
    decision: Decision,
    *,
    new_owner: Person | None,
    justification: str,
    actor: Actor,
    now: datetime,
) -> bool:
    """Record one decision and apply its effect, rescore the identity, write the audit rows; commit.

    Returns False, writing nothing, when the submission repeats the item's stored decision,
    new owner and justification (audit F14): a second save of the same decision is not a
    second rotation, assessment or audit row. A save that changes only the justification
    writes the item row alone.

    Raises CaseError, with a message the route flashes, when the case is closed,
    the item was revoked, the decision is not one of the four, the identity is
    not active for rotate, transfer or revoke, the transfer names no active
    person, or keep comes without a justification.
    """
    case = item.case
    nhi = item.nhi
    justification = justification.strip()
    if case.status == CaseStatus.closed:
        raise CaseError(f"case #{case.id} is closed; its decisions are final")
    if item.decision == Decision.revoke:
        raise CaseError(f"{nhi.name} was revoked through this case; that decision is final")
    if decision not in DECISIONS:
        raise CaseError("choose rotate, transfer, revoke or keep")
    if decision != Decision.keep and nhi.status != NhiStatus.active:
        raise CaseError(f"{nhi.name} is {nhi.status.value}; only keep applies to an identity that is not active")
    if decision == Decision.transfer:
        if new_owner is None:
            raise CaseError(f"choose the person who takes over {nhi.name}")
        if new_owner.status != PersonStatus.active:
            raise CaseError(f"{new_owner.full_name} is departed and cannot receive an identity")
    if decision == Decision.keep and not justification:
        raise CaseError(f"keeping {nhi.name} needs a justification")
    new_owner_id = new_owner.id if decision == Decision.transfer and new_owner is not None else None
    if (item.decision, item.new_owner_id, item.justification or "") == (decision, new_owner_id, justification):
        return False  # the same decision with the same fields: nothing to apply, record or rescore
    # A save that changes only the justification keeps the identity as it is: no second rotation,
    # no assessment, no identity row (S4 finding F2); the item row still records the new text.
    effect_changed = decision != item.decision or new_owner_id != item.new_owner_id

    before_item = _item_payload(item)
    before_nhi = nhi_payload(nhi)
    if effect_changed and decision == Decision.rotate:
        nhi.last_rotated_at = now
    elif effect_changed and decision == Decision.transfer:
        nhi.owner = new_owner
    elif effect_changed and decision == Decision.revoke:
        nhi.status = NhiStatus.revoked
    if effect_changed and decision != Decision.keep:
        nhi.updated_at = now
    item.decision = decision
    item.new_owner_id = new_owner_id
    item.justification = justification or None
    item.decided_by = actor.user_id
    item.decided_at = now
    if case.status == CaseStatus.open:
        case.status = CaseStatus.in_progress
    db.session.flush()
    if effect_changed:
        risk.assess_nhi(nhi, now=now, trigger=RiskTrigger.offboarding)
        if decision != Decision.keep:
            audit.record(EFFECT_ACTIONS[decision], nhi, actor=actor, before=before_nhi, after=nhi_payload(nhi), created_at=now)
    audit.record("case.decide", item, actor=actor, before=before_item, after=_item_payload(item), created_at=now)
    db.session.commit()
    return True


def _latest_scores(nhi_ids: Sequence[int], *, at: datetime | None) -> dict[int, int]:
    """The score of the latest assessment per identity, at or before an instant when one is given."""
    if not nhi_ids:
        return {}
    statement = select(RiskAssessment.nhi_id, RiskAssessment.score).where(RiskAssessment.nhi_id.in_(list(nhi_ids)))
    if at is not None:
        statement = statement.where(RiskAssessment.computed_at <= at)
    statement = statement.order_by(RiskAssessment.nhi_id, RiskAssessment.computed_at.desc(), RiskAssessment.id.desc())
    scores: dict[int, int] = {}
    for nhi_id, score in db.session.execute(statement):
        scores.setdefault(nhi_id, score)
    return scores


def score_delta(case: OffboardingCase) -> CaseDelta:
    """Per identity, the latest score at or before the case opened against the latest score now, and the totals.

    For a closed case the second side is read at or before the close, so the
    page keeps the totals its case.close row recorded whatever is rescored
    later. The totals count the identities that have a score on both sides;
    an identity never scored before the case opened is shown with no delta.
    """
    ids = [item.nhi_id for item in case.items]
    before = _latest_scores(ids, at=case.opened_at)
    after = _latest_scores(ids, at=case.closed_at if case.status == CaseStatus.closed else None)
    rows = tuple(ItemScores(item=item, before=before.get(item.nhi_id), after=after.get(item.nhi_id)) for item in case.items)
    counted = [row for row in rows if row.delta is not None]
    return CaseDelta(
        rows=rows,
        before_total=sum(row.before for row in counted),  # type: ignore[misc]
        after_total=sum(row.after for row in counted),  # type: ignore[misc]
        counted=len(counted),
    )


def close_case(case: OffboardingCase, *, actor: Actor, now: datetime) -> CaseDelta:
    """Close a case whose items are all decided; write case.close with the score totals; commit."""
    if case.status == CaseStatus.closed:
        raise CaseError(f"case #{case.id} is already closed")
    pending = sum(1 for item in case.items if item.decision == Decision.pending)
    if pending:
        noun = "decision is" if pending == 1 else "decisions are"
        raise CaseError(f"{pending} of {len(case.items)} {noun} still pending; decide every identity before closing")
    delta = score_delta(case)
    before = audit.snapshot(case)
    before["score_total"] = delta.before_total
    before["identities"] = [{"nhi_id": row.item.nhi_id, "score": row.before} for row in delta.rows]
    case.status = CaseStatus.closed
    case.closed_by = actor.user_id
    case.closed_at = now
    db.session.flush()
    after = audit.snapshot(case)
    after["score_total"] = delta.after_total
    after["identities"] = [{"nhi_id": row.item.nhi_id, "score": row.after} for row in delta.rows]
    audit.record("case.close", case, actor=actor, before=before, after=after, created_at=now)
    db.session.commit()
    return delta


def list_cases(status: str = "all") -> list[CaseRow]:
    """The S12 rows, newest first, with the item and pending counts."""
    items = select(func.count(OffboardingItem.id)).where(OffboardingItem.case_id == OffboardingCase.id).scalar_subquery()
    pending = (
        select(func.count(OffboardingItem.id))
        .where(OffboardingItem.case_id == OffboardingCase.id, OffboardingItem.decision == Decision.pending)
        .scalar_subquery()
    )
    statement = (
        select(OffboardingCase, items.label("items"), pending.label("pending"))
        .options(selectinload(OffboardingCase.person))
        .order_by(OffboardingCase.opened_at.desc(), OffboardingCase.id.desc())
    )
    if status == NOT_CLOSED:
        statement = statement.where(OffboardingCase.status != CaseStatus.closed)
    elif status in CaseStatus.__members__:
        statement = statement.where(OffboardingCase.status == CaseStatus(status))
    return [CaseRow(case=case, items=item_count, pending=pending_count) for case, item_count, pending_count in db.session.execute(statement).all()]


def load_case(case_id: int) -> OffboardingCase | None:
    """A case with its person, items, identities, their owners and systems, and the items' new owners."""
    return db.session.get(
        OffboardingCase,
        case_id,
        options=[
            selectinload(OffboardingCase.person),
            selectinload(OffboardingCase.items).selectinload(OffboardingItem.nhi).selectinload(Nhi.owner),
            selectinload(OffboardingCase.items).selectinload(OffboardingItem.nhi).selectinload(Nhi.system),
            selectinload(OffboardingCase.items).selectinload(OffboardingItem.new_owner),
        ],
    )


def case_trail(case: OffboardingCase, limit: int = TRAIL_LIMIT) -> list[AuditEvent]:
    """The newest audit rows about the case and its items, for the S13 trail."""
    item_ids = [item.id for item in case.items]
    about_case = and_(AuditEvent.entity_type == OffboardingCase.__tablename__, AuditEvent.entity_id == case.id)
    about_items = and_(AuditEvent.entity_type == OffboardingItem.__tablename__, AuditEvent.entity_id.in_(item_ids)) if item_ids else False
    statement = (
        select(AuditEvent)
        .where(or_(about_case, about_items))
        .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
        .limit(limit)
        .options(selectinload(AuditEvent.actor))
    )
    return list(db.session.execute(statement).scalars())


def cases_of(person: Person) -> list[OffboardingCase]:
    """The person's cases, newest first, for the S08 card."""
    statement = select(OffboardingCase).where(OffboardingCase.person_id == person.id).order_by(OffboardingCase.opened_at.desc(), OffboardingCase.id.desc())
    return list(db.session.execute(statement).scalars())
