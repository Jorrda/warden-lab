"""Posture figures for the dashboard S02 and the report S10 (spec 6.2 and 6.6),
read side only: no mutation, no commit.

One PostureSummary feeds both pages so their numbers cannot disagree. Every
count runs over every identity regardless of status (decision D-056, audit
F01): a revoked identity scores 0 and stays in the population. The risk tiles
count the flags of the latest assessment per identity (audit F10), so a flag
has one definition, the engine's; the two owner tiles are the D-033 pair
(owner recorded; owner null or departed). Lists reuse the inventory's own
ordering so the top ten reads as the S03 list sorted by score.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, or_, select
from sqlalchemy.orm import selectinload

from warden.extensions import db
from warden.filters import label
from warden.models import AuditEvent, CaseStatus, Nhi, NhiType, OffboardingCase, Person, PersonStatus, System
from warden.services import risk
from warden.services.inventory import ListQuery, ListRow, latest_flags_subquery, list_nhis
from warden.services.risk_policy import FLAG_CODES, POLICY_V1

BAND_COLOURS = {"critical": "#dc3545", "high": "#fd7e14", "medium": "#ffc107", "low": "#198754"}  # the band-* classes of app.css


@dataclass(frozen=True)
class Distribution:
    """One row of a by-type or by-system table: how many identities and their average score."""

    label: str
    count: int
    average: int | None


@dataclass(frozen=True)
class PostureSummary:
    total: int
    scored: int
    with_owner: int
    without_clear_owner: int
    bands: dict[str, int]
    average: int | None
    flag_counts: dict[str, int]
    open_cases: int
    by_type: list[Distribution]
    by_system: list[Distribution]
    last_recompute_at: datetime | None
    policy_version: str

    def flag(self, code: str) -> int:
        return self.flag_counts.get(code, 0)

    def percent(self, part: int) -> int:
        return round(100 * part / self.total) if self.total else 0


def _count(*conditions: object) -> int:
    return db.session.execute(select(func.count(Nhi.id)).where(*conditions)).scalar_one()


def posture_summary() -> PostureSummary:
    total = _count()
    departed_owner = Nhi.owner_id.in_(select(Person.id).where(Person.status == PersonStatus.departed))
    band_rows = db.session.execute(select(Nhi.current_band, func.count(Nhi.id)).where(Nhi.current_band.is_not(None)).group_by(Nhi.current_band)).all()
    bands = {band.value: 0 for _, band in POLICY_V1.band_floors}  # the policy's order: critical first
    bands.update({band.value: count for band, count in band_rows})
    average = db.session.execute(select(func.avg(Nhi.current_score))).scalar_one()
    # One row per identity with its latest assessment's flags; the subquery correlates to nhis.
    latest = db.session.execute(select(Nhi.id, latest_flags_subquery())).all()
    flags = Counter(code for _, row_flags in latest for code in (row_flags or []))
    by_system_rows = db.session.execute(  # an outer join, so a system with no identity is listed at zero (S4 finding F3)
        select(System.name, func.count(Nhi.id), func.avg(Nhi.current_score)).outerjoin(Nhi, Nhi.system_id == System.id).group_by(System.name).order_by(System.name)
    ).all()
    by_system = [Distribution(label=name, count=count, average=None if avg is None else round(avg)) for name, count, avg in by_system_rows]
    return PostureSummary(
        total=total,
        scored=_count(Nhi.current_score.is_not(None)),
        with_owner=_count(Nhi.owner_id.is_not(None)),
        without_clear_owner=_count(or_(Nhi.owner_id.is_(None), departed_owner)),
        bands=bands,
        average=None if average is None else round(average),
        flag_counts={code: flags.get(code, 0) for code in FLAG_CODES},
        open_cases=db.session.execute(select(func.count(OffboardingCase.id)).where(OffboardingCase.status != CaseStatus.closed)).scalar_one(),
        by_type=[Distribution(label=label(nhi_type), count=count, average=None if avg is None else round(avg)) for nhi_type, count, avg in _type_rows()],
        by_system=by_system,
        last_recompute_at=risk.last_recompute_at(),
        policy_version=POLICY_V1.version,
    )


def _type_rows() -> list[tuple[NhiType, int, float | None]]:
    rows = db.session.execute(select(Nhi.type, func.count(Nhi.id), func.avg(Nhi.current_score)).group_by(Nhi.type)).all()
    by_type = {nhi_type: (count, avg) for nhi_type, count, avg in rows}
    return [(nhi_type, *by_type.get(nhi_type, (0, None))) for nhi_type in NhiType]  # spec 4.1 order, every type listed


def top_riskiest(limit: int) -> list[ListRow]:
    """The first rows of the S03 list in its default order: score descending, unscored last, then name."""
    return list_nhis(ListQuery(sort="score"))[:limit]


def orphans() -> list[ListRow]:
    return list_nhis(ListQuery(flag="ORPHAN", sort="score"))


def expiring() -> list[ListRow]:
    return list_nhis(ListQuery(flag="EXPIRES_30D", sort="score"))


def open_cases() -> list[OffboardingCase]:
    statement = select(OffboardingCase).where(OffboardingCase.status != CaseStatus.closed).options(selectinload(OffboardingCase.person)).order_by(OffboardingCase.opened_at)
    return list(db.session.execute(statement).scalars())


def recent_events(limit: int = 10) -> list[AuditEvent]:
    statement = select(AuditEvent).options(selectinload(AuditEvent.actor)).order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc()).limit(limit)
    return list(db.session.execute(statement).scalars())


def chart_data(summary: PostureSummary) -> dict[str, dict[str, list[object]]]:
    """What static/js/dashboard.js draws, embedded as a non-executing JSON block (phase 0 rule)."""
    return {
        "band": {
            "labels": [label(band) for band in summary.bands],
            "values": list(summary.bands.values()),
            "colors": [BAND_COLOURS[band] for band in summary.bands],
        },
        "type": {"labels": [row.label for row in summary.by_type], "values": [row.count for row in summary.by_type]},
        "system": {"labels": [row.label for row in summary.by_system], "values": [row.count for row in summary.by_system]},
    }
