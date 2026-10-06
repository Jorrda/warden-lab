"""Scoring identities from the database and writing the result (spec 5.2).

The engine is pure (warden/services/risk_engine.py); this module builds its
snapshot from an ORM row and its relationships, writes one risk_assessments
row per assessment and keeps nhis.current_score and current_band as copies
of the latest row (decision D-037). assess_nhi() and assess_many() add rows
to the caller's transaction and never commit, so a write and its rescore
land together: the eight hook points of the phase 3 services plus
systems.update_system, all with trigger write, call them before they write
their audit row, so the row's after snapshot carries the new score.

The copies are read back from the stored rows after the flush, ordered by
computed_at then id as every reader of the latest assessment orders them
(decision D-051), not taken from the result just computed: when two requests
overlap on the threaded development server and the later one commits first,
the earlier one would otherwise overwrite the copies with the older score
(phase 4 S8a finding R07). One query per batch, not per identity.
recompute_all() is the batch behind the seed command, the recompute-risk
command and the dashboard button: it scores every identity, writes one
risk.recompute audit row (entity_type nhis, entity_id null, decision D-056)
and commits.
"""
from __future__ import annotations

import time
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from warden.extensions import db
from warden.models import Finding, FindingStatus, Nhi, NhiScope, RiskAssessment, RiskBand, RiskTrigger
from warden.services import audit
from warden.services.audit import Actor
from warden.services.risk_engine import NhiSnapshot, RiskResult, assess
from warden.services.risk_policy import POLICY_V1, RiskPolicy

CONFIRMED_STATUSES = (FindingStatus.confirmed, FindingStatus.linked)
RECOMPUTE_ACTION = "risk.recompute"


@dataclass(frozen=True)
class RecomputeReport:
    """What a batch recompute did: the command output, the flash and the audit payload read it."""

    trigger: RiskTrigger
    count: int
    elapsed_ms: int
    bands: dict[str, int]
    policy_version: str
    computed_at: datetime

    def summary(self) -> str:
        return f"critical {self.bands['critical']}, high {self.bands['high']}, medium {self.bands['medium']}, low {self.bands['low']}"


def nhi_ids_with_confirmed_findings() -> set[int]:
    """Identities with a linked finding whose status is confirmed or linked (SECRET_IN_SOURCE, decision D-030)."""
    statement = select(Finding.nhi_id).where(Finding.nhi_id.is_not(None), Finding.status.in_(CONFIRMED_STATUSES)).distinct()
    return set(db.session.execute(statement).scalars())


def snapshot_of(nhi: Nhi, *, has_confirmed_source_finding: bool = False) -> NhiSnapshot:
    """The engine's view of one loaded identity: its columns, the owner's status, the system's criticality, the scopes' sensitivities."""
    return NhiSnapshot(
        status=nhi.status,
        nhi_type=nhi.type,
        environment=nhi.environment,
        privilege_level=nhi.privilege_level,
        storage_location=nhi.storage_location,
        created_at=nhi.created_at,
        last_used_at=nhi.last_used_at,
        last_rotated_at=nhi.last_rotated_at,
        expires_at=nhi.expires_at,
        owner_status=nhi.owner.status if nhi.owner is not None else None,
        system_criticality=nhi.system.criticality,
        scope_sensitivities=tuple(link.scope.sensitivity for link in nhi.scope_links),
        has_confirmed_source_finding=has_confirmed_source_finding,
    )


def store(nhi: Nhi, result: RiskResult, *, now: datetime, trigger: RiskTrigger) -> RiskAssessment:
    """Add the assessment row; no commit. The copies on the identity are set by copy_latest() after the flush."""
    row = RiskAssessment(
        nhi_id=nhi.id,
        score=result.score,
        band=result.band,
        factors=result.factors_json(),
        flags=list(result.flags),
        policy_version=result.policy_version,
        computed_at=now,
        trigger=trigger,
    )
    db.session.add(row)
    return row


def copy_latest(nhis: Sequence[Nhi]) -> None:
    """Set current_score and current_band from each identity's latest stored assessment (computed_at, then id)."""
    ids = [nhi.id for nhi in nhis]
    if not ids:
        return
    statement = (
        select(RiskAssessment.nhi_id, RiskAssessment.score, RiskAssessment.band)
        .where(RiskAssessment.nhi_id.in_(ids))
        .order_by(RiskAssessment.nhi_id, RiskAssessment.computed_at.desc(), RiskAssessment.id.desc())
    )
    latest: dict[int, tuple[int, RiskBand]] = {}
    for nhi_id, score, band in db.session.execute(statement):
        latest.setdefault(nhi_id, (score, band))
    for nhi in nhis:
        nhi.current_score, nhi.current_band = latest[nhi.id]


def assess_many(nhis: Sequence[Nhi], *, now: datetime, trigger: RiskTrigger, policy: RiskPolicy = POLICY_V1) -> list[RiskAssessment]:
    """Score loaded identities inside the caller's transaction; one query settles the finding flag for all of them,
    one flush stores the rows and one query copies the latest score and band onto each identity."""
    flagged = nhi_ids_with_confirmed_findings()
    rows = [store(nhi, assess(snapshot_of(nhi, has_confirmed_source_finding=nhi.id in flagged), now, policy), now=now, trigger=trigger) for nhi in nhis]
    db.session.flush()
    copy_latest(nhis)
    return rows


def assess_nhi(nhi: Nhi, *, now: datetime, trigger: RiskTrigger, policy: RiskPolicy = POLICY_V1) -> RiskAssessment:
    """Score one flushed identity inside the caller's transaction; the caller commits."""
    return assess_many([nhi], now=now, trigger=trigger, policy=policy)[0]


def all_identities() -> list[Nhi]:
    statement = (
        select(Nhi)
        .options(selectinload(Nhi.owner), selectinload(Nhi.system), selectinload(Nhi.scope_links).selectinload(NhiScope.scope))
        .order_by(Nhi.id)
    )
    return list(db.session.execute(statement).scalars())


def recompute_all(*, now: datetime, trigger: RiskTrigger, actor: Actor | None, policy: RiskPolicy = POLICY_V1) -> RecomputeReport:
    """Score every identity at one instant, write the risk.recompute audit row and commit."""
    started = time.perf_counter()
    rows = assess_many(all_identities(), now=now, trigger=trigger, policy=policy)
    db.session.flush()
    elapsed_ms = round((time.perf_counter() - started) * 1000)
    bands = {band.value: sum(1 for row in rows if row.band == band) for band in RiskBand}
    report = RecomputeReport(trigger=trigger, count=len(rows), elapsed_ms=elapsed_ms, bands=bands, policy_version=policy.version, computed_at=now)
    audit.record(
        RECOMPUTE_ACTION,
        entity_type=Nhi.__tablename__,
        actor=actor,
        after={"trigger": trigger.value, "identities": report.count, "elapsed_ms": elapsed_ms, "policy_version": policy.version, "bands": bands},
        created_at=now,
    )
    db.session.commit()
    return report


def last_recompute_at() -> datetime | None:
    """When the newest assessment was computed, any trigger (spec 6.2, audit F05)."""
    return db.session.execute(select(func.max(RiskAssessment.computed_at))).scalar_one()
