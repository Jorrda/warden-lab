"""The risk engine (spec section 5): a pure function over a plain snapshot.

assess(snapshot, now, policy) scores one identity: five factor sub-scores of
0 to 100, their weighted sum rounded to an integer, the band, and the flags
of spec 5.3. Nothing here touches the database or Flask; warden/services/risk.py
builds the snapshot from an ORM row and writes the result.

Ages are whole elapsed days (decision D-045), the rule the seed's predicates
and the ago filter use, so a boundary falls on the same day on screen, in the
seed targets and in the score. The score is Python's round() of the weighted
sum, half to even, taken on an exact integer number of hundredths so a tie at
.5 is exact (phase 4 audit F09). A revoked or decommissioned identity keeps
its computed factors and flags but scores 0 and band low (spec 5.1, phase 3
audit F32).
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from fractions import Fraction
from typing import Any, Mapping

from warden.models.enums import Criticality, Environment, NhiStatus, NhiType, PersonStatus, PrivilegeLevel, RiskBand, Sensitivity, StorageLocation
from warden.services.risk_policy import POLICY_V1, RiskPolicy

FINAL_STATUSES = (NhiStatus.revoked, NhiStatus.decommissioned)


@dataclass(frozen=True)
class NhiSnapshot:
    """What the engine reads about one identity: its own columns plus the owner's
    status, the system's criticality and the sensitivities of its scopes."""

    status: NhiStatus
    nhi_type: NhiType
    environment: Environment
    privilege_level: PrivilegeLevel
    storage_location: StorageLocation
    created_at: datetime
    last_used_at: datetime | None
    last_rotated_at: datetime | None
    expires_at: datetime | None
    owner_status: PersonStatus | None  # None when no owner is recorded
    system_criticality: Criticality
    scope_sensitivities: tuple[Sensitivity, ...] = ()
    has_confirmed_source_finding: bool = False  # a finding linked to the identity with status confirmed or linked (decision D-030)


@dataclass(frozen=True)
class FactorScore:
    score: int
    weight: float
    contribution: float


@dataclass(frozen=True)
class RiskResult:
    score: int
    band: RiskBand
    factors: Mapping[str, FactorScore]
    flags: tuple[str, ...]
    policy_version: str

    def factors_json(self) -> dict[str, dict[str, Any]]:
        """The risk_assessments.factors shape the S04 template reads: per factor weight, score, contribution."""
        return {key: {"weight": factor.weight, "score": factor.score, "contribution": factor.contribution} for key, factor in self.factors.items()}


def days_since(now: datetime, moment: datetime | None) -> int | None:
    """Whole elapsed days, or None when the date is unknown."""
    return None if moment is None else (now - moment).days


def rotation_age_days(snapshot: NhiSnapshot, now: datetime) -> int:
    """Days since the last rotation, or since creation when never rotated (spec 5.1)."""
    return (now - (snapshot.last_rotated_at or snapshot.created_at)).days


def is_expired(snapshot: NhiSnapshot, now: datetime) -> bool:
    return snapshot.expires_at is not None and snapshot.expires_at < now


def is_expiring(snapshot: NhiSnapshot, now: datetime, policy: RiskPolicy) -> bool:
    return snapshot.expires_at is not None and now < snapshot.expires_at <= now + timedelta(days=policy.expiring_window_days)


def _banded(age: int | None, bands: tuple[tuple[int, int], ...], beyond: int) -> int:
    if age is None:
        return beyond
    for last_day, score in bands:
        if age <= last_day:
            return score
    return beyond


def ownership_score(snapshot: NhiSnapshot, now: datetime, policy: RiskPolicy) -> int:
    return 0 if snapshot.owner_status == PersonStatus.active else 100


def staleness_score(snapshot: NhiSnapshot, now: datetime, policy: RiskPolicy) -> int:
    return _banded(days_since(now, snapshot.last_used_at), policy.staleness_bands, policy.stale_score)


def rotation_score(snapshot: NhiSnapshot, now: datetime, policy: RiskPolicy) -> int:
    return _banded(rotation_age_days(snapshot, now), policy.rotation_bands, policy.unrotated_score)


def privilege_score(snapshot: NhiSnapshot, now: datetime, policy: RiskPolicy) -> int:
    score = policy.privilege_scores[snapshot.privilege_level]
    if snapshot.system_criticality == Criticality.high:
        score += policy.high_criticality_bonus
    if Sensitivity.high in snapshot.scope_sensitivities:
        score += policy.high_scope_bonus
    return min(score, 100)


def exposure_score(snapshot: NhiSnapshot, now: datetime, policy: RiskPolicy) -> int:
    if is_expired(snapshot, now):
        return policy.expired_exposure
    return policy.exposure_scores[snapshot.storage_location]


Scorer = Callable[[NhiSnapshot, datetime, RiskPolicy], int]

SCORERS: dict[str, Scorer] = {
    "ownership": ownership_score,
    "staleness": staleness_score,
    "rotation_age": rotation_score,
    "privilege": privilege_score,
    "exposure": exposure_score,
}


def _no_active_owner(snapshot: NhiSnapshot) -> bool:
    return snapshot.owner_status != PersonStatus.active


def _high_scope(snapshot: NhiSnapshot) -> bool:
    return Sensitivity.high in snapshot.scope_sensitivities


Predicate = Callable[[NhiSnapshot, datetime, RiskPolicy], bool]

# The thresholds are the ones the codes name; the graduated pairs are nested and, for
# staleness, null-inclusive (phase 3 audit F27). EXPIRED and EXPIRES_30D partition.
FLAG_PREDICATES: dict[str, Predicate] = {
    "ORPHAN": lambda s, now, p: s.owner_status is None,
    "OWNER_DEPARTED": lambda s, now, p: s.owner_status == PersonStatus.departed,
    "STALE_90": lambda s, now, p: (age := days_since(now, s.last_used_at)) is None or age > 90,
    "STALE_180": lambda s, now, p: (age := days_since(now, s.last_used_at)) is None or age > 180,
    "NEVER_ROTATED": lambda s, now, p: s.last_rotated_at is None,
    "ROTATION_OVER_365": lambda s, now, p: rotation_age_days(s, now) > 365,
    "ROTATION_OVER_730": lambda s, now, p: rotation_age_days(s, now) > 730,
    "ADMIN_WITHOUT_OWNER": lambda s, now, p: s.privilege_level == PrivilegeLevel.admin and _no_active_owner(s),
    "EXPIRED": lambda s, now, p: is_expired(s, now),
    "EXPIRES_30D": is_expiring,
    "SECRET_IN_SOURCE": lambda s, now, p: s.storage_location == StorageLocation.source_code or s.has_confirmed_source_finding,
    "AI_AGENT_HIGH_PRIVILEGE": lambda s, now, p: s.nhi_type == NhiType.ai_agent and (s.privilege_level == PrivilegeLevel.admin or _high_scope(s)),
    "PROD_UNKNOWN_STORAGE": lambda s, now, p: s.environment == Environment.prod and s.storage_location == StorageLocation.unknown,
}


def flags_for(snapshot: NhiSnapshot, now: datetime, policy: RiskPolicy = POLICY_V1) -> tuple[str, ...]:
    """The spec 5.3 codes that hold, in the policy's order."""
    return tuple(code for code in policy.flag_codes if FLAG_PREDICATES[code](snapshot, now, policy))


def weighted_score(scores: Mapping[str, int], policy: RiskPolicy = POLICY_V1) -> int:
    """round(sum(weight * factor)) on exact hundredths; Python's round() is half to even."""
    if set(scores) != {rule.key for rule in policy.factors}:
        raise ValueError(f"scores cover {sorted(scores)}, the policy's factors are {[rule.key for rule in policy.factors]}")
    hundredths = sum(policy.weight_percent(key) * score for key, score in scores.items())
    return round(Fraction(hundredths, 100))


def band_for(score: int, policy: RiskPolicy = POLICY_V1) -> RiskBand:
    for floor, band in policy.band_floors:
        if score >= floor:
            return band
    raise ValueError(f"score {score} is below every band floor")


def assess(snapshot: NhiSnapshot, now: datetime, policy: RiskPolicy = POLICY_V1) -> RiskResult:
    """Score one identity. Pure: the same snapshot, now and policy give the same result."""
    scores = {rule.key: SCORERS[rule.key](snapshot, now, policy) for rule in policy.factors}
    factors = {
        key: FactorScore(score=score, weight=policy.weight_percent(key) / 100, contribution=policy.weight_percent(key) * score / 100)
        for key, score in scores.items()
    }
    flags = flags_for(snapshot, now, policy)
    if snapshot.status in FINAL_STATUSES:
        return RiskResult(score=0, band=RiskBand.low, factors=factors, flags=flags, policy_version=policy.version)
    score = weighted_score(scores, policy)
    return RiskResult(score=score, band=band_for(score, policy), factors=factors, flags=flags, policy_version=policy.version)
