"""The v1 scoring policy (spec 5.1 and 5.3): weights, factor rules, band
thresholds and flag definitions, the one place the engine, the policy page
S11 and the report S10 read them from.

Weights are integer percents (25, 20, 20, 20, 15), so a weighted sum is an
exact integer number of hundredths and a tie at .5 is exact; the JSON the S04
template reads shows them as the fractions of spec 5.1 (0.25, 0.2, 0.15).
The rule and rationale strings are the spec 5.1 table verbatim. A flag names
the factor it derives from and carries no citation of its own: CLAUDE.md 8
forbids inventing a reference (phase 4 audit F04). The thirteen flag codes
live here once; warden/services/inventory.py imports them for the S03 filter.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from warden.models.enums import PrivilegeLevel, RiskBand, StorageLocation

POLICY_VERSION = "v1"


@dataclass(frozen=True)
class FactorRule:
    """One row of the spec 5.1 table: the key stored in the factors JSON, the label
    the pages show, the weight and the two text columns."""

    key: str
    label: str
    weight_percent: int
    rule: str
    rationale: str


@dataclass(frozen=True)
class FlagDefinition:
    """One code of spec 5.3 with the factor it derives from and its predicate in plain English."""

    code: str
    factor: str
    predicate: str


@dataclass(frozen=True)
class RiskPolicy:
    """Everything the engine needs to score an identity. An organization tunes
    these values; the report presents them as a policy, not a law (spec 5.1)."""

    version: str
    factors: tuple[FactorRule, ...]
    staleness_bands: tuple[tuple[int, int], ...]  # (last day of the band inclusive, sub-score); past the last band or never used: stale_score
    stale_score: int
    rotation_bands: tuple[tuple[int, int], ...]  # (last day of the band inclusive, sub-score); past the last band: unrotated_score
    unrotated_score: int
    privilege_scores: Mapping[PrivilegeLevel, int]
    high_criticality_bonus: int
    high_scope_bonus: int
    exposure_scores: Mapping[StorageLocation, int]
    expired_exposure: int
    band_floors: tuple[tuple[int, RiskBand], ...]  # (lowest score of the band, band), highest band first
    expiring_window_days: int
    flags: tuple[FlagDefinition, ...]

    def weight_percent(self, key: str) -> int:
        return self._rule(key).weight_percent

    def factor_label(self, key: str) -> str:
        return self._rule(key).label

    def _rule(self, key: str) -> FactorRule:
        rule = next((rule for rule in self.factors if rule.key == key), None)
        if rule is None:
            raise KeyError(key)
        return rule

    @property
    def flag_codes(self) -> tuple[str, ...]:
        return tuple(flag.code for flag in self.flags)


FACTORS_V1: tuple[FactorRule, ...] = (
    FactorRule(
        "ownership",
        "Ownership",
        25,
        "no owner: 100; owner departed: 100; owner active: 0",
        "CSA 2026: over half of organizations cannot say who owns their NHIs; OWASP NHI1 improper offboarding is the top risk",
    ),
    FactorRule(
        "staleness",
        "Staleness (last use)",
        20,
        "0-30 days: 0; 31-90: 30; 91-180: 60; over 180 or never used: 100",
        "Unused credentials are pure liability; stale accounts are the classic orphaned-access finding",
    ),
    FactorRule(
        "rotation_age",
        "Rotation age",
        20,
        "under 90 days: 0; 90-365: 40; 1-2 years: 70; over 2 years or never rotated (use created_at): 100",
        "OWASP NHI7 long-lived secrets; CSA 2024 on rotation practices",
    ),
    FactorRule(
        "privilege",
        "Privilege",
        20,
        "read: 10; write: 50; admin: 100; plus 20 if system criticality is high, plus 10 if any scope sensitivity is high; cap 100",
        "OWASP NHI5 overprivileged NHI; least privilege literature in the review",
    ),
    FactorRule(
        "exposure",
        "Exposure (storage)",
        15,
        "vault: 0; env_var: 30; config_file: 50; chat_or_ticket: 80; source_code: 100; unknown: 60; expired credential: force 100",
        "Meli et al. 2019 and Krause et al. 2023 on secrets in repositories; OWASP NHI2 secret leakage",
    ),
)

FLAGS_V1: tuple[FlagDefinition, ...] = (
    FlagDefinition("ORPHAN", "ownership", "no owner is recorded"),
    FlagDefinition("OWNER_DEPARTED", "ownership", "the owner is marked departed"),
    FlagDefinition("STALE_90", "staleness", "last used over 90 days ago, or never used"),
    FlagDefinition("STALE_180", "staleness", "last used over 180 days ago, or never used"),
    FlagDefinition("NEVER_ROTATED", "rotation_age", "no rotation was ever recorded"),
    FlagDefinition("ROTATION_OVER_365", "rotation_age", "rotation age over 365 days (since the last rotation, or since creation when never rotated)"),
    FlagDefinition("ROTATION_OVER_730", "rotation_age", "rotation age over 730 days (since the last rotation, or since creation when never rotated)"),
    FlagDefinition("ADMIN_WITHOUT_OWNER", "privilege", "privilege level admin and either no owner or a departed owner (toxic combination)"),
    FlagDefinition("EXPIRED", "exposure", "the expiry date has passed"),
    FlagDefinition("EXPIRES_30D", "exposure", "the expiry date falls within the next 30 days"),
    FlagDefinition("SECRET_IN_SOURCE", "exposure", "stored in source code, or a scanner finding linked to the identity is confirmed or linked"),
    FlagDefinition("AI_AGENT_HIGH_PRIVILEGE", "privilege", "an AI agent with privilege level admin or any high-sensitivity scope"),
    FlagDefinition("PROD_UNKNOWN_STORAGE", "exposure", "a production identity whose storage location is unknown"),
)

POLICY_V1 = RiskPolicy(
    version=POLICY_VERSION,
    factors=FACTORS_V1,
    staleness_bands=((30, 0), (90, 30), (180, 60)),
    stale_score=100,
    rotation_bands=((89, 0), (365, 40), (730, 70)),
    unrotated_score=100,
    privilege_scores=MappingProxyType({PrivilegeLevel.read: 10, PrivilegeLevel.write: 50, PrivilegeLevel.admin: 100}),
    high_criticality_bonus=20,
    high_scope_bonus=10,
    exposure_scores=MappingProxyType(
        {
            StorageLocation.vault: 0,
            StorageLocation.env_var: 30,
            StorageLocation.config_file: 50,
            StorageLocation.chat_or_ticket: 80,
            StorageLocation.source_code: 100,
            StorageLocation.unknown: 60,
        }
    ),
    expired_exposure=100,
    band_floors=((75, RiskBand.critical), (50, RiskBand.high), (25, RiskBand.medium), (0, RiskBand.low)),
    expiring_window_days=30,
    flags=FLAGS_V1,
)

FLAG_CODES: tuple[str, ...] = POLICY_V1.flag_codes
