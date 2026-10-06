"""The polymorphic non-human identity (spec 4.1 nhis, nhi_scopes).

One table for every type; type-specific data lives in the attributes JSON
column whose keys ATTRIBUTE_SCHEMA fixes per type (spec 4.1, decision D-038).

ON DELETE RESTRICT on every foreign key out of this table and on the keys
into it from nhi_scopes, offboarding_items and findings; the one cascade
into it is risk_assessments.nhi_id, as the spec names (no route deletes an
NHI in v1). Through the ORM, `scope_links` is deleted with its identity
(delete-orphan, decision Q21 of the phase 2 plan), so that RESTRICT guards
direct SQL only. unique(system_id, name) is the importer's upsert key
(decision D-031).

The attributes column is a plain JSON type: an in-place edit of the loaded
dict (item assignment, update()) is not detected and is never written.
Assign a new dict, for example the return value of validate_attributes(),
as the seed does; a merge is a new dict too.
"""
from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import JSON, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from warden.extensions import db
from warden.models.enums import Environment, NhiStatus, NhiType, PrivilegeLevel, RiskBand, StorageLocation
from warden.models.types import UtcDateTime, enum_column, utcnow

# Allowed attribute keys per type and the Python type of each value.
# list means a list of strings. Every key is optional; unknown keys are rejected.
ATTRIBUTE_SCHEMA: dict[NhiType, dict[str, type]] = {
    NhiType.service_account: {"login": str, "auth_method": str},
    NhiType.api_key: {"key_prefix": str},
    NhiType.oauth_grant: {"client_id": str, "grant_type": str},
    NhiType.webhook: {"target_url": str, "events": list},
    NhiType.deploy_key: {"repo": str},
    NhiType.certificate: {"issuer": str, "san": list},
    NhiType.ci_token: {"pipeline": str, "token_scope": str},
    NhiType.ai_agent: {"model_provider": str, "tool_list": list},
}

# Allowed on every type. The offboarding checklist (spec 6.7) reads created_by_email.
COMMON_ATTRIBUTE_KEYS: dict[str, type] = {"created_by_email": str}

# The longest value each key accepts: the S05 form's Length validators, the importer's cells and every other writer
# share this one table through validate_attributes() (phase 6 whole-branch review N1). A list-valued key is bounded
# on its canonical comma-joined text; the form's ListLength validator measures the same text however the list is
# typed or rendered.
ATTRIBUTE_LIMITS: dict[str, int] = {
    "login": 120,
    "auth_method": 60,
    "key_prefix": 32,
    "client_id": 120,
    "grant_type": 60,
    "target_url": 500,
    "events": 500,
    "repo": 200,
    "issuer": 120,
    "san": 500,
    "pipeline": 120,
    "token_scope": 120,
    "model_provider": 120,
    "tool_list": 500,
    "created_by_email": 254,
}


def validate_attributes(nhi_type: NhiType, attributes: Mapping[str, Any] | None) -> dict[str, Any]:
    """Return a clean copy of the attributes for the type, or raise ValueError naming the first problem."""
    allowed = {**ATTRIBUTE_SCHEMA[nhi_type], **COMMON_ATTRIBUTE_KEYS}
    clean: dict[str, Any] = {}
    for key, value in (attributes or {}).items():
        if key not in allowed:
            raise ValueError(f"unknown attribute {key!r} for type {nhi_type.value}")
        if allowed[key] is list:
            if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                raise ValueError(f"attribute {key!r} must be a list of strings")
        elif not isinstance(value, str):
            raise ValueError(f"attribute {key!r} must be a string")
        if len(",".join(value) if allowed[key] is list else value) > ATTRIBUTE_LIMITS[key]:
            raise ValueError(f"attribute {key!r} is over {ATTRIBUTE_LIMITS[key]} characters")
        clean[key] = value
    return clean


class Nhi(db.Model):
    __tablename__ = "nhis"
    __table_args__ = (
        UniqueConstraint("system_id", "name", name="uq_nhis_system_name"),
        {"comment": "Every non-human identity, all types in one table (single-table inheritance)."},
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), comment="Unique within its system.")
    type: Mapped[NhiType] = mapped_column(enum_column(NhiType, "nhi_type"))
    system_id: Mapped[int] = mapped_column(ForeignKey("systems.id", ondelete="RESTRICT"))
    owner_id: Mapped[int | None] = mapped_column(
        ForeignKey("people.id", ondelete="RESTRICT"), comment="Null means no owner recorded (ORPHAN)."
    )
    purpose: Mapped[str] = mapped_column(Text, default="")
    environment: Mapped[Environment] = mapped_column(enum_column(Environment, "nhi_environment"))
    privilege_level: Mapped[PrivilegeLevel] = mapped_column(enum_column(PrivilegeLevel, "nhi_privilege_level"))
    storage_location: Mapped[StorageLocation] = mapped_column(enum_column(StorageLocation, "nhi_storage_location"))
    status: Mapped[NhiStatus] = mapped_column(
        enum_column(NhiStatus, "nhi_status"),
        default=NhiStatus.active,
        comment="rotated and transferred are reserved; rotation and transfer do not change the status in v1.",
    )
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow, comment="Identity creation date, seedable; the rotation reference when never rotated.")
    last_used_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    last_rotated_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    expires_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, comment="Type-specific keys fixed by ATTRIBUTE_SCHEMA.")
    fingerprint: Mapped[str | None] = mapped_column(
        String(64), comment="Lowercase hex SHA-256 of the secret literal; correlates scanner findings; null when hand-registered."
    )
    registered_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), comment="Null for seeded rows.")
    registered_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow, onupdate=utcnow)
    current_score: Mapped[int | None] = mapped_column(comment="Copy of the latest risk_assessments.score; null until the first assessment.")
    current_band: Mapped[RiskBand | None] = mapped_column(
        enum_column(RiskBand, "nhi_current_band"), comment="Copy of the latest risk_assessments.band; null until the first assessment."
    )

    system: Mapped["System"] = relationship(back_populates="nhis")
    owner: Mapped[Optional["Person"]] = relationship(back_populates="owned_nhis")
    scope_links: Mapped[list["NhiScope"]] = relationship(back_populates="nhi", cascade="all, delete-orphan")
    assessments: Mapped[list["RiskAssessment"]] = relationship(
        back_populates="nhi", order_by="RiskAssessment.computed_at.desc(), RiskAssessment.id.desc()", passive_deletes=True
    )


class NhiScope(db.Model):
    __tablename__ = "nhi_scopes"
    __table_args__ = {"comment": "Scopes granted to an NHI (M:N with a grant date)."}

    nhi_id: Mapped[int] = mapped_column(ForeignKey("nhis.id", ondelete="RESTRICT"), primary_key=True)
    scope_id: Mapped[int] = mapped_column(ForeignKey("scopes.id", ondelete="RESTRICT"), primary_key=True)
    granted_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)

    nhi: Mapped["Nhi"] = relationship(back_populates="scope_links")
    scope: Mapped["Scope"] = relationship(back_populates="nhi_links")
