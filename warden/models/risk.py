"""Risk assessment history (spec 4.1 risk_assessments).

ON DELETE CASCADE from nhis, as the spec names: an identity's history goes with
it. The index on (nhi_id, computed_at DESC) serves "latest row per NHI".
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, CheckConstraint, ForeignKey, Index, String, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from warden.extensions import db
from warden.models.enums import RiskBand, RiskTrigger
from warden.models.types import UtcDateTime, enum_column, utcnow


class RiskAssessment(db.Model):
    __tablename__ = "risk_assessments"
    __table_args__ = (
        CheckConstraint("score >= 0 AND score <= 100", name="ck_risk_assessments_score_range"),
        Index("ix_risk_assessments_nhi_computed", "nhi_id", text("computed_at DESC")),
        {"comment": "One row per score computation; the latest row per NHI is the current score."},
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    nhi_id: Mapped[int] = mapped_column(ForeignKey("nhis.id", ondelete="CASCADE"))
    score: Mapped[int] = mapped_column(comment="0 to 100, round(sum(weight * factor)).")
    band: Mapped[RiskBand] = mapped_column(enum_column(RiskBand, "risk_band"), comment="critical 75 to 100, high 50 to 74, medium 25 to 49, low 0 to 24.")
    factors: Mapped[dict[str, Any]] = mapped_column(JSON, comment="Per factor: sub-score, weight, contribution.")
    flags: Mapped[list[str]] = mapped_column(JSON, comment="Rule codes of spec 5.3.")
    policy_version: Mapped[str] = mapped_column(String(16), comment="The weight set used, v1 at launch.")
    computed_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    trigger: Mapped[RiskTrigger] = mapped_column(enum_column(RiskTrigger, "risk_trigger"))

    nhi: Mapped["Nhi"] = relationship(back_populates="assessments")
