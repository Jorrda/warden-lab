"""Scanner runs and findings (spec 4.1 scan_runs, findings).

ON DELETE RESTRICT everywhere: findings keep their run and their linked NHI.
passive_deletes on the relationships keeps the ORM from nulling or deleting
the children first, so the database rule is what decides. The ground-truth
columns of scan_runs are nullable because they exist only when the scanned
path carries a ground_truth.json (spec 4.1). findings store a fingerprint and
a masked preview, never the secret (CLAUDE.md 2).
"""
from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Optional

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from warden.extensions import db
from warden.models.enums import FindingStatus
from warden.models.types import UtcDateTime, enum_column, utcnow

if TYPE_CHECKING:
    from warden.models.nhi import Nhi
    from warden.models.user import User


class ScanRun(db.Model):
    __tablename__ = "scan_runs"
    __table_args__ = {"comment": "One execution of the repository scanner."}

    id: Mapped[int] = mapped_column(primary_key=True)
    target_path: Mapped[str] = mapped_column(Text, comment="The directory scanned, relative to the allowed base with forward slashes (. for the base itself).")
    started_by: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    started_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    files_scanned: Mapped[int] = mapped_column(default=0)
    findings_count: Mapped[int] = mapped_column(default=0)
    true_positives: Mapped[int | None] = mapped_column(comment="Ground-truth secrets with a finding on their file and line, when ground truth is present.")
    false_positives: Mapped[int | None] = mapped_column(comment="Findings on no ground-truth file and line, when present.")
    missed: Mapped[int | None] = mapped_column(comment="Ground-truth secrets with no finding on their file and line, when present.")
    recall: Mapped[float | None] = mapped_column(comment="true_positives over ground-truth secrets, when present.")
    precision: Mapped[float | None] = mapped_column(comment="Findings on a ground-truth file and line over all findings, when present.")

    findings: Mapped[list["Finding"]] = relationship(back_populates="scan_run", passive_deletes="all")
    starter: Mapped["User"] = relationship()


class Finding(db.Model):
    __tablename__ = "findings"
    __table_args__ = {"comment": "A secret-shaped literal found by the scanner; fingerprint and masked preview only."}

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_run_id: Mapped[int] = mapped_column(ForeignKey("scan_runs.id", ondelete="RESTRICT"))
    nhi_id: Mapped[int | None] = mapped_column(ForeignKey("nhis.id", ondelete="RESTRICT"), comment="Linked during triage or by fingerprint match.")
    file_path: Mapped[str] = mapped_column(Text, comment="Relative to the scan root, forward slashes.")
    line_no: Mapped[int] = mapped_column()
    secret_type: Mapped[str] = mapped_column(String(64), comment="Detector name, for example aws_access_key_id.")
    masked_preview: Mapped[str] = mapped_column(String(64), comment="First 4 and last 2 characters, or a fixed mask for short literals.")
    fingerprint: Mapped[str] = mapped_column(String(64), comment="Lowercase hex SHA-256 of the literal, the same input as nhis.fingerprint.")
    entropy: Mapped[float | None] = mapped_column(comment="Shannon entropy of the literal in bits per character; the threshold applies to generic detections only.")
    status: Mapped[FindingStatus] = mapped_column(
        enum_column(FindingStatus, "finding_status"), default=FindingStatus.new, comment="linked implies confirmed and is set together with nhi_id."
    )
    detected_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)

    scan_run: Mapped["ScanRun"] = relationship(back_populates="findings")
    nhi: Mapped[Optional["Nhi"]] = relationship()
