"""CSV import batches (spec 4.1 import_batches). Written by the phase 6
importer; the row summarises one upload. ON DELETE RESTRICT on the uploader.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from warden.extensions import db
from warden.models.types import UtcDateTime, utcnow


class ImportBatch(db.Model):
    __tablename__ = "import_batches"
    __table_args__ = {"comment": "Summary of one CSV import."}

    id: Mapped[int] = mapped_column(primary_key=True)
    filename: Mapped[str] = mapped_column(String(255))
    uploaded_by: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    uploaded_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    rows_total: Mapped[int] = mapped_column(default=0)
    rows_created: Mapped[int] = mapped_column(default=0)
    rows_updated: Mapped[int] = mapped_column(default=0)
    rows_rejected: Mapped[int] = mapped_column(default=0)
    error_report: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, comment="One entry per rejected row: row number, name, system and reason.")
