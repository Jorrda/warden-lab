"""Systems and their scopes (spec 4.1 systems, scopes).

ON DELETE RESTRICT: a system with NHIs or scopes, and a scope granted to an
NHI, cannot be deleted; no route deletes either in v1. passive_deletes on the
relationships keeps the ORM from nulling or deleting the children first, so
the database rule is what decides.
"""
from __future__ import annotations

from sqlalchemy import ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from warden.extensions import db
from warden.models.enums import Criticality, Sensitivity, SystemCategory
from warden.models.types import enum_column


class System(db.Model):
    __tablename__ = "systems"
    __table_args__ = {"comment": "Platforms that NHIs belong to or grant access into."}

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    category: Mapped[SystemCategory] = mapped_column(enum_column(SystemCategory, "system_category"))
    criticality: Mapped[Criticality] = mapped_column(
        enum_column(Criticality, "system_criticality"), comment="high adds 20 to the privilege factor (spec 5.1)."
    )
    description: Mapped[str] = mapped_column(Text, default="")

    nhis: Mapped[list["Nhi"]] = relationship(back_populates="system", passive_deletes="all")
    scopes: Mapped[list["Scope"]] = relationship(back_populates="system", order_by="Scope.name", passive_deletes="all")


class Scope(db.Model):
    __tablename__ = "scopes"
    __table_args__ = (
        UniqueConstraint("system_id", "name", name="uq_scopes_system_name"),
        {"comment": "Permissions or grants that can be attached to an NHI."},
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    system_id: Mapped[int] = mapped_column(ForeignKey("systems.id", ondelete="RESTRICT"))
    name: Mapped[str] = mapped_column(String(120), comment="For example sap.invoices.read or aws.s3.full; unique per system.")
    sensitivity: Mapped[Sensitivity] = mapped_column(
        enum_column(Sensitivity, "scope_sensitivity"), comment="high adds 10 to the privilege factor (spec 5.1)."
    )

    system: Mapped["System"] = relationship(back_populates="scopes")
    nhi_links: Mapped[list["NhiScope"]] = relationship(back_populates="scope", passive_deletes="all")
