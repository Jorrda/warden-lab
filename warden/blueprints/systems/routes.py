"""S09 systems list and detail (spec 6.5)."""
from __future__ import annotations

from flask import Blueprint, Response, abort, flash, redirect, render_template, request, url_for
from flask_login import login_required
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from warden.blueprints.auth.access import admin_required, current_actor
from warden.blueprints.systems.forms import SystemForm
from warden.extensions import db
from warden.models import Criticality, Nhi, RiskBand, Scope, System, SystemCategory
from warden.models.types import utcnow
from warden.services import audit
from warden.services import inventory as inventory_service
from warden.services import systems as systems_service

bp = Blueprint("systems", __name__, url_prefix="/systems")


@bp.get("/")
@login_required
def list_systems() -> str:
    category = request.args.get("category", "")
    criticality = request.args.get("criticality", "")
    nhi_count = select(func.count(Nhi.id)).where(Nhi.system_id == System.id).scalar_subquery()
    scope_count = select(func.count(Scope.id)).where(Scope.system_id == System.id).scalar_subquery()
    statement = select(System, nhi_count.label("nhi_count"), scope_count.label("scope_count")).order_by(System.name)
    if category in SystemCategory.__members__:
        statement = statement.where(System.category == SystemCategory(category))
    else:
        category = ""
    if criticality in Criticality.__members__:
        statement = statement.where(System.criticality == Criticality(criticality))
    else:
        criticality = ""
    rows = db.session.execute(statement).all()
    return render_template(
        "systems/list.html",
        rows=rows,
        count=len(rows),
        category=category,
        criticality=criticality,
        categories=list(SystemCategory),
        criticalities=list(Criticality),
    )


def _system_or_404(system_id: int) -> System:
    system = db.session.get(
        System,
        system_id,
        options=[selectinload(System.nhis).selectinload(Nhi.owner), selectinload(System.scopes).selectinload(Scope.nhi_links)],
    )
    if system is None:
        abort(404)
    return system


def aggregate_risk(nhis: list[Nhi]) -> dict[str, object]:
    """Average score and band counts over the scored identities; empty until the first assessment is written."""
    scored = [nhi.current_score for nhi in nhis if nhi.current_score is not None]
    bands = {band.value: sum(1 for nhi in nhis if nhi.current_band == band) for band in RiskBand}
    average = round(sum(scored) / len(scored)) if scored else None
    return {"scored": len(scored), "total": len(nhis), "average": average, "bands": bands}


@bp.get("/<int:system_id>")
@login_required
def detail(system_id: int) -> str:
    system = _system_or_404(system_id)
    nhis = sorted(system.nhis, key=inventory_service.detail_sort_key)
    return render_template(
        "systems/detail.html",
        system=system,
        nhis=nhis,
        risk=aggregate_risk(system.nhis),
        trail=audit.trail(system),
        now=utcnow(),
    )


@bp.route("/<int:system_id>/edit", methods=["GET", "POST"])
@admin_required
def edit(system_id: int) -> str | Response:
    system = _system_or_404(system_id)
    form = SystemForm(obj=system)
    if request.method == "GET":
        form.category.data = system.category.value
        form.criticality.data = system.criticality.value
    if form.validate_on_submit():
        if systems_service.name_taken(form.name.data, except_id=system.id):
            form.name.errors.append("Another system already has this name.")
        else:
            systems_service.update_system(
                system,
                name=form.name.data,
                category=SystemCategory(form.category.data),
                criticality=Criticality(form.criticality.data),
                description=form.description.data or "",
                actor=current_actor(),
                now=utcnow(),
            )
            flash(f"Saved {system.name}.", "success")
            return redirect(url_for("systems.detail", system_id=system.id))
    return render_template("systems/form.html", form=form, system=system)
