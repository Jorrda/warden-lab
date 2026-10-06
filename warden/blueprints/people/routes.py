"""S07 people list and S08 person detail (spec 6.4)."""
from __future__ import annotations

from flask import Blueprint, Response, abort, flash, redirect, render_template, request, url_for
from flask_login import login_required
from markupsafe import Markup
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from warden.blueprints.auth.access import admin_required, current_actor
from warden.blueprints.people.forms import PersonForm
from warden.extensions import db
from warden.models import Nhi, Person, PersonStatus
from warden.models.types import utcnow
from warden.services import audit
from warden.services import inventory as inventory_service
from warden.services import offboarding as offboarding_service
from warden.services import people as people_service

bp = Blueprint("people", __name__, url_prefix="/people")

STATUS_FILTERS = ("all", PersonStatus.active.value, PersonStatus.departed.value)


@bp.get("/")
@login_required
def list_people() -> str:
    status = request.args.get("status", "all")
    if status not in STATUS_FILTERS:
        status = "all"
    nhi_count = select(func.count(Nhi.id)).where(Nhi.owner_id == Person.id).scalar_subquery()
    statement = select(Person, nhi_count.label("nhi_count")).order_by(Person.full_name)
    if status != "all":
        statement = statement.where(Person.status == PersonStatus(status))
    rows = db.session.execute(statement).all()
    return render_template("people/list.html", rows=rows, status=status, status_filters=STATUS_FILTERS, count=len(rows))


def _person_or_404(person_id: int) -> Person:
    person = db.session.get(Person, person_id, options=[selectinload(Person.owned_nhis).selectinload(Nhi.system)])
    if person is None:
        abort(404)
    return person


@bp.get("/<int:person_id>")
@login_required
def detail(person_id: int) -> str:
    person = _person_or_404(person_id)
    nhis = sorted(person.owned_nhis, key=inventory_service.detail_sort_key)
    return render_template(
        "people/detail.html",
        person=person,
        nhis=nhis,
        cases=offboarding_service.cases_of(person),
        open_case=offboarding_service.open_case_for(person),
        trail=audit.trail(person),
        now=utcnow(),
    )


@bp.route("/<int:person_id>/edit", methods=["GET", "POST"])
@admin_required
def edit(person_id: int) -> str | Response:
    person = _person_or_404(person_id)
    form = PersonForm(obj=person)
    if form.validate_on_submit():
        if people_service.email_taken(form.email.data, except_id=person.id):
            form.email.errors.append("Another person already has this email.")
        else:
            people_service.update_person(
                person,
                full_name=form.full_name.data,
                email=form.email.data,
                department=form.department.data,
                job_title=form.job_title.data,
                actor=current_actor(),
                now=utcnow(),
            )
            flash(f"Saved {person.full_name}.", "success")
            return redirect(url_for("people.detail", person_id=person.id))
    return render_template("people/form.html", form=form, person=person)


@bp.post("/<int:person_id>/mark-departed")
@admin_required
def mark_departed(person_id: int) -> Response:
    person = _person_or_404(person_id)
    try:
        count = people_service.mark_departed(person, actor=current_actor(), now=utcnow())
    except ValueError as error:
        flash(str(error), "warning")
        return redirect(url_for("people.detail", person_id=person.id))
    phrase = "1 identity now has" if count == 1 else f"{count} identities now have"
    # The flash carries the "open an offboarding case?" button (decision D-052); the partial
    # renders through Jinja, so the name is escaped there, and Markup keeps the form intact.
    flash(Markup(render_template("people/_departed_flash.html", person=person, phrase=phrase)), "warning")
    return redirect(url_for("people.detail", person_id=person.id))


@bp.post("/<int:person_id>/reactivate")
@admin_required
def reactivate(person_id: int) -> Response:
    person = _person_or_404(person_id)
    try:
        people_service.reactivate(person, actor=current_actor(), now=utcnow())
    except ValueError as error:
        flash(str(error), "warning")
        return redirect(url_for("people.detail", person_id=person.id))
    flash(f"{person.full_name} is active again.", "success")
    return redirect(url_for("people.detail", person_id=person.id))
