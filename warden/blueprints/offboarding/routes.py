"""S12 case list and S13 case detail with the open, decide and close actions (spec 6.7)."""
from __future__ import annotations

from flask import Blueprint, Response, abort, flash, redirect, render_template, request, url_for
from flask_login import login_required

from warden.blueprints.auth.access import admin_required, current_actor
from warden.blueprints.offboarding.forms import DecisionForm, OpenCaseForm
from warden.extensions import db
from warden.filters import label
from warden.models import Decision, OffboardingCase, Person
from warden.models.types import utcnow
from warden.services import inventory as inventory_service
from warden.services import offboarding as offboarding_service
from warden.services.offboarding import DECISIONS, STATUS_FILTERS, CaseError

bp = Blueprint("offboarding", __name__, url_prefix="/offboarding")


def _open_form() -> OpenCaseForm:
    form = OpenCaseForm()
    form.person_id.choices = [(person.id, person.full_name) for person in offboarding_service.people_for_open_case()]
    return form


@bp.get("/")
@login_required
def list_cases() -> str:
    status = request.args.get("status", "all")
    if status not in STATUS_FILTERS:
        status = "all"
    rows = offboarding_service.list_cases(status)
    return render_template(
        "offboarding/list.html",
        rows=rows,
        count=len(rows),
        status=status,
        status_filters=STATUS_FILTERS,
        form=_open_form(),
        now=utcnow(),
    )


@bp.post("/open")
@admin_required
def open_case() -> Response:
    form = _open_form()
    if not form.validate_on_submit():
        flash("Choose a departed person to open a case for.", "warning")
        return redirect(url_for("offboarding.list_cases"))
    person = db.session.get(Person, form.person_id.data)
    if person is None:
        abort(404)
    try:
        case = offboarding_service.open_case(person, actor=current_actor(), now=utcnow())
    except CaseError as error:
        flash(str(error), "warning")
        return redirect(url_for("people.detail", person_id=person.id))
    count = len(case.items)
    noun = "identity" if count == 1 else "identities"
    flash(f"Opened offboarding case #{case.id} for {person.full_name}: {count} {noun} to review.", "success")
    return redirect(url_for("offboarding.detail", case_id=case.id))


def _case_or_404(case_id: int) -> OffboardingCase:
    case = offboarding_service.load_case(case_id)
    if case is None:
        abort(404)
    return case


@bp.get("/<int:case_id>")
@login_required
def detail(case_id: int) -> str:
    case = _case_or_404(case_id)
    delta = offboarding_service.score_delta(case)
    pending = sum(1 for item in case.items if item.decision == Decision.pending)
    return render_template(
        "offboarding/detail.html",
        case=case,
        rows=delta.rows,
        delta=delta,
        reasons={item.id: offboarding_service.listed_because(item) for item in case.items},
        pending=pending,
        decided=len(case.items) - pending,
        people=inventory_service.people_for_select(),
        decisions=DECISIONS,
        trail=offboarding_service.case_trail(case),
        now=utcnow(),
    )


@bp.post("/<int:case_id>/items/<int:item_id>")
@admin_required
def decide(case_id: int, item_id: int) -> Response:
    case = _case_or_404(case_id)
    item = next((candidate for candidate in case.items if candidate.id == item_id), None)
    if item is None:
        abort(404)
    form = DecisionForm()
    form.new_owner_id.choices = [(0, "Choose a person")] + [(person.id, person.full_name) for person in inventory_service.people_for_select()]
    if not form.validate_on_submit():
        first = next((errors[0] for errors in form.errors.values() if errors), "Choose rotate, transfer, revoke or keep.")
        flash(first, "warning")
        return redirect(url_for("offboarding.detail", case_id=case.id))
    decision = Decision(form.decision.data)
    new_owner = db.session.get(Person, form.new_owner_id.data) if form.new_owner_id.data else None
    try:
        changed = offboarding_service.decide(item, decision, new_owner=new_owner, justification=form.justification.data or "", actor=current_actor(), now=utcnow())
    except CaseError as error:
        flash(str(error), "warning")
    else:
        if changed:
            flash(f"Recorded {label(decision).lower()} for {item.nhi.name}.", "success")
        else:
            flash(f"No change to {item.nhi.name}: {label(decision).lower()} was already recorded.", "info")
    return redirect(url_for("offboarding.detail", case_id=case.id))


@bp.post("/<int:case_id>/close")
@admin_required
def close(case_id: int) -> Response:
    case = _case_or_404(case_id)
    try:
        delta = offboarding_service.close_case(case, actor=current_actor(), now=utcnow())
    except CaseError as error:
        flash(str(error), "warning")
    else:
        noun = "identity" if delta.counted == 1 else "identities"
        flash(f"Closed case #{case.id}. Score total {delta.before_total} at open, {delta.after_total} at close over {delta.counted} {noun}: delta {delta.delta:+d}.", "success")
    return redirect(url_for("offboarding.detail", case_id=case.id))
