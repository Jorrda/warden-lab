"""S03 list, S04 detail, S05 create and edit and S06 import (spec 6.3), plus the admin actions."""
from __future__ import annotations

from collections.abc import Callable

from flask import Blueprint, Response, abort, flash, redirect, render_template, request, url_for
from flask_login import login_required
from sqlalchemy.orm import selectinload

from warden.blueprints.auth.access import admin_required, current_actor
from warden.blueprints.inventory.forms import ATTRIBUTE_LABELS, ImportCommitForm, ImportForm, NhiForm, to_utc
from warden.extensions import db
from warden.models import ATTRIBUTE_SCHEMA, Environment, Finding, FindingStatus, Nhi, NhiScope, NhiStatus, NhiType, Person, PrivilegeLevel, RiskBand, StorageLocation
from warden.models.enums import ValueEnum
from warden.models.types import utcnow
from warden.routing import parse_id
from warden.services import audit
from warden.services import importer as importer_service
from warden.services import inventory as inventory_service
from warden.services import scanner as scanner_service
from warden.services.importer import ImportError_
from warden.services.inventory import FLAG_CODES, SORTS, ListQuery, NhiFields, StatusError
from warden.services.scanner import TriageError

bp = Blueprint("inventory", __name__, url_prefix="/nhis")


def _enum_arg(enum_class: type[ValueEnum], name: str) -> ValueEnum | None:
    value = request.args.get(name, "")
    return enum_class(value) if value in enum_class.__members__ else None


def _parse_query() -> ListQuery:
    owner = request.args.get("owner", "")
    flag = request.args.get("flag", "")
    sort = request.args.get("sort", "score")
    return ListQuery(
        q=request.args.get("q", "").strip()[:120],
        type=_enum_arg(NhiType, "type"),
        system_id=parse_id(request.args.get("system", "")),
        owner=owner if owner in ("none", "departed") or parse_id(owner) is not None else "",
        environment=_enum_arg(Environment, "environment"),
        privilege=_enum_arg(PrivilegeLevel, "privilege"),
        storage=_enum_arg(StorageLocation, "storage"),
        status=_enum_arg(NhiStatus, "status"),
        band=_enum_arg(RiskBand, "band"),
        flag=flag if flag in FLAG_CODES else "",
        sort=sort if sort in SORTS else "score",
    )


@bp.get("/")
@login_required
def list_nhis() -> str:
    query = _parse_query()
    rows = inventory_service.list_nhis(query)
    return render_template(
        "inventory/list.html",
        rows=rows,
        query=query,
        count=len(rows),
        total=inventory_service.count_all(),
        systems=inventory_service.systems_for_select(),
        people=inventory_service.people_for_select(),
        types=list(NhiType),
        environments=list(Environment),
        privileges=list(PrivilegeLevel),
        storages=list(StorageLocation),
        statuses=list(NhiStatus),
        bands=list(RiskBand),
        flags=FLAG_CODES,
        sorts=SORTS,
        now=utcnow(),
    )


def _nhi_or_404(nhi_id: int) -> Nhi:
    nhi = db.session.get(
        Nhi,
        nhi_id,
        options=[
            selectinload(Nhi.system),
            selectinload(Nhi.owner),
            selectinload(Nhi.scope_links).selectinload(NhiScope.scope),
            selectinload(Nhi.assessments),
        ],
    )
    if nhi is None:
        abort(404)
    return nhi


@bp.get("/<int:nhi_id>")
@login_required
def detail(nhi_id: int) -> str:
    nhi = _nhi_or_404(nhi_id)
    return render_template(
        "inventory/detail.html",
        nhi=nhi,
        attribute_keys=[*ATTRIBUTE_SCHEMA[nhi.type], "created_by_email"],
        attribute_labels=ATTRIBUTE_LABELS,
        assessment=inventory_service.latest_assessment(nhi),
        history=nhi.assessments[:20],
        people=inventory_service.people_for_select(),
        findings=scanner_service.findings_of(nhi),
        trail=audit.trail(nhi),
        now=utcnow(),
    )


def _load_choices(form: NhiForm, current_owner: Person | None = None) -> None:
    form.system_id.choices = [(system.id, system.name) for system in inventory_service.systems_for_select()]
    form.owner_id.choices = [(0, "No owner recorded")] + [(person.id, person.full_name) for person in inventory_service.people_for_select(current_owner)]


def _submitted_type(form: NhiForm) -> NhiType | None:
    return NhiType(form.type.data) if form.type.data in NhiType.__members__ else None


def _fields_from(form: NhiForm, nhi_type: NhiType) -> NhiFields:
    return NhiFields(
        type=nhi_type,
        name=form.name.data,
        system_id=form.system_id.data,
        owner_id=form.owner_id.data or None,
        purpose=form.purpose.data or "",
        environment=Environment(form.environment.data),
        privilege_level=PrivilegeLevel(form.privilege_level.data),
        storage_location=StorageLocation(form.storage_location.data),
        created_at=to_utc(form.created_at.data),
        last_used_at=to_utc(form.last_used_at.data),
        last_rotated_at=to_utc(form.last_rotated_at.data),
        expires_at=to_utc(form.expires_at.data),
        attributes=form.attributes_for(nhi_type),
    )


def _finding_for_create(raw: str | None) -> Finding | None:
    """The scanner finding an identity is created from (spec 6.9), when the query string or the form names one; 404 when it does not exist."""
    finding_id = parse_id(raw or "")
    if finding_id is None:
        return None
    finding = db.session.get(Finding, finding_id)
    if finding is None:
        abort(404)
    return finding


@bp.route("/new", methods=["GET", "POST"])
@admin_required
def create() -> str | Response:
    form = NhiForm()
    _load_choices(form)
    finding = _finding_for_create(request.args.get("finding") if request.method == "GET" else form.finding_id.data)
    if finding is not None and finding.status == FindingStatus.linked:
        if request.method == "GET":
            abort(404)  # the link is done; there is nothing to prefill (phase 6 plan Q33)
        # The form was posted twice, or another admin linked the finding meanwhile (phase 6 S8a finding R12): say so.
        flash(f"Finding #{finding.id} is already linked to {finding.nhi.name}; nothing was registered.", "warning")
        return redirect(url_for("scanner.detail", run_id=finding.scan_run_id))
    if request.method == "GET":
        form.created_at.data = utcnow().date()
        if finding is not None:
            # Prefilled with the type and system guessed from the secret type, nothing else (spec 6.9, audit F05); the
            # fingerprint is set on save.
            guess = scanner_service.guess_for(finding)
            form.finding_id.data = str(finding.id)
            form.type.data = guess.nhi_type.value
            if guess.system is not None:
                form.system_id.data = guess.system.id
    nhi_type = _submitted_type(form)
    if form.is_submitted() and form.validate_for(nhi_type) and nhi_type is not None:
        if inventory_service.name_taken(form.system_id.data, form.name.data):
            form.name.errors.append("An identity with this name already exists on that system.")
        elif finding is not None:
            try:
                nhi = scanner_service.create_from_finding(finding, _fields_from(form, nhi_type), actor=current_actor(), now=utcnow())
            except TriageError as error:
                flash(str(error), "warning")
                return redirect(url_for("scanner.detail", run_id=finding.scan_run_id))
            flash(f"Registered {nhi.name} and linked finding #{finding.id}.", "success")
            return redirect(url_for("inventory.detail", nhi_id=nhi.id))
        else:
            nhi = inventory_service.create_nhi(_fields_from(form, nhi_type), actor=current_actor(), now=utcnow())
            flash(f"Registered {nhi.name}.", "success")
            return redirect(url_for("inventory.detail", nhi_id=nhi.id))
    return render_template("inventory/form.html", form=form, nhi=None, schema=ATTRIBUTE_SCHEMA, finding=finding)


@bp.get("/import")
@admin_required
def import_nhis() -> str:
    """S06: the upload form, the template link and the past batches (spec 6.3)."""
    return render_template(
        "inventory/import.html",
        form=ImportForm(),
        batches=importer_service.list_batches(),
        count=importer_service.count_batches(),
        columns=importer_service.TEMPLATE_COLUMNS,
        max_bytes=importer_service.MAX_BYTES,
        max_rows=importer_service.MAX_ROWS,
        now=utcnow(),
    )


@bp.get("/import/template.csv")
@admin_required
def import_template() -> Response:
    response = Response(importer_service.template_text(), mimetype="text/csv")
    response.headers["Content-Disposition"] = f'attachment; filename="{importer_service.TEMPLATE_FILENAME}"'
    return response


@bp.post("/import/preview")
@admin_required
def import_preview() -> str | Response:
    form = ImportForm()
    if not form.validate_on_submit():
        flash(next((errors[0] for errors in form.errors.values() if errors), "Choose a .csv file to import."), "warning")
        return redirect(url_for("inventory.import_nhis"))
    upload = form.file.data
    filename = (upload.filename or "import.csv")[:255]
    try:
        text = importer_service.decode(upload.read())
        plan = importer_service.validate(text, filename)
    except ImportError_ as error:
        flash(f"{filename}: {error}", "warning")
        return redirect(url_for("inventory.import_nhis"))
    commit_form = ImportCommitForm()
    commit_form.csv_text.data = text
    commit_form.filename.data = filename
    return render_template("inventory/import_preview.html", plan=plan, form=commit_form)


@bp.post("/import/commit")
@admin_required
def import_commit() -> Response:
    form = ImportCommitForm()
    if not form.validate_on_submit():
        flash("The preview has expired; upload the file again.", "warning")
        return redirect(url_for("inventory.import_nhis"))
    try:
        plan = importer_service.validate(form.csv_text.data, form.filename.data)
    except ImportError_ as error:
        flash(f"{form.filename.data}: {error}", "warning")
        return redirect(url_for("inventory.import_nhis"))
    batch = importer_service.commit(plan, actor=current_actor(), now=utcnow())
    flash(
        f"Imported {batch.filename}: {batch.rows_created} created, {batch.rows_updated} updated, {batch.rows_rejected} rejected of {batch.rows_total} rows.",
        "success" if batch.rows_rejected == 0 else "warning",
    )
    return redirect(url_for("inventory.import_nhis"))


@bp.route("/<int:nhi_id>/edit", methods=["GET", "POST"])
@admin_required
def edit(nhi_id: int) -> str | Response:
    nhi = _nhi_or_404(nhi_id)
    form = NhiForm(obj=nhi)
    _load_choices(form, nhi.owner)
    if request.method == "GET":
        form.type.data = nhi.type.value
        form.owner_id.data = nhi.owner_id or 0
        form.environment.data = nhi.environment.value
        form.privilege_level.data = nhi.privilege_level.value
        form.storage_location.data = nhi.storage_location.value
        form.fill_attributes(nhi.type, nhi.attributes)
    nhi_type = _submitted_type(form)
    if form.is_submitted() and form.validate_for(nhi_type) and nhi_type is not None:
        if inventory_service.name_taken(form.system_id.data, form.name.data, except_id=nhi.id):
            form.name.errors.append("An identity with this name already exists on that system.")
        else:
            inventory_service.update_nhi(nhi, _fields_from(form, nhi_type), actor=current_actor(), now=utcnow())
            flash(f"Saved {nhi.name}.", "success")
            return redirect(url_for("inventory.detail", nhi_id=nhi.id))
    return render_template("inventory/form.html", form=form, nhi=nhi, schema=ATTRIBUTE_SCHEMA)


def _action(nhi_id: int, apply: Callable[[Nhi], Nhi], success: Callable[[Nhi], str]) -> Response:
    """Run one lifecycle action and flash its outcome; success builds the message from data, never through str.format."""
    nhi = _nhi_or_404(nhi_id)
    try:
        apply(nhi)
    except (StatusError, ValueError) as error:
        flash(str(error), "warning")
    else:
        flash(success(nhi), "success")
    return redirect(url_for("inventory.detail", nhi_id=nhi.id))


@bp.post("/<int:nhi_id>/transfer")
@admin_required
def transfer(nhi_id: int) -> Response:
    owner_id = parse_id(request.form.get("new_owner_id", ""))
    new_owner = db.session.get(Person, owner_id) if owner_id is not None else None
    if new_owner is None:
        flash("Choose the person who takes over this identity.", "warning")
        return redirect(url_for("inventory.detail", nhi_id=nhi_id))
    return _action(
        nhi_id,
        lambda nhi: inventory_service.transfer_owner(nhi, new_owner, actor=current_actor(), now=utcnow()),
        lambda nhi: f"Transferred {nhi.name} to {new_owner.full_name}.",
    )


@bp.post("/<int:nhi_id>/rotate")
@admin_required
def rotate(nhi_id: int) -> Response:
    return _action(nhi_id, lambda nhi: inventory_service.record_rotation(nhi, actor=current_actor(), now=utcnow()), lambda nhi: f"Recorded a rotation of {nhi.name}.")


@bp.post("/<int:nhi_id>/revoke")
@admin_required
def revoke(nhi_id: int) -> Response:
    return _action(nhi_id, lambda nhi: inventory_service.revoke(nhi, actor=current_actor(), now=utcnow()), lambda nhi: f"Revoked {nhi.name}.")


@bp.post("/<int:nhi_id>/decommission")
@admin_required
def decommission(nhi_id: int) -> Response:
    return _action(nhi_id, lambda nhi: inventory_service.decommission(nhi, actor=current_actor(), now=utcnow()), lambda nhi: f"Decommissioned {nhi.name}.")
