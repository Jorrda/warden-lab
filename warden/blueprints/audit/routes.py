"""S14 audit log (spec 6.8): filters by actor, action, entity type and date range, pages of
100 rows newest first, each row expandable to its before and after values. Read-only and
viewer-readable: login_required only, no form but the filters; the viewer sees the failed-login
username masked (warden.services.audit.VIEWER_MASKED)."""
from __future__ import annotations

from datetime import date

from flask import Blueprint, render_template, request, url_for
from flask_login import current_user, login_required

from warden.models import AuditEvent, UserRole
from warden.models.types import utcnow
from warden.routing import page_number, parse_id
from warden.services import audit as audit_service
from warden.services.audit import ACTOR_SYSTEM, LogQuery

bp = Blueprint("audit", __name__, url_prefix="/audit")

# The entity pages the log links to; the other entity types have no page of their own.
ENTITY_PAGES: dict[str, tuple[str, str]] = {
    "nhis": ("inventory.detail", "nhi_id"),
    "people": ("people.detail", "person_id"),
    "systems": ("systems.detail", "system_id"),
    "offboarding_cases": ("offboarding.detail", "case_id"),
    "scan_runs": ("scanner.detail", "run_id"),
}
# Rows whose page is their parent's, found through a key of the payload (an item links to its case, a finding to its run).
PARENT_PAGES: dict[str, tuple[str, str, str]] = {
    "offboarding_items": ("case_id", "offboarding.detail", "case_id"),
    "findings": ("scan_run_id", "scanner.detail", "run_id"),
}


def _date_arg(name: str) -> date | None:
    raw = request.args.get(name, "").strip()
    try:
        return date.fromisoformat(raw) if raw else None
    except ValueError:
        return None


def _parse_query(actions: list[str], entity_types: list[str]) -> LogQuery:
    actor = request.args.get("actor", "")
    action = request.args.get("action", "")
    entity_type = request.args.get("entity_type", "")
    return LogQuery(
        actor=actor if actor == ACTOR_SYSTEM or parse_id(actor) is not None else "",
        action=action if action in actions else "",
        entity_type=entity_type if entity_type in entity_types else "",
        date_from=_date_arg("date_from"),
        date_to=_date_arg("date_to"),
        page=page_number(request.args.get("page", "1")),
    )


def entity_url(event: AuditEvent) -> str | None:
    """The page of the row's entity, when it has one; an item links to its case, a finding to its run, a batch to the import page."""
    if event.entity_type in PARENT_PAGES:
        key, endpoint, parameter = PARENT_PAGES[event.entity_type]
        payload = event.after or event.before or {}
        parent_id = payload.get(key)
        return url_for(endpoint, **{parameter: parent_id}) if isinstance(parent_id, int) else None
    if event.entity_type == "import_batches":
        return url_for("inventory.import_nhis") if current_user.role == UserRole.admin else None  # the page is admin-only; the viewer keeps the text
    if event.entity_id is None or event.entity_type not in ENTITY_PAGES:
        return None
    endpoint, parameter = ENTITY_PAGES[event.entity_type]
    return url_for(endpoint, **{parameter: event.entity_id})


@bp.get("/")
@login_required
def log() -> str:
    actions = audit_service.actions()
    entity_types = audit_service.entity_types()
    query = _parse_query(actions, entity_types)
    page = audit_service.search(query)
    filters = {  # the set filters only, so the pager's links carry nothing empty
        name: value
        for name, value in (
            ("actor", query.actor),
            ("action", query.action),
            ("entity_type", query.entity_type),
            ("date_from", query.date_from.isoformat() if query.date_from else ""),
            ("date_to", query.date_to.isoformat() if query.date_to else ""),
        )
        if value
    }
    return render_template(
        "audit/log.html",
        page=page,
        query=query,
        filters=filters,
        actors=audit_service.actors(),
        actions=actions,
        entity_types=entity_types,
        entity_url=entity_url,
        rows_of=lambda event: audit_service.masked_rows(event, viewer=current_user.role != UserRole.admin),
        actor_system=ACTOR_SYSTEM,
        now=utcnow(),
    )
