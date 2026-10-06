"""S15 scan runs and S16 run detail with the triage actions (spec 6.9)."""
from __future__ import annotations

from pathlib import Path

from flask import Blueprint, Response, abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import login_required

from warden.blueprints.auth.access import admin_required, current_actor
from warden.blueprints.scanner.forms import LinkForm, ScanForm, TriageForm
from warden.extensions import db
from warden.models import Finding, Nhi, ScanRun
from warden.models.types import utcnow
from warden.services import scanner as scanner_service
from warden.services.scanner import TargetError

bp = Blueprint("scanner", __name__, url_prefix="/scanner")


def scan_base() -> Path:
    return Path(current_app.config["SCAN_BASE"])


def app_root() -> Path:
    """The folder holding app.py, whose own .env a scan never reads (S4 finding O3)."""
    return Path(current_app.root_path).parent


def _percent(value: float | None) -> str:
    return "n/a" if value is None else f"{round(100 * value)}%"


@bp.get("/")
@login_required
def list_runs() -> str:
    form = ScanForm()
    form.target.data = current_app.config["SCAN_TARGET"]
    targets = scanner_service.targets()
    selected = request.args.get("target", "")
    if selected not in targets:
        selected = ""  # a value never scanned widens the filter, the phase 3 rule for query strings
    runs = scanner_service.list_runs(selected)
    count = len(runs)
    total = count if not selected else len(scanner_service.list_runs())  # the page names the whole only when filtered
    return render_template(
        "scanner/list.html",
        runs=runs,
        count=count,
        total=total,
        targets=targets,
        selected=selected,
        form=form,
        base=str(scan_base()),
        base_label=current_app.config["SCAN_BASE_LABEL"],
        percent=_percent,
        now=utcnow(),
    )


@bp.post("/run")
@admin_required
def run() -> Response:
    form = ScanForm()
    if not form.validate_on_submit():
        flash("Enter a directory to scan, or leave the field as it is.", "warning")
        return redirect(url_for("scanner.list_runs"))
    target = form.target.data or current_app.config["SCAN_TARGET"]
    try:
        scan = scanner_service.run_scan(target, base=scan_base(), own_config=app_root(), actor=current_actor(), now=utcnow())
    except TargetError as error:
        flash(str(error), "warning")
        return redirect(url_for("scanner.list_runs"))
    elapsed_ms = round((scan.finished_at - scan.started_at).total_seconds() * 1000)
    noun = "finding" if scan.findings_count == 1 else "findings"
    summary = f"Scanned {scan.files_scanned} files in {elapsed_ms} ms: {scan.findings_count} {noun}"
    if scan.recall is not None:
        summary += f", recall {_percent(scan.recall)}, precision {_percent(scan.precision)}"
    flash(summary + ".", "success")
    return redirect(url_for("scanner.detail", run_id=scan.id))


def _run_or_404(run_id: int) -> ScanRun:
    scan = scanner_service.load_run(run_id)
    if scan is None:
        abort(404)
    return scan


@bp.get("/<int:run_id>")
@login_required
def detail(run_id: int) -> str:
    scan = _run_or_404(run_id)
    findings = scanner_service.run_findings(scan)
    nhis = list(db.session.execute(db.select(Nhi).order_by(Nhi.name)).scalars())
    return render_template(
        "scanner/detail.html",
        run=scan,
        findings=findings,
        comparison=scanner_service.comparison_of(scan, base=scan_base()),
        suggestions=scanner_service.suggestions(scan),
        nhis=nhis,
        percent=_percent,
        trail=scanner_service.run_trail(scan),
        now=utcnow(),
    )


def _finding_or_404(run_id: int, finding_id: int) -> Finding:
    finding = db.session.get(Finding, finding_id)
    if finding is None or finding.scan_run_id != run_id:
        abort(404)
    return finding


def _back(run_id: int, finding_id: int) -> Response:
    return redirect(url_for("scanner.detail", run_id=run_id) + f"#finding-{finding_id}")


@bp.post("/<int:run_id>/findings/<int:finding_id>/confirm")
@admin_required
def confirm(run_id: int, finding_id: int) -> Response:
    finding = _finding_or_404(run_id, finding_id)
    if not TriageForm().validate_on_submit():
        abort(400)
    if scanner_service.confirm(finding, actor=current_actor(), now=utcnow()):
        flash(f"Confirmed finding #{finding.id} ({finding.file_path}:{finding.line_no}).", "success")
    else:
        flash(f"No change to finding #{finding.id}: confirmed was already recorded.", "info")
    return _back(run_id, finding_id)


@bp.post("/<int:run_id>/findings/<int:finding_id>/false-positive")
@admin_required
def false_positive(run_id: int, finding_id: int) -> Response:
    finding = _finding_or_404(run_id, finding_id)
    if not TriageForm().validate_on_submit():
        abort(400)
    if scanner_service.mark_false_positive(finding, actor=current_actor(), now=utcnow()):
        flash(f"Marked finding #{finding.id} ({finding.file_path}:{finding.line_no}) a false positive.", "success")
    else:
        flash(f"No change to finding #{finding.id}: false positive was already recorded.", "info")
    return _back(run_id, finding_id)


@bp.post("/<int:run_id>/findings/<int:finding_id>/link")
@admin_required
def link(run_id: int, finding_id: int) -> Response:
    finding = _finding_or_404(run_id, finding_id)
    form = LinkForm()
    if not form.validate_on_submit():
        flash("Choose the identity to link the finding to.", "warning")
        return _back(run_id, finding_id)
    nhi = db.session.get(Nhi, form.nhi_id.data)
    if nhi is None:
        flash("Choose the identity to link the finding to.", "warning")
        return _back(run_id, finding_id)
    if scanner_service.link(finding, nhi, actor=current_actor(), now=utcnow()):
        flash(f"Linked finding #{finding.id} to {nhi.name}.", "success")
    else:
        flash(f"No change to finding #{finding.id}: it is already linked to {nhi.name}.", "info")
    return _back(run_id, finding_id)
