"""S10 posture report, S11 policy page and the dashboard's recompute button (spec 6.6 and 5.2).

Both pages are read-only and viewer-readable (decision D-056, audit F17). The
report's footer prints the server time its data took to assemble, measured
with perf_counter around the queries (audit F11); spec 10 budgets it under
one second.
"""
from __future__ import annotations

import time

from flask import Blueprint, Response, flash, redirect, render_template, url_for
from flask_login import login_required

from warden.blueprints.auth.access import admin_required, current_actor
from warden.models import RiskTrigger
from warden.models.types import utcnow
from warden.services import reports, risk
from warden.services.risk_policy import POLICY_V1

bp = Blueprint("risk", __name__, url_prefix="/risk")

TOP_IN_REPORT = 20


@bp.get("/report")
@login_required
def report() -> str:
    started = time.perf_counter()
    now = utcnow()
    summary = reports.posture_summary()
    top = reports.top_riskiest(TOP_IN_REPORT)
    orphans = reports.orphans()
    expiring = reports.expiring()
    cases = reports.open_cases()
    elapsed_ms = (time.perf_counter() - started) * 1000
    return render_template(
        "risk/report.html",
        summary=summary,
        top=top,
        orphans=orphans,
        expiring=expiring,
        cases=cases,
        policy=POLICY_V1,
        generated_at=now,
        elapsed_ms=elapsed_ms,
        now=now,
    )


@bp.get("/policy")
@login_required
def policy() -> str:
    return render_template("risk/policy.html", policy=POLICY_V1)


@bp.post("/recompute")
@admin_required
def recompute() -> Response:
    result = risk.recompute_all(now=utcnow(), trigger=RiskTrigger.manual, actor=current_actor())
    flash(f"Recomputed {result.count} identities in {result.elapsed_ms} ms: {result.summary()}.", "success")
    return redirect(url_for("dashboard.index"))
