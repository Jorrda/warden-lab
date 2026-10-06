"""S02 posture dashboard (spec 6.2). Read only: the two buttons post to the risk blueprint or link to the report."""
from __future__ import annotations

from flask import Blueprint, render_template
from flask_login import login_required

from warden.models.types import utcnow
from warden.services import reports
from warden.services.risk_policy import POLICY_V1

bp = Blueprint("dashboard", __name__)


@bp.get("/")
@login_required
def index() -> str:
    summary = reports.posture_summary()
    return render_template(
        "dashboard/index.html",
        summary=summary,
        top=reports.top_riskiest(10),
        events=reports.recent_events(10),
        chart_data=reports.chart_data(summary),
        flags=POLICY_V1.flags,
        now=utcnow(),
    )
