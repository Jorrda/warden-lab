"""S01 login and logout (spec 6.1). Thin handlers: parse, call the service, redirect.

A successful login always lands on the dashboard; Flask-Login's next parameter
is ignored, so there is no redirect target to validate (phase 3 audit F18).
"""
from __future__ import annotations

from flask import Blueprint, Response, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user

from warden.blueprints.auth.access import current_actor
from warden.blueprints.auth.forms import LoginForm
from warden.models.types import utcnow
from warden.services import auth as auth_service

bp = Blueprint("auth", __name__, url_prefix="/auth")


@bp.route("/login", methods=["GET", "POST"])
def login() -> str | Response:
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))
    form = LoginForm()
    if request.method == "GET":
        return render_template("auth/login.html", form=form)
    if not form.validate_on_submit():
        flash("Enter your username and password.", "danger")
        return redirect(url_for("auth.login"))
    result = auth_service.authenticate(
        form.username.data,
        form.password.data,
        throttle=current_app.extensions["login_throttle"],
        now=utcnow(),
        actor=current_actor(),
    )
    if not result.ok:
        flash(result.message or auth_service.GENERIC_MESSAGE, "danger")
        return redirect(url_for("auth.login"))
    login_user(result.user)
    flash(f"Signed in as {result.user.username}.", "success")
    return redirect(url_for("dashboard.index"))


@bp.post("/logout")
@login_required
def logout() -> Response:
    auth_service.sign_out(current_user, now=utcnow(), actor=current_actor())
    logout_user()
    flash("Signed out.", "info")
    return redirect(url_for("auth.login"))
