"""Application factory. Mental model: create_app() is NestFactory.create()."""
from __future__ import annotations

import os
import secrets
from pathlib import Path

import click
from flask import Flask, Response, make_response, render_template
from sqlalchemy.engine import make_url
from sqlalchemy.exc import OperationalError

from warden.config import Config
from warden.extensions import csrf, db, login_manager
from warden.filters import register_filters
from warden.routing import BoundedIntConverter
from warden.services.auth import LoginThrottle

__all__ = ["create_app"]

SECURITY_HEADERS: dict[str, str] = {
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
    # Keeps a signed-in page out of the browser's back/forward cache, so Back after a sign-out
    # cannot redisplay it. Applied with setdefault, so a static file keeps its own directive.
    "Cache-Control": "no-store",
}


def create_app(config: Config | None = None, *, instance_path: str | None = None) -> Flask:
    app = Flask(__name__, instance_path=instance_path)
    cfg = config or Config()
    app.config.from_object(cfg)

    os.makedirs(app.instance_path, exist_ok=True)
    default_db = "sqlite:///" + (Path(app.instance_path) / "warden.db").as_posix()
    app.config["SQLALCHEMY_DATABASE_URI"] = cfg.DATABASE_URL or default_db
    app.config["SCAN_BASE"] = str(Path(cfg.SCAN_BASE).resolve() if cfg.SCAN_BASE else Path(app.root_path).parent.resolve())
    # What S15 prints for the base: a fixed phrase, never the machine path (S4 finding O6).
    app.config["SCAN_BASE_LABEL"] = "the configured scan base (WARDEN_SCAN_BASE)" if cfg.SCAN_BASE else "the folder holding app.py"

    db.init_app(app)
    csrf.init_app(app)
    app.extensions["login_throttle"] = LoginThrottle()  # in-memory sign-in throttle, one per app (D-049)
    _configure_login(app)
    app.url_map.converters["int"] = BoundedIntConverter  # bounds every <int:...> rule, so no path id reaches the database oversized
    _register_blueprints(app)
    _register_error_handlers(app)
    _register_security_headers(app)
    register_filters(app)
    _register_cli(app)
    return app


def _configure_login(app: Flask) -> None:
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message_category = "warning"

    @login_manager.user_loader
    def load_user(user_id: str) -> "User | None":
        # Flask-Login stores str(user.id) in the session; an unknown or malformed id means anonymous.
        from warden.models import User

        try:
            return db.session.get(User, int(user_id))
        except (TypeError, ValueError):
            return None


def _register_blueprints(app: Flask) -> None:
    from warden.blueprints.audit import bp as audit_bp
    from warden.blueprints.auth import bp as auth_bp
    from warden.blueprints.dashboard import bp as dashboard_bp
    from warden.blueprints.inventory import bp as inventory_bp
    from warden.blueprints.offboarding import bp as offboarding_bp
    from warden.blueprints.people import bp as people_bp
    from warden.blueprints.risk import bp as risk_bp
    from warden.blueprints.scanner import bp as scanner_bp
    from warden.blueprints.systems import bp as systems_bp

    app.register_blueprint(dashboard_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(inventory_bp)
    app.register_blueprint(people_bp)
    app.register_blueprint(systems_bp)
    app.register_blueprint(risk_bp)
    app.register_blueprint(offboarding_bp)
    app.register_blueprint(scanner_bp)
    app.register_blueprint(audit_bp)


def _register_error_handlers(app: Flask) -> None:
    @app.errorhandler(400)
    def bad_request(error: Exception) -> tuple[str, int]:
        # Flask-WTF's CSRFError is a BadRequest, so a missing or stale token lands here too.
        return render_template("errors/400.html", description=getattr(error, "description", "")), 400

    @app.errorhandler(403)
    def forbidden(_error: Exception) -> tuple[str, int]:
        return render_template("errors/403.html"), 403

    @app.errorhandler(404)
    def not_found(_error: Exception) -> tuple[str, int]:
        return render_template("errors/404.html"), 404

    @app.errorhandler(413)
    def too_large(_error: Exception) -> tuple[str, int]:
        # MAX_CONTENT_LENGTH (spec 7, the upload size limit): Werkzeug refuses the body before any view runs.
        return render_template("errors/413.html", limit=app.config["MAX_CONTENT_LENGTH"]), 413

    @app.errorhandler(405)
    def method_not_allowed(error: Exception) -> Response:
        # Keep the Allow header Werkzeug's MethodNotAllowed carries (RFC 9110 section 15.5.6).
        response = make_response(render_template("errors/405.html"), 405)
        allowed = getattr(error, "valid_methods", None)
        if allowed:
            response.headers["Allow"] = ", ".join(sorted(allowed))
        return response

    @app.errorhandler(500)
    def server_error(error: Exception) -> tuple[str, int]:
        db.session.rollback()
        app.logger.exception("Unhandled error: %s", error)
        return render_template("errors/500.html"), 500


def _register_security_headers(app: Flask) -> None:
    @app.after_request
    def set_security_headers(response: Response) -> Response:
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        return response


def _register_cli(app: Flask) -> None:
    @app.cli.command("init-db")
    def init_db() -> None:
        """Create the database schema for every model registered in warden.models."""
        import warden.models  # noqa: F401  (imports register tables on db.metadata)

        db.create_all()
        url = make_url(app.config["SQLALCHEMY_DATABASE_URI"])
        click.echo(f"Initialised database at {url.render_as_string(hide_password=True)}")

    @app.cli.command("seed")
    def seed() -> None:
        """Load the deterministic FleetLine demo dataset into an empty database."""
        import warden.models  # noqa: F401
        from warden.models import RiskTrigger
        from warden.models.types import utcnow
        from warden.seed.generator import generate, table_counts
        from warden.services import risk

        try:
            existing = table_counts()
        except OperationalError:
            raise click.ClickException("No schema found. Run `flask --app app init-db` first.") from None
        populated = {name: count for name, count in existing.items() if count}
        if populated:
            summary = ", ".join(f"{name}={count}" for name, count in populated.items())
            raise click.ClickException(
                f"The database already holds data ({summary}); nothing was changed. "
                "To reseed, delete the database file, then run init-db and seed again."
            )
        passwords: dict[str, str] = {}
        generated: list[str] = []
        for account, variable in (("admin", "WARDEN_ADMIN_PASSWORD"), ("viewer", "WARDEN_VIEWER_PASSWORD")):
            raw = os.environ.get(variable, "")
            value = raw if raw.strip() else ""
            if not value:
                value = secrets.token_urlsafe(12)
                generated.append(account)
            passwords[account] = value
        now = utcnow()
        report = generate(now=now, admin_password=passwords["admin"], viewer_password=passwords["viewer"])
        # The post-seed recompute of spec 5.2 at the seed's own instant, so every age is the
        # drawn offset; recompute_all commits the dataset and the assessments together (D-056).
        scored = risk.recompute_all(now=now, trigger=RiskTrigger.seed, actor=None)
        click.echo(
            f"Seeded {report.people} people, {report.users} users, {report.systems} systems, "
            f"{report.scopes} scopes, {report.nhis} NHIs and {report.audit_events} audit rows."
        )
        click.echo(f"Scored {scored.count} identities with policy {scored.policy_version}: {scored.summary()}.")
        click.echo("Dates are offsets from the seed time, so these counts hold today; before a demo, delete the database file and seed again.")
        for account in generated:
            click.echo(f"Generated password for {account} (shown once, stored only as a hash): {passwords[account]}")
        if generated:
            click.echo("Set WARDEN_ADMIN_PASSWORD and WARDEN_VIEWER_PASSWORD in .env to choose the passwords yourself.")

    @app.cli.command("recompute-risk")
    def recompute_risk() -> None:
        """Recompute every identity's risk score with the current policy (spec 5.2, trigger manual)."""
        import warden.models  # noqa: F401
        from warden.models import RiskTrigger
        from warden.models.types import utcnow
        from warden.services import risk

        try:
            report = risk.recompute_all(now=utcnow(), trigger=RiskTrigger.manual, actor=None)
        except OperationalError:
            raise click.ClickException("No schema found. Run `flask --app app init-db` first.") from None
        click.echo(f"Recomputed {report.count} identities in {report.elapsed_ms} ms with policy {report.policy_version}: {report.summary()}.")
