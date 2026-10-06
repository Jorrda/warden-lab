"""Role checks (CLAUDE.md 5): @require_role fails closed, and current_actor()
turns the request into the Actor that services record in the audit log."""
from __future__ import annotations

from collections.abc import Callable
from functools import wraps
from typing import Any

from flask import abort, request
from flask_login import current_user

from warden.extensions import login_manager
from warden.models.enums import UserRole
from warden.services.audit import Actor


def require_role(*roles: UserRole) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Allow the view only to a signed-in user whose role is one of roles.

    Anonymous: the Flask-Login unauthorized response (redirect to the login
    page with next). Signed in with another role: 403. Nothing else passes.
    """
    allowed = frozenset(roles)

    def decorator(view: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(view)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if current_user.role not in allowed:
                abort(403)
            return view(*args, **kwargs)

        return wrapped

    return decorator


admin_required = require_role(UserRole.admin)


def current_actor() -> Actor:
    """The signed-in user (or None) with the request's address and user agent."""
    user_id = current_user.id if current_user.is_authenticated else None
    return Actor(user_id=user_id, ip=request.remote_addr, user_agent=request.user_agent.string or None)
