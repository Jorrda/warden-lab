"""Jinja filters and the two form helpers every blueprint form shares.

ago() gives whole elapsed days, the age rule of decision D-045, so what a
page says matches what the risk engine will count. label() turns an enum
value or snake_case string into display text; enum_choices() builds a
SelectField's choices from it. EMAIL_PATTERN is the conservative email check
the forms use instead of WTForms' Email validator (no email_validator package).
"""
from __future__ import annotations

from datetime import datetime

from flask import Flask

from warden.models.types import utcnow

EMAIL_PATTERN = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
URL_PATTERN = r"^https?://\S+$"  # the S05 form's target_url rule, mirrored by the importer (phase 7 audit F21)

LABELS: dict[str, str] = {
    "api_key": "API key",
    "oauth_grant": "OAuth grant",
    "ci_token": "CI token",
    "ai_agent": "AI agent",
    "ai_agent_platform": "AI agent platform",
    "ci_cd": "CI/CD",
    "erp": "ERP",
    "saas": "SaaS",
    "env_var": "Environment variable",
    "config_file": "Config file",
    "chat_or_ticket": "Chat or ticket",
    "source_code": "Source code",
    "prod": "Production",
    "dev": "Development",
}


def ago(value: datetime | None, now: datetime | None = None) -> str:
    """'never', 'today', 'N days ago' or 'in N days', in whole elapsed days."""
    if value is None:
        return "never"
    reference = now or utcnow()
    if value > reference:
        ahead = (value - reference).days
        if ahead == 0:
            return "later today"
        return "in 1 day" if ahead == 1 else f"in {ahead} days"
    days = (reference - value).days
    if days == 0:
        return "today"
    return "1 day ago" if days == 1 else f"{days} days ago"


def isodate(value: datetime | None) -> str:
    """The calendar date in UTC, or an empty string."""
    return "" if value is None else value.date().isoformat()


def label(value: object) -> str:
    """Display text for an enum member or snake_case string."""
    if value is None:
        return ""
    text = str(value)
    return LABELS.get(text, text.replace("_", " ").capitalize())


def enum_choices(enum_class: type) -> list[tuple[str, str]]:
    """(value, display text) pairs for a SelectField over an enum."""
    return [(member.value, label(member)) for member in enum_class]


def register_filters(app: Flask) -> None:
    app.add_template_filter(ago)
    app.add_template_filter(isodate)
    app.add_template_filter(label)
