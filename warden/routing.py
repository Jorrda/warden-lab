"""The URL map's converters. Mental model: a converter is a route parameter type.

Registered in create_app() before the blueprints, so every `<int:...>` rule
carries the bound with no change at the decorators (whole-branch finding I2).
"""
from __future__ import annotations

from werkzeug.routing import IntegerConverter

ID_DIGITS = 9  # an id longer than this is treated as absent; int() would refuse thousands of digits


def parse_id(raw: str) -> int | None:
    """A query-string or form id: at most ID_DIGITS decimal digits, else None (the bound the path converter keeps)."""
    return int(raw) if raw.isdecimal() and len(raw) <= ID_DIGITS else None


def page_number(raw: str) -> int:
    """A page argument: a bounded positive integer, else the first page."""
    value = parse_id(raw)
    return value if value is not None and value >= 1 else 1


class BoundedIntConverter(IntegerConverter):
    """A path id has at most nine decimal digits; anything else is a 404.

    This is the bound the query-string and form ids keep too, in
    parse_id() above. Without it a path id of
    twenty digits reaches SQLite, which stores 64 bits and raises
    OverflowError, and one of thousands of digits fails in int() itself.
    """

    regex = rf"\d{{1,{ID_DIGITS}}}"
