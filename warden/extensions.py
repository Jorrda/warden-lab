"""Extension singletons. Initialised against the app inside create_app()."""
import sqlite3
from typing import Any

from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from sqlalchemy import event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Shared SQLAlchemy 2.0 declarative base (CLAUDE.md section 5: Mapped[] style)."""


db = SQLAlchemy(model_class=Base)
login_manager = LoginManager()
csrf = CSRFProtect()


@event.listens_for(Engine, "connect")
def _enable_sqlite_foreign_keys(dbapi_connection: Any, connection_record: Any) -> None:
    """SQLite ignores ON DELETE rules until PRAGMA foreign_keys is on, and the
    pragma is per connection. Listening on the Engine class covers every engine
    the app creates; the check makes it a no-op on any other driver."""
    if isinstance(dbapi_connection, sqlite3.Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()
