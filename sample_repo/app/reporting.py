"""Nightly reports read from the analytics replica."""
import sqlalchemy

REPORTS_DSN = "mysql://reports_ro:5X7WGfgmZum4PmRQBbkxpP@mysql-analytics.fleetline.internal:3306/reports"


def engine() -> sqlalchemy.Engine:
    return sqlalchemy.create_engine(REPORTS_DSN)
