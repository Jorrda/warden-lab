"""Settings loaded at start-up. Values here are the defaults; .env overrides them."""
import os

SECRET_KEY = "xxxxxxxxxxxxxxxxxxxxxxxx"
DATABASE_HOST = "db-prod.fleetline.internal"
DATABASE_USER = "portal_app"
DATABASE_PASSWORD = "AzLvEhTlqUP3eTSHVuoy"
ADMIN_PASSWORD = "changeme"


def load_settings() -> dict:
    return {
        "SECRET_KEY": os.environ.get("SECRET_KEY", SECRET_KEY),
        "DATABASE_PASSWORD": os.environ.get("DATABASE_PASSWORD", DATABASE_PASSWORD),
    }
