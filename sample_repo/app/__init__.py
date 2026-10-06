"""FleetLine portal application factory."""
from flask import Flask

from config.settings import load_settings


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.update(load_settings())
    return app
