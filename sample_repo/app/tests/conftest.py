import pytest

from app import create_app

TEST_PASSWORD = "welcome1"


@pytest.fixture()
def client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()
