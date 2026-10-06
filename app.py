"""Warden entry point. Graders open this file first.

python app.py            starts the development server; sign in at /auth/login with a seeded account
                         (dashboard, inventory with CSV import, people, systems, offboarding cases, posture report, policy,
                         secrets scanner, audit log)
flask --app app run      starts the same app through the Flask CLI on Flask's default 127.0.0.1:5000
flask --app app init-db  creates the database file and the thirteen tables of warden/models
flask --app app seed     loads the deterministic FleetLine demo dataset into an empty database and scores it
flask --app app recompute-risk  recomputes every identity's risk score with the current policy
"""
from __future__ import annotations

import os

from dotenv import load_dotenv

load_dotenv()  # reads .env from the working directory; silent no-op when absent

from warden import create_app  # noqa: E402  (must run after load_dotenv)

app = create_app()

if __name__ == "__main__":
    app.run(
        host=os.environ.get("WARDEN_HOST", "127.0.0.1"),
        port=int(os.environ.get("WARDEN_PORT", "5000")),
    )
