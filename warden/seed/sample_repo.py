"""The synthetic repository the scanner is measured against (spec section 9).

build_corpus() returns every file of sample_repo/ as bytes, keyed by its path
relative to the root with forward slashes, and the ground truth that goes with
it. write_corpus() writes them to disk; scripts/gen_sample_repo.py is the
command, and tests/test_scanner.py fails when the committed folder drifts from
a fresh build, the way the data dictionary is guarded.

The corpus is a small fictitious FleetLine portal: 45 text files and one PNG
across Python, JavaScript, YAML, JSON, Terraform, shell, a Dockerfile, a
Bitbucket pipeline, an .env file and Markdown. The portal's own .gitignore
does not list .env: git honours a nested .gitignore, and the planted .env has
to reach the repository (the top-level .gitignore already negates it). It plants the twenty true
secrets of spec section 9: the twelve literals of synthetic_literals(), whose
fingerprints the seed already stores on the twelve source_code identities
(decision D-042), plus the eight of extra_literals(); and twelve decoys the
scanner must not report, six caught by the placeholder allowlist, two by the
entropy threshold, and four by the shape of a detector (a Stripe test-mode
key in a plainly named variable, a public key block, a URI without
credentials, one JWT segment). Every literal is synthetic and matches nothing
real; the shapes are what the detectors look for.

ground_truth.json lists each true secret by file, line and detector name and
each decoy by file, line and reason. Line numbers are found by searching the
rendered file for the literal, so a change to a file's text moves them
without any hand edit. Nothing here depends on the clock.
"""
from __future__ import annotations

import json
import shutil
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from warden.seed.synthetic_secrets import extra_literals, synthetic_literals

GENERATOR = "scripts/gen_sample_repo.py"
GROUND_TRUTH_FILE = "ground_truth.json"


@dataclass(frozen=True)
class Plant:
    """A literal placed in a file: a true secret with its detector name, or a decoy with the reason it is one."""

    kind: str  # "secret" or "decoy"
    label: str  # the detector name of a secret; the reason of a decoy
    literal: str


@dataclass(frozen=True)
class CorpusFile:
    path: str
    content: bytes
    plants: tuple[Plant, ...] = ()


# The five placeholders of the allowlist appear here as decoy values; PLACEHOLDERS is the scanner's list.
DECOY_CHANGEME = "changeme"
DECOY_YOUR_KEY = "<your-key>"
DECOY_AWS_DOCS_KEY = "AKIAIOSFODNN7EXAMPLE"  # the key id the AWS documentation uses in every example
DECOY_XXX = "xxxxxxxxxxxxxxxxxxxxxxxx"
DECOY_AKIAEXAMPLE = "AKIAEXAMPLEKEY000000"
DECOY_LOW_ENTROPY_PASSWORD = "password123"
DECOY_EXAMPLE_TOKEN = "example-token-value"
DECOY_PUBLIC_KEY = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfleetlinefleetlinefleetlinefleetl\n"
    "inefleetlinefleetlinefleetlinefleetlinefleetlinefleetlinefleetline00\n"
    "-----END PUBLIC KEY-----"
)
DECOY_STRIPE_TEST_KEY = "sk_test_4eC39HqLyjWDarjtT1zdp7dc"
DECOY_URI_WITHOUT_CREDENTIALS = "postgresql://localhost:5432/fleetline"
DECOY_WELCOME = "welcome1"
DECOY_JWT_SEGMENT = "eyJhbGciOiJIUzI1NiJ9"

LOGO_PNG = (
    b"\x89PNG\r\n\x1a\n"
    + struct.pack(">I", 13) + b"IHDR" + struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0) + struct.pack(">I", zlib.crc32(b"IHDR" + struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)))
    + (lambda data: struct.pack(">I", len(data)) + b"IDAT" + data + struct.pack(">I", zlib.crc32(b"IDAT" + data)))(zlib.compress(b"\x00\x1f\x77\xb4"))
    + struct.pack(">I", 0) + b"IEND" + struct.pack(">I", zlib.crc32(b"IEND"))
)


def _text(path: str, text: str, *plants: Plant) -> CorpusFile:
    return CorpusFile(path, text.encode("utf-8"), plants)


def build_corpus() -> list[CorpusFile]:
    """Every file of the corpus, in path order, with the literals each one plants."""
    seed = dict(synthetic_literals())
    extra = dict(extra_literals())
    files = [
        _text(
            "README.md",
            "# FleetLine portal\n\n"
            "Customer and driver portal of FleetLine Logistics. Python backend, static frontend, Terraform for the AWS account.\n\n"
            "## Configuration\n\n"
            "Copy `.env.example` to `.env` and fill in the values. Third-party keys go in `config/integrations.yaml`:\n\n"
            "```yaml\n"
            f'api_key = "{DECOY_YOUR_KEY}"\n'
            "```\n\n"
            "Run `make dev` for a local server and `make test` for the suite.\n",
            Plant("decoy", "placeholder <your-key>", DECOY_YOUR_KEY),
        ),
        _text(
            ".env",
            "# Local settings for the portal. Never commit this file.\n"
            "FLASK_ENV=development\n"
            f"AWS_ACCESS_KEY_ID={seed['aws_access_key_id']}\n"
            f"AWS_SECRET_ACCESS_KEY={seed['aws_secret_access_key']}\n"
            "AWS_DEFAULT_REGION=eu-central-1\n"
            "PORTAL_BASE_URL=http://127.0.0.1:8000\n",
            Plant("secret", "aws_access_key_id", seed["aws_access_key_id"]),
            Plant("secret", "aws_secret_access_key", seed["aws_secret_access_key"]),
        ),
        _text(
            ".env.example",
            "# Copy to .env and fill in. Leave a value empty to disable the integration.\n"
            "FLASK_ENV=development\n"
            "AWS_ACCESS_KEY_ID=\n"
            "AWS_SECRET_ACCESS_KEY=\n"
            "AWS_DEFAULT_REGION=eu-central-1\n"
            "PORTAL_BASE_URL=http://127.0.0.1:8000\n",
        ),
        # No .env line: git honours a nested .gitignore, and the planted .env must reach the repository (spec 9, CLAUDE.md 8).
        _text(".gitignore", ".venv/\n__pycache__/\n*.pyc\nnode_modules/\nweb/static/dist/\n"),
        _text(
            "Dockerfile",
            "FROM python:3.12-slim\n"
            "WORKDIR /srv/portal\n"
            "COPY requirements.txt .\n"
            "RUN pip install --no-cache-dir -r requirements.txt\n"
            "COPY . .\n"
            "ENV FLASK_ENV=production\n"
            'CMD ["gunicorn", "-b", "0.0.0.0:8000", "app:create_app()"]\n',
        ),
        _text(
            "docker-compose.yml",
            "services:\n"
            "  portal:\n"
            "    build: .\n"
            "    ports:\n"
            '      - "8000:8000"\n'
            "    environment:\n"
            f"      DATABASE_URL: {seed['database_uri']}\n"
            "      REDIS_URL: redis://cache:6379/0\n"
            "  cache:\n"
            "    image: redis:7\n",
            Plant("secret", "database_uri", seed["database_uri"]),
        ),
        _text(
            "bitbucket-pipelines.yml",
            "image: python:3.12\n\n"
            "pipelines:\n"
            "  default:\n"
            "    - step:\n"
            "        name: Test\n"
            "        script:\n"
            "          - pip install -r requirements.txt\n"
            "          - pytest -q\n"
            "  branches:\n"
            "    main:\n"
            "      - step:\n"
            "          name: Deploy\n"
            "          script:\n"
            f'            - export BB_APP_PASSWORD="{seed["bitbucket_app_password"]}"\n'
            "            - ./scripts/deploy.sh\n",
            Plant("secret", "bitbucket_app_password", seed["bitbucket_app_password"]),
        ),
        _text(
            "Makefile",
            ".PHONY: dev test lint\n\n"
            "dev:\n"
            "\tflask --app app run --port 8000\n\n"
            "test:\n"
            "\tpytest -q\n\n"
            "lint:\n"
            "\truff check app\n",
        ),
        _text(
            "package.json",
            "{\n"
            '  "name": "fleetline-portal-web",\n'
            '  "version": "1.4.0",\n'
            '  "private": true,\n'
            '  "scripts": {\n'
            '    "build": "esbuild web/static/js/app.js --bundle --outfile=web/static/dist/app.js"\n'
            "  }\n"
            "}\n",
        ),
        _text("requirements.txt", "Flask==3.1.3\ngunicorn==23.0.0\nrequests==2.32.3\nstripe==11.1.0\n"),
        _text("pyproject.toml", '[tool.pytest.ini_options]\ntestpaths = ["app/tests"]\n\n[tool.ruff]\nline-length = 120\n'),
        _text(
            "app/__init__.py",
            '"""FleetLine portal application factory."""\n'
            "from flask import Flask\n\n"
            "from config.settings import load_settings\n\n\n"
            "def create_app() -> Flask:\n"
            "    app = Flask(__name__)\n"
            "    app.config.update(load_settings())\n"
            "    return app\n",
        ),
        _text(
            "app/auth.py",
            '"""Sign-in against the identity provider and the service token the scheduler uses."""\n'
            "import requests\n\n"
            'IDP_URL = "https://idp.fleetline.example/oauth/token"\n'
            "# The scheduler authenticates with a long-lived token minted for the portal service account.\n"
            f'SERVICE_JWT = "{seed["jwt"]}"\n\n\n'
            "def service_headers() -> dict[str, str]:\n"
            '    return {"Authorization": f"Bearer {SERVICE_JWT}"}\n\n\n'
            "def exchange_code(code: str) -> dict:\n"
            '    response = requests.post(IDP_URL, data={"code": code, "grant_type": "authorization_code"}, timeout=10)\n'
            "    response.raise_for_status()\n"
            "    return response.json()\n",
            Plant("secret", "jwt", seed["jwt"]),
        ),
        _text(
            "app/models.py",
            '"""Portal models."""\n'
            "from dataclasses import dataclass\n\n\n"
            "@dataclass\n"
            "class Shipment:\n"
            "    id: int\n"
            "    customer_id: int\n"
            "    status: str\n\n\n"
            "@dataclass\n"
            "class Driver:\n"
            "    id: int\n"
            "    name: str\n"
            "    vehicle: str\n",
        ),
        _text(
            "app/notifications.py",
            '"""Slack alerts for the operations channel."""\n'
            "import requests\n\n"
            f'SLACK_BOT_TOKEN = "{seed["slack_token"]}"\n'
            'SLACK_CHANNEL = "#ops-alerts"\n\n\n'
            "def post_alert(text: str) -> None:\n"
            "    requests.post(\n"
            '        "https://slack.com/api/chat.postMessage",\n'
            '        headers={"Authorization": f"Bearer {SLACK_BOT_TOKEN}"},\n'
            '        json={"channel": SLACK_CHANNEL, "text": text},\n'
            "        timeout=10,\n"
            "    )\n",
            Plant("secret", "slack_token", seed["slack_token"]),
        ),
        _text(
            "app/payments.py",
            '"""Card payments for customer invoices."""\n'
            "import stripe\n\n"
            f'stripe.api_key = "{seed["stripe_live_key"]}"\n\n\n'
            "def charge(customer_id: str, amount_cents: int) -> str:\n"
            '    intent = stripe.PaymentIntent.create(amount=amount_cents, currency="ils", customer=customer_id)\n'
            "    return intent.id\n",
            Plant("secret", "stripe_live_key", seed["stripe_live_key"]),
        ),
        _text(
            "app/reporting.py",
            '"""Nightly reports read from the analytics replica."""\n'
            "import sqlalchemy\n\n"
            f'REPORTS_DSN = "{extra["database_uri"]}"\n\n\n'
            "def engine() -> sqlalchemy.Engine:\n"
            "    return sqlalchemy.create_engine(REPORTS_DSN)\n",
            Plant("secret", "database_uri", extra["database_uri"]),
        ),
        _text(
            "app/storage.py",
            '"""Document storage on S3. Credentials come from the environment (see .env)."""\n'
            "import os\n\n"
            "import boto3\n\n"
            'BUCKET = "fleetline-portal-documents"\n\n\n'
            "def client():\n"
            '    return boto3.client("s3", region_name=os.environ.get("AWS_DEFAULT_REGION", "eu-central-1"))\n\n\n'
            "def upload(path: str, key: str) -> None:\n"
            "    client().upload_file(path, BUCKET, key)\n",
        ),
        _text(
            "app/utils.py",
            '"""Small helpers."""\n'
            "import hashlib\n\n\n"
            "def digest(value: str) -> str:\n"
            '    return hashlib.sha256(value.encode("utf-8")).hexdigest()\n\n\n'
            "def mask(value: str) -> str:\n"
            '    return value[:4] + "..." + value[-2:] if len(value) >= 12 else "********"\n',
        ),
        _text("app/tests/__init__.py", ""),
        _text(
            "app/tests/conftest.py",
            "import pytest\n\n"
            "from app import create_app\n\n"
            f'TEST_PASSWORD = "{DECOY_WELCOME}"\n\n\n'
            "@pytest.fixture()\n"
            "def client():\n"
            "    app = create_app()\n"
            '    app.config["TESTING"] = True\n'
            "    return app.test_client()\n",
            Plant("decoy", "entropy below the threshold", DECOY_WELCOME),
        ),
        _text(
            "app/tests/test_payments.py",
            "import stripe\n\n"
            "from app import payments\n\n"
            "# Test mode only: sk_test keys cannot move money.\n"
            f'STRIPE_TEST = "{DECOY_STRIPE_TEST_KEY}"\n\n\n'
            "def test_charge_returns_an_intent_id(monkeypatch):\n"
            '    monkeypatch.setattr(stripe.PaymentIntent, "create", lambda **kwargs: type("Intent", (), {"id": "pi_1"})())\n'
            '    assert payments.charge("cus_1", 1000) == "pi_1"\n',
            Plant("decoy", "test-mode key, no detector matches", DECOY_STRIPE_TEST_KEY),
        ),
        _text(
            "app/tests/test_utils.py",
            "from app.utils import digest, mask\n\n\n"
            "def test_digest_is_hex():\n"
            f'    password = "{DECOY_LOW_ENTROPY_PASSWORD}"\n'
            "    assert len(digest(password)) == 64\n\n\n"
            "def test_mask_keeps_the_ends():\n"
            '    assert mask("abcdefghijkl") == "abcd...kl"\n',
            Plant("decoy", "entropy below the threshold", DECOY_LOW_ENTROPY_PASSWORD),
        ),
        _text(
            "config/settings.py",
            '"""Settings loaded at start-up. Values here are the defaults; .env overrides them."""\n'
            "import os\n\n"
            f'SECRET_KEY = "{DECOY_XXX}"\n'
            'DATABASE_HOST = "db-prod.fleetline.internal"\n'
            'DATABASE_USER = "portal_app"\n'
            f'DATABASE_PASSWORD = "{seed["generic_password"]}"\n'
            f'ADMIN_PASSWORD = "{DECOY_CHANGEME}"\n\n\n'
            "def load_settings() -> dict:\n"
            "    return {\n"
            '        "SECRET_KEY": os.environ.get("SECRET_KEY", SECRET_KEY),\n'
            '        "DATABASE_PASSWORD": os.environ.get("DATABASE_PASSWORD", DATABASE_PASSWORD),\n'
            "    }\n",
            Plant("decoy", "placeholder xxx", DECOY_XXX),
            Plant("secret", "generic_password", seed["generic_password"]),
            Plant("decoy", "placeholder changeme", DECOY_CHANGEME),
        ),
        _text(
            "config/settings.yaml",
            "portal:\n"
            "  name: FleetLine portal\n"
            "  timezone: Asia/Jerusalem\n"
            "maps:\n"
            "  provider: internal\n"
            f'  api_key: "{extra["generic_api_key"]}"\n'
            "features:\n"
            "  driver_tracking: true\n",
            Plant("secret", "generic_api_key", extra["generic_api_key"]),
        ),
        _text(
            "config/integrations.yaml",
            "slack:\n"
            "  workspace: fleetline\n"
            f"  slack_user_token: {extra['slack_token']}\n"
            "crm:\n"
            "  base_url: https://crm.fleetline.example\n",
            Plant("secret", "slack_token", extra["slack_token"]),
        ),
        _text(
            "config/app.json",
            "{\n"
            f'  "database_url": "{DECOY_URI_WITHOUT_CREDENTIALS}",\n'
            '  "pool_size": 5,\n'
            '  "log_level": "INFO"\n'
            "}\n",
            Plant("decoy", "URI without credentials", DECOY_URI_WITHOUT_CREDENTIALS),
        ),
        _text(
            "config/logging.yaml",
            "version: 1\n"
            "formatters:\n"
            "  plain:\n"
            '    format: "%(asctime)s %(levelname)s %(name)s %(message)s"\n'
            "handlers:\n"
            "  console:\n"
            "    class: logging.StreamHandler\n"
            "    formatter: plain\n"
            "root:\n"
            "  level: INFO\n"
            "  handlers: [console]\n",
        ),
        _text(
            "data/fixtures.json",
            "{\n"
            '  "customers": [\n'
            '    {"id": 1, "name": "Negev Agro Ltd."},\n'
            '    {"id": 2, "name": "Carmel Textiles"}\n'
            "  ],\n"
            '  "integration": {\n'
            f'    "api_key": "{seed["generic_api_key"]}",\n'
            '    "endpoint": "https://crm.fleetline.example/api"\n'
            "  }\n"
            "}\n",
            Plant("secret", "generic_api_key", seed["generic_api_key"]),
        ),
        _text(
            "docs/setup.md",
            "# Developer setup\n\n"
            "1. Create a virtualenv and install `requirements.txt`.\n"
            "2. Copy `.env.example` to `.env`.\n"
            "3. Request an integration token from the CRM administrator and set it in `config/integrations.yaml`, for example:\n\n"
            "```python\n"
            f'token = "{DECOY_EXAMPLE_TOKEN}"\n'
            "```\n\n"
            "4. Run `make dev`.\n",
            Plant("decoy", "placeholder example", DECOY_EXAMPLE_TOKEN),
        ),
        _text(
            "docs/architecture.md",
            "# Architecture\n\n"
            "The portal is a Flask application behind gunicorn. Documents live in S3, reports come from a MySQL replica, "
            "alerts go to Slack, and payments run through Stripe. Infrastructure is described in `infra/`.\n",
        ),
        _text(
            "infra/main.tf",
            'terraform {\n  required_version = ">= 1.5"\n}\n\n'
            'provider "aws" {\n'
            "  region     = var.region\n"
            f'  access_key = "{extra["aws_access_key_id"]}"\n'
            "  secret_key = var.aws_secret\n"
            "}\n\n"
            'resource "aws_s3_bucket" "documents" {\n'
            '  bucket = "fleetline-portal-documents"\n'
            "}\n",
            Plant("secret", "aws_access_key_id", extra["aws_access_key_id"]),
        ),
        _text(
            "infra/variables.tf",
            'variable "region" {\n'
            '  default = "eu-central-1"\n'
            "}\n\n"
            'variable "aws_secret" {\n'
            "  sensitive = true\n"
            "}\n\n"
            'variable "example_access_key" {\n'
            '  description = "Shape of an access key id, for documentation only"\n'
            f'  default     = "{DECOY_AKIAEXAMPLE}"\n'
            "}\n",
            Plant("decoy", "placeholder akiaexample", DECOY_AKIAEXAMPLE),
        ),
        _text("infra/outputs.tf", 'output "documents_bucket" {\n  value = aws_s3_bucket.documents.bucket\n}\n'),
        _text("keys/deploy_key.pem", seed["private_key_pem"] + "\n", Plant("secret", "private_key_pem", seed["private_key_pem"])),
        _text("keys/tls_server.key", extra["private_key_pem"] + "\n", Plant("secret", "private_key_pem", extra["private_key_pem"])),
        _text("keys/public.pem", DECOY_PUBLIC_KEY + "\n", Plant("decoy", "public key, not private", DECOY_PUBLIC_KEY)),
        _text(
            "scripts/deploy.sh",
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "# Deploys the current build; the token below was pasted in for a hotfix and never removed.\n"
            f'GITHUB_TOKEN="{seed["github_token"]}"\n'
            'curl -sf -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/repos/fleetline/portal/deployments\n'
            "scp -r web/static/dist portal@portal.fleetline.internal:/srv/portal/web/static/\n",
            Plant("secret", "github_token", seed["github_token"]),
        ),
        _text(
            "scripts/release.sh",
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            'VERSION="${1:?version}"\n'
            f'curl -sf -X POST -H "Authorization: token {extra["github_token"]}" \\\n'
            '  https://api.github.com/repos/fleetline/portal/releases -d "{\\"tag_name\\": \\"$VERSION\\"}"\n',
            Plant("secret", "github_token", extra["github_token"]),
        ),
        _text(
            "scripts/backup.sh",
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            f'export PGPASSWORD="{extra["generic_password"]}"\n'
            "pg_dump -h db-prod.fleetline.internal -U portal_app fleetline | gzip > /backups/fleetline-$(date +%F).sql.gz\n",
            Plant("secret", "generic_password", extra["generic_password"]),
        ),
        _text(
            "scripts/rotate_keys.py",
            '"""Rotate the portal access key.\n\n'
            f"Usage: rotate_keys.py OLD_KEY_ID, for example {DECOY_AWS_DOCS_KEY}, the id every AWS document uses.\n"
            '"""\n'
            "import sys\n\n\n"
            "def main(argv: list[str]) -> int:\n"
            "    if len(argv) != 2:\n"
            '        print(__doc__)\n'
            "        return 2\n"
            '    print(f"would rotate {argv[1]}")\n'
            "    return 0\n\n\n"
            'if __name__ == "__main__":\n'
            "    raise SystemExit(main(sys.argv))\n",
            Plant("decoy", "placeholder example", DECOY_AWS_DOCS_KEY),
        ),
        _text(
            "web/static/js/app.js",
            '"use strict";\n\n'
            f'const MAPS_KEY = "{seed["google_api_key"]}";\n\n'
            "function loadMap(element) {\n"
            '  const script = document.createElement("script");\n'
            '  script.src = "https://maps.example.com/api/js?key=" + MAPS_KEY;\n'
            "  element.appendChild(script);\n"
            "}\n\n"
            'document.addEventListener("DOMContentLoaded", function () {\n'
            '  const map = document.getElementById("map");\n'
            "  if (map) {\n"
            "    loadMap(map);\n"
            "  }\n"
            "});\n",
            Plant("secret", "google_api_key", seed["google_api_key"]),
        ),
        _text(
            "web/static/js/analytics.js",
            '"use strict";\n\n'
            f'const HEADER = "{DECOY_JWT_SEGMENT}";\n\n'
            "async function sendEvent(name) {\n"
            '  await fetch("https://analytics.fleetline.example/events", {\n'
            '    method: "POST",\n'
            f'    headers: {{ Authorization: "Bearer {extra["jwt"]}" }},\n'
            "    body: JSON.stringify({ name: name, header: HEADER }),\n"
            "  });\n"
            "}\n",
            Plant("decoy", "one JWT segment, not a token", DECOY_JWT_SEGMENT),
            Plant("secret", "jwt", extra["jwt"]),
        ),
        _text("web/static/css/site.css", "body { font-family: system-ui, sans-serif; }\n.map { height: 320px; }\n"),
        CorpusFile("web/static/img/logo.png", LOGO_PNG),
        _text(
            "web/templates/index.html",
            "<!doctype html>\n"
            '<html lang="en">\n'
            "<head><meta charset=\"utf-8\"><title>FleetLine portal</title></head>\n"
            "<body>\n"
            '  <div id="map" class="map"></div>\n'
            '  <script src="/static/js/app.js"></script>\n'
            "</body>\n"
            "</html>\n",
        ),
    ]
    files.sort(key=lambda entry: entry.path)
    return files


def line_of(content: bytes, literal: str) -> int:
    """The 1-based line on which the literal starts (its first line, for a PEM block)."""
    text = content.decode("utf-8")
    first_line = literal.split("\n", 1)[0]
    index = text.index(first_line)
    return text.count("\n", 0, index) + 1


def ground_truth(files: list[CorpusFile]) -> dict[str, Any]:
    """The ground_truth.json content: secrets by file, line and detector name; decoys by file, line and reason."""
    secrets: list[dict[str, Any]] = []
    decoys: list[dict[str, Any]] = []
    for entry in files:
        for plant in entry.plants:
            line = line_of(entry.content, plant.literal)
            if plant.kind == "secret":
                secrets.append({"file": entry.path, "line": line, "type": plant.label})
            else:
                decoys.append({"file": entry.path, "line": line, "reason": plant.label})
    secrets.sort(key=lambda item: (item["file"], item["line"]))
    decoys.sort(key=lambda item: (item["file"], item["line"]))
    return {"generated_by": GENERATOR, "secrets": secrets, "decoys": decoys}


def render(files: list[CorpusFile] | None = None) -> dict[str, bytes]:
    """Every file of the corpus plus ground_truth.json, keyed by relative path."""
    files = files or build_corpus()
    rendered = {entry.path: entry.content for entry in files}
    rendered[GROUND_TRUTH_FILE] = (json.dumps(ground_truth(files), indent=2) + "\n").encode("utf-8")
    return rendered


def write_corpus(root: Path) -> dict[str, bytes]:
    """Replace the folder at root with a fresh corpus; root must be named sample_repo (a guard against a wrong path)."""
    if root.name != "sample_repo":
        raise ValueError(f"refusing to replace {root}: the corpus folder is named sample_repo")
    if root.exists():
        shutil.rmtree(root)
    rendered = render()
    for relative, content in rendered.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    return rendered
