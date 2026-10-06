"""Synthetic secret literals: the seed's twelve source_code identities (decision
D-042) and the eight more that complete the twenty true secrets of sample_repo/
(spec section 9).

Nothing here is a real credential. Every literal is built from a seeded RNG at
run time; the seed stores only the SHA-256 of the twelve, and the only files
that ever hold a literal are the ones warden/seed/sample_repo.py writes under
sample_repo/, the fixture CLAUDE.md 8 allows. synthetic_literals() must stay
byte for byte what phase 2 shipped, because the seeded fingerprints are its
hashes; extra_literals() draws from its own stream so adding to it never moves
the twelve. The twelve kinds cover the eleven layer 1 detectors of spec
section 9; the generic assignment detector is represented twice (a password
and an API key). The eight extra literals span the same families a second
time, in the shapes the scanner's other detectors accept.
"""
from __future__ import annotations

import hashlib
import random

SECRET_SEED = 20260908
UPPER_DIGITS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
BASE64 = ALNUM + "+/"
URL_SAFE = ALNUM + "-_"
HEX = "0123456789abcdef"

# Substrings the scanner's allowlist (spec section 9) treats as placeholders.
PLACEHOLDERS = ("example", "changeme", "xxx", "<your-key>", "akiaexample")

KINDS: tuple[str, ...] = (
    "aws_access_key_id",
    "aws_secret_access_key",
    "github_token",
    "slack_token",
    "stripe_live_key",
    "google_api_key",
    "private_key_pem",
    "jwt",
    "bitbucket_app_password",
    "generic_password",
    "database_uri",
    "generic_api_key",
)


def fingerprint(literal: str) -> str:
    """Lowercase hex SHA-256 of the UTF-8 bytes of the exact literal (decision D-029)."""
    return hashlib.sha256(literal.encode("utf-8")).hexdigest()


def synthetic_literals(seed: int = SECRET_SEED) -> list[tuple[str, str]]:
    """The twelve (kind, literal) pairs, always in the same order for the same seed."""
    rng = random.Random(seed * 7 + 1)

    def draw(alphabet: str, length: int) -> str:
        # Rejection sampling keeps the literals free of allowlisted substrings
        # such as "xxx" while staying deterministic for a given seed.
        while True:
            candidate = "".join(rng.choice(alphabet) for _ in range(length))
            if not any(placeholder in candidate.lower() for placeholder in PLACEHOLDERS):
                return candidate

    pem_body = "\n".join(draw(BASE64, 64) for _ in range(4))
    literals = [
        ("aws_access_key_id", "AKIA" + draw(UPPER_DIGITS, 16)),
        ("aws_secret_access_key", draw(BASE64, 40)),
        ("github_token", "ghp_" + draw(ALNUM, 36)),
        ("slack_token", "xoxb-" + draw("0123456789", 12) + "-" + draw("0123456789", 12) + "-" + draw(ALNUM, 24)),
        ("stripe_live_key", "sk_live_" + draw(ALNUM, 24)),
        ("google_api_key", "AIza" + draw(URL_SAFE, 35)),
        ("private_key_pem", "-----BEGIN RSA PRIVATE KEY-----\n" + pem_body + "\n-----END RSA PRIVATE KEY-----"),
        ("jwt", "eyJ" + draw(URL_SAFE, 20) + ".eyJ" + draw(URL_SAFE, 40) + "." + draw(URL_SAFE, 43)),
        ("bitbucket_app_password", "ATBB" + draw(ALNUM, 28)),
        ("generic_password", draw(ALNUM, 20)),
        ("database_uri", "postgresql://warden_app:" + draw(ALNUM, 18) + "@db-prod.fleetline.internal:5432/warden"),
        ("generic_api_key", draw(HEX, 32)),
    ]
    assert [kind for kind, _ in literals] == list(KINDS)
    _assert_placeholder_free(literals)
    return literals


EXTRA_KINDS: tuple[str, ...] = (
    "github_token",
    "slack_token",
    "aws_access_key_id",
    "private_key_pem",
    "jwt",
    "database_uri",
    "generic_api_key",
    "generic_password",
)


def extra_literals(seed: int = SECRET_SEED) -> list[tuple[str, str]]:
    """The eight (kind, literal) pairs that join the twelve in sample_repo/, from a separate stream."""
    rng = random.Random(seed * 7 + 2)

    def draw(alphabet: str, length: int) -> str:
        while True:
            candidate = "".join(rng.choice(alphabet) for _ in range(length))
            if not any(placeholder in candidate.lower() for placeholder in PLACEHOLDERS):
                return candidate

    ec_body = "\n".join(draw(BASE64, 64) for _ in range(3))
    literals = [
        ("github_token", "github_pat_" + draw(ALNUM, 22) + "_" + draw(ALNUM, 59)),
        ("slack_token", "xoxp-" + draw("0123456789", 11) + "-" + draw("0123456789", 12) + "-" + draw(ALNUM, 24)),
        ("aws_access_key_id", "AKIA" + draw(UPPER_DIGITS, 16)),
        ("private_key_pem", "-----BEGIN EC PRIVATE KEY-----\n" + ec_body + "\n-----END EC PRIVATE KEY-----"),
        ("jwt", "eyJ" + draw(URL_SAFE, 24) + ".eyJ" + draw(URL_SAFE, 52) + "." + draw(URL_SAFE, 43)),
        ("database_uri", "mysql://reports_ro:" + draw(ALNUM, 22) + "@mysql-analytics.fleetline.internal:3306/reports"),
        ("generic_api_key", draw(HEX, 40)),
        ("generic_password", draw(ALNUM, 24)),
    ]
    assert [kind for kind, _ in literals] == list(EXTRA_KINDS)
    _assert_placeholder_free(literals)
    return literals


def _assert_placeholder_free(literals: list[tuple[str, str]]) -> None:
    for _, literal in literals:
        lowered = literal.lower()
        assert not any(placeholder in lowered for placeholder in PLACEHOLDERS), "a synthetic literal collides with the scanner allowlist"
