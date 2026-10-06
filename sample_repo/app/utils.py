"""Small helpers."""
import hashlib


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def mask(value: str) -> str:
    return value[:4] + "..." + value[-2:] if len(value) >= 12 else "********"
