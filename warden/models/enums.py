"""Enumerations shared by the models.

Every enum derives from ValueEnum, a str subclass whose members compare equal
to their stored value and render as that value: without the __str__ below,
str(), format() and f-strings give the qualified name (NhiStatus.active) on
Python 3.11 and later, and Jinja renders through str(), so templates would
print the member name. The stored strings are the lowercase values of spec
section 4.1; the SQL side is a VARCHAR with a CHECK constraint (see
enum_column in warden/models/types.py).
"""
from __future__ import annotations

import enum


class ValueEnum(str, enum.Enum):
    """A str enum that prints its value (phase 3 rendering rule, S8a finding R03 of phase 2)."""

    def __str__(self) -> str:
        return str(self.value)


class PersonStatus(ValueEnum):
    active = "active"
    departed = "departed"


class UserRole(ValueEnum):
    admin = "admin"
    viewer = "viewer"


class SystemCategory(ValueEnum):
    erp = "erp"
    cloud = "cloud"
    saas = "saas"
    ci_cd = "ci_cd"
    messaging = "messaging"
    ai_agent_platform = "ai_agent_platform"
    network = "network"
    database = "database"
    other = "other"


class Criticality(ValueEnum):
    low = "low"
    medium = "medium"
    high = "high"


class Sensitivity(ValueEnum):
    low = "low"
    medium = "medium"
    high = "high"


class NhiType(ValueEnum):
    service_account = "service_account"
    api_key = "api_key"
    oauth_grant = "oauth_grant"
    webhook = "webhook"
    deploy_key = "deploy_key"
    certificate = "certificate"
    ci_token = "ci_token"
    ai_agent = "ai_agent"


class Environment(ValueEnum):
    prod = "prod"
    staging = "staging"
    dev = "dev"


class PrivilegeLevel(ValueEnum):
    read = "read"
    write = "write"
    admin = "admin"


class StorageLocation(ValueEnum):
    vault = "vault"
    config_file = "config_file"
    env_var = "env_var"
    source_code = "source_code"
    chat_or_ticket = "chat_or_ticket"
    unknown = "unknown"


class NhiStatus(ValueEnum):
    active = "active"
    rotated = "rotated"
    transferred = "transferred"
    revoked = "revoked"
    decommissioned = "decommissioned"


class RiskBand(ValueEnum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class RiskTrigger(ValueEnum):
    seed = "seed"
    write = "write"
    manual = "manual"
    offboarding = "offboarding"


class CaseStatus(ValueEnum):
    open = "open"
    in_progress = "in_progress"
    closed = "closed"


class Decision(ValueEnum):
    pending = "pending"
    rotate = "rotate"
    transfer = "transfer"
    revoke = "revoke"
    keep = "keep"


class FindingStatus(ValueEnum):
    new = "new"
    confirmed = "confirmed"
    false_positive = "false_positive"
    linked = "linked"
