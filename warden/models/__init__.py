"""Model package. Every model module must be imported here so that
`flask --app app init-db` and `db.create_all()` see its table on `db.metadata`.
A module that is not imported here creates no table."""
from warden.models.audit import AuditEvent
from warden.models.enums import (
    CaseStatus,
    Criticality,
    Decision,
    Environment,
    FindingStatus,
    NhiStatus,
    NhiType,
    PersonStatus,
    PrivilegeLevel,
    RiskBand,
    RiskTrigger,
    Sensitivity,
    StorageLocation,
    SystemCategory,
    UserRole,
)
from warden.models.finding import Finding, ScanRun
from warden.models.import_batch import ImportBatch
from warden.models.nhi import ATTRIBUTE_LIMITS, ATTRIBUTE_SCHEMA, COMMON_ATTRIBUTE_KEYS, Nhi, NhiScope, validate_attributes
from warden.models.offboarding import OffboardingCase, OffboardingItem
from warden.models.person import Person
from warden.models.risk import RiskAssessment
from warden.models.system import Scope, System
from warden.models.user import User

__all__ = [
    "ATTRIBUTE_LIMITS",
    "ATTRIBUTE_SCHEMA",
    "AuditEvent",
    "COMMON_ATTRIBUTE_KEYS",
    "CaseStatus",
    "Criticality",
    "Decision",
    "Environment",
    "Finding",
    "FindingStatus",
    "ImportBatch",
    "Nhi",
    "NhiScope",
    "NhiStatus",
    "NhiType",
    "OffboardingCase",
    "OffboardingItem",
    "Person",
    "PersonStatus",
    "PrivilegeLevel",
    "RiskAssessment",
    "RiskBand",
    "RiskTrigger",
    "ScanRun",
    "Scope",
    "Sensitivity",
    "StorageLocation",
    "System",
    "SystemCategory",
    "User",
    "UserRole",
    "validate_attributes",
]
