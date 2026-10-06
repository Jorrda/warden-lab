"""CSV import of identities (spec 6.3, S06): the template, the validation preview and the commit.

The template's columns are the S05 form's fields plus one column per attribute
key of ATTRIBUTE_SCHEMA and created_by_email; list-valued keys are comma
separated, dates are YYYY-MM-DD (midnight UTC, as the form), enum columns hold
the stored values of spec 4.1 exactly. The header must hold every template
column and nothing else; the file is read as UTF-8 (a byte order mark is
tolerated) with the csv module, never eval or pandas (spec 7), and is refused
over MAX_BYTES or MAX_ROWS, when a column is missing, unknown or repeated, or
when the csv module cannot read it (a cell over its 128 KiB field limit).

validate() measures the text's size once more, with CRLF folded to LF, so
the commit path holds the same bound as the upload path whatever line ends the
browser re-posts; then it turns the text into a plan, one RowPlan per data
row, without writing anything: create when no identity has the row's name on the row's
system, update when one does (the upsert key of decision D-031), or reject
with the reason; a re-imported row whose cells equal the stored values is an
update like any other, because the import touched the identity (phase 6 S8a
finding R08, phase 7 audit F01: spec 6.3's three verdicts are the whole list).
A later row of the file with the key of an earlier one is
an update of what that earlier row creates or updates, judged over the
earlier row's values (phase 6 audit F15). Reject rules (spec 6.3, never
silently coerced): unknown system, unknown owner email, invalid enum, bad
date (a value date.fromisoformat cannot read; a date in the past is data);
and, for the same reason, a missing name, type, system, environment,
privilege level, storage location or created_at on a create (the cells the
S05 form requires), a type that differs from the stored one on an update
(type, status, fingerprint and registered_by are never written by an import,
phase 0 plan 18.3), an attribute column that does not belong to the row's
type, whose cell is over the key's bound in ATTRIBUTE_LIMITS or whose value
fails the key's shape rule (the S05 form's own validators, mirrored here:
the http or https target_url, the created_by_email address; phase 6 review
N1, phase 7 audit F21), or a name or purpose over its length. On an update a
blank cell leaves the stored value unchanged and attribute cells merge per
key over the stored dict, so a cleared owner or date is done on the identity
page, not by import. A departed person is an accepted owner: the import
records the inventory as it is and the flags say the rest (audit F17).

commit() applies a plan row by row through inventory.create_nhi() and
update_nhi(), each of which scores the identity, writes its nhi.create or
nhi.update row and commits (phase 4 plan section 14, audit F20); a row that
fails at that point despite the preview (a name taken meanwhile) is rolled
back on its own and recorded as rejected. Then one import_batches row with
the counts and the rejected rows as error_report and one import.commit audit
row on it are committed together. The route re-validates the text at commit
time, so what is applied is what the database allowed at that moment, not
what the preview showed. Nothing here imports Flask request objects
(CLAUDE.md 5).
"""
from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass, field, replace
from datetime import date, datetime, time, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from warden.extensions import db
from warden.filters import EMAIL_PATTERN, URL_PATTERN
from warden.models import ATTRIBUTE_SCHEMA, COMMON_ATTRIBUTE_KEYS, Environment, ImportBatch, Nhi, NhiType, Person, PrivilegeLevel, StorageLocation, System, validate_attributes
from warden.models.enums import ValueEnum
from warden.services import audit, inventory
from warden.services.audit import Actor
from warden.services.inventory import NhiFields

MAX_BYTES = 262_144  # 256 KiB of CSV: under Werkzeug's form memory limit, so the preview can hand the text back for the commit
MAX_ROWS = 1000
NAME_MAX = 120
PURPOSE_MAX = 2000
COMMIT_ACTION = "import.commit"
TEMPLATE_FILENAME = "warden-import-template.csv"

FIELD_COLUMNS: tuple[str, ...] = (
    "name",
    "type",
    "system",
    "owner_email",
    "purpose",
    "environment",
    "privilege_level",
    "storage_location",
    "created_at",
    "last_used_at",
    "last_rotated_at",
    "expires_at",
)
ATTRIBUTE_COLUMNS: tuple[str, ...] = tuple(dict.fromkeys([key for keys in ATTRIBUTE_SCHEMA.values() for key in keys] + list(COMMON_ATTRIBUTE_KEYS)))
TEMPLATE_COLUMNS: tuple[str, ...] = FIELD_COLUMNS + ATTRIBUTE_COLUMNS
LIST_KEYS = frozenset(key for keys in ATTRIBUTE_SCHEMA.values() for key, kind in keys.items() if kind is list)
REQUIRED_ON_CREATE: tuple[str, ...] = ("name", "type", "system", "environment", "privilege_level", "storage_location", "created_at")
ENUM_COLUMNS: dict[str, type[ValueEnum]] = {"type": NhiType, "environment": Environment, "privilege_level": PrivilegeLevel, "storage_location": StorageLocation}
EXAMPLE_ROW: dict[str, str] = {
    "name": "example-api-key",
    "type": "api_key",
    "system": "AWS Account",
    "owner_email": "",
    "purpose": "Reporting export on AWS Account.",
    "environment": "prod",
    "privilege_level": "read",
    "storage_location": "vault",
    "created_at": "2026-01-15",
    "last_used_at": "2026-09-01",
    "last_rotated_at": "2026-07-01",
    "expires_at": "",
    "key_prefix": "FLKR",
}


class ImportError_(ValueError):
    """The whole file is refused: the reason is the message."""


@dataclass(frozen=True)
class RowPlan:
    """What the commit will do with one data row."""

    row_no: int  # 1 for the first data row (the header is row 0)
    action: str  # create, update or reject
    name: str
    system: str
    reason: str = ""  # the reject reason, or the columns an update fills
    fields: NhiFields | None = None
    nhi_id: int | None = None  # the identity an update edits; None when an earlier row of the file creates it
    after_row: int | None = None  # for an update of a row this file creates: that row's number


@dataclass(frozen=True)
class ImportPlan:
    filename: str
    rows: tuple[RowPlan, ...]

    def count(self, action: str) -> int:
        return sum(1 for row in self.rows if row.action == action)

    @property
    def rejected(self) -> tuple[RowPlan, ...]:
        return tuple(row for row in self.rows if row.action == "reject")


@dataclass
class _Lookups:
    systems: dict[str, System] = field(default_factory=dict)
    people: dict[str, Person] = field(default_factory=dict)


def template_text() -> str:
    """The downloadable template: the header and one example row."""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=TEMPLATE_COLUMNS, lineterminator="\r\n")
    writer.writeheader()
    writer.writerow({column: EXAMPLE_ROW.get(column, "") for column in TEMPLATE_COLUMNS})
    return buffer.getvalue()


def decode(data: bytes) -> str:
    """The file's text; refused when over MAX_BYTES or not UTF-8."""
    if len(data) > MAX_BYTES:
        raise ImportError_(f"the file is {len(data)} bytes; the limit is {MAX_BYTES} bytes")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ImportError_("the file is not UTF-8 text") from None


def _read_rows(text: str) -> list[dict[str, str]]:
    # The size bound is measured here on both paths, over the text with CRLF folded to LF: a browser re-posts the
    # preview's textarea with CRLF ends, so an LF file at the cap would otherwise grow one byte per line on commit
    # and be refused there after the preview accepted it (S5 architecture finding A-2).
    text = text.replace("\r\n", "\n")
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise ImportError_(f"the text is {len(text.encode('utf-8'))} bytes; the limit is {MAX_BYTES} bytes")
    reader = csv.DictReader(io.StringIO(text, newline=""))  # the csv module's own rule: no newline translation on its stream
    try:
        header = [column.strip() for column in (reader.fieldnames or [])]
    except csv.Error as error:
        raise ImportError_(f"the file could not be read as CSV: {error}") from None
    missing = [column for column in TEMPLATE_COLUMNS if column not in header]
    extra = [column for column in header if column not in TEMPLATE_COLUMNS]
    repeated = sorted({column for column in header if header.count(column) > 1})  # the last copy would win silently (S4 finding F4)
    if missing or extra or repeated:
        parts = []
        if missing:
            parts.append("missing columns " + ", ".join(missing))
        if extra:
            parts.append("unknown columns " + ", ".join(column or "(blank)" for column in extra))
        if repeated:
            parts.append("repeated columns " + ", ".join(repeated))
        raise ImportError_("the header does not match the template: " + "; ".join(parts))
    rows: list[dict[str, str]] = []
    try:
        for raw in reader:
            if None in raw:
                raise ImportError_(f"row {len(rows) + 1} has more cells than the header has columns")
            row = {column.strip(): (value or "").strip() for column, value in raw.items()}
            if not any(row.values()):
                continue  # a blank line
            rows.append(row)
            if len(rows) > MAX_ROWS:
                raise ImportError_(f"the file has more than {MAX_ROWS} rows")
    except csv.Error as error:  # a cell over the module's 128 KiB field limit, or a quote the parser cannot close (S5 architecture pass)
        raise ImportError_(f"the file could not be read as CSV: {error}") from None
    return rows


def _parse_date(value: str) -> datetime:
    try:
        return datetime.combine(date.fromisoformat(value), time.min, tzinfo=timezone.utc)
    except ValueError:
        raise ValueError(f"bad date {value!r}, expected YYYY-MM-DD") from None


def _parse_enum(column: str, value: str) -> ValueEnum:
    enum_class = ENUM_COLUMNS[column]
    if value not in enum_class.__members__:
        raise ValueError(f"invalid {column} {value!r}, expected one of {', '.join(member.value for member in enum_class)}")
    return enum_class(value)


def _lookups() -> _Lookups:
    systems = {system.name: system for system in db.session.execute(select(System)).scalars()}
    people = {person.email.lower(): person for person in db.session.execute(select(Person)).scalars()}
    return _Lookups(systems=systems, people=people)


def _attributes(row: dict[str, str], nhi_type: NhiType, stored: dict[str, Any] | None) -> dict[str, Any]:
    """The row's attribute cells over the stored dict (update) or alone (create); a cell of another type's key is an error."""
    allowed = set(ATTRIBUTE_SCHEMA[nhi_type]) | set(COMMON_ATTRIBUTE_KEYS)
    merged: dict[str, Any] = dict(stored or {})
    for column in ATTRIBUTE_COLUMNS:
        value = row.get(column, "")
        if not value:
            continue
        if column not in allowed:
            raise ValueError(f"attribute {column} does not apply to type {nhi_type.value}")
        if column == "created_by_email" and not re.match(EMAIL_PATTERN, value):
            raise ValueError(f"invalid created_by_email {value!r}")
        if column == "target_url" and not re.match(URL_PATTERN, value):
            raise ValueError(f"invalid target_url {value!r}, expected an http or https URL")
        merged[column] = [item.strip() for item in value.split(",") if item.strip()] if column in LIST_KEYS else value
    return validate_attributes(nhi_type, merged)


def _plan_row(row_no: int, row: dict[str, str], lookups: _Lookups, planned: dict[tuple[int, str], RowPlan]) -> RowPlan:
    name, system_name = row["name"], row["system"]
    try:
        if not name:
            raise ValueError("missing name")
        if len(name) > NAME_MAX:
            raise ValueError(f"name is over {NAME_MAX} characters")
        if not system_name:
            raise ValueError("missing system")
        system = lookups.systems.get(system_name)
        if system is None:
            raise ValueError(f"unknown system {system_name!r}")
        earlier = planned.get((system.id, name))  # an earlier row of this file with the same key (audit F15)
        existing = db.session.execute(select(Nhi).where(Nhi.system_id == system.id, Nhi.name == name)).scalar_one_or_none()
        if len(row["purpose"]) > PURPOSE_MAX:
            raise ValueError(f"purpose is over {PURPOSE_MAX} characters")
        owner: Person | None = None
        if row["owner_email"]:
            owner = lookups.people.get(row["owner_email"].lower())
            if owner is None:
                raise ValueError(f"unknown owner email {row['owner_email']!r}")
        if existing is None and earlier is None:
            missing = [column for column in REQUIRED_ON_CREATE if not row[column]]
            if missing:
                raise ValueError("missing " + ", ".join(missing))
            nhi_type = _parse_enum("type", row["type"])
            fields = NhiFields(
                type=nhi_type,
                name=name,
                system_id=system.id,
                owner_id=owner.id if owner else None,
                purpose=row["purpose"],
                environment=_parse_enum("environment", row["environment"]),
                privilege_level=_parse_enum("privilege_level", row["privilege_level"]),
                storage_location=_parse_enum("storage_location", row["storage_location"]),
                created_at=_parse_date(row["created_at"]),
                last_used_at=_parse_date(row["last_used_at"]) if row["last_used_at"] else None,
                last_rotated_at=_parse_date(row["last_rotated_at"]) if row["last_rotated_at"] else None,
                expires_at=_parse_date(row["expires_at"]) if row["expires_at"] else None,
                attributes=_attributes(row, nhi_type, None),
            )
            plan = RowPlan(row_no, "create", name, system_name, fields=fields)
            planned[(system.id, name)] = plan
            return plan
        # An update: over the stored identity, or over what the earlier row of this file leaves (its fields carry
        # the stored values it did not touch, so a blank cell here still means unchanged).
        base: NhiFields = earlier.fields if earlier is not None and earlier.fields is not None else _fields_of(existing)  # type: ignore[arg-type]
        if row["type"] and _parse_enum("type", row["type"]) != base.type:
            raise ValueError(f"type cannot change on update: the identity is {base.type.value}")
        filled = [column for column in TEMPLATE_COLUMNS if row[column] and column not in ("name", "system", "type")]
        fields = replace(
            base,
            name=name,
            system_id=system.id,
            owner_id=owner.id if owner else base.owner_id,
            purpose=row["purpose"] or base.purpose,
            environment=_parse_enum("environment", row["environment"]) if row["environment"] else base.environment,
            privilege_level=_parse_enum("privilege_level", row["privilege_level"]) if row["privilege_level"] else base.privilege_level,
            storage_location=_parse_enum("storage_location", row["storage_location"]) if row["storage_location"] else base.storage_location,
            created_at=_parse_date(row["created_at"]) if row["created_at"] else base.created_at,
            last_used_at=_parse_date(row["last_used_at"]) if row["last_used_at"] else base.last_used_at,
            last_rotated_at=_parse_date(row["last_rotated_at"]) if row["last_rotated_at"] else base.last_rotated_at,
            expires_at=_parse_date(row["expires_at"]) if row["expires_at"] else base.expires_at,
            attributes=_attributes(row, base.type, base.attributes),
        )
        reason = ", ".join(filled) if filled else "no cell filled"
        if earlier is not None and earlier.nhi_id is None:
            reason += f" (row {earlier.after_row or earlier.row_no} creates it)"
            plan = RowPlan(row_no, "update", name, system_name, reason=reason, fields=fields, nhi_id=None, after_row=earlier.after_row or earlier.row_no)
        else:
            plan = RowPlan(row_no, "update", name, system_name, reason=reason, fields=fields, nhi_id=existing.id if existing is not None else earlier.nhi_id)  # type: ignore[union-attr]
        planned[(system.id, name)] = plan
        return plan
    except ValueError as error:
        return RowPlan(row_no, "reject", name, system_name, reason=str(error))


def _fields_of(nhi: Nhi) -> NhiFields:
    return NhiFields(
        type=nhi.type,
        name=nhi.name,
        system_id=nhi.system_id,
        owner_id=nhi.owner_id,
        purpose=nhi.purpose,
        environment=nhi.environment,
        privilege_level=nhi.privilege_level,
        storage_location=nhi.storage_location,
        created_at=nhi.created_at,
        last_used_at=nhi.last_used_at,
        last_rotated_at=nhi.last_rotated_at,
        expires_at=nhi.expires_at,
        attributes=dict(nhi.attributes),
    )


def validate(text: str, filename: str) -> ImportPlan:
    """The per-row plan of spec 6.3's preview: create, update or reject with the reason; nothing is written."""
    rows = _read_rows(text)
    lookups = _lookups()
    planned: dict[tuple[int, str], RowPlan] = {}
    plans = tuple(_plan_row(index, row, lookups, planned) for index, row in enumerate(rows, start=1))
    return ImportPlan(filename=filename, rows=plans)


def commit(plan: ImportPlan, *, actor: Actor, now: datetime) -> ImportBatch:
    """Apply the plan row by row (each create or update commits on its own), then record the batch and its audit row."""
    if actor.user_id is None:
        raise ValueError("an import is committed by a signed-in admin; import_batches.uploaded_by cannot be null")
    created: list[int] = []
    updated: list[int] = []
    by_row: dict[int, int] = {}  # row number to the id of the identity it created, for updates of rows this file creates
    rejected: list[dict[str, Any]] = [{"row": row.row_no, "name": row.name, "system": row.system, "reason": row.reason} for row in plan.rejected]
    for row in plan.rows:
        if row.fields is None or row.action == "reject":
            continue
        try:
            if row.action == "create":
                nhi = inventory.create_nhi(row.fields, actor=actor, now=now)
                created.append(nhi.id)
                by_row[row.row_no] = nhi.id
            else:
                nhi_id = row.nhi_id if row.nhi_id is not None else by_row.get(row.after_row or 0)
                nhi = db.session.get(Nhi, nhi_id) if nhi_id is not None else None
                if nhi is None:
                    raise ValueError("the identity to update no longer exists")
                inventory.update_nhi(nhi, row.fields, actor=actor, now=now)
                updated.append(nhi.id)
        except (IntegrityError, ValueError) as error:
            db.session.rollback()
            reason = "an identity with this name already exists on that system" if isinstance(error, IntegrityError) else str(error)
            rejected.append({"row": row.row_no, "name": row.name, "system": row.system, "reason": f"failed at commit: {reason}"})
    rejected.sort(key=lambda item: item["row"])
    batch = ImportBatch(
        filename=plan.filename[:255],
        uploaded_by=actor.user_id,
        uploaded_at=now,
        rows_total=len(plan.rows),
        rows_created=len(created),
        rows_updated=len(updated),
        rows_rejected=len(rejected),
        error_report=rejected or None,
    )
    db.session.add(batch)
    db.session.flush()
    payload = audit.snapshot(batch)
    payload["created_ids"] = created
    payload["updated_ids"] = updated
    audit.record(COMMIT_ACTION, batch, actor=actor, after=payload, created_at=now)
    db.session.commit()
    return batch


def list_batches(limit: int = 20) -> list[ImportBatch]:
    """The newest batches for the import page."""
    statement = select(ImportBatch).order_by(ImportBatch.uploaded_at.desc(), ImportBatch.id.desc()).limit(limit)
    return list(db.session.execute(statement).scalars())


def count_batches() -> int:
    return db.session.execute(select(func.count(ImportBatch.id))).scalar_one()
