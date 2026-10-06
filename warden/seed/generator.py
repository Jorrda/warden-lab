"""Deterministic demo dataset for FleetLine Logistics (spec section 8).

generate() fills an empty database from random.Random(20260908) and the fixed
PROFILES table, then assert_targets() re-reads the database and checks every
section 8 target as amended by decisions D-035, D-038, D-040 and D-045.
Dates are offsets from now, so the counts hold on any run date; the random
draws never depend on the clock. Only randint(), choice(), sample() and
shuffle() of one Random instance are used, always over ordered sequences, so a
run is reproducible on one interpreter and the assertions catch any drift on
another.
"""
from __future__ import annotations

import random
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from werkzeug.security import generate_password_hash

from warden.extensions import db
from warden.models import (
    AuditEvent,
    Environment,
    Nhi,
    NhiScope,
    NhiStatus,
    NhiType,
    Person,
    PersonStatus,
    PrivilegeLevel,
    Scope,
    Sensitivity,
    StorageLocation,
    System,
    User,
    UserRole,
    validate_attributes,
)
from warden.seed import fixtures as fx
from warden.seed.synthetic_secrets import fingerprint, synthetic_literals
from warden.services import audit

SEED = 20260908
SEED_ACTION = "seed.load"

READ = (PrivilegeLevel.read,)
WRITE = (PrivilegeLevel.write,)
ADMIN = (PrivilegeLevel.admin,)
READ_WRITE = (PrivilegeLevel.read, PrivilegeLevel.write)
VAULT = (StorageLocation.vault,)
ENV = (StorageLocation.env_var,)
CONFIG = (StorageLocation.config_file,)
SOURCE = (StorageLocation.source_code,)
CHAT = (StorageLocation.chat_or_ticket,)
VAULT_ENV = (StorageLocation.vault, StorageLocation.env_var)
ENV_CONFIG = (StorageLocation.env_var, StorageLocation.config_file)
VAULT_UNKNOWN = (StorageLocation.vault, StorageLocation.unknown)

# Day offsets from now. "used" and "rotated" are days ago; "expires" is days
# ahead, except "expired", which is days ago. The spec boundaries are 30, 90,
# 180, 365 and 730 days (section 5.1); every range stays clear of them.
USED_DAYS = {"recent": (1, 29), "stale": (181, 600)}
ROTATED_DAYS = {"recent": (1, 89), "mid": (120, 300), "old": (731, 1100)}
EXPIRES_DAYS = {"far": (200, 700), "soon": (5, 29), "expired": (5, 120)}
NEVER_ROTATED_CREATED_DAYS = (800, 1200)
DEMO_DEPLOY_KEY_AGE_DAYS = 1100
ENVIRONMENTS = (Environment.prod, Environment.prod, Environment.prod, Environment.staging, Environment.dev)

TYPE_MIX: dict[NhiType, int] = {
    NhiType.service_account: 32,
    NhiType.api_key: 38,
    NhiType.oauth_grant: 18,
    NhiType.webhook: 12,
    NhiType.deploy_key: 12,
    NhiType.certificate: 6,
    NhiType.ci_token: 10,
    NhiType.ai_agent: 2,
}

LABEL_NAMES = {
    "deploy_key": "deploy-prod-release",
    "pipeline_token": "ci-release-pipeline",
    "sap_account": "svc-sap-integration",
    "keep": "key-crm-sync",
    "invoice_agent": "agent-invoice-reader",
    "support_agent": "agent-support-reply",
}


@dataclass(frozen=True)
class Profile:
    """One row of the seed's profile table. count NHIs get this shape."""

    key: str
    count: int
    owner: str  # leaver, departed, none or active
    privilege: tuple[PrivilegeLevel, ...]  # one value, or several to draw from
    storage: tuple[StorageLocation, ...]
    used: str  # recent, stale or never
    rotated: str  # recent, mid, old, never or old_or_never
    expires: str  # none, far, soon, expired or none_or_far
    nhi_type: NhiType | None = None  # None draws from the remaining type mix
    system: str | None = None  # None draws from fixtures.TYPE_SYSTEMS
    label: str | None = None  # storyline rows get a fixed name


# Every NHI belongs to exactly one profile. The comments give the spec targets
# each block feeds; the intersections are stated in the plan's seed section.
PROFILES: tuple[Profile, ...] = (
    # The demo leaver's ten identities (spec 14, decision D-035).
    Profile("leaver_deploy_key", 1, "leaver", ADMIN, SOURCE, "recent", "never", "none", NhiType.deploy_key, "Bitbucket", "deploy_key"),
    Profile("leaver_pipeline_token", 1, "leaver", WRITE, ENV, "recent", "mid", "none", NhiType.ci_token, "Bitbucket", "pipeline_token"),
    Profile("leaver_sap_account", 1, "leaver", WRITE, CONFIG, "stale", "never", "none", NhiType.service_account, "SAP Business One", "sap_account"),
    Profile("leaver_keep", 1, "leaver", READ, VAULT, "recent", "recent", "none", NhiType.api_key, "CRM", "keep"),
    Profile("leaver_api_keys_unrotated_stale", 2, "leaver", WRITE, CONFIG, "stale", "old", "none", NhiType.api_key),
    Profile("leaver_oauth_stale", 1, "leaver", READ, CHAT, "stale", "mid", "none", NhiType.oauth_grant),
    Profile("leaver_webhook_in_source", 1, "leaver", WRITE, SOURCE, "recent", "mid", "none", NhiType.webhook),
    Profile("leaver_certificate_expiring", 1, "leaver", READ, VAULT, "recent", "mid", "soon", NhiType.certificate),
    Profile("leaver_admin_account_unrotated", 1, "leaver", ADMIN, CONFIG, "recent", "never", "none", NhiType.service_account),
    # The other seven departed owners: 14 identities.
    Profile("departed_admin_unrotated", 2, "departed", ADMIN, CONFIG, "recent", "old", "none"),
    Profile("departed_unrotated", 4, "departed", WRITE, ENV, "recent", "never", "none"),
    Profile("departed_stale", 2, "departed", READ, VAULT, "stale", "mid", "none"),
    Profile("departed_never_used", 1, "departed", READ, VAULT, "never", "mid", "none"),
    Profile("departed_in_source", 2, "departed", WRITE, SOURCE, "recent", "mid", "none"),
    Profile("departed_plain", 3, "departed", READ_WRITE, VAULT_ENV, "recent", "recent", "none"),
    # No owner recorded: 54 identities.
    Profile("orphan_admin_unrotated", 2, "none", ADMIN, CONFIG, "recent", "old", "none"),
    Profile("orphan_admin_never_used", 1, "none", ADMIN, ENV, "never", "mid", "none"),
    Profile("orphan_admin_in_source", 1, "none", ADMIN, SOURCE, "recent", "mid", "none"),
    Profile("orphan_in_source_unrotated", 3, "none", WRITE, SOURCE, "recent", "never", "none"),
    Profile("orphan_in_source_stale", 2, "none", WRITE, SOURCE, "stale", "mid", "none"),
    Profile("orphan_in_source", 2, "none", READ, SOURCE, "recent", "recent", "none"),
    Profile("orphan_unrotated_stale", 4, "none", READ, ENV, "stale", "old", "none"),
    Profile("orphan_unrotated_never_used", 2, "none", WRITE, CONFIG, "never", "never", "none"),
    Profile("orphan_unrotated", 12, "none", READ_WRITE, ENV_CONFIG, "recent", "old_or_never", "none"),
    Profile("orphan_stale", 7, "none", READ, VAULT_UNKNOWN, "stale", "mid", "none"),
    Profile("orphan_never_used", 5, "none", READ, VAULT, "never", "mid", "none"),
    Profile("orphan_expired_certificate", 2, "none", READ, VAULT, "recent", "mid", "expired", NhiType.certificate),
    Profile("orphan_expired_api_key", 1, "none", READ, VAULT, "recent", "mid", "expired", NhiType.api_key),
    Profile("orphan_expiring_certificate", 1, "none", READ, VAULT, "recent", "mid", "soon", NhiType.certificate),
    Profile("orphan_expiring_deploy_key", 1, "none", READ, VAULT, "recent", "mid", "soon", NhiType.deploy_key, "Bitbucket"),
    Profile("orphan_plain", 8, "none", READ_WRITE, VAULT_ENV, "recent", "recent", "none"),
    # Active owners: 52 identities, 37 of them healthy.
    Profile("owned_unrotated", 6, "active", WRITE, ENV, "recent", "old_or_never", "none"),
    Profile("owned_stale", 3, "active", READ, VAULT, "stale", "mid", "none"),
    Profile("owned_never_used", 1, "active", READ, VAULT, "never", "mid", "none"),
    Profile("owned_expired_certificate", 1, "active", READ, VAULT, "recent", "mid", "expired", NhiType.certificate),
    Profile("owned_expired_api_key", 1, "active", READ, VAULT, "recent", "mid", "expired", NhiType.api_key),
    Profile("owned_expiring_deploy_key", 1, "active", READ, VAULT, "recent", "mid", "soon", NhiType.deploy_key, "Bitbucket"),
    Profile("invoice_reader_agent", 1, "active", WRITE, VAULT, "recent", "recent", "none", NhiType.ai_agent, "Invoice Reader Agent", "invoice_agent"),
    Profile("support_reply_agent", 1, "active", WRITE, VAULT, "recent", "recent", "none", NhiType.ai_agent, "Support Reply Agent", "support_agent"),
    Profile("healthy", 37, "active", READ_WRITE, VAULT_ENV, "recent", "recent", "none_or_far"),
)

SEEDED_TABLES = ("people", "users", "systems", "scopes", "nhis", "nhi_scopes", "audit_events")


@dataclass(frozen=True)
class SeedReport:
    """The numbers the report quotes. assert_targets() builds and checks it."""

    people: int
    departed: int
    users: int
    systems: int
    scopes: int
    nhis: int
    nhi_scopes: int
    audit_events: int
    type_counts: dict[str, int]
    owner_null: int
    departed_owned: int
    active_owned: int
    leaver_owned: int
    created_by_leaver: int
    unrotated: int
    stale: int
    never_used: int
    admin_without_active_owner: int
    in_source_code: int
    expired: int
    expiring_30d: int
    ai_agents: int
    nhis_with_high_scope: int
    healthy: int
    injected_union: int

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


# The targets, from spec section 8 as amended, plus two counts measured on the
# first run and pinned (nhi_scopes, nhis_with_high_scope; decision D-045).
TARGETS: dict[str, Any] = {
    "people": 60,
    "departed": 8,
    "users": 2,
    "systems": 13,
    "scopes": 59,
    "nhis": 130,
    "nhi_scopes": 307,
    "audit_events": 60 + 2 + 13 + 59 + 130,
    "type_counts": {t.value: n for t, n in TYPE_MIX.items()},
    "owner_null": 54,
    "departed_owned": 24,
    "active_owned": 52,
    "leaver_owned": 10,
    "created_by_leaver": 3,
    "unrotated": 40,
    "stale": 32,
    "never_used": 10,
    "admin_without_active_owner": 8,
    "in_source_code": 12,
    "expired": 5,
    "expiring_30d": 4,
    "ai_agents": 2,
    "nhis_with_high_scope": 103,
    "healthy": 37,
    "injected_union": 130 - 37,
}


def table_counts() -> dict[str, int]:
    """Row counts of the seeded tables; the CLI refuses to seed when any is non-zero."""
    return {name: db.session.execute(select(func.count()).select_from(db.metadata.tables[name])).scalar_one() for name in SEEDED_TABLES}


def generate(*, now: datetime, admin_password: str, viewer_password: str) -> SeedReport:
    """Fill the empty database and return the verified report. The caller commits."""
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be an aware UTC datetime")
    rng = random.Random(SEED)
    people = _people(now)
    users = _users(people, admin_password, viewer_password)
    systems, scopes = _systems()
    nhis = _nhis(rng, now, people, systems, scopes)
    db.session.flush()
    for row in [*people, *users, *systems, *scopes]:
        audit.record(SEED_ACTION, row, after=audit.snapshot(row), created_at=now)
    for identity in nhis:
        payload = audit.snapshot(identity)
        payload["scope_ids"] = sorted(link.scope_id for link in identity.scope_links)
        audit.record(SEED_ACTION, identity, after=payload, created_at=now)
    db.session.flush()
    return assert_targets(now)


def _days_ago(now: datetime, days: int) -> datetime:
    return now - timedelta(days=days)


def _people(now: datetime) -> list[Person]:
    departed_days = dict(fx.DEPARTED)
    people: list[Person] = []
    index = 0
    for department, headcount, titles in fx.DEPARTMENTS:
        for position in range(headcount):
            first, last = fx.NAMES[index]
            domain = fx.CONSULTANCY_DOMAIN if department == "External Development" else fx.EMAIL_DOMAIN
            departed = index in departed_days
            people.append(
                Person(
                    full_name=f"{first} {last}",
                    email=f"{first}.{last}@{domain}".lower(),
                    department=department,
                    job_title=titles[position % len(titles)],
                    status=PersonStatus.departed if departed else PersonStatus.active,
                    departed_at=_days_ago(now, departed_days[index]) if departed else None,
                    created_at=now,
                    updated_at=now,
                )
            )
            index += 1
    db.session.add_all(people)
    return people


def _users(people: list[Person], admin_password: str, viewer_password: str) -> list[User]:
    users = [
        User(person=people[fx.ADMIN_PERSON_INDEX], username="admin", password_hash=generate_password_hash(admin_password), role=UserRole.admin),
        User(person=people[fx.VIEWER_PERSON_INDEX], username="viewer", password_hash=generate_password_hash(viewer_password), role=UserRole.viewer),
    ]
    db.session.add_all(users)
    return users


def _systems() -> tuple[list[System], list[Scope]]:
    systems = [System(name=name, category=category, criticality=criticality, description=description) for name, category, criticality, description in fx.SYSTEMS]
    by_name = {system.name: system for system in systems}
    scopes = [Scope(system=by_name[system_name], name=name, sensitivity=sensitivity) for system_name, entries in fx.SCOPES.items() for name, sensitivity in entries]
    db.session.add_all(systems + scopes)
    return systems, scopes


def _pick(rng: random.Random, options: tuple[Any, ...]) -> Any:
    return options[0] if len(options) == 1 else rng.choice(options)


def _nhis(rng: random.Random, now: datetime, people: list[Person], systems: list[System], scopes: list[Scope]) -> list[Nhi]:
    system_by_name = {system.name: system for system in systems}
    scopes_by_system = {name: [scope for scope in scopes if scope.system is system_by_name[name]] for name in system_by_name}
    scope_by_key = {(scope.system.name, scope.name): scope for scope in scopes}
    leaver = people[fx.DEMO_LEAVER_INDEX]
    other_departed = [person for person in people if person.status == PersonStatus.departed and person is not leaver]
    active_people = [person for person in people if person.status == PersonStatus.active]
    literals = synthetic_literals()

    slots = [profile for profile in PROFILES for _ in range(profile.count)]
    pool: list[NhiType] = [nhi_type for nhi_type, count in TYPE_MIX.items() for _ in range(count)]
    for profile in slots:
        if profile.nhi_type is not None:
            pool.remove(profile.nhi_type)
    rng.shuffle(pool)

    nhis: list[Nhi] = []
    next_literal = 0
    created_by_leaver_left = TARGETS["created_by_leaver"]
    for index, profile in enumerate(slots, start=1):
        nhi_type = profile.nhi_type or pool.pop()
        system = system_by_name[profile.system] if profile.system else system_by_name[rng.choice(fx.TYPE_SYSTEMS[nhi_type])]
        if profile.owner == "leaver":
            owner: Person | None = leaver
        elif profile.owner == "departed":
            owner = rng.choice(other_departed)
        elif profile.owner == "none":
            owner = None
        else:
            owner = rng.choice(active_people)

        used_days = None if profile.used == "never" else rng.randint(*USED_DAYS[profile.used])
        rotated_kind = rng.choice(("old", "never")) if profile.rotated == "old_or_never" else profile.rotated
        rotated_days = None if rotated_kind == "never" else rng.randint(*ROTATED_DAYS[rotated_kind])
        expires_kind = rng.choice(("none", "far")) if profile.expires == "none_or_far" else profile.expires
        if nhi_type == NhiType.certificate and expires_kind == "none":
            expires_kind = "far"
        if expires_kind == "none":
            expires_at = None
        elif expires_kind == "expired":
            expires_at = _days_ago(now, rng.randint(*EXPIRES_DAYS["expired"]))
        else:
            expires_at = now + timedelta(days=rng.randint(*EXPIRES_DAYS[expires_kind]))
        if profile.label == "deploy_key":
            created_days = DEMO_DEPLOY_KEY_AGE_DAYS
        elif rotated_days is None:
            created_days = rng.randint(*NEVER_ROTATED_CREATED_DAYS)
        else:
            created_days = rotated_days + rng.randint(30, 300)
        created_days = max(created_days, (used_days or 0) + 1)

        purpose_word = rng.choice(fx.PURPOSES)
        base_name = LABEL_NAMES.get(profile.label or "") or f"{fx.NAME_PREFIX[nhi_type]}-{purpose_word}"
        attributes = _attributes(rng, nhi_type, system, base_name, profile.label)
        if profile.key == "healthy" and created_by_leaver_left and owner is not leaver:
            attributes["created_by_email"] = leaver.email
            created_by_leaver_left -= 1
        storage = _pick(rng, profile.storage)
        identity = Nhi(
            name=f"{base_name}-{index:03d}",
            type=nhi_type,
            system=system,
            owner=owner,
            purpose=f"{purpose_word.replace('-', ' ').capitalize()} on {system.name}.",
            environment=Environment.prod if profile.label else rng.choice(ENVIRONMENTS),
            privilege_level=_pick(rng, profile.privilege),
            storage_location=storage,
            status=NhiStatus.active,
            created_at=_days_ago(now, created_days),
            last_used_at=None if used_days is None else _days_ago(now, used_days),
            last_rotated_at=None if rotated_days is None else _days_ago(now, rotated_days),
            expires_at=expires_at,
            attributes=validate_attributes(nhi_type, attributes),
            fingerprint=None,
            registered_by=None,
            registered_at=now,
            updated_at=now,
        )
        if storage == StorageLocation.source_code:
            identity.fingerprint = fingerprint(literals[next_literal][1])
            next_literal += 1
        for scope in _scopes_for(rng, profile, system, scopes_by_system, scope_by_key):
            identity.scope_links.append(NhiScope(scope=scope, granted_at=identity.created_at))
        nhis.append(identity)
    db.session.add_all(nhis)
    return nhis


def _attributes(rng: random.Random, nhi_type: NhiType, system: System, base_name: str, label: str | None) -> dict[str, Any]:
    slug = system.name.lower().replace(" ", "-")
    if nhi_type == NhiType.service_account:
        return {"login": f"{base_name}@{slug}", "auth_method": rng.choice(fx.AUTH_METHODS)}
    if nhi_type == NhiType.api_key:
        return {"key_prefix": "FLK" + rng.choice("ABCDEFGHJKLMNPQRSTUVWXYZ")}
    if nhi_type == NhiType.oauth_grant:
        return {"client_id": "".join(rng.choice("0123456789abcdef") for _ in range(16)), "grant_type": rng.choice(fx.GRANT_TYPES)}
    if nhi_type == NhiType.webhook:
        return {"target_url": f"https://hooks.{fx.EMAIL_DOMAIN}/{base_name}", "events": sorted(rng.sample(fx.WEBHOOK_EVENTS, 2))}
    if nhi_type == NhiType.deploy_key:
        return {"repo": rng.choice(fx.REPOS)}
    if nhi_type == NhiType.certificate:
        return {"issuer": rng.choice(fx.CERTIFICATE_ISSUERS), "san": [f"{slug}.{fx.EMAIL_DOMAIN}"]}
    if nhi_type == NhiType.ci_token:
        return {"pipeline": rng.choice(fx.PIPELINES), "token_scope": rng.choice(fx.TOKEN_SCOPES)}
    if label == "invoice_agent":
        return {"model_provider": "llm-provider-a", "tool_list": ["gmail.read", "sap.invoice.create"]}
    return {"model_provider": "llm-provider-b", "tool_list": ["crm.ticket.read", "crm.reply.draft", "slack.post"]}


def _scopes_for(
    rng: random.Random,
    profile: Profile,
    system: System,
    scopes_by_system: dict[str, list[Scope]],
    scope_by_key: dict[tuple[str, str], Scope],
) -> list[Scope]:
    if profile.label == "invoice_agent":
        return [scope_by_key[key] for key in fx.INVOICE_AGENT_SCOPES]
    if profile.label == "support_agent":
        return [scope_by_key[key] for key in fx.SUPPORT_AGENT_SCOPES]
    available = scopes_by_system[system.name]
    count = min(rng.randint(1, 4), len(available))
    return sorted(rng.sample(available, count), key=lambda scope: scope.name)


def days_since(now: datetime, moment: datetime | None) -> int | None:
    """Whole elapsed days, the age rule of decision D-045; None stays None."""
    return None if moment is None else (now - moment).days


def is_unrotated(nhi: Nhi, now: datetime) -> bool:
    return nhi.last_rotated_at is None or days_since(now, nhi.last_rotated_at) > 730


def is_stale(nhi: Nhi, now: datetime) -> bool:
    return nhi.last_used_at is None or days_since(now, nhi.last_used_at) > 180


def has_active_owner(nhi: Nhi) -> bool:
    return nhi.owner is not None and nhi.owner.status == PersonStatus.active


def is_expired(nhi: Nhi, now: datetime) -> bool:
    return nhi.expires_at is not None and nhi.expires_at < now


def is_expiring_30d(nhi: Nhi, now: datetime) -> bool:
    return nhi.expires_at is not None and now < nhi.expires_at <= now + timedelta(days=30)


def has_high_scope(nhi: Nhi) -> bool:
    return any(link.scope.sensitivity == Sensitivity.high for link in nhi.scope_links)


def is_agent_high_privilege(nhi: Nhi) -> bool:
    return nhi.type == NhiType.ai_agent and (nhi.privilege_level == PrivilegeLevel.admin or has_high_scope(nhi))


def is_prod_unknown_storage(nhi: Nhi) -> bool:
    return nhi.environment == Environment.prod and nhi.storage_location == StorageLocation.unknown


def is_healthy(nhi: Nhi, now: datetime) -> bool:
    """The healthy predicate of decision D-040, on columns only."""
    return (
        has_active_owner(nhi)
        and nhi.last_used_at is not None
        and days_since(now, nhi.last_used_at) <= 30
        and nhi.last_rotated_at is not None
        and days_since(now, nhi.last_rotated_at) < 90
        and not is_expired(nhi, now)
        and not is_expiring_30d(nhi, now)
        and nhi.storage_location in (StorageLocation.vault, StorageLocation.env_var)
        and nhi.privilege_level in (PrivilegeLevel.read, PrivilegeLevel.write)
        and not is_agent_high_privilege(nhi)
        and not is_prod_unknown_storage(nhi)
    )


def has_injected_condition(nhi: Nhi, now: datetime) -> bool:
    """True when the NHI is in at least one of the section 8 failure-mode sets.

    Invariant with is_healthy(): every identity that is not healthy must satisfy
    this predicate, so a new profile row that adds a failure mode has to be
    reflected in both. assert_targets() names any identity in the gap.
    """
    return (
        not has_active_owner(nhi)
        or is_unrotated(nhi, now)
        or is_stale(nhi, now)
        or nhi.storage_location == StorageLocation.source_code
        or is_expired(nhi, now)
        or is_expiring_30d(nhi, now)
        or is_agent_high_privilege(nhi)
        or is_prod_unknown_storage(nhi)
    )


def assert_targets(now: datetime) -> SeedReport:
    """Re-read the database and check every target; return the counts."""
    people = db.session.execute(select(Person).order_by(Person.id)).scalars().all()
    nhis = db.session.execute(select(Nhi).order_by(Nhi.id)).scalars().all()
    users = db.session.execute(select(User).order_by(User.id)).scalars().all()
    systems = db.session.execute(select(System).order_by(System.id)).scalars().all()
    scopes = db.session.execute(select(Scope).order_by(Scope.id)).scalars().all()
    events = db.session.execute(select(AuditEvent).order_by(AuditEvent.id)).scalars().all()
    leaver = next(person for person in people if person.email == "eitan.barak@devhouse.example")
    departed = [person for person in people if person.status == PersonStatus.departed]
    type_counts = {nhi_type.value: sum(1 for nhi in nhis if nhi.type == nhi_type) for nhi_type in NhiType}
    agents = [nhi for nhi in nhis if nhi.type == NhiType.ai_agent]
    in_source = [nhi for nhi in nhis if nhi.storage_location == StorageLocation.source_code]

    report = SeedReport(
        people=len(people),
        departed=len(departed),
        users=len(users),
        systems=len(systems),
        scopes=len(scopes),
        nhis=len(nhis),
        nhi_scopes=sum(len(nhi.scope_links) for nhi in nhis),
        audit_events=len(events),
        type_counts=type_counts,
        owner_null=sum(1 for nhi in nhis if nhi.owner is None),
        departed_owned=sum(1 for nhi in nhis if nhi.owner is not None and nhi.owner.status == PersonStatus.departed),
        active_owned=sum(1 for nhi in nhis if has_active_owner(nhi)),
        leaver_owned=sum(1 for nhi in nhis if nhi.owner is leaver),
        created_by_leaver=sum(1 for nhi in nhis if nhi.attributes.get("created_by_email") == leaver.email),
        unrotated=sum(1 for nhi in nhis if is_unrotated(nhi, now)),
        stale=sum(1 for nhi in nhis if is_stale(nhi, now)),
        never_used=sum(1 for nhi in nhis if nhi.last_used_at is None),
        admin_without_active_owner=sum(1 for nhi in nhis if nhi.privilege_level == PrivilegeLevel.admin and not has_active_owner(nhi)),
        in_source_code=len(in_source),
        expired=sum(1 for nhi in nhis if is_expired(nhi, now)),
        expiring_30d=sum(1 for nhi in nhis if is_expiring_30d(nhi, now)),
        ai_agents=len(agents),
        nhis_with_high_scope=sum(1 for nhi in nhis if has_high_scope(nhi)),
        healthy=sum(1 for nhi in nhis if is_healthy(nhi, now)),
        injected_union=sum(1 for nhi in nhis if has_injected_condition(nhi, now)),
    )
    for key, expected in TARGETS.items():
        actual = getattr(report, key)
        assert actual == expected, f"seed target {key}: expected {expected}, got {actual}"
    gap = [nhi.name for nhi in nhis if not is_healthy(nhi, now) and not has_injected_condition(nhi, now)]
    assert not gap, f"identities neither healthy nor in an injected set: {gap}"
    assert report.healthy + report.injected_union == report.nhis, "healthy plus injected must cover every NHI"

    # Shape checks the counts alone do not prove.
    assert all(90 <= days_since(now, person.departed_at) <= 900 for person in departed), "departed_at outside 3 to 30 months"
    assert sum(1 for person in departed if person.department == "External Development") >= 2, "fewer than two departed consultancy developers"
    assert sum(1 for person in people if person.job_title == "IT Coordinator") == 1, "exactly one IT coordinator"
    assert sum(1 for person in people if person.job_title in ("Driver", "Field Technician")) == 20, "twenty drivers and field technicians"
    assert leaver.status == PersonStatus.departed and leaver.department == "External Development" and leaver.job_title == "DevOps Engineer"
    recipient = next(person for person in people if person.email == "maya.peretz@devhouse.example")
    assert recipient.status == PersonStatus.active and recipient.department == "External Development"
    assert all(3 <= len(system.scopes) <= 8 for system in systems), "scopes per system outside 3 to 8"
    assert all(nhi.status == NhiStatus.active for nhi in nhis), "every seeded NHI is active"
    assert all(nhi.current_score is None and nhi.current_band is None for nhi in nhis), "no score before the first assessment (D-037)"
    assert all(nhi.owner is not leaver and has_active_owner(nhi) for nhi in nhis if nhi.attributes.get("created_by_email") == leaver.email)
    assert all(days_since(now, nhi.created_at) > 730 for nhi in nhis if is_unrotated(nhi, now)), "unrotated NHIs must be older than two years"
    fingerprints = [nhi.fingerprint for nhi in in_source]
    assert len(set(fingerprints)) == len(in_source) and all(len(value) == 64 and set(value) <= set("0123456789abcdef") for value in fingerprints)
    assert all(nhi.fingerprint is None for nhi in nhis if nhi.storage_location != StorageLocation.source_code)
    assert all(is_agent_high_privilege(nhi) for nhi in agents), "both AI agents over-privileged"
    demo_key = next(nhi for nhi in nhis if nhi.name.startswith(LABEL_NAMES["deploy_key"]))
    assert demo_key.owner is leaver and demo_key.privilege_level == PrivilegeLevel.admin and demo_key.last_rotated_at is None
    assert days_since(now, demo_key.created_at) >= 3 * 365 and demo_key.storage_location == StorageLocation.source_code
    assert {user.username: user.role for user in users} == {"admin": UserRole.admin, "viewer": UserRole.viewer}
    assert all(event.action == SEED_ACTION and event.actor_user_id is None and event.ip is None and event.user_agent is None for event in events)
    assert all("password_hash" not in event.after for event in events if event.entity_type == "users")
    return report
