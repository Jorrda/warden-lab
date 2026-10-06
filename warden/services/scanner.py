"""Repository secrets scanner (spec section 9, FR4) and the triage of its findings (spec 6.9).

Three detection layers, the ones Meli et al. 2019 name. Layer 1 is a list of
signature regexes with high precision plus one generic pattern: an assignment
whose name contains password, passwd, secret, token or api_key followed by a
quoted literal of at least MIN_CANDIDATE_LENGTH characters. Before anything
else, every candidate from every detector is dropped when it contains one of
the placeholders of warden.seed.synthetic_secrets.PLACEHOLDERS, matched
case-insensitively as a substring (phase 3 audit F34). Layer 2 runs on the
generic candidates only and drops a literal whose Shannon entropy, in bits per
character over its own characters, is under ENTROPY_THRESHOLD; the entropy of
every kept literal is stored so the run page can show it. Layer 3 keeps the
SHA-256 of the literal (the same input as nhis.fingerprint, decision D-029)
and a masked preview of its first 4 and last 2 characters, or a fixed mask
under MASK_MIN_LENGTH characters (phase 0 plan 18.3). The literal itself is
never stored, logged or handed to a page (CLAUDE.md 2).

The walk is sorted, prunes the directories of SKIP_DIRS, skips symbolic
links, files over MAX_FILE_BYTES, unreadable files and binaries (a NUL byte in
the first BINARY_SNIFF_BYTES, or bytes that are not UTF-8), and normalises line endings
to "\\n" before matching, so a PEM block hashes the same on a CRLF checkout.
The application's own configuration is never read: an .env file directly
under the folder holding app.py (own_config, whatever the allowed base) and
the instance/ folder are skipped, while an .env inside a scanned project
(sample_repo/.env) is a file like any other (phase 6 audit F22, S4 finding
O3). Paths are relative to the scan root with forward slashes. A target is
accepted only when its resolved path stays inside the configured base and
names none of the skipped directories (spec 6.9; a target of .git or instance
would otherwise walk what a child of that name is pruned for, S4 finding
O4); the run stores the target relative to that base (audit F10).

Ground truth: when the scan root holds ground_truth.json, each entry is
matched on (file, line) only; a type mismatch still counts as detected and
is shown as a warning; several findings on one line collapse to one detection
(phase 0 plan 18.3). The counters are stored on the run; the lists are rebuilt
from the file when the run page renders (phase 2 audit F13). Precision is the
share of findings that sit on a ground-truth line; recall the share of
ground-truth entries with a finding.

run_scan() writes the scan_runs row, one findings row per detection in status
new with nhi_id null (a fingerprint match is a triage suggestion, phase 3
audit F33) and one scan.run audit row, none per finding (phase 4 audit F18).
Each triage action writes its own row: finding.confirm, finding.false_positive,
finding.link and finding.create_nhi. A triage decision can be changed: the
last action wins, confirm or false positive on a linked finding clears nhi_id
(linked and nhi_id go together, decision D-030), a link can move to another
identity, and repeating the recorded decision writes nothing (audit F06, the
D-059 shape). Every change of the (status, nhi_id) pair rescores the identity
on each side with trigger write, because SECRET_IN_SOURCE reads a finding with
nhi_id set whose status is confirmed or linked (D-030, audit F16). Nothing here
imports Flask request objects (CLAUDE.md 5).
"""
from __future__ import annotations

import json
import math
import os
import re
import time
from collections import Counter
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Protocol

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import selectinload

from warden.extensions import db
from warden.models import AuditEvent, Finding, FindingStatus, Nhi, NhiType, RiskTrigger, ScanRun, System, SystemCategory
from warden.seed.synthetic_secrets import PLACEHOLDERS, fingerprint
from warden.services import audit, inventory, risk
from warden.services.audit import Actor
from warden.services.inventory import NhiFields

SKIP_DIRS: frozenset[str] = frozenset({".git", ".venv", "venv", "node_modules", "__pycache__", "instance"})
OWN_CONFIG_PREFIX = ".env"  # a file named .env or .env.* directly under the folder holding app.py is the application's own configuration
MAX_FILE_BYTES = 1_000_000
BINARY_SNIFF_BYTES = 8192
ENTROPY_THRESHOLD = 3.4  # bits per character; the rounded midpoint between the corpus decoys (3.28 at most) and its generic secrets (3.57 at least)
MIN_CANDIDATE_LENGTH = 8
MASK_MIN_LENGTH = 12
SHORT_MASK = "********"
GROUND_TRUTH_FILE = "ground_truth.json"
RUN_ACTION = "scan.run"


class TargetError(ValueError):
    """The requested path is not a directory inside the allowed base."""


class TriageError(ValueError):
    """The triage action does not apply to the finding in its current status."""


@dataclass(frozen=True)
class Detector:
    """One layer 1 pattern: the literal is the given group; generic detectors also pass layer 2."""

    name: str
    pattern: re.Pattern[str]
    group: int = 1
    generic: bool = False


DETECTORS: tuple[Detector, ...] = (
    Detector("private_key_pem", re.compile(r"(-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----\n[\s\S]{0,16000}?\n-----END (?:[A-Z]+ )?PRIVATE KEY-----)")),
    Detector("aws_access_key_id", re.compile(r"(?<![A-Za-z0-9])((?:AKIA|ASIA)[A-Z0-9]{16})(?![A-Za-z0-9])")),
    Detector(
        "aws_secret_access_key",
        re.compile(r"(?i)aws[_\- ]?secret[_\- ]?(?:access[_\- ]?)?key[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"),
    ),
    Detector("github_token", re.compile(r"(?<![A-Za-z0-9_])(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})(?![A-Za-z0-9_])")),
    Detector("slack_token", re.compile(r"(?<![A-Za-z0-9])(xox[abpr]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,34})(?![A-Za-z0-9])")),
    Detector("stripe_live_key", re.compile(r"(?<![A-Za-z0-9_])([sr]k_live_[A-Za-z0-9]{24,})(?![A-Za-z0-9])")),
    Detector("google_api_key", re.compile(r"(?<![A-Za-z0-9_\-])(AIza[0-9A-Za-z_\-]{35})(?![0-9A-Za-z_\-])")),
    Detector("jwt", re.compile(r"(?<![A-Za-z0-9_\-])(eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})(?![A-Za-z0-9_\-.])")),
    Detector("bitbucket_app_password", re.compile(r"(?<![A-Za-z0-9])(ATBB[A-Za-z0-9]{28,})(?![A-Za-z0-9])")),
    Detector(
        "database_uri",
        re.compile(r"(?<![A-Za-z0-9+.\-])((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp|mssql)://[^\s:/@'\"]+:[^\s@'\"]+@[^\s'\"<>]+)"),
    ),
    Detector(
        "generic",
        re.compile(r"(?i)\b[A-Za-z_]{0,64}?(password|passwd|secret|token|api[_\-]?key)[A-Za-z_]{0,64}[\"']?\s*[:=]\s*([\"'])([^\"'\s]{8,})\2"),
        group=3,
        generic=True,
    ),
)


class Located(Protocol):
    """What compare() reads from a detection or a stored finding: where it is and what detector named it."""

    @property
    def file_path(self) -> str: ...

    @property
    def line_no(self) -> int: ...

    @property
    def secret_type(self) -> str: ...


@dataclass(frozen=True)
class Detection:
    """One layer 3 result: what is stored, never the literal."""

    file_path: str
    line_no: int
    secret_type: str
    fingerprint: str
    masked_preview: str
    entropy: float


@dataclass(frozen=True)
class ScanReport:
    files_scanned: int
    files_skipped: int
    detections: tuple[Detection, ...]


@dataclass(frozen=True)
class TruthEntry:
    file: str
    line: int
    secret_type: str


@dataclass(frozen=True)
class Comparison:
    """The run against its ground truth: every entry detected or missed, every finding on no ground-truth line."""

    detected: tuple[tuple[TruthEntry, tuple[str, ...]], ...]  # the entry and the detector names that found the line
    missed: tuple[TruthEntry, ...]
    false_positives: tuple[Located, ...]  # detections or findings, whichever the caller passed
    findings_count: int

    @property
    def true_positives(self) -> int:
        return len(self.detected)

    @property
    def total(self) -> int:
        return len(self.detected) + len(self.missed)

    @property
    def recall(self) -> float | None:
        return None if self.total == 0 else self.true_positives / self.total

    @property
    def precision(self) -> float | None:
        return None if self.findings_count == 0 else (self.findings_count - len(self.false_positives)) / self.findings_count


def shannon_entropy(literal: str) -> float:
    """Bits per character over the literal's own character frequencies; 0 for the empty string."""
    if not literal:
        return 0.0
    counts = Counter(literal)
    length = len(literal)
    return -sum(count / length * math.log2(count / length) for count in counts.values())


def is_placeholder(literal: str) -> bool:
    lowered = literal.lower()
    return any(placeholder in lowered for placeholder in PLACEHOLDERS)


def mask(literal: str) -> str:
    """First 4 and last 2 characters around three dots, or the fixed mask for a short literal."""
    if len(literal) < MASK_MIN_LENGTH:
        return SHORT_MASK
    return literal[:4] + "..." + literal[-2:]


def _generic_name(keyword: str) -> str:
    lowered = keyword.lower()
    if lowered == "passwd":
        lowered = "password"
    elif lowered.startswith("api"):
        lowered = "api_key"
    return "generic_" + lowered


def scan_text(text: str, file_path: str) -> list[Detection]:
    """Every detection in one file's text, one per (line, literal), the first detector in order winning."""
    seen: set[tuple[int, str]] = set()
    found: list[Detection] = []
    for detector in DETECTORS:
        for match in detector.pattern.finditer(text):
            literal = match.group(detector.group)
            if len(literal) < MIN_CANDIDATE_LENGTH or is_placeholder(literal):
                continue
            entropy = shannon_entropy(literal)
            if detector.generic and entropy < ENTROPY_THRESHOLD:
                continue
            digest = fingerprint(literal)
            line_no = text.count("\n", 0, match.start(detector.group)) + 1
            if (line_no, digest) in seen:
                continue
            seen.add((line_no, digest))
            name = _generic_name(match.group(1)) if detector.generic else detector.name
            found.append(Detection(file_path, line_no, name, digest, mask(literal), entropy))
    return sorted(found, key=lambda item: (item.line_no, item.secret_type))


def read_text(path: Path) -> str | None:
    """The file's text with line endings normalised, or None for a binary, an oversized or an unreadable file."""
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        data = path.read_bytes()
    except OSError:  # unreadable, locked or gone since the walk listed it: skipped like a binary, never a 500 (S5 architecture finding B-2)
        return None
    if b"\x00" in data[:BINARY_SNIFF_BYTES]:
        return None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return text.replace("\r\n", "\n").replace("\r", "\n")


def walk(root: Path, *, own_config: Path | None = None) -> Iterator[tuple[str, Path]]:
    """Every regular file under root in a sorted walk, as (relative posix path, path).

    SKIP_DIRS are pruned, links are skipped, and so is an .env file directly
    under own_config, the folder holding app.py: that is the application's own
    configuration, whose masked preview would be four characters of a real
    secret. An .env deeper down (sample_repo/.env) is scanned like any file.
    """
    own = own_config.resolve() if own_config is not None else None
    for directory, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(name for name in dirnames if name.lower() not in SKIP_DIRS)
        for name in sorted(filenames):
            path = Path(directory) / name
            if path.is_symlink() or not path.is_file():
                continue
            if own is not None and name.startswith(OWN_CONFIG_PREFIX) and path.parent.resolve() == own:
                continue
            yield path.relative_to(root).as_posix(), path


def scan_directory(root: Path, *, own_config: Path | None = None) -> ScanReport:
    """Layer 1 to 3 over every text file under root; own_config is the folder holding app.py, whose .env is skipped."""
    scanned = skipped = 0
    detections: list[Detection] = []
    for relative, path in walk(root, own_config=own_config):
        text = read_text(path)
        if text is None:
            skipped += 1
            continue
        scanned += 1
        detections.extend(scan_text(text, relative))
    return ScanReport(files_scanned=scanned, files_skipped=skipped, detections=tuple(detections))


def resolve_target(raw: str, base: Path) -> Path:
    """The directory to scan: raw relative to base or absolute, resolved, inside base or base itself, and not a skipped name."""
    base = base.resolve()
    candidate = Path(raw.strip() or ".")
    try:
        target = (candidate if candidate.is_absolute() else base / candidate).resolve()
    except (OSError, ValueError):  # a NUL byte or a name the OS refuses: a refusal naming no part of the input, never a 500 (S8a finding R01)
        raise TargetError("the target is not a usable path") from None
    if target != base and base not in target.parents:
        raise TargetError(f"{raw.strip() or '.'} is outside the allowed base directory")
    if not target.is_dir():
        raise TargetError(f"{raw.strip() or '.'} is not a directory")
    skipped = [part for part in target.relative_to(base).parts if part.lower() in SKIP_DIRS]
    if skipped:
        raise TargetError(f"{raw.strip() or '.'} is inside {skipped[0]}, which a scan never reads")
    return target


def load_ground_truth(root: Path) -> list[TruthEntry] | None:
    """The secrets listed in root/ground_truth.json, or None when the file is absent, unreadable or not in the fixture's shape."""
    path = root / GROUND_TRUTH_FILE
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        entries = [TruthEntry(str(item["file"]), int(item["line"]), str(item["type"])) for item in data["secrets"]]
    except (OSError, ValueError, KeyError, TypeError):
        return None
    return entries


def compare(truth: list[TruthEntry], findings: Sequence[Located]) -> Comparison:
    """Match on (file, line) only: an entry with any finding on its line is detected, a finding on no entry's line is a false positive."""
    by_line: dict[tuple[str, int], list[str]] = {}
    for item in findings:
        by_line.setdefault((item.file_path, item.line_no), []).append(item.secret_type)
    truth_lines = {(entry.file, entry.line) for entry in truth}
    detected = tuple((entry, tuple(by_line[(entry.file, entry.line)])) for entry in truth if (entry.file, entry.line) in by_line)
    missed = tuple(entry for entry in truth if (entry.file, entry.line) not in by_line)
    false_positives = tuple(item for item in findings if (item.file_path, item.line_no) not in truth_lines)
    return Comparison(detected=detected, missed=missed, false_positives=false_positives, findings_count=len(findings))


def relative_target(target: Path, base: Path) -> str:
    resolved = target.resolve()
    base = base.resolve()
    return "." if resolved == base else resolved.relative_to(base).as_posix()


def run_scan(raw_target: str, *, base: Path, own_config: Path | None, actor: Actor, now: datetime) -> ScanRun:
    """Scan the target, store the run and its findings with one scan.run audit row; commit.

    own_config is the folder holding app.py, whose .env is never read; None skips no file (a service caller with no application).
    """
    if actor.user_id is None:
        raise ValueError("a scan is started by a signed-in admin; scan_runs.started_by cannot be null")
    root = resolve_target(raw_target, base)
    started = time.perf_counter()
    report = scan_directory(root, own_config=own_config)
    truth = load_ground_truth(root)
    comparison = compare(truth, list(report.detections)) if truth is not None else None
    elapsed = time.perf_counter() - started
    run = ScanRun(
        target_path=relative_target(root, base),
        started_by=actor.user_id,
        started_at=now,
        finished_at=now + timedelta(seconds=elapsed),
        files_scanned=report.files_scanned,
        findings_count=len(report.detections),
        true_positives=None if comparison is None else comparison.true_positives,
        false_positives=None if comparison is None else len(comparison.false_positives),
        missed=None if comparison is None else len(comparison.missed),
        recall=None if comparison is None else comparison.recall,
        precision=None if comparison is None else comparison.precision,
    )
    db.session.add(run)
    db.session.flush()
    for item in report.detections:
        db.session.add(
            Finding(
                scan_run_id=run.id,
                nhi_id=None,
                file_path=item.file_path,
                line_no=item.line_no,
                secret_type=item.secret_type,
                masked_preview=item.masked_preview,
                fingerprint=item.fingerprint,
                entropy=item.entropy,
                status=FindingStatus.new,
                detected_at=now,
            )
        )
    db.session.flush()
    payload = audit.snapshot(run)
    payload["files_skipped"] = report.files_skipped
    payload["ground_truth"] = "absent" if truth is None else "present"
    audit.record(RUN_ACTION, run, actor=actor, after=payload, created_at=now)
    db.session.commit()
    return run


def list_runs(target: str = "") -> list[ScanRun]:
    """The S15 rows, newest first, all of them or those of one target (the list's filter, CLAUDE.md 5)."""
    statement = select(ScanRun).options(selectinload(ScanRun.starter)).order_by(ScanRun.started_at.desc(), ScanRun.id.desc())
    if target:
        statement = statement.where(ScanRun.target_path == target)
    return list(db.session.execute(statement).scalars())


def targets() -> list[str]:
    """Every target scanned so far, for the S15 filter."""
    return list(db.session.execute(select(ScanRun.target_path).distinct().order_by(ScanRun.target_path)).scalars())


def load_run(run_id: int) -> ScanRun | None:
    return db.session.get(ScanRun, run_id, options=[selectinload(ScanRun.starter), selectinload(ScanRun.findings).selectinload(Finding.nhi)])


def run_findings(run: ScanRun) -> list[Finding]:
    """The run's findings in file and line order."""
    return sorted(run.findings, key=lambda item: (item.file_path, item.line_no, item.id))


def run_trail(run: ScanRun, limit: int = audit.TRAIL_LIMIT) -> list[AuditEvent]:
    """The newest audit rows about the run and its findings, for the S16 trail (the case_trail shape of phase 5)."""
    finding_ids = [finding.id for finding in run.findings]
    about_run = and_(AuditEvent.entity_type == ScanRun.__tablename__, AuditEvent.entity_id == run.id)
    about_findings = and_(AuditEvent.entity_type == Finding.__tablename__, AuditEvent.entity_id.in_(finding_ids)) if finding_ids else False
    statement = (
        select(AuditEvent)
        .where(or_(about_run, about_findings))
        .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
        .limit(limit)
        .options(selectinload(AuditEvent.actor))
    )
    return list(db.session.execute(statement).scalars())


def comparison_of(run: ScanRun, *, base: Path) -> Comparison | None:
    """The ground-truth lists rebuilt from the file at render time; None when the file is gone or the target moved."""
    try:
        root = resolve_target(run.target_path, base)
    except TargetError:
        return None
    truth = load_ground_truth(root)
    return None if truth is None else compare(truth, run_findings(run))


def findings_of(nhi: Nhi) -> list[Finding]:
    """The findings linked to one identity, for the S04 panel, newest run first."""
    statement = select(Finding).where(Finding.nhi_id == nhi.id).options(selectinload(Finding.scan_run)).order_by(Finding.scan_run_id.desc(), Finding.file_path, Finding.line_no)
    return list(db.session.execute(statement).scalars())


def suggestions(run: ScanRun) -> dict[int, Nhi]:
    """Per finding id, the identity whose fingerprint equals the finding's, when one exists (the by-fingerprint suggestion of spec 6.9)."""
    digests = {item.fingerprint for item in run.findings}
    if not digests:
        return {}
    statement = select(Nhi).where(Nhi.fingerprint.in_(list(digests))).options(selectinload(Nhi.system)).order_by(Nhi.id)
    by_digest: dict[str, Nhi] = {}
    for nhi in db.session.execute(statement).scalars():
        by_digest.setdefault(nhi.fingerprint, nhi)  # type: ignore[arg-type]
    return {item.id: by_digest[item.fingerprint] for item in run.findings if item.fingerprint in by_digest}


def _set_status(finding: Finding, status: FindingStatus, nhi: Nhi | None, action: str, *, actor: Actor, now: datetime) -> bool:
    """Move the finding to (status, nhi), rescore the identities the change touches, write the row, commit.

    Returns False and writes nothing when the finding already holds that pair
    (the D-059 shape: repeating a decision is not a second decision).
    """
    target_id = nhi.id if nhi is not None else None
    if finding.status == status and finding.nhi_id == target_id:
        return False
    before = audit.snapshot(finding)
    previous = finding.nhi if finding.nhi_id is not None and finding.nhi_id != target_id else None
    finding.nhi = nhi
    finding.status = status
    db.session.flush()
    after = audit.snapshot(finding)
    if nhi is not None:
        risk.assess_nhi(nhi, now=now, trigger=RiskTrigger.write)
    if previous is not None:
        risk.assess_nhi(previous, now=now, trigger=RiskTrigger.write)
        after["unlinked_nhi_id"] = previous.id
    audit.record(action, finding, actor=actor, before=before, after=after, created_at=now)
    db.session.commit()
    return True


def confirm(finding: Finding, *, actor: Actor, now: datetime) -> bool:
    """To confirmed with no identity: a new finding confirmed, a false positive reopened, a linked finding unlinked."""
    return _set_status(finding, FindingStatus.confirmed, None, "finding.confirm", actor=actor, now=now)


def mark_false_positive(finding: Finding, *, actor: Actor, now: datetime) -> bool:
    """To false_positive with no identity; a linked finding is unlinked and its identity rescored."""
    return _set_status(finding, FindingStatus.false_positive, None, "finding.false_positive", actor=actor, now=now)


def link(finding: Finding, nhi: Nhi, *, actor: Actor, now: datetime) -> bool:
    """To linked with the identity (linked implies confirmed, D-030); a link can move to another identity."""
    return _set_status(finding, FindingStatus.linked, nhi, "finding.link", actor=actor, now=now)


# Which identity type and system a secret type suggests for "create NHI from finding" (spec 6.9): the system whose
# name contains the hint, else the first system of the category by name, else none. Only the type and the system
# are prefilled; every other field is the admin's choice on the unchanged S05 form (audit F05).
GUESSES: dict[str, tuple[NhiType, SystemCategory | None, str | None]] = {
    "aws_access_key_id": (NhiType.api_key, SystemCategory.cloud, "aws"),
    "aws_secret_access_key": (NhiType.api_key, SystemCategory.cloud, "aws"),
    "github_token": (NhiType.ci_token, SystemCategory.ci_cd, None),
    "bitbucket_app_password": (NhiType.ci_token, SystemCategory.ci_cd, "bitbucket"),
    "slack_token": (NhiType.api_key, SystemCategory.messaging, "slack"),
    "stripe_live_key": (NhiType.api_key, None, "stripe"),
    "google_api_key": (NhiType.api_key, SystemCategory.saas, "google"),
    "private_key_pem": (NhiType.deploy_key, SystemCategory.ci_cd, None),
    "jwt": (NhiType.oauth_grant, None, None),
    "database_uri": (NhiType.service_account, SystemCategory.database, None),
    "generic_password": (NhiType.service_account, None, None),
    "generic_secret": (NhiType.api_key, None, None),
    "generic_token": (NhiType.ci_token, None, None),
    "generic_api_key": (NhiType.api_key, None, None),
}


@dataclass(frozen=True)
class Guess:
    nhi_type: NhiType
    system: System | None


def guess_for(finding: Finding) -> Guess:
    """The type and system the S05 form is prefilled with when an identity is created from the finding."""
    nhi_type, category, hint = GUESSES.get(finding.secret_type, (NhiType.api_key, None, None))
    systems = list(db.session.execute(select(System).order_by(System.name)).scalars())
    by_hint = next((system for system in systems if hint and hint in system.name.lower()), None)
    by_category = next((system for system in systems if category is not None and system.category == category), None)
    return Guess(nhi_type=nhi_type, system=by_hint or by_category)


def create_from_finding(finding: Finding, fields: NhiFields, *, actor: Actor, now: datetime) -> Nhi:
    """Register an identity carrying the finding's fingerprint and link the finding to it in one transaction; commit."""
    if finding.status == FindingStatus.linked:
        raise TriageError(f"finding #{finding.id} is already linked to an identity")
    before = audit.snapshot(finding)
    nhi = inventory.add_nhi(fields, actor=actor, now=now, fingerprint=finding.fingerprint)
    finding.nhi = nhi
    finding.status = FindingStatus.linked
    db.session.flush()
    inventory.record_create(nhi, actor=actor, now=now)  # scores the identity with its linked finding in view
    audit.record("finding.create_nhi", finding, actor=actor, before=before, after=audit.snapshot(finding), created_at=now)
    db.session.commit()
    return nhi
