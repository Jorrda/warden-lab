"""S05 create and edit form (spec 6.3). One StringField per attribute key of
ATTRIBUTE_SCHEMA, each bounded by ATTRIBUTE_LIMITS, the table validate_attributes()
and the importer share; the route reads only the keys of the submitted type and
validate_attributes() checks the result. List-valued keys are entered as
comma-separated text. They are bounded on their canonical comma-joined text,
the measure the model uses. The type is editable on edit too, and the attributes
are rebuilt from the submitted type's group (phase 3 audit F13). There is no
secret input (decision D-029) and no scope picker (phase 3 audit F03)."""
from __future__ import annotations

from datetime import date, datetime, time, timezone
from typing import Any

from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed, FileField, FileRequired
from wtforms import DateField, HiddenField, SelectField, StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, Optional, Regexp, ValidationError

from warden.filters import EMAIL_PATTERN, URL_PATTERN, enum_choices
from warden.models import ATTRIBUTE_LIMITS, ATTRIBUTE_SCHEMA, COMMON_ATTRIBUTE_KEYS, Environment, NhiType, PrivilegeLevel, StorageLocation
from warden.routing import ID_DIGITS
from warden.services.importer import MAX_BYTES

strip = [lambda value: value.strip() if value else value]

ATTRIBUTE_LABELS: dict[str, str] = {
    "login": "Login",
    "auth_method": "Authentication method",
    "key_prefix": "Key prefix",
    "client_id": "Client id",
    "grant_type": "Grant type",
    "target_url": "Target URL",
    "events": "Events (comma separated)",
    "repo": "Repository",
    "issuer": "Issuer",
    "san": "Subject alternative names (comma separated)",
    "pipeline": "Pipeline",
    "token_scope": "Token scope",
    "model_provider": "Model provider",
    "tool_list": "Tools (comma separated)",
    "created_by_email": "Created by (email)",
}
LIST_KEYS = frozenset(key for keys in ATTRIBUTE_SCHEMA.values() for key, kind in keys.items() if kind is list)
ALL_ATTRIBUTE_KEYS = frozenset(key for keys in ATTRIBUTE_SCHEMA.values() for key in keys) | frozenset(COMMON_ATTRIBUTE_KEYS)


def to_utc(value: date | None) -> datetime | None:
    """A form date becomes midnight UTC of that day (CLAUDE.md 5: aware UTC in the database)."""
    return None if value is None else datetime.combine(value, time.min, tzinfo=timezone.utc)


def split_list(value: str | None) -> list[str]:
    return [item.strip() for item in (value or "").split(",") if item.strip()]


class ListLength:
    """Bound a comma-separated list field on its canonical comma-joined text, the measure validate_attributes()
    uses, so the form, the model and the importer agree however the list is typed or rendered (S8a finding R02)."""

    def __init__(self, max: int) -> None:
        self.max = max

    def __call__(self, form: FlaskForm, field: StringField) -> None:
        if len(",".join(split_list(field.data))) > self.max:
            raise ValidationError(f"Field cannot be longer than {self.max} characters.")


class NhiForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired(), Length(max=120)], filters=strip)
    type = SelectField("Type", choices=enum_choices(NhiType), validators=[DataRequired()])
    system_id = SelectField("System", coerce=int, validators=[DataRequired()])
    owner_id = SelectField("Owner", coerce=int, validators=[Optional()])
    purpose = TextAreaField("Purpose", validators=[Optional(), Length(max=2000)], filters=strip)
    environment = SelectField("Environment", choices=enum_choices(Environment), validators=[DataRequired()])
    privilege_level = SelectField("Privilege level", choices=enum_choices(PrivilegeLevel), validators=[DataRequired()])
    storage_location = SelectField("Storage location", choices=enum_choices(StorageLocation), validators=[DataRequired()])
    created_at = DateField("Created on", validators=[DataRequired()])
    last_used_at = DateField("Last used on", validators=[Optional()])
    last_rotated_at = DateField("Last rotated on", validators=[Optional()])
    expires_at = DateField("Expires on", validators=[Optional()])

    # Attribute keys of every type; the route reads the group of the identity's type.
    login = StringField(ATTRIBUTE_LABELS["login"], validators=[Optional(), Length(max=ATTRIBUTE_LIMITS["login"])], filters=strip)
    auth_method = StringField(ATTRIBUTE_LABELS["auth_method"], validators=[Optional(), Length(max=ATTRIBUTE_LIMITS["auth_method"])], filters=strip)
    key_prefix = StringField(ATTRIBUTE_LABELS["key_prefix"], validators=[Optional(), Length(max=ATTRIBUTE_LIMITS["key_prefix"])], filters=strip)
    client_id = StringField(ATTRIBUTE_LABELS["client_id"], validators=[Optional(), Length(max=ATTRIBUTE_LIMITS["client_id"])], filters=strip)
    grant_type = StringField(ATTRIBUTE_LABELS["grant_type"], validators=[Optional(), Length(max=ATTRIBUTE_LIMITS["grant_type"])], filters=strip)
    target_url = StringField(ATTRIBUTE_LABELS["target_url"], validators=[Optional(), Length(max=ATTRIBUTE_LIMITS["target_url"]), Regexp(URL_PATTERN, message="Enter an http or https URL.")], filters=strip)
    events = StringField(ATTRIBUTE_LABELS["events"], validators=[Optional(), ListLength(max=ATTRIBUTE_LIMITS["events"])], filters=strip)
    repo = StringField(ATTRIBUTE_LABELS["repo"], validators=[Optional(), Length(max=ATTRIBUTE_LIMITS["repo"])], filters=strip)
    issuer = StringField(ATTRIBUTE_LABELS["issuer"], validators=[Optional(), Length(max=ATTRIBUTE_LIMITS["issuer"])], filters=strip)
    san = StringField(ATTRIBUTE_LABELS["san"], validators=[Optional(), ListLength(max=ATTRIBUTE_LIMITS["san"])], filters=strip)
    pipeline = StringField(ATTRIBUTE_LABELS["pipeline"], validators=[Optional(), Length(max=ATTRIBUTE_LIMITS["pipeline"])], filters=strip)
    token_scope = StringField(ATTRIBUTE_LABELS["token_scope"], validators=[Optional(), Length(max=ATTRIBUTE_LIMITS["token_scope"])], filters=strip)
    model_provider = StringField(ATTRIBUTE_LABELS["model_provider"], validators=[Optional(), Length(max=ATTRIBUTE_LIMITS["model_provider"])], filters=strip)
    tool_list = StringField(ATTRIBUTE_LABELS["tool_list"], validators=[Optional(), ListLength(max=ATTRIBUTE_LIMITS["tool_list"])], filters=strip)
    created_by_email = StringField(ATTRIBUTE_LABELS["created_by_email"], validators=[Optional(), Length(max=ATTRIBUTE_LIMITS["created_by_email"]), Regexp(EMAIL_PATTERN, message="Enter a valid email address.")], filters=strip)
    # Set when the identity is created from a scanner finding (spec 6.9): the finding is linked on save.
    finding_id = HiddenField(validators=[Optional(), Regexp(rf"^\d{{1,{ID_DIGITS}}}$")])
    submit = SubmitField("Save")

    def validate_for(self, nhi_type: NhiType | None) -> bool:
        """Validate, ignoring errors on attribute fields of other types' groups.

        The page hides the groups that do not apply, but a value typed before
        the type was changed still arrives; only the identity's own group counts.
        """
        self.validate()
        if nhi_type is not None:
            active = set(ATTRIBUTE_SCHEMA[nhi_type]) | set(COMMON_ATTRIBUTE_KEYS)
            for key in ALL_ATTRIBUTE_KEYS - active:
                getattr(self, key).errors = []
        return not any(field.errors for field in self)

    def attributes_for(self, nhi_type: NhiType) -> dict[str, Any]:
        """The attributes dict of one type from the form data; empty fields are left out."""
        clean: dict[str, Any] = {}
        for key in [*ATTRIBUTE_SCHEMA[nhi_type], *COMMON_ATTRIBUTE_KEYS]:
            raw = getattr(self, key).data
            if key in LIST_KEYS:
                items = split_list(raw)
                if items:
                    clean[key] = items
            elif raw:
                clean[key] = raw
        return clean

    def fill_attributes(self, nhi_type: NhiType, attributes: dict[str, Any]) -> None:
        for key, value in attributes.items():
            field = getattr(self, key, None)
            if field is not None:
                field.data = ", ".join(value) if isinstance(value, list) else value


class ImportForm(FlaskForm):
    """S06 step one: the CSV upload (spec 6.3). The size limit is the app's MAX_CONTENT_LENGTH (413) plus the importer's MAX_BYTES."""

    file = FileField("CSV file", validators=[FileRequired(), FileAllowed(["csv"], "Upload a .csv file.")])
    submit = SubmitField("Preview")


class ImportCommitForm(FlaskForm):
    """S06 step two: the preview hands the file's text back, and the commit validates it again.

    csv_text is a TextAreaField, not a HiddenField, so hidden_tag() does not
    render it beside the template's own hidden textarea (rendered once, the
    text is posted once; S4 finding F1). Its Length is a loose guard only: a
    browser re-posts the textarea with CRLF line ends, and the importer measures
    the real bound on the normalised text (S5 architecture finding A-2).
    """

    csv_text = TextAreaField(validators=[DataRequired(), Length(max=2 * MAX_BYTES)])
    filename = HiddenField(validators=[DataRequired(), Length(max=255)])
    submit = SubmitField("Commit")
