"""The scanner forms (spec 6.9): the run form with its target path, and the link form of a finding.

ScanForm checks the shape (a path of at most 500 characters); whether the path
stays inside the allowed base is the service's check. LinkForm's picker lists
every identity, so a finding can be linked to any of them; the fingerprint
suggestion is a preselected option, not a separate form. The confirm and
false-positive actions carry only the CSRF token. The S16 template writes the
token input of its many small forms by hand, as the other multi-form pages
do, so one page never repeats the id hidden_tag() gives the field (S5
architecture finding A-6); the forms here are the server's check of each POST."""
from __future__ import annotations

from flask_wtf import FlaskForm
from wtforms import SelectField, StringField, SubmitField
from wtforms.validators import DataRequired, Length, NumberRange, Optional

from warden.routing import ID_DIGITS

strip = [lambda value: value.strip() if value else value]


class ScanForm(FlaskForm):
    target = StringField("Directory to scan", validators=[Optional(), Length(max=500)], filters=strip)
    submit = SubmitField("Run scan")


class LinkForm(FlaskForm):
    nhi_id = SelectField("Identity", coerce=int, validate_choice=False, validators=[DataRequired(), NumberRange(min=1, max=10**ID_DIGITS - 1)])
    submit = SubmitField("Link")


class TriageForm(FlaskForm):
    """CSRF only: confirm and false positive carry no field."""
