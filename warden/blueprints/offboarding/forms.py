"""The two offboarding forms (spec 6.7): open a case for a departed person, decide one item.

DecisionForm checks the shape (one of the four decisions, an integer owner id,
the justification length); the conditional rules (a transfer needs an active
person, keep needs a justification) are the service's. The person picker of
OpenCaseForm lists the departed people without an open case; the S08 button
posts the same field with a hidden value, so the choice is checked by the
service rather than by validate_choice; the id keeps the nine-digit bound
every id carries (S4 finding O1)."""
from __future__ import annotations

from flask_wtf import FlaskForm
from wtforms import SelectField, StringField, SubmitField
from wtforms.validators import DataRequired, Length, NumberRange, Optional

from warden.filters import label
from warden.routing import ID_DIGITS
from warden.services.offboarding import DECISIONS

strip = [lambda value: value.strip() if value else value]


class OpenCaseForm(FlaskForm):
    person_id = SelectField("Departed person", coerce=int, validate_choice=False, validators=[DataRequired(), NumberRange(min=1, max=10**ID_DIGITS - 1)])
    submit = SubmitField("Open case")


class DecisionForm(FlaskForm):
    decision = SelectField("Decision", choices=[(decision.value, label(decision)) for decision in DECISIONS], validators=[DataRequired()])
    new_owner_id = SelectField("New owner", coerce=int, validators=[Optional()])
    justification = StringField("Justification", validators=[Optional(), Length(max=2000)], filters=strip)
