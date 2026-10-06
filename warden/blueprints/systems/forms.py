from flask_wtf import FlaskForm
from wtforms import SelectField, StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, Optional

from warden.filters import enum_choices
from warden.models import Criticality, SystemCategory

strip = [lambda value: value.strip() if value else value]


class SystemForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired(), Length(max=120)], filters=strip)
    category = SelectField("Category", choices=enum_choices(SystemCategory), validators=[DataRequired()])
    criticality = SelectField("Criticality", choices=enum_choices(Criticality), validators=[DataRequired()])
    description = TextAreaField("Description", validators=[Optional(), Length(max=2000)], filters=strip)
    submit = SubmitField("Save")
