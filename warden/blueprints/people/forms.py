from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Length, Regexp

from warden.filters import EMAIL_PATTERN

strip = [lambda value: value.strip() if value else value]


class PersonForm(FlaskForm):
    full_name = StringField("Full name", validators=[DataRequired(), Length(max=120)], filters=strip)
    email = StringField("Email", validators=[DataRequired(), Length(max=254), Regexp(EMAIL_PATTERN, message="Enter a valid email address.")], filters=strip)
    department = StringField("Department", validators=[DataRequired(), Length(max=64)], filters=strip)
    job_title = StringField("Job title", validators=[DataRequired(), Length(max=80)], filters=strip)
    submit = SubmitField("Save")
