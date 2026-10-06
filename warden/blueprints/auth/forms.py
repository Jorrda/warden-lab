from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, Length


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(max=64)], filters=[lambda value: value.strip() if value else value])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign in")
