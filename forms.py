from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Length, Email, Optional, EqualTo

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)], description="Use a strong password.")
    confirm = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match.')])
    role = SelectField('Role', choices=[('doctor','Doctor'), ('nurse','Nurse')])
    submit = SubmitField('Register')

class PatientForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired(), Length(max=120)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(max=120)])
    dob = StringField('Date of Birth', validators=[Optional(), Length(max=30)])
    gender = SelectField('Gender', choices=[('Male','Male'), ('Female','Female'), ('Other','Other')])
    phone = StringField('Phone', validators=[Optional(), Length(max=40)])
    email = StringField('Email', validators=[Optional(), Email(), Length(max=120)])
    address = TextAreaField('Address', validators=[Optional()])
    submit = SubmitField('Save Patient')

class NoteForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=200)])
    body = TextAreaField('Note', validators=[DataRequired()])
    submit = SubmitField('Save Note')
