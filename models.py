from flask import Flask
from wtforms import Form, BooleanField, StringField, PasswordField, validators
from flask_sqlalchemy import SQLAlchemy
from config import Config

class RegistrationForm(Form):
    name = StringField('Name', [validators.DataRequired(), validators.Length(min=2, max=25)])
    email = StringField('Email Address', [validators.DataRequired(), validators.Email()])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Confirm Password')

class LoginForm(Form):
    email = StringField('Email Address', [validators.DataRequired(), validators.Email()])
    password = PasswordField('Password', [validators.DataRequired()])    

application = Flask(__name__)
application.secret_key = application.config['SECRET_KEY']

application.config.from_object(Config)

db = SQLAlchemy(application)

class User(db.Model):

    __tablename__ = 'users'
    email = db.Column(db.String, primary_key=True)
    id = db.Column(db.String)
    password = db.Column(db.String)
    #authenticated = db.Column(db.Boolean, default=False)
    
    def is_active(self):
        """True, as all users are active."""
        return True

    def get_id(self):
        """Return the email address to satisfy Flask-Login's requirements."""
        return self.email

    def get_user_id(self):
        """Return the email address to satisfy Flask-Login's requirements."""
        return self.id    

    def is_authenticated(self):
        """Return True if the user is authenticated."""
        return self.authenticated

    def is_anonymous(self):
        """False, as anonymous users aren't supported."""
        return False    