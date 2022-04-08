from flask import Flask
from wtforms import Form, BooleanField, StringField, PasswordField, validators
from flask_sqlalchemy import SQLAlchemy
from config import Config
import sqlalchemy
import os
import boto3, botocore
from config import Config, S3_KEY, S3_SECRET, S3_BUCKET


class RegistrationForm(Form):
    email = StringField('Email', [validators.DataRequired(message='Email field is required'), validators.Email(message='Please enter a valid email address')])
    name = StringField('Your Name', [validators.DataRequired(message='Please enter an appearance name for your account'), validators.Length(min=1, max=25, message='Name must be between 1 and 25 characters')])
    username = StringField('Username', [validators.DataRequired(message='Please enter a username for your account'), validators.Length(min=1, max=25, message='Username must be between 1 and 25 characters')])
    password = PasswordField('Password', [
        validators.DataRequired(message='This field cannot be blank'),
        validators.EqualTo('confirm', message='Passwords must match'),
        validators.Length(min=8, max=50, message='Password must be between 8 and 50 characters')
    ])
    confirm = PasswordField('Confirm Password')

class LoginForm(Form):
    email = StringField('Email Address', [validators.DataRequired(message='Email field is required'), validators.Email(message='Please enter a valid email address')])
    password = PasswordField('Password', [validators.DataRequired(message='Please enter your password')])    

class PasswordResetForm(Form):
    email = StringField('Email Address', [validators.DataRequired(message='Email field is required'), validators.Email(message='Please enter the email address you created your account with')])

class PasswordChangeForm(Form):
    password = PasswordField('Password', [
        validators.DataRequired(message='This field cannot be blank'),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Confirm Password')

application = Flask(__name__)
application.secret_key = application.config['SECRET_KEY']

application.config.from_object(Config)

#Enginge options here: https://flask-sqlalchemy.palletsprojects.com/en/2.x/api/
#db = SQLAlchemy(application, engine_options={"pool_recycle": 1800})




#Set up S3
s3 = boto3.client(
   "s3",
   aws_access_key_id = S3_KEY,
   aws_secret_access_key = S3_SECRET
)

def upload_file_to_s3(file, bucket_name, acl="public-read"):
    try:
        s3.upload_fileobj(
            file,
            bucket_name,
            file.filename,
            ExtraArgs={
                "ACL": acl,
                "ContentType": file.content_type
            }
        )
        

    except Exception as e:
        # This is a catch all exception, edit this part to fit your needs.
        print("Something Happened: ", e)
        return e

def time_ago(time=False):
    """
    Get a datetime object or a int() Epoch timestamp and return a
    pretty string like 'an hour ago', 'Yesterday', '3 months ago',
    'just now', etc
    """
    from datetime import datetime
    from dateutil import tz
    to_zone = tz.tzlocal()
    now = datetime.now(to_zone)
    if type(time) is int:
        diff = now - datetime.fromtimestamp(time)
    elif isinstance(time, datetime):
        diff = now - time
    elif not time:
        diff = 0
    second_diff = diff.seconds
    day_diff = diff.days

    if day_diff <= 0:
        if second_diff < 10:
            return "just now"
        if second_diff < 60:
            return str(second_diff) + " sec"
        if second_diff < 120:
            return " min"
        if second_diff < 3600:
            return str(second_diff // 60) + " min"
        if second_diff < 86400:
            return str(second_diff // 3600) + " hr"
    if day_diff == 1:
        return "1d"
    if day_diff < 7:
        return str(day_diff) + "d"
    if day_diff < 31:
        return str(day_diff // 7) + "w"
    if day_diff < 365:
        return str(day_diff // 30) + "mo"
    return str(day_diff // 365) + "y"