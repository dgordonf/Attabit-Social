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