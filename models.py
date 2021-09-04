from flask import Flask
from wtforms import Form, BooleanField, StringField, PasswordField, validators
from flask_sqlalchemy import SQLAlchemy
from config import Config
import sqlalchemy
import os
import boto3, botocore
from config import Config, S3_KEY, S3_SECRET, S3_BUCKET


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