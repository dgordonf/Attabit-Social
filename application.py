from gzip import READ
from flask import Flask, request, render_template, redirect, url_for, flash, jsonify, send_from_directory, current_app, Markup
import requests
from string import Template
from flask_sqlalchemy import SQLAlchemy
from numpy import isnan
import sqlalchemy
import pandas as pd
pd.options.mode.chained_assignment = None
from pandas import DataFrame
from pandas.util import hash_pandas_object
import re
from flask_gtts import gtts
from config import GMAIL_PASSWORD, GMAIL_USERNAME, Config, S3_KEY, S3_SECRET, S3_BUCKET, SES_REGION_NAME, SES_EMAIL_SOURCE, GMAIL_USERNAME, GMAIL_PASSWORD, SERVER_NAME, SECRET_KEY
from flask_login import LoginManager
import models
from wtforms import validators
from wtforms.fields.html5 import EmailField
import email_validator
from passlib.hash import sha256_crypt
from flask_login import login_user, logout_user, login_required, current_user
import bcrypt
from datetime import datetime, timedelta
from dateutil import tz
from colour import Color
import re
import boto3, botocore
from django.utils.crypto import get_random_string
from werkzeug.utils import secure_filename
from PIL import Image
import os
import base64
import six
import uuid
import imghdr
import io
import pytz
from flask_mail import Mail, Message
import emoji

#You build this with this tutorial: https://medium.com/techfront/step-by-step-visual-guide-on-deploying-a-flask-application-on-aws-ec2-8e3e8b82c4f7
#https://www.digitalocean.com/community/tutorials/how-to-serve-flask-applications-with-gunicorn-and-nginx-on-ubuntu-20-04

#Database fix guide: https://docs.sqlalchemy.org/en/14/core/connections.html

#Removed server upgrades becasue of mysql disconnect: https://askubuntu.com/questions/1037285/starting-daily-apt-upgrade-and-clean-activities-stopping-mysql-service

# Not the entire world, just your best friends. 
application = Flask(__name__)
application.secret_key = application.config['SECRET_KEY']

application.config.from_object(Config)


#This is for users table
db = SQLAlchemy(application, engine_options={"pool_recycle": 1800})
db.init_app(application)

##Create SQL Engine Look at this: https://docs.sqlalchemy.org/en/14/core/pooling.html#pool-disconnects
engine = sqlalchemy.create_engine(application.config['SQLALCHEMY_DATABASE_URI'], pool_recycle=3600,)

### AUTH SECTION ###
login_manager = LoginManager()
login_manager.init_app(application)
login_manager.login_view = 'login'

#Set up S3
s3 = boto3.client(
   "s3",
   aws_access_key_id = S3_KEY,
   aws_secret_access_key = S3_SECRET
   )

class User(db.Model):

    __tablename__ = 'users'
    email = db.Column(db.String, primary_key=True)
    id = db.Column(db.String)
    handle = db.Column(db.String)
    profile_photo = db.Column(db.String)
    password = db.Column(db.String)
    authenticated = db.Column(db.Boolean, default=False)
    
    def is_active(self):
        """True, as all users are active."""
        return True
    
    def get_id(self):
        """Return the email address to satisfy Flask-Login's requirements."""
        return self.email

    def get_user_id(self):
        """Return the email address to satisfy Flask-Login's requirements."""
        return self.id   

    def get_user_handle(self):
        """Return the handle."""
        return self.handle         
    def get_user_profile_photo(self):
        """Return the Profile Photo of the user."""
        return self.profile_photo   
        
    def is_authenticated(self):
        """Return True if the user is authenticate#d."""
        return self.authenticated

def send_email(app, recipients, sender=None, subject='', text='', html=''):
    ses = boto3.client(
        'ses',
        region_name = SES_REGION_NAME,
        aws_access_key_id = S3_KEY,
        aws_secret_access_key = S3_SECRET
    )
    if not sender:
        sender = SES_EMAIL_SOURCE

    ses.send_email(
        Source=sender,
        Destination={'ToAddresses': recipients},
        Message={
            'Subject': {'Data': subject},
            'Body': {
                'Text': {'Data': text},
                'Html': {'Data': html}
            }
        }
    )

#Set up mail
application.config['MAIL_SERVER']='smtp.gmail.com'
application.config['MAIL_PORT'] = 465
application.config['MAIL_USERNAME'] = GMAIL_USERNAME
application.config['MAIL_PASSWORD'] = GMAIL_PASSWORD
application.config['MAIL_USE_TLS'] = False
application.config['MAIL_USE_SSL'] = True

mail = Mail(application)    

def linkify(text):
    return Markup(re.sub(r'@([a-zA-Z0-9_]+)', r'<a href="/@\1">@\1</a>', text))

application.jinja_env.filters['linkify'] = linkify

#def kelly_crown(text):
#    return Markup(re.sub(r'(Kelly)', r'\1 👑', text))
#
#application.jinja_env.filters['kelly_crown'] = kelly_crown

@application.template_filter('emojify')
def emoji_filter(s):
    return emoji.emojize(s)

@login_manager.user_loader
def load_user(user_id):
    """Check if user is logged-in on every page load."""
    if user_id is not None:
        try:
            user_id = User.query.get(user_id)
            db.session.commit()
            return user_id
        except:
            db.session.rollback()
            return None
    return None
   
@login_manager.unauthorized_handler
def unauthorized():
    #flash('You must be logged in to view that page.')
    return redirect('/landing')

@application.route('/landing', methods = ['GET'])
def landing():
    return render_template('landing.html')

@application.route('/login', methods = ['POST', 'GET'])
def login():
    form = models.LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        try:
            user = User.query.get(form.email.data)
        except Exception as e:
            # e holds description of the error
            db.session.rollback()
            print("Rollback")
            error_text = "<p>The error:<br>" + str(e) + "</p>"
            hed = '<h1>Something is broken.</h1>'
            return hed + error_text
                
        try:
            user
        except:
            print("User variable not defined")
            return redirect('/login')
        
        if user:
            form_password = form.password.data.encode('utf-8')
            user_password = user.password.encode('utf-8')
            if bcrypt.checkpw(form_password, user_password):
                user.authenticated = True
                login_user(user, remember=True)
                current_user.is_authenticated = True

                try:
                    current_db_sessions = db.session.object_session(user)
                    current_db_sessions.add(user)
                except:
                    db.session.add(user)
                
                db.session.commit()
                #db.session.close()
                #db.session.remove()
                #db.engine.dispose()
                return redirect("/")
            else: 
                flash('Your password was incorrect. Please check your email and password.')
                return redirect('/login')
        else:
            flash('Your password was incorrect or we could not find an account assocated with that email. Please check your email and password.')
            return redirect('/login')
    else:
        render_template('login.html', form=form)
    return render_template('login.html', form=form)

@application.route("/logout")
def logout():
    logout_user()
    return redirect("/login")


@application.route('/signup', methods = ['POST', 'GET'])
def signup(): 
    form = models.RegistrationForm(request.form)
    if request.method == 'POST' and form.validate(): 

        #check if email is already in use
        if User.query.filter_by(email=form.email.data).first():
            flash('That email is already in use.')
            return redirect('/signup')

        #check if handle is already in use
        if User.query.filter_by(handle=form.username.data).first():
            flash('That username is already in use.')
            return redirect('/signup')  

        #Else, create the user
        email = form.email.data
        name = form.name.data
        handle = form.username.data
        password = form.password.data.encode('utf-8')

        salt = bcrypt.gensalt()
        password_hash = bcrypt.hashpw(password, salt)
        password_hash = password_hash.decode('utf8')

        with engine.connect() as connection:
            connection.execute("INSERT INTO users (first_name, email, handle, password) VALUES (%s, %s, %s, %s);", (name, email, handle, password_hash))
        
        db.session.commit()
        user = User.query.get(email)

        if user:
            user.authenticated = True
            login_user(user, remember=True)
            current_user.is_authenticated = True

            try:
                current_db_sessions = db.session.object_session(user)
                current_db_sessions.add(user)
            except:
                db.session.add(user)
            
            db.session.commit()
            return redirect('/')
    else:
        return render_template('signup.html', form=form)

@application.route('/', methods = ['POST', 'GET'])
def feed():
    camp_id = 0

    try:
        user_id = current_user.get_user_id()
    except:
        return redirect('/top')
    
    if request.method == 'POST':
        type = request.form.get('update_type')
        post_text = request.form.get('post_text')
        reply_to_id = request.form.get('reply_to_id')
                
        if type == 'post_text':
            
            try:
                with engine.connect() as connection:
                    connection.execute('INSERT INTO posts (camp_id, user_id, reply_to_id, post_text) VALUES (%s, %s, %s, %s);', (camp_id, user_id, reply_to_id, post_text))

            except Exception as e:
                # e holds description of the error
                error_text = "<p>The error:<br>" + str(e) + "</p>"
                hed = '<h1>Something is broken.</h1>'
                return hed + error_text 

            #Notify any mentioned users
            models.notify_mentionted_users(post_text, user_id)

        if type == 'post_vote':
            try:
                value = request.form.get('post_vote')
                value = float(value)
                if value >= 0:
                    value = 1
                else:
                    value = -1
                post_id = request.form.get('post_id')

                #Check if this user has voted on this already
                with engine.connect() as connection:
                    ResultProxy = connection.execute("""SELECT pv.vote_id 
                                                            FROM post_votes pv
                                                            WHERE pv.camp_id = %s AND pv.user_id = %s AND post_id = %s;
                                                            """, (camp_id, user_id, post_id))

                df = DataFrame(ResultProxy.fetchall())
                
                if len(df.index) > 0:
                    with engine.connect() as connection:
                        ResultProxy = connection.execute("""UPDATE post_votes pv
                                                            SET value = %s
                                                            WHERE pv.camp_id = %s AND pv.user_id = %s AND post_id = %s;
                                                            """, (value, camp_id, user_id, post_id))
                else:
                    with engine.connect() as connection:
                        connection.execute('INSERT INTO post_votes (camp_id, user_id, post_id, value) VALUES (%s, %s, %s, %s);', (camp_id, user_id, post_id, value))
                    
            except Exception as e:
                # e holds description of the error
                error_text = "<p>The error:<br>" + str(e) + "</p>"
                hed = '<h1>Something is broken.</h1>'
                return hed + error_text 
        
    ##Get thier color and make sure there is at least 1 post for them to see
    #### Come back to when you have followers table
    with engine.connect() as connection:
        ResultProxy = connection.execute("""SELECT  u.id, u.profile_photo, SUM(p1.value) AS user_score
                                                    FROM users u
                                                    LEFT JOIN posts p ON p.user_id = u.id
                                                    LEFT JOIN post_votes p1 ON p1.post_id = p.post_id
                                                    WHERE u.id = %s
                                                    GROUP BY u.id
                                                """, (user_id))
    df = DataFrame(ResultProxy.fetchall())

    #If yes, load page
    if len(df.index) > 0: 
        try:
            df.columns = ResultProxy.keys()
            #Get Profile Photo
            user_profile_photo = df['profile_photo'][0]

            #Get Posts
            df = models.get_feed(user_id, None)
            df = models.format_feed(df)

            #get smalled post_id from df
            min_post_id = df['post_id'].min()

            handle = current_user.get_user_handle()

            data = models.get_notifications(user_id)
            notifications = data[0] 
            unseen_count = data[1]
            
            return render_template('feed.html', current_user_id = user_id, current_user_handle = handle, current_user_profile_photo = user_profile_photo, posts=df, min_post_id = min_post_id, camp_id=camp_id, notifications = notifications, notification_count = unseen_count)
        except Exception as e:
            # e holds description of the error
            error_text = "<p>The error:<br>" + str(e) + "</p>"
            hed = '<h1>Something is broken.</h1>'
            return hed + error_text
           
    else:
        #flash('You are not a member of that camp')
        return redirect('/landing')


@application.route('/favicon.png') 
def favicon(): 
    return send_from_directory(os.path.join(application.root_path, 'static'), 'favicon.png', mimetype='image/vnd.microsoft.icon')

@application.route('/post/favicon.png') 
def favicon2(): 
    return send_from_directory(os.path.join(application.root_path, 'static'), 'favicon.png', mimetype='image/vnd.microsoft.icon')

@application.route('/@<username>', methods = ['POST','GET'])
def profile(username):
    
    camp_id = 0
    profile_username = username

    #Get the user_id of the profile we are looking at
    with engine.connect() as connection:
        ResultProxy = connection.execute('''SELECT u.id 
                                            FROM users u
                                            WHERE u.handle = %s;''', (profile_username))
    df = DataFrame(ResultProxy.fetchall())
    df.columns = ResultProxy.keys()
    profile_user_id = df['id'][0]

    
    ### Get the current user id    
    try:
        current_user_id = current_user.get_user_id()

        #Get current user profile photo
        with engine.connect() as connection:
            ResultProxy = connection.execute('''SELECT u.profile_photo, u.handle
                                                FROM users u
                                                WHERE u.id = %s;''', (current_user_id))
        df = DataFrame(ResultProxy.fetchall())
        df.columns = ResultProxy.keys()
        current_user_profile_photo = df['profile_photo'][0]
        current_user_handle = df['handle'][0]
    except:
        current_user_id = 0
        current_user_profile_photo = None
        current_user_handle = ""



    #Get Profile Page's User ID
    try:
        with engine.connect() as connection:
            ResultProxy = connection.execute('''SELECT u.id, u.handle, u.first_name, u.profile_photo, COALESCE(u.bio,"") as bio, SUM(p1.value) AS user_score
                                                    FROM users u
                                                    LEFT JOIN posts p ON p.user_id = u.id
                                                    LEFT JOIN post_votes p1 ON p1.post_id = p.post_id
                                                    WHERE u.handle = %s;''', (profile_username))
        
        profile_info = DataFrame(ResultProxy.fetchall())
        profile_info.columns = ResultProxy.keys()
    except Exception as e:
        print(e)

    profile_info['user_score'] = profile_info['user_score'].fillna(0).astype(int)
               
    #Create User Score bar chart
    profile_info['user_score'] = profile_info['user_score']/10
    profile_info['user_score_bars'] = ((profile_info['user_score'] % 1) * 10).astype(int)
    profile_info['user_score'] = profile_info['user_score'].astype(int)

    #Create Score Bar Print
    profile_info['user_score_bars_print'] = profile_info['user_score_bars'].apply(lambda x: '⬛' * x)
    profile_info['user_score_bars_print'] = profile_info['user_score_bars_print'] + profile_info['user_score_bars'].apply(lambda x: '⬜' * (10 - x))

    #Get Posts
    df = models.get_user_posts(current_user_id, profile_user_id, None)

    #format posts
    df = models.format_feed(df)

    ##Get Follow Value
    with engine.connect() as connection:
        ResultProxy = connection.execute("""SELECT u.id, u.handle, COALESCE(f.follow_value, 0 ) as follow_status
                                                FROM users u
                                                LEFT JOIN follows f ON f.following = u.id
                                                WHERE u.id = %s AND f.user_id = %s AND f.last_update_time IS NULL; """, (profile_user_id, current_user_id))
    try:
        follow = DataFrame(ResultProxy.fetchall())
        follow.columns = ResultProxy.keys()
        follow_status = follow['follow_status'][0]
    except:
        follow_status = 0

    #get notifications
    data = models.get_notifications(current_user_id)
    notifications = data[0] 
    unseen_count = data[1]

    is_president = models.is_president(profile_info['id'])
    return render_template('profile.html', profile_handle = username, profile_user_id = profile_user_id, current_user_handle = current_user_handle, profile_info = profile_info, follow_status = follow_status, current_user_id = current_user_id, is_president = is_president, current_user_profile_photo = current_user_profile_photo, posts=df, notifications=notifications, notification_count=unseen_count)



@application.route('/@<username>/follow', methods = ['POST'])
@login_required
def follow(username):
    profile_username = username
    user_id = current_user.get_user_id()
    
    follow_value = int(request.form.get('follow_value'))
    if follow_value > 0:
        follow_value = 1
    else:
        follow_value = 0

    #Get user_id of follow account
    with engine.connect() as connection:
        ResultProxy = connection.execute('''SELECT u.id 
                                            FROM users u 
                                            WHERE u.handle = %s; ''', (profile_username))

    df = DataFrame(ResultProxy.fetchall())
    df.columns = ResultProxy.keys()
    
    following = df['id'][0]
    
    ##Stop someone here from following themself
    if user_id != following:
        #If follow request, then insert. If unfollow, update
        if follow_value == 1:
            with engine.connect() as connection:
                ResultProxy = connection.execute('INSERT INTO follows (user_id, following, follow_value) VALUES (%s, %s, %s);', (user_id, following, follow_value))
        else:
            with engine.connect() as connection:
                ResultProxy = connection.execute('''UPDATE follows f
                                                    SET follow_value = 0
                                                    WHERE f.user_id = %s AND f.following = %s;''', (user_id, following))
    return redirect("/@" + username)

@application.route('/@<username>/quickfollow', methods = ['POST'])
def quickfollow(username):
    profile_username = username
    user_id = current_user.get_user_id()

    if user_id is None: 
        response = jsonify(success=False, new_follow_value=0)
        return response
    
    follow_value = int(request.form.get('follow_value'))
    if follow_value > 0:
        follow_value = 1
        new_follow_value = 0
    else:
        follow_value = 0
        new_follow_value = 1

    #Get user_id of follow account
    with engine.connect() as connection:
        ResultProxy = connection.execute('''SELECT u.id 
                                            FROM users u 
                                            WHERE u.handle = %s; ''', (profile_username))

    df = DataFrame(ResultProxy.fetchall())
    df.columns = ResultProxy.keys()
    
    following = df['id'][0]

    ##Stop someone here from following themself
    if user_id != following:
        #If follow request, then insert. If unfollow, update
        if follow_value == 1:
            with engine.connect() as connection:
                ResultProxy = connection.execute('INSERT INTO follows (user_id, following, follow_value) VALUES (%s, %s, %s);', (user_id, following, follow_value))

            #Notify user that someone has followed them
            event_type_id = 1
            with engine.connect() as connection:
                connection.execute('INSERT INTO notifications (user_id, triggered_by_user_id, event_type_id) VALUES (%s, %s, %s);', (following, user_id, event_type_id))    
        else:
            with engine.connect() as connection:
                ResultProxy = connection.execute('''UPDATE follows f
                                                    SET follow_value = 0
                                                    WHERE f.user_id = %s AND f.following = %s;''', (user_id, following))
    response = jsonify(success=True, new_follow_value=new_follow_value)
    return response  


def get_file_extension(file_name, decoded_file):
    extension = imghdr.what(file_name, decoded_file)
    extension = "jpg" if extension == "jpeg" else extension
    return extension

def decode_base64_file(data):
    """
    Fuction to convert base 64 to readable IO bytes and auto-generate file name with extension
    :param data: base64 file input
    :return: tuple containing IO bytes file and filename
    """
    # Check if this is a base64 string
    if isinstance(data, six.string_types):
        # Check if the base64 string is in the "data:" format
        if 'data:' in data and ';base64,' in data:
            # Break out the header from the base64 content
            header, data = data.split(';base64,')
            
        # Try to decode the file. Return validation error if it fails.
        try:
            missing_padding = len(data) % 4
            if missing_padding:
                data += b'='* (4 - missing_padding)
            decoded_file = base64.b64decode(data)
        except TypeError:
            TypeError('invalid_image')

   
        while True:
            file_name = str(uuid.uuid4())[:12]
            file_name_search = file_name + ".jpg"
            file_name_search2 = file_name + ".png"
            with engine.connect() as connection:
                ResultProxy = connection.execute('''SELECT u.id 
                                                    FROM users u
                                                    WHERE u.profile_photo = %s OR u.profile_photo = %s;''', (file_name_search, file_name_search2))
            
            df = DataFrame(ResultProxy.fetchall())
            if len(df.index) == 0:
                break

        # Get the file name extension:
        file_extension = get_file_extension(file_name, decoded_file)

        complete_file_name = "%s.%s" % (file_name, file_extension,)

        return io.BytesIO(decoded_file), complete_file_name

@application.route('/@<username>/edit', methods = ['POST'])
@login_required
def edit_user(username):
    try:
        user_id = current_user.get_user_id()

        #Add check if username is taken before uncommenting, should also be a paid feature
        #handle = request.form.get('handle')
        name = request.form.get('name')
        bio = request.form.get('bio')
        imageData64 = request.form.get('imageData64')

        if imageData64 != "" and imageData64 != None:
            
            try:
                file, file_name = decode_base64_file(imageData64)
            except Exception as e:
                # e holds description of the error
                print(e)
                error_text = "<p>The error:<br>" + str(e) + "</p>"
                hed = '<h1>Something is broken.</h1>'
                return hed + error_text + imageData64
            
            #Save image to S3
            s3.upload_fileobj(
                    file,
                    S3_BUCKET,
                    "media/" + file_name,
                    ExtraArgs={
                        "ACL": "public-read"
                        })
            print("Uploaded to S3")
            ##Add check if username is taken before letting them update username
            with engine.connect() as connection:
                connection.execute('''UPDATE users u
                                        SET u.first_name = %s,
                                            u.bio = %s,
                                            u.profile_photo = %s
                                        WHERE u.id = %s;''', (name, bio, file_name, user_id))
        else:
            print("I went into the else statement")
            with engine.connect() as connection:
                connection.execute('''UPDATE users u
                                        SET u.first_name = %s,
                                            u.bio = %s
                                        WHERE u.id = %s;''', (name, bio, user_id))
            
        response = jsonify(success=True)
        return response  
    except Exception as e:
        # e holds description of the error
        print(e)
        error_text = "<p>The error:<br>" + str(e) + "</p>"
        hed = '<h1>Something is broken.</h1>'
        return hed + error_text + imageData64


@application.route('/search', methods = ['GET'])
@login_required
def search():
    user_id = current_user.get_user_id()
    q = request.args.get('q')

    #Get current user profile photo
    with engine.connect() as connection:
        ResultProxy = connection.execute('''SELECT u.profile_photo 
                                            FROM users u
                                            WHERE u.id = %s;''', (user_id))
    df = DataFrame(ResultProxy.fetchall())
    df.columns = ResultProxy.keys()
    current_user_profile_photo = df['profile_photo'][0]

    if q == "" or q == None:

        #Get all users
        with engine.connect() as connection:
            ResultProxy = connection.execute('''SELECT u.id, u.first_name, u.handle, COALESCE(b.user_score, 0) as user_score, u.profile_photo, u.creation_time, COALESCE(f.follow_value, 0) as follow_value
                                                    FROM users u
                                                    LEFT JOIN
                                                        (
                                                            SELECT u.id, SUM(p1.value) AS user_score
                                                                FROM users u
                                                                LEFT JOIN posts p ON p.user_id = u.id
                                                                LEFT JOIN post_votes p1 ON p1.post_id = p.post_id
                                                                GROUP BY u.id
                                                        ) b ON b.id = u.id
                                                    LEFT JOIN (
                                                        SELECT f.following, f.follow_value
                                                        FROM follows f
                                                        WHERE f.user_id = %s AND f.last_update_time IS NULL
                                                        ) f ON f.following = u.id
                                                    ORDER BY b.user_score DESC
                                                    LIMIT 100;''', (user_id))

            df = DataFrame(ResultProxy.fetchall())
            
            if df is not None and (df.empty == False):
                df.columns = ResultProxy.keys()    
                
                #Create User Score bar chart
                df['user_score'] = df['user_score'].astype(int)
                df['user_score'] = df['user_score']/10
                df['user_score_bars'] = ((df['user_score'] % 1) * 10).astype(int)
                
                #Create Score Bar Print
                df['user_score_bars_print'] = df['user_score_bars'].apply(lambda x: '⬛' * x)
                df['user_score_bars_print'] = df['user_score_bars_print'] + df['user_score_bars'].apply(lambda x: '⬜' * (10 - x))
                df['user_score'] = df['user_score'].astype(int)
        
        handle = current_user.get_user_handle()

        data = models.get_notifications(user_id)
        notifications = data[0] 
        unseen_count = data[1]

        return render_template('search.html', 
                                    df = df, 
                                    user_id = user_id, 
                                    q = q, 
                                    current_user_id = user_id,
                                    current_user_profile_photo = current_user_profile_photo,
                                    current_user_handle = handle,
                                    notifications = notifications,
                                    notification_count = unseen_count)
    else:
        with engine.connect() as connection:
            search = "%" + q + "%"
            ResultProxy = connection.execute('''SELECT u.id, u.first_name, u.handle, COALESCE(b.user_score, 0) as user_score, u.profile_photo, u.creation_time, COALESCE(f.follow_value, 0) as follow_value
                                                    FROM users u
                                                    LEFT JOIN
                                                        (
                                                            SELECT u.id, SUM(p1.value) AS user_score
                                                                FROM users u
                                                                LEFT JOIN posts p ON p.user_id = u.id
                                                                LEFT JOIN post_votes p1 ON p1.post_id = p.post_id
                                                                GROUP BY u.id
                                                        ) b ON b.id = u.id
                                                    LEFT JOIN (
                                                            SELECT f.following, f.follow_value
                                                            FROM follows f
                                                            WHERE f.user_id = 8 AND f.last_update_time IS NULL
                                                            ) f ON f.following = u.id
                                                    WHERE u.handle LIKE %s OR u.first_name LIKE %s
                                                    ORDER BY u.creation_time ASC
                                                    LIMIT 50;''', (search, search))

        df = DataFrame(ResultProxy.fetchall())

        if df is not None and (df.empty == False):
            df.columns = ResultProxy.keys()   

            #Create User Score bar chart
            df['user_score'] = df['user_score'].fillna(0).astype(int)
            df['user_score'] = df['user_score']/10
            df['user_score_bars'] = ((df['user_score'] % 1) * 10).astype(int)
            
            #Create Score Bar Print
            df['user_score_bars_print'] = df['user_score_bars'].apply(lambda x: '⬛' * x)
            df['user_score_bars_print'] = df['user_score_bars_print'] + df['user_score_bars'].apply(lambda x: '⬜' * (10 - x)) 
            df['user_score'] = df['user_score'].astype(int)

        data = models.get_notifications(user_id)
        notifications = data[0] 
        unseen_count = data[1]
            
        return render_template('search.html',
                                user_id = user_id,
                                df = df, 
                                q = q,
                                current_user_id = user_id,
                                current_user_profile_photo = current_user_profile_photo,
                                notifications = notifications,
                                notification_count = unseen_count)
    
@application.route('/post/<post_id>', methods = ['GET', 'POST'])
def post(post_id):
    camp_id = 0
    
    post_id = int(post_id)
    
    try:
        user_id = current_user.get_user_id()
    except Exception as e:
        print(e)
        return redirect('/login')

    #Get current user profile photo
    try:
        with engine.connect() as connection:
            ResultProxy = connection.execute('''SELECT u.profile_photo 
                                                FROM users u
                                                WHERE u.id = %s;''', (user_id))
        df = DataFrame(ResultProxy.fetchall())
        df.columns = ResultProxy.keys()
        current_user_profile_photo = df['profile_photo'][0]
    except Exception as e:
        print(e)
        return redirect('/landing')
    
    if request.method == 'POST':
        type = request.form.get('update_type')
        post_text = request.form.get('post_text')
        reply_to_id = request.form.get('reply_to_id')
        
        if type == 'post_text':
            
            #Create new post
            with engine.connect() as connection:
                connection.execute('INSERT INTO posts (camp_id, user_id, reply_to_id, post_text) VALUES (%s, %s, %s, %s);', (camp_id, user_id, reply_to_id, post_text))
            
            #get user_id of post creator
            with engine.connect() as connection:
                ResultProxy = connection.execute('''SELECT p.user_id 
                                                    FROM posts p
                                                    WHERE p.post_id = %s;''', (reply_to_id))
            a = DataFrame(ResultProxy.fetchall())
            a.columns = ResultProxy.keys()
            post_creator_user_id = a['user_id'][0]


            #Notify user of reply_to_id
            # 1 for follow, 2 for post
            if post_creator_user_id != user_id:
                event_type_id = 2
                with engine.connect() as connection:
                    connection.execute('INSERT INTO notifications (user_id, triggered_by_user_id, event_type_id, reference_post_id) VALUES (%s, %s, %s, %s);', (post_creator_user_id, user_id, event_type_id, reply_to_id))

            #Notify any mentioned users
            models.notify_mentionted_users(post_text, user_id)
                    
            
        if type == 'post_vote':
            try:
                value = request.form.get('post_vote')
                value = float(value)
                if value >= 0:
                    value = 1
                else:
                    value = -1
                vote_post_id = request.form.get('post_id')

                #Check if this user has voted on this already
                with engine.connect() as connection:
                    ResultProxy = connection.execute("""SELECT pv.vote_id 
                                                            FROM post_votes pv
                                                            WHERE pv.camp_id = %s AND pv.user_id = %s AND post_id = %s;
                                                            """, (camp_id, user_id, vote_post_id))

                df = DataFrame(ResultProxy.fetchall())
                
                if len(df.index) > 0:
                    with engine.connect() as connection:
                        ResultProxy = connection.execute("""UPDATE post_votes pv
                                                            SET value = %s
                                                            WHERE pv.camp_id = %s AND pv.user_id = %s AND post_id = %s;
                                                            """, (value, camp_id, user_id, vote_post_id))
                else:
                    with engine.connect() as connection:
                        connection.execute('INSERT INTO post_votes (camp_id, user_id, post_id, value) VALUES (%s, %s, %s, %s);', (camp_id, user_id, vote_post_id, value))
                    
            except Exception as e:
                # e holds description of the error
                error_text = "<p>The error:<br>" + str(e) + "</p>"
                hed = '<h1>Something is broken.</h1>'
                return hed + error_text 

    #Get Post by Post_id
    with engine.connect() as connection:
        ResultProxy = connection.execute("""SELECT p.post_id, p.camp_id, p.user_id, p.reply_to_id, u.first_name, u.handle, u.profile_photo, p.creation_time, p.post_text, p.media_id, b.user_score, COALESCE(c.current_user_vote, 0 ) as current_user_vote, p2.reply_count, pv.down_votes, pv2.up_votes
                                        FROM posts p
                                        LEFT JOIN users u ON p.user_id = u.id 
                                        LEFT JOIN
                                            (
                                                SELECT p.reply_to_id, COUNT(p.post_id) AS reply_count
                                                    FROM posts p
                                                    WHERE p.reply_to_id = %s AND p.is_deleted = 0
                                                    GROUP BY p.reply_to_id
                                            ) p2 ON p2.reply_to_id = p.post_id
                                        LEFT JOIN
                                            (
                                                SELECT pv.post_id, COUNT(pv.value) AS down_votes
                                                    FROM post_votes pv
                                                    WHERE pv.post_id = %s AND pv.value < 0
                                                    GROUP BY pv.post_id
                                            ) pv ON pv.post_id = p.post_id
                                        LEFT JOIN
                                            (
                                                SELECT pv.post_id, COUNT(pv.value) AS up_votes
                                                    FROM post_votes pv
                                                    WHERE pv.post_id = %s AND pv.value > 0
                                                    GROUP BY pv.post_id
                                            ) pv2 ON pv2.post_id = p.post_id
                                        LEFT JOIN
                                                (
                                                    SELECT u.id, SUM(p1.value) AS user_score
                                                        FROM users u
                                                        LEFT JOIN posts p ON p.user_id = u.id
                                                        LEFT JOIN post_votes p1 ON p1.post_id = p.post_id
                                                        GROUP BY u.id
                                                ) b ON b.id = u.id
                                        LEFT JOIN
                                                (
                                                SELECT p2.post_id, SUM(p2.value) AS current_user_vote
                                                    FROM post_votes p2
                                                    WHERE p2.user_id = %s
                                                    GROUP BY p2.post_id
                                                ) c on c.post_id = p.post_id 
                                        WHERE p.post_id = %s AND p.is_deleted = 0; """, (post_id, post_id, post_id, user_id, post_id))
        post_info = DataFrame(ResultProxy.fetchall())
    
    #If yes, load page
    if len(post_info.index) > 0: 
        try:
            post_info.columns = ResultProxy.keys()
            
            #Correct Score for post_info
            post_info['user_score'] = post_info['user_score'].fillna(0).astype(int)
            
            post_info['reply_count'] = round(post_info['reply_count'].fillna(0).astype(int), 0)
            post_info['down_votes'] = round(post_info['down_votes'].fillna(0).astype(int), 0)
            post_info['up_votes'] = round(post_info['up_votes'].fillna(0).astype(int), 0)

            post_info['post_score'] = post_info['up_votes'] - post_info['down_votes']

            
            post_info['reply_count'] = post_info['reply_count'].replace(0, " ")
            post_info['down_votes'] = post_info['down_votes'].replace(0, " ")
            post_info['up_votes'] = post_info['up_votes'].replace(0, " ")

            #Correct Timezone
            to_zone = tz.tzlocal()
                                            
            post_info['creation_time'] = pd.to_datetime(post_info['creation_time'])
            #Cover to time ago for each post
            post_info['time_ago'] = ""
            for i in range(len(post_info.index)):
                post_info['time_ago'][i] = models.time_ago(post_info['creation_time'][i].tz_localize('UTC').tz_convert(to_zone))

            post_info['creation_time'] = post_info['creation_time'].dt.tz_localize('UTC').dt.tz_convert(to_zone)
            post_info['creation_time'] = post_info['creation_time'].dt.strftime('%m-%d-%Y')

            #Create User Score bar chart
            post_info['user_score'] = post_info['user_score']/10
            post_info['user_score_bars'] = ((post_info['user_score'] % 1) * 10).astype(int)
            post_info['user_score'] = post_info['user_score'].astype(int)

            #Create Score Bar Print
            post_info['user_score_bars_print'] = post_info['user_score_bars'].apply(lambda x: '⬛' * x)
            post_info['user_score_bars_print'] = post_info['user_score_bars_print'] + post_info['user_score_bars'].apply(lambda x: '⬜' * (10 - x))

            post_info['is_president'] = models.is_president(post_info['user_id'])

            
            #Get all first replies on page
            with engine.connect() as connection:
                ResultProxy = connection.execute(
                        """SELECT p.post_id, p.user_id, p.reply_to_id, p.media_id, p.creation_time, p.post_text, b.user_score, COALESCE(c.current_user_vote, 0 ) as current_user_vote, u.first_name, u.handle, u.profile_photo
                                    FROM posts p
                                    LEFT JOIN users u ON p.user_id = u.id 
                                    LEFT JOIN
                                            (
                                                SELECT u.id, SUM(p1.value) AS user_score
                                                    FROM users u
                                                    LEFT JOIN posts p ON p.user_id = u.id
                                                    LEFT JOIN post_votes p1 ON p1.post_id = p.post_id
                                                    GROUP BY u.id
                                            ) b ON b.id = u.id
                                    LEFT JOIN
                                            (
                                            SELECT p2.post_id, SUM(p2.value) AS current_user_vote
                                                FROM post_votes p2
                                                WHERE p2.user_id = %s
                                                GROUP BY p2.post_id
                                            ) c on c.post_id = p.post_id 
                                    WHERE  p.reply_to_id = %s AND p.is_deleted = 0 """, (user_id, post_id))
            df = DataFrame(ResultProxy.fetchall())

            if len(df.index) > 0:
                df.columns = ResultProxy.keys()

                #Get comments and scores for each post_id
                ids = ', '.join(f'{w}' for w in df.post_id)
                ids = "(" + ids + ")"

                with engine.connect() as connection:
                    ResultProxy = connection.execute("""SELECT p.post_id, p2.reply_count, pv.down_votes, pv2.up_votes
                                                                FROM posts p
                                                                LEFT JOIN
                                                                    (
                                                                        SELECT p.reply_to_id, COUNT(p.post_id) AS reply_count
                                                                            FROM posts p
                                                                            WHERE p.reply_to_id IN %s AND p.is_deleted = 0
                                                                            GROUP BY p.reply_to_id
                                                                    ) p2 ON p2.reply_to_id = p.post_id
                                                                LEFT JOIN
                                                                    (
                                                                        SELECT pv.post_id, COUNT(pv.value) AS down_votes
                                                                            FROM post_votes pv
                                                                            WHERE pv.post_id IN %s AND pv.value < 0
                                                                            GROUP BY pv.post_id
                                                                    ) pv ON pv.post_id = p.post_id
                                                                LEFT JOIN
                                                                    (
                                                                        SELECT pv.post_id, COUNT(pv.value) AS up_votes
                                                                            FROM post_votes pv
                                                                            WHERE pv.post_id IN %s AND pv.value > 0
                                                                            GROUP BY pv.post_id
                                                                    ) pv2 ON pv2.post_id = p.post_id	
                                                                WHERE p.post_id IN %s AND p.camp_id = %s; """ % (ids, ids, ids, ids, camp_id))
                    
                    df2 = DataFrame(ResultProxy.fetchall())
                    df2.columns = ResultProxy.keys()
                    df2['reply_count'] = round(df2['reply_count'].fillna(0).astype(int), 0)
                    df2['down_votes'] = round(df2['down_votes'].fillna(0).astype(int), 0)
                    df2['up_votes'] = round(df2['up_votes'].fillna(0).astype(int), 0)

                    df2['post_score'] = df2['up_votes'] - df2['down_votes']

                    df2['reply_count'] = df2['reply_count'].replace(0, " ")
                    df2['down_votes'] = df2['down_votes'].replace(0, " ")
                    df2['up_votes'] = df2['up_votes'].replace(0, " ")

                    
              
                df = pd.merge(df, df2, on=['post_id'], how='left')
                
                #Correct Timezone
                to_zone = tz.tzlocal()
                                                
                df['creation_time'] = pd.to_datetime(df['creation_time'])
                #Cover to time ago for each post
                df['time_ago'] = ""
                for i in range(len(df.index)):
                    df['time_ago'][i] = models.time_ago(df['creation_time'][i].tz_localize('UTC').tz_convert(to_zone))

                df['creation_time'] = df['creation_time'].dt.tz_localize('UTC').dt.tz_convert(to_zone)
                df['creation_time'] = df['creation_time'].dt.strftime('%m-%d-%Y')

                #Correct Update Post Score (All posts begin at a score of 0) and round
                df['post_score'] = df['post_score'].fillna(0).astype(int)
                df['user_score'] = df['user_score'].fillna(0).astype(int)

                #Create User Score bar chart
                df['user_score'] = df['user_score']/10
                df['user_score_bars'] = ((df['user_score'] % 1) * 10).astype(int)
                df['user_score'] = df['user_score'].astype(int)

                #Create Score Bar Print
                df['user_score_bars_print'] = df['user_score_bars'].apply(lambda x: '⬛' * x)
                df['user_score_bars_print'] = df['user_score_bars_print'] + df['user_score_bars'].apply(lambda x: '⬜' * (10 - x))

                df['is_president'] = models.is_president(df['user_id'])

                #Sort by post_score
                df = df.sort_values(by=['post_score'], ascending=False)

                ids = ', '.join(f'{w}' for w in df.post_id)
                ids = "(" + ids + ")"

                #Get all second replies
                with engine.connect() as connection:
                    ResultProxy = connection.execute(
                            """SELECT p.post_id, p.user_id, p.reply_to_id, p.media_id, p.creation_time, p.post_text, b.user_score, COALESCE(c.current_user_vote, 0 ) as current_user_vote, u.first_name, u.handle, u.profile_photo
                                        FROM posts p
                                        LEFT JOIN users u ON p.user_id = u.id 
                                        LEFT JOIN
                                                (
                                                    SELECT u.id, SUM(p1.value) AS user_score
                                                        FROM users u
                                                        LEFT JOIN posts p ON p.user_id = u.id
                                                        LEFT JOIN post_votes p1 ON p1.post_id = p.post_id
                                                        GROUP BY u.id
                                                ) b ON b.id = u.id
                                        LEFT JOIN
                                                (
                                                SELECT p2.post_id, SUM(p2.value) AS current_user_vote
                                                    FROM post_votes p2
                                                    WHERE p2.user_id = %s
                                                    GROUP BY p2.post_id
                                                ) c on c.post_id = p.post_id 
                                        WHERE  p.reply_to_id IN %s AND p.is_deleted = 0 """ % (user_id, ids))
                replys = DataFrame(ResultProxy.fetchall())

                if len(replys.index) > 0:
                    replys.columns = ResultProxy.keys()

                    #Get comments and scores for each post_id
                    ids2 = ', '.join(f'{w}' for w in replys.post_id)
                    ids2 = "(" + ids2 + ")"

                    with engine.connect() as connection:
                        ResultProxy = connection.execute("""SELECT p.post_id, p2.reply_count, pv.down_votes, pv2.up_votes
                                                                    FROM posts p
                                                                    LEFT JOIN
                                                                        (
                                                                            SELECT p.reply_to_id, COUNT(p.post_id) AS reply_count
                                                                                FROM posts p
                                                                                WHERE p.reply_to_id IN %s AND p.is_deleted = 0
                                                                                GROUP BY p.reply_to_id
                                                                        ) p2 ON p2.reply_to_id = p.post_id
                                                                    LEFT JOIN
                                                                        (
                                                                            SELECT pv.post_id, COUNT(pv.value) AS down_votes
                                                                                FROM post_votes pv
                                                                                WHERE pv.post_id IN %s AND pv.value < 0
                                                                                GROUP BY pv.post_id
                                                                        ) pv ON pv.post_id = p.post_id
                                                                    LEFT JOIN
                                                                        (
                                                                            SELECT pv.post_id, COUNT(pv.value) AS up_votes
                                                                                FROM post_votes pv
                                                                                WHERE pv.post_id IN %s AND pv.value > 0
                                                                                GROUP BY pv.post_id
                                                                        ) pv2 ON pv2.post_id = p.post_id	
                                                                    WHERE p.post_id IN %s AND p.camp_id = %s; """ % (ids2, ids2, ids2, ids2, camp_id))
                        
                        replys2 = DataFrame(ResultProxy.fetchall())
                        replys2.columns = ResultProxy.keys()
                        replys2['reply_count'] = round(replys2['reply_count'].fillna(0).astype(int), 0)
                        replys2['down_votes'] = round(replys2['down_votes'].fillna(0).astype(int), 0)
                        replys2['up_votes'] = round(replys2['up_votes'].fillna(0).astype(int), 0)

                        replys2['post_score'] = replys2['up_votes'] - replys2['down_votes']

                        replys2['reply_count'] = replys2['reply_count'].replace(0, " ")
                        replys2['down_votes'] = replys2['down_votes'].replace(0, " ")
                        replys2['up_votes'] = replys2['up_votes'].replace(0, " ")

              
                        replys = pd.merge(replys, replys2, on=['post_id'], how='left')
                        
                        #Correct Timezone
                        to_zone = tz.tzlocal()
                                                        
                        replys['creation_time'] = pd.to_datetime(replys['creation_time'])
                        
                        replys['time_ago'] = ""
                        for i in range(len(replys.index)):
                            replys['time_ago'][i] = models.time_ago(replys['creation_time'][i].tz_localize('UTC').tz_convert(to_zone))

                        replys['creation_time'] = replys['creation_time'].dt.tz_localize('UTC').dt.tz_convert(to_zone)
                        replys['creation_time'] = replys['creation_time'].dt.strftime('%m-%d-%Y')

                        #Correct Update Post Score (All posts begin at a score of 0) and round
                        replys['post_score'] = replys['post_score'].fillna(0).astype(int)
                        replys['user_score'] = replys['user_score'].fillna(0).astype(int)

                        #Create User Score bar chart
                        replys['user_score'] = replys['user_score']/10
                        replys['user_score_bars'] = ((replys['user_score'] % 1) * 10).astype(int)
                        replys['user_score'] = replys['user_score'].astype(int)

                        #Create Score Bar Print
                        replys['user_score_bars_print'] = replys['user_score_bars'].apply(lambda x: '⬛' * x)
                        replys['user_score_bars_print'] = replys['user_score_bars_print'] + replys['user_score_bars'].apply(lambda x: '⬜' * (10 - x))

                        replys['is_president'] = models.is_president(replys['user_id'])

                        #Sort by post_score
                        replys = replys.sort_values(by=['post_score'], ascending=False)    
            else:
                replys = pd.DataFrame()
            
            handle = current_user.get_user_handle()

            data = models.get_notifications(user_id)
            notifications = data[0] 
            unseen_count = data[1]

            return render_template('post.html', current_user_id = user_id, current_user_profile_photo = current_user_profile_photo, current_user_handle = handle, post_info=post_info, posts=df, replys = replys, notifications = notifications, notification_count = unseen_count)
        except Exception as e:
            # e holds description of the error
            error_text = "<p>The error:<br>" + str(e) + "</p>"
            hed = '<h1>Something is broken.</h1>'
            return hed + error_text
           
@application.route('/quickvote', methods = ['POST'])
@login_required
def quickvote():
    camp_id = 0
    user_id = current_user.get_user_id()
    value = request.form.get('post_vote')
    value = float(value)
    
    #Value can be 0, 1, or -1
    if value == 1:
        value = 1
    elif value == -1:
        value = -1
    else:
        value = 0
    
    post_id = request.form.get('post_id')

    #confirm this user did not create this post
    with engine.connect() as connection:
        ResultProxy = connection.execute("""SELECT p.user_id
                                                FROM posts p
                                                WHERE post_id = %s AND p.user_id = %s;
                                                """, (post_id, user_id))
        df = DataFrame(ResultProxy.fetchall())

    #Check that there is nothing in the database that is both this post_id AND the current user_id (meaning: check this user didn't create this post)
    if len(df.index) == 0:

        #Check if this user has voted on this already
        with engine.connect() as connection:
            ResultProxy = connection.execute("""SELECT pv.vote_id 
                                                    FROM post_votes pv
                                                    WHERE pv.camp_id = %s AND pv.user_id = %s AND post_id = %s;
                                                    """, (camp_id, user_id, post_id))

        df = DataFrame(ResultProxy.fetchall())
        
        if len(df.index) == 0:
            with engine.connect() as connection:
                connection.execute('INSERT INTO post_votes (camp_id, user_id, post_id, value) VALUES (%s, %s, %s, %s);', (camp_id, user_id, post_id, value))
        else:
            with engine.connect() as connection:
                ResultProxy = connection.execute("""UPDATE post_votes pv
                                                    SET value = %s
                                                    WHERE pv.camp_id = %s AND pv.user_id = %s AND post_id = %s;
                                                    """, (value, camp_id, user_id, post_id))

    #Get this post now
    with engine.connect() as connection:
        ResultProxy = connection.execute("""SELECT p.post_id, p.camp_id, p.user_id, p.reply_to_id, u.first_name, u.handle, u.profile_photo, p.creation_time, p.post_text, p.media_id, b.user_score, COALESCE(c.current_user_vote, 0 ) as current_user_vote, p2.reply_count, pv.down_votes, pv2.up_votes
                                        FROM posts p
                                        LEFT JOIN users u ON p.user_id = u.id 
                                        LEFT JOIN
                                            (
                                                SELECT p.reply_to_id, COUNT(p.post_id) AS reply_count
                                                    FROM posts p
                                                    WHERE p.reply_to_id = %s AND p.is_deleted = 0
                                                    GROUP BY p.reply_to_id
                                            ) p2 ON p2.reply_to_id = p.post_id
                                        LEFT JOIN
                                            (
                                                SELECT pv.post_id, COUNT(pv.value) AS down_votes
                                                    FROM post_votes pv
                                                    WHERE pv.post_id = %s AND pv.value < 0
                                                    GROUP BY pv.post_id
                                            ) pv ON pv.post_id = p.post_id
                                        LEFT JOIN
                                            (
                                                SELECT pv.post_id, COUNT(pv.value) AS up_votes
                                                    FROM post_votes pv
                                                    WHERE pv.post_id = %s AND pv.value > 0
                                                    GROUP BY pv.post_id
                                            ) pv2 ON pv2.post_id = p.post_id
                                        LEFT JOIN
                                                (
                                                    SELECT u.id, SUM(p1.value) AS user_score
                                                        FROM users u
                                                        LEFT JOIN posts p ON p.user_id = u.id
                                                        LEFT JOIN post_votes p1 ON p1.post_id = p.post_id
                                                        GROUP BY u.id
                                                ) b ON b.id = u.id
                                        LEFT JOIN
                                                (
                                                SELECT p2.post_id, SUM(p2.value) AS current_user_vote
                                                    FROM post_votes p2
                                                    WHERE p2.user_id = %s
                                                    GROUP BY p2.post_id
                                                ) c on c.post_id = p.post_id 
                                        WHERE p.post_id = %s AND p.is_deleted = 0; """, (post_id, post_id, post_id, user_id, post_id))
        post_info = DataFrame(ResultProxy.fetchall())

    if len(post_info.index) > 0:
        post_info.columns = ResultProxy.keys()
         #Correct Score for post_info
        post_info['user_score'] = post_info['user_score'].fillna(0).astype(int)
        
        post_info['reply_count'] = round(post_info['reply_count'].fillna(0).astype(int), 0)
        post_info['down_votes'] = round(post_info['down_votes'].fillna(0).astype(int), 0)
        post_info['up_votes'] = round(post_info['up_votes'].fillna(0).astype(int), 0)

        post_info['post_score'] = post_info['up_votes'] - post_info['down_votes']

        
        post_info['reply_count'] = post_info['reply_count'].replace(0, " ")
        post_info['down_votes'] = post_info['down_votes'].replace(0, " ")
        post_info['up_votes'] = post_info['up_votes'].replace(0, " ")

        #Correct Timezone
        to_zone = tz.tzlocal()
                                        
        post_info['creation_time'] = pd.to_datetime(post_info['creation_time'])
        post_info['time_ago'] = ""
        for i in range(len(post_info.index)):
            post_info['time_ago'][i] = models.time_ago(post_info['creation_time'][i].tz_localize('UTC').tz_convert(to_zone))
        
        post_info['creation_time'] = post_info['creation_time'].dt.tz_localize('UTC').dt.tz_convert(to_zone)
        post_info['creation_time'] = post_info['creation_time'].dt.strftime('%m-%d-%Y')

        #Create User Score bar chart
        post_info['user_score'] = post_info['user_score']/10
        post_info['user_score_bars'] = ((post_info['user_score'] % 1) * 10).astype(int)
        post_info['user_score'] = post_info['user_score'].astype(int)

        #Create Score Bar Print
        post_info['user_score_bars_print'] = post_info['user_score_bars'].apply(lambda x: '⬛' * x)
        post_info['user_score_bars_print'] = post_info['user_score_bars_print'] + post_info['user_score_bars'].apply(lambda x: '⬜' * (10 - x))

        response = jsonify(post_info=post_info.to_json())
    else: 
        response = jsonify(success=False)
    return response   

@application.route('/post_delete/<post_id>', methods = ['POST'])
@login_required
def post_delete(post_id):
    try:
        user_id = current_user.get_user_id()
    except Exception as e:
        print(e)
        return redirect('/')
    
    if request.method == 'POST':
        with engine.connect() as connection:
            ResultProxy = connection.execute('''UPDATE posts p
                                                    SET p.is_deleted = 1
                                                    WHERE p.post_id = %s AND p.user_id = %s;''', (post_id, user_id))

    response = jsonify(success=True)
    return response

@application.route('/notification_seen', methods = ['POST'])
@login_required
def notification_seen():
    #Get current user
    user_id = current_user.get_user_id()
    
    if request.method == 'POST':
        #get current time
        with engine.connect() as connection:
            ResultProxy = connection.execute('''UPDATE notifications n
                                                    SET n.seen = 1, n.seen_time = CURRENT_TIMESTAMP
                                                    WHERE n.user_id = %s AND n.seen = 0;''', (user_id))

        response = jsonify(success=True)
    else:
        response = jsonify(success=False)

    return response

@application.route('/top', methods = ['GET'])
def top():
    try:
        user_id = current_user.get_user_id()
    except:
        user_id = 0

    #Get Posts
    df = models.get_top_feed(user_id, None)

    if df is not None and len(df) > 0:
        df = models.format_feed(df)

        #order df by post_score
        df = df.sort_values(by=['post_score', 'user_score', 'creation_time'], ascending=False)

        #re-index
        df.index = range(len(df.index))
    else:
        df = DataFrame()

    #Get notifications
    data = models.get_notifications(user_id)
    notifications = data[0] 
    unseen_count = data[1]

    try:
        handle = current_user.get_user_handle()
        user_profile_photo = current_user.get_user_profile_photo() 
    except:
        handle = None
        user_profile_photo = None

    df_type = 'top'  

    return render_template('top.html', posts=df, df_type = df_type, current_user_id = user_id, current_user_handle = handle, current_user_profile_photo = user_profile_photo, notifications = notifications, notification_count = unseen_count)

           

### Rest User Password Section ###
@application.route('/account/password/reset', methods = ['GET', 'POST'])
def reset_password_request():
    form = models.PasswordResetForm(request.form)
    if request.method == 'POST' and form.validate(): 
        ##See if they are a user
        user = User.query.filter_by(email=form.email.data).first()

        if user:
            #create token
            token = get_random_string(50)

            #store token in database
            with engine.connect() as connection:
                connection.execute("INSERT INTO tokens (user_id, token) VALUES (%s, %s);", (user.get_user_id(), token))
                
                recipients = [user.email]
                subject = 'Attabit - Password Reset'
                
            html = render_template('reset_pw_email.html', token = token)

            # send_email(application, 
            #             recipients= recipients, 
            #             subject = subject, 
            #             html = html
            #             )
            
            msg = Message(subject, sender = (GMAIL_USERNAME), recipients = recipients)
            msg.html = html
            mail.send(msg)
                
                
            flash('If an account with that email exists, instructions to reset your password will be sent to that email.')
            return redirect(url_for('login'))
        else:
            flash('If an account with that email exists, instructions to reset your password will be sent to that email.')
            return redirect(url_for('reset_password_request'))
    return render_template('reset_password_request.html', form = form)

@application.route('/account/password/reset/confirm', methods = ['GET', 'POST'])
def reset_password_with_token():
    form = models.PasswordChangeForm(request.form)
    token = request.args.get('token')

    #Check if token is legit
    with engine.connect() as connection:
        ResultProxy = connection.execute("SELECT * FROM tokens WHERE token = %s;", (token))
        token_df = DataFrame(ResultProxy.fetchall())
    
    
    if len(token_df.index) > 0:
        token_df.columns = ResultProxy.keys()

        #check if token is expired
        if pd.to_datetime(token_df['creation_time'][0]) + timedelta(hours=24) < datetime.now() :
            flash('Error: The password reset link has expired')
            return redirect(url_for('login'))

        #check if token has been used already
        if token_df['used'][0] > 0:    
            flash('Error: The password reset link has expired')
            return redirect(url_for('login'))

        #if Post request update password
        if request.method == 'POST' and form.validate():
            user_id = token_df['user_id'][0]
            user = User.query.filter_by(id=user_id).first()

            #update password
            password = form.password.data.encode('utf-8')

            salt = bcrypt.gensalt()
            password_hash = bcrypt.hashpw(password, salt)
            password_hash = password_hash.decode('utf8')

            with engine.connect() as connection:
                connection.execute('''UPDATE users
                                        SET password = %s
                                        WHERE id = %s;''', (password_hash, user_id))
         
            #Destroy token
            with engine.connect() as connection:
                connection.execute("UPDATE tokens SET used = 1 WHERE token = %s;", (token))

            #Now login user
            flash('Your password has been reset')
            if user:
                user.authenticated = True
                login_user(user, remember=True)
                current_user.is_authenticated = True

                try:
                    current_db_sessions = db.session.object_session(user)
                    current_db_sessions.add(user)
                except:
                    db.session.add(user)
                
                db.session.commit()
                return redirect('/')
            
            flash('Error: Something went wrong')
            return redirect(url_for('login'))
        else:    
            #load page and allow user to change password
            return render_template('reset_password_with_token.html', form = form)
        
    flash('Error: Something went wrong')
    return redirect(url_for('login'))
   
@application.route('/quickfeed', methods = ['GET'])
def quickfeed():

    #Get type (if listed)
    df_type = request.args.get('type')
    offset = request.args.get('offset')

    if offset is not None:
        try:
            offset = int(offset)
        except:
            offset = 0
    
    #get last_post_id from get request
    min_post_id = request.args.get('min_post_id')

    #get profile_user_id from get request
    profile_user_id = request.args.get('profile_user_id')

    #if min_post_id is not int, set to None
    if min_post_id is not None:
        try:
            min_post_id = int(min_post_id)
        except:
            min_post_id = None

    if profile_user_id is not None:
        try:
            profile_user_id = int(profile_user_id)
        except:
            profile_user_id = None

    #Get current user
    try:
        user_id = current_user.get_user_id()
    except:
        user_id = None
    
    #Get Posts
    if df_type == 'top':
        df = models.get_top_feed(user_id, offset)
    else:
        #check if we are getting the normal feed or a profile feed
        if profile_user_id is not None:
            #Get Posts
            df = models.get_user_posts(user_id, profile_user_id, min_post_id)
        else:
            df = models.get_feed(user_id, min_post_id)

    if df is not None and len(df) > 0:
        df = models.format_feed(df)

        #get smalled post_id from df
        min_post_id = df['post_id'].min()
    else:
        df = DataFrame()
        min_post_id = None

    return render_template('quickfeed.html', posts=df, min_post_id = min_post_id, df_type = df_type)


@application.route('/topquickfeed', methods = ['GET'])
@login_required
def topquickfeed():

    #get last_post_id from get request
    min_post_id = request.args.get('min_post_id')

    #get last_post_id from get request
    date = request.args.get('date')

    #if min_post_id is not int, set to None
    if min_post_id is not None:
        try:
            min_post_id = int(min_post_id)
        except:
            min_post_id = None

    try:
        user_id = current_user.get_user_id()
    except Exception as e:
        print(e)
        return redirect('/landing')
  
    #Get Posts
    result = models.get_top_feed(user_id, min_post_id, date)

    df = result[0]

    if len(df.index) == 0 and min_post_id is not None:
        return jsonify({'status': 'failed'})


    if df is not None and len(result[0]) > 0:
        df = result[0]
        df = models.format_feed(df)
        
        #get smalled post_id from df
        min_post_id = df['post_id'].min()
    else:
        df = DataFrame()
        min_post_id = None

    return render_template('quickfeed.html', posts=df, min_post_id = min_post_id)

if __name__ == '__main__':
    #Need to make this port 443 in prod
    application.run(debug=True, use_reloader = True)