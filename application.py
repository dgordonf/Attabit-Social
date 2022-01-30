from flask import Flask, request, render_template, redirect, url_for, flash, jsonify, send_from_directory
import requests
from string import Template
from flask_sqlalchemy import SQLAlchemy
from numpy import isnan
import sqlalchemy
import pandas as pd
from pandas import DataFrame
from pandas.util import hash_pandas_object
import re
from flask_gtts import gtts
from config import Config, S3_KEY, S3_SECRET, S3_BUCKET
from flask_login import LoginManager
from models import LoginForm, RegistrationForm, upload_file_to_s3
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
engine = sqlalchemy.create_engine(application.config['SQLALCHEMY_DATABASE_URI'], pool_recycle=3600)

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
        """Return the email address to satisfy Flask-Login's requirements."""
        return self.handle         
        
    def is_authenticated(self):
        """Return True if the user is authenticate#d."""
        return self.authenticated

# @application.route('/')
# def homepage():
#     try:
#         try:
#             user_id =  current_user.get_user_id()
#         except:
#             db.session.rollback()
#         if user_id is None:
#             form = LoginForm(request.form)
#             form2 = RegistrationForm(request.form)
#             return render_template('login.html', form=form, form2=form2)
#         else:
#             return redirect("/")
#     except:
#         form = LoginForm(request.form)
#         form2 = RegistrationForm(request.form)
#         return render_template('login.html', form=form, form2=form2)

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
    flash('You must be logged in to view that page.')
    return redirect('/login')

@application.route('/login', methods = ['POST', 'GET'])
def login():
    form = LoginForm(request.form)
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
                print("Nope") 
        else:
            print("Not a user")        
    else:
        render_template('login.html', form=form)
    return render_template('login.html', form=form)

@application.route("/logout")
def logout():
    logout_user()
    return redirect("/login")


@application.route('/signup', methods = ['POST', 'GET'])
def signup(): 
    form = RegistrationForm(request.form)
    if request.method == 'POST' and form.validate() and User.query.filter_by(email=form.email.data).first() is None:
        
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

        try:
            user
        except:
            print("User variable not defined")
            return redirect('/login')
        
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
            #db.session.close()
            #db.session.remove()
            #db.engine.dispose()
        return redirect("/")
          
    else:
        return render_template('signup.html', form=form)

@application.route('/', methods = ['POST', 'GET'])
@login_required
def feed():
    camp_id = 0

    try:
        user_id = current_user.get_user_id()
    except Exception as e:
        print(e)
        return redirect('/')
    
    if request.method == 'POST':
        type = request.form.get('update_type')
        post_text = request.form.get('post_text')
        reply_to_id = request.form.get('reply_to_id')
                
        if type == 'post_text':
            try:
                media_file = request.files["user_file"]
                #First check if there is a photo to upload
            
                if media_file.filename != "":
                    filename = secure_filename(media_file.filename)
                    media_id = get_random_string(12)
                    
                    #Get image Size
                    with Image.open(media_file, mode='r') as img:
                        width, height = img.size
                    
                    media_file.seek(0)
                    s3.upload_fileobj(
                            media_file,
                            S3_BUCKET,
                            "media/" + filename,
                            ExtraArgs={
                                "ACL": "public-read",
                                "ContentType": media_file.content_type
                                })
                            
                    try:
                        with engine.connect() as connection:
                            connection.execute('INSERT INTO photos (media_id, photo_url, width, height) VALUES (%s, %s, %s, %s);', (media_id, filename, width, height))
                    except Exception as e:
                        # e holds description of the error
                        error_text = "<p>The error:<br>" + str(e) + "</p>"
                        hed = '<h1>Something is broken.</h1>'
                        return hed + error_text 
                else:
                    media_id = ""

            except:
                media_id = ""

            try:
                with engine.connect() as connection:
                    connection.execute('INSERT INTO posts (camp_id, user_id, reply_to_id, media_id, post_text) VALUES (%s, %s, %s, %s, %s);', (camp_id, user_id, reply_to_id, media_id, post_text))
                
            except Exception as e:
                # e holds description of the error
                error_text = "<p>The error:<br>" + str(e) + "</p>"
                hed = '<h1>Something is broken.</h1>'
                return hed + error_text 

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
            if df['user_score'][0] is None:
                user_badge_score = 0
            else:
                user_badge_score = int(round(df['user_score'][0], 0))

            #Get Profile Photo
            user_profile_photo = df['profile_photo'][0]


            with engine.connect() as connection:
                ResultProxy = connection.execute("""SELECT p.post_id, p.camp_id, p.user_id, p.reply_to_id, p.media_id, p.creation_time, p.post_text, SUM(pv.value) AS post_score, b.user_score, COALESCE(c.current_user_vote, 0 ) as current_user_vote, u.first_name, u.handle, u.profile_photo
                                                    FROM follows f
				                                    LEFT JOIN posts p ON p.user_id = f.following
                                                    LEFT JOIN users u ON p.user_id = u.id 
                                                    LEFT JOIN post_votes pv ON p.camp_id = pv.camp_id AND p.post_id = pv.post_id 
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
																WHERE p2.camp_id = %s AND p2.user_id = %s
																GROUP BY p2.post_id
                                                    		) c on c.post_id = p.post_id 
                                                    WHERE (f.user_id = %s AND f.follow_value = 1 AND (p.reply_to_id IS NULL) AND p.is_deleted = 0) OR p.user_id = %s AND p.camp_id = %s AND p.is_deleted = 0            
                                                    GROUP BY p.post_id; """, (camp_id, user_id, user_id, user_id, camp_id))
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

                    df2['reply_count'] = df2['reply_count'].replace(0, " ")
                    df2['down_votes'] = df2['down_votes'].replace(0, " ")
                    df2['up_votes'] = df2['up_votes'].replace(0, " ")

              
                df = pd.merge(df, df2, on=['post_id'], how='left')
                #Correct Timezone
                to_zone = tz.tzlocal()

                df['creation_time'] = pd.to_datetime(df['creation_time'])
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
                df['user_score_bars_print'] = df['user_score_bars'].apply(lambda x: '■' * x)
                df['user_score_bars_print'] = df['user_score_bars_print'] + df['user_score_bars'].apply(lambda x: '□' * (10 - x))
       
                ##Split into posts and replys
                posts = df[df["reply_to_id"].isnull()]
                posts = posts.sort_values(by=['post_id'], ascending=False)  
                
                replys = df[df["reply_to_id"].notnull()]
                replys = replys.sort_values(by=['post_id'], ascending=True)  
          
            else:
                posts = df
                replys = df
                

            #Get Photos for all IDs
            if len(posts.index) > 0:
                ids = ', '.join(f'"{w}"' for w in posts.media_id)
                ids = "(" + ids + ")"
                
                with engine.connect() as connection:
                    ResultProxy = connection.execute('SELECT * FROM photos ph WHERE ph.media_id IN %s;' % (ids))

                photos = DataFrame(ResultProxy.fetchall())
                if len(photos.index) > 0:
                    photos.columns = ResultProxy.keys()
                    photos['bottom-padding'] = ((photos['height']/photos['width'])*100) - 5
                else:
                    photos = pd.DataFrame({"media_id": [0]})
            else:
                photos = pd.DataFrame({"media_id": [0]})

            handle = current_user.get_user_handle()

            return render_template('feed.html', current_user_id = user_id, current_user_handle = handle, current_user_profile_photo = user_profile_photo, posts=posts, photos=photos, replys=replys, camp_id=camp_id)
        except Exception as e:
            # e holds description of the error
            error_text = "<p>The error:<br>" + str(e) + "</p>"
            hed = '<h1>Something is broken.</h1>'
            return hed + error_text
           
    else:
        flash('You are not a member of that camp')
        return redirect('/')


@application.route('/favicon.png') 
def favicon(): 
    return send_from_directory(os.path.join(application.root_path, 'static'), 'favicon.png', mimetype='image/vnd.microsoft.icon')

@application.route('/@<username>', methods = ['POST','GET'])
@login_required
def user_page(username):
    
    camp_id = 0
    profile_username = username

    try:
        user_id = current_user.get_user_id()
    except Exception as e:
        print(e)
        return redirect('/')

    #Get current user profile photo
    with engine.connect() as connection:
        ResultProxy = connection.execute('''SELECT u.profile_photo 
                                            FROM users u
                                            WHERE u.id = %s;''', (user_id))
    df = DataFrame(ResultProxy.fetchall())
    df.columns = ResultProxy.keys()
    current_user_profile_photo = df['profile_photo'][0]

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
    profile_info['user_score_bars_print'] = profile_info['user_score_bars'].apply(lambda x: '■' * x)
    profile_info['user_score_bars_print'] = profile_info['user_score_bars_print'] + profile_info['user_score_bars'].apply(lambda x: '□' * (10 - x))

    if request.method == 'POST':
        type = request.form.get('update_type')
        post_text = request.form.get('post_text')
        reply_to_id = request.form.get('reply_to_id')
                
        if type == 'post_text':
            try:
                media_file = request.files["user_file"]
                #First check if there is a photo to upload
            
                if media_file.filename != "":
                    filename = secure_filename(media_file.filename)
                    media_id = get_random_string(12)
                    
                    #Get image Size
                    with Image.open(media_file, mode='r') as img:
                        width, height = img.size
                    
                    media_file.seek(0)
                    s3.upload_fileobj(
                            media_file,
                            S3_BUCKET,
                            "media/" + filename,
                            ExtraArgs={
                                "ACL": "public-read",
                                "ContentType": media_file.content_type
                                })
                            
                    try:
                        with engine.connect() as connection:
                            connection.execute('INSERT INTO photos (media_id, photo_url, width, height) VALUES (%s, %s, %s, %s);', (media_id, filename, width, height))
                    except Exception as e:
                        # e holds description of the error
                        error_text = "<p>The error:<br>" + str(e) + "</p>"
                        hed = '<h1>Something is broken.</h1>'
                        return hed + error_text 
                else:
                    media_id = ""

            except:
                media_id = ""

            try:
                with engine.connect() as connection:
                    connection.execute('INSERT INTO posts (camp_id, user_id, reply_to_id, media_id, post_text) VALUES (%s, %s, %s, %s, %s);', (camp_id, user_id, reply_to_id, media_id, post_text))
                
            except Exception as e:
                # e holds description of the error
                error_text = "<p>The error:<br>" + str(e) + "</p>"
                hed = '<h1>Something is broken.</h1>'
                return hed + error_text 

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
                print(e)
                error_text = "<p>The error:<br>" + str(e) + "</p>"
                hed = '<h1>Something is broken.</h1>'
                return hed + error_text 
        

    ##Get thier color and make sure there is at least 1 post for them to see
    #### Come back to when you have followers table
    with engine.connect() as connection:
        ResultProxy = connection.execute("""SELECT  u.id, SUM(p1.value) AS user_score
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

            with engine.connect() as connection:
                ResultProxy = connection.execute("""SELECT p.post_id, p.camp_id, p.user_id, p.reply_to_id, p.media_id, p.creation_time, p.post_text, SUM(pv.value) AS post_score, b.user_score, COALESCE(c.current_user_vote, 0 ) as current_user_vote, u.first_name, u.handle, u.profile_photo
                                                    FROM posts p 
                                                    LEFT JOIN users u ON p.user_id = u.id 
                                                    LEFT JOIN post_votes pv ON p.camp_id = pv.camp_id AND p.post_id = pv.post_id 
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
																WHERE p2.camp_id = %s AND p2.user_id = %s
																GROUP BY p2.post_id
                                                    		) c on c.post_id = p.post_id     
                                                    WHERE p.camp_id = %s AND p.reply_to_id IS NULL AND u.handle = %s AND p.is_deleted = 0
                                                    GROUP BY p.post_id; """, (camp_id, user_id, camp_id, profile_username))
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

                    df2['reply_count'] = df2['reply_count'].replace(0, " ")
                    df2['down_votes'] = df2['down_votes'].replace(0, " ")
                    df2['up_votes'] = df2['up_votes'].replace(0, " ")

              
                df = pd.merge(df, df2, on=['post_id'], how='left')
                #Correct Timezone
                to_zone = tz.tzlocal()
                                                
                df['creation_time'] = pd.to_datetime(df['creation_time'])
                df['creation_time'] = df['creation_time'].dt.tz_localize('UTC').dt.tz_convert(to_zone)
                df['creation_time'] = df['creation_time'].dt.strftime('%m•%d•%Y')

                #Correct Update Post Score (All posts begin at a score of 0) and round
                df['post_score'] = df['post_score'].fillna(0).astype(int)
                df['user_score'] = df['user_score'].fillna(0).astype(int)
               
                #Create User Score bar chart
                df['user_score'] = df['user_score']/10
                df['user_score_bars'] = ((df['user_score'] % 1) * 10).astype(int)
                df['user_score'] = df['user_score'].astype(int)

                #Create Score Bar Print
                df['user_score_bars_print'] = df['user_score_bars'].apply(lambda x: '■' * x)
                df['user_score_bars_print'] = df['user_score_bars_print'] + df['user_score_bars'].apply(lambda x: '□' * (10 - x))
                                
                ##Split into posts and replys
                posts = df[df["reply_to_id"].isnull()]
                posts = posts.sort_values(by=['post_id'], ascending=False)  
                
                replys = df[df["reply_to_id"].notnull()]
                replys = replys.sort_values(by=['post_id'], ascending=True)  
                
            else:
                posts = df
                replys = df

            #Get Photos for all IDs
            if len(posts.index) > 0:
                ids = ', '.join(f'"{w}"' for w in posts.media_id)
                ids = "(" + ids + ")"
                
                with engine.connect() as connection:
                    ResultProxy = connection.execute('SELECT * FROM photos ph WHERE ph.media_id IN %s;' % ids)

                photos = DataFrame(ResultProxy.fetchall())
                if len(photos.index) > 0:
                    photos.columns = ResultProxy.keys()
                    photos['bottom-padding'] = ((photos['height']/photos['width'])*100) - 5
                else:
                    photos = pd.DataFrame({"media_id": [0]})
            else:
                photos = pd.DataFrame({"media_id": [0]})

            ##Get Follow Value
            with engine.connect() as connection:
                ResultProxy = connection.execute("""SELECT u.handle, COALESCE(f.follow_value, 0 ) as follow_status
                                                        FROM users u
                                                        LEFT JOIN follows f ON f.following = u.id
                                                        WHERE u.handle = %s AND f.user_id = %s AND f.last_update_time IS NULL; """, (username, user_id))
            try:
                follow = DataFrame(ResultProxy.fetchall())
                follow.columns = ResultProxy.keys()
                follow_status = follow['follow_status'][0]
            except:
                follow_status = 0

            return render_template('profile.html', profile_handle = username, profile_info = profile_info, follow_status = follow_status, current_user_id = user_id, current_user_profile_photo = current_user_profile_photo, posts=posts, photos=photos, replys=replys, camp_id=camp_id)
        except Exception as e:
            # e holds description of the error
            print(e)
            error_text = "<p>The error:<br>" + str(e) + "</p>"
            hed = '<h1>Something is broken.</h1>'
            return hed + error_text
           
    else:
        flash('You are not logged In')
        return redirect('/login')

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
@login_required
def quickfollow(username):
    profile_username = username
    user_id = current_user.get_user_id()
    
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

        # Generate file name:
        #Check if they have uploaded a file, if they have, use that name, if not, use a random name
        # with engine.connect() as connection:
        #         ResultProxy = connection.execute('''SELECT u.profile_photo 
        #                                             FROM users u
        #                                             WHERE u.profile_photo IS NOT NULL AND u.id = %s;''', (current_user.get_user_id()))
        # df = DataFrame(ResultProxy.fetchall())
        # if len(df.index) > 0:
        #     df.columns = ResultProxy.keys()
        #     file_name = df['profile_photo'][0]
        #     file_name = file_name.split('.')[0]
        # else:
        #     file_name = None
        
        # if file_name != None:
        #     df.columns = ResultProxy.keys()
        #     file_name = df['profile_photo'][0]
        #     file_name = file_name.split('.')[0]
        # else:
        #     #Create new file_name
        #     #Check that this isn't already in the database
        #     while True:
        #         file_name = str(uuid.uuid4())[:12]
        #         file_name_search = file_name + ".jpg"
        #         file_name_search2 = file_name + ".png"
        #         with engine.connect() as connection:
        #             ResultProxy = connection.execute('''SELECT u.id 
        #                                                 FROM users u
        #                                                 WHERE u.profile_photo = %s OR u.profile_photo = %s;''', (file_name_search, file_name_search2))
                
        #         df = DataFrame(ResultProxy.fetchall())
        #         if len(df.index) == 0:
        #             break

        #Come up with new filename
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
                df['user_score_bars_print'] = df['user_score_bars'].apply(lambda x: '■' * x)
                df['user_score_bars_print'] = df['user_score_bars_print'] + df['user_score_bars'].apply(lambda x: '□' * (10 - x))
                df['user_score'] = df['user_score'].astype(int)

        return render_template('search.html', 
                                    df = df, 
                                    user_id = user_id, 
                                    q = q, 
                                    current_user_id = user_id,
                                    current_user_profile_photo = current_user_profile_photo)
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
            df['user_score_bars_print'] = df['user_score_bars'].apply(lambda x: '■' * x)
            df['user_score_bars_print'] = df['user_score_bars_print'] + df['user_score_bars'].apply(lambda x: '□' * (10 - x)) 
            df['user_score'] = df['user_score'].astype(int)
            
        return render_template('search.html',
                                user_id = user_id,
                                df = df, 
                                q = q,
                                current_user_id = user_id,
                                current_user_profile_photo = current_user_profile_photo)
    
@application.route('/post/<post_id>', methods = ['GET', 'POST'])
@login_required
def post(post_id):
    camp_id = 0
    post_id = int(post_id)
    
    try:
        user_id = current_user.get_user_id()
    except Exception as e:
        print(e)
        return redirect('/')

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
        return redirect('/')
    
    if request.method == 'POST':
        type = request.form.get('update_type')
        post_text = request.form.get('post_text')
        reply_to_id = request.form.get('reply_to_id')
        
                
        if type == 'post_text':
            try:
                media_file = request.files["user_file"]
                #First check if there is a photo to upload
            
                if media_file.filename != "":
                    filename = secure_filename(media_file.filename)
                    media_id = get_random_string(12)
                    
                    #Get image Size
                    with Image.open(media_file, mode='r') as img:
                        width, height = img.size
                    
                    media_file.seek(0)
                    s3.upload_fileobj(
                            media_file,
                            S3_BUCKET,
                            "media/" + filename,
                            ExtraArgs={
                                "ACL": "public-read",
                                "ContentType": media_file.content_type
                                })
                            
                    try:
                        with engine.connect() as connection:
                            connection.execute('INSERT INTO photos (media_id, photo_url, width, height) VALUES (%s, %s, %s, %s);', (media_id, filename, width, height))
                    except Exception as e:
                        # e holds description of the error
                        error_text = "<p>The error:<br>" + str(e) + "</p>"
                        hed = '<h1>Something is broken.</h1>'
                        return hed + error_text 
                else:
                    media_id = ""

            except:
                media_id = ""

            with engine.connect() as connection:
                connection.execute('INSERT INTO posts (camp_id, user_id, reply_to_id, media_id, post_text) VALUES (%s, %s, %s, %s, %s);', (camp_id, user_id, reply_to_id, media_id, post_text))
            
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
            post_info['creation_time'] = post_info['creation_time'].dt.tz_localize('UTC').dt.tz_convert(to_zone)
            post_info['creation_time'] = post_info['creation_time'].dt.strftime('%m-%d-%Y')

            #Create User Score bar chart
            post_info['user_score'] = post_info['user_score']/10
            post_info['user_score_bars'] = ((post_info['user_score'] % 1) * 10).astype(int)
            post_info['user_score'] = post_info['user_score'].astype(int)

            #Create Score Bar Print
            post_info['user_score_bars_print'] = post_info['user_score_bars'].apply(lambda x: '■' * x)
            post_info['user_score_bars_print'] = post_info['user_score_bars_print'] + post_info['user_score_bars'].apply(lambda x: '□' * (10 - x))

            
            #Get all replies on page
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
                df['user_score_bars_print'] = df['user_score_bars'].apply(lambda x: '■' * x)
                df['user_score_bars_print'] = df['user_score_bars_print'] + df['user_score_bars'].apply(lambda x: '□' * (10 - x))

                #Sort by post_score
                df = df.sort_values(by=['post_score'], ascending=False)

            #Get Photos for all IDs
            if len(post_info.index) > 0:
                ids = ', '.join(f'"{w}"' for w in post_info.media_id)
                ids = "(" + ids + ")"
                
                with engine.connect() as connection:
                    ResultProxy = connection.execute('SELECT * FROM photos ph WHERE ph.media_id IN %s;' % (ids))

                photos = DataFrame(ResultProxy.fetchall())
                if len(photos.index) > 0:
                    photos.columns = ResultProxy.keys()
                    photos['bottom-padding'] = ((photos['height']/photos['width'])*100) - 5
                else:
                    photos = pd.DataFrame({"media_id": [0]})
            else:
                photos = pd.DataFrame({"media_id": [0]})

            #This is so it works when you click on your face
            handle = current_user.get_user_handle()

            return render_template('post.html', current_user_id = user_id, current_user_handle = handle, current_user_profile_photo = current_user_profile_photo, post_info=post_info, posts=df, photos = photos)
        except Exception as e:
            # e holds description of the error
            error_text = "<p>The error:<br>" + str(e) + "</p>"
            hed = '<h1>Something is broken.</h1>'
            return hed + error_text
           
@application.route('/post_vote', methods = ['POST'])
@login_required
def post_vote(post_id):
    camp_id = 0
    user_id = current_user.get_user_id()
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

    response = jsonify(success=True)
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

@application.route('/<date>', methods = ['GET'])
@login_required
def top(date):
    camp_id = 0
    
    try:
        user_id = current_user.get_user_id()
    except Exception as e:
        return redirect('/login')
    
    ## Format date
    if date == 'today':
        date_q1 = datetime.now(pytz.timezone('US/Eastern')).strftime('%Y-%m-%d')

        #get tomorrow's date
        date_q2 = (datetime.now(pytz.timezone('US/Eastern')) + timedelta(days=1)).strftime('%Y-%m-%d')

    else:
        #remove anything that isn't a number or "-"
        date = re.sub('[^0-9-]', '', date)
        date_q1 = datetime.strptime(date, '%Y-%m-%d')
        date_q2 = date_q1 + timedelta(days=1)

        date_q1 = date_q1.strftime('%Y-%m-%d')
        date_q2 = date_q2.strftime('%Y-%m-%d')

    #Get display dates
    today = str(datetime.now(pytz.timezone('US/Eastern')).strftime('%Y-%m-%d'))
    date_selected = str(date_q1)

    #turn to string
    date_q1 = str(date_q1) + "T05:00:00.000"
    date_q2 = str(date_q2) + "T05:00:00.000"

    #Not sure we need this
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
            if df['user_score'][0] is None:
                user_badge_score = 0
            else:
                user_badge_score = int(round(df['user_score'][0], 0))

            #Get Profile Photo
            user_profile_photo = df['profile_photo'][0]

            with engine.connect() as connection:
                ResultProxy = connection.execute("""SELECT p.post_id, p.camp_id, p.user_id, p.reply_to_id, p.media_id, p.creation_time, p.post_text, SUM(pv.value) AS post_score, b.user_score, COALESCE(c.current_user_vote, 0 ) as current_user_vote, u.first_name, u.handle, u.profile_photo
                                                    FROM posts p
				                                    LEFT JOIN users u ON p.user_id = u.id 
                                                    LEFT JOIN post_votes pv ON p.camp_id = pv.camp_id AND p.post_id = pv.post_id 
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
																WHERE p2.camp_id = 0 AND p2.user_id = 8
																GROUP BY p2.post_id
                                                    		) c on c.post_id = p.post_id 
                                                    WHERE (p.reply_to_id IS NULL) AND p.is_deleted = 0 
                                                    AND p.creation_time >= %s  
      												AND p.creation_time <= %s
                                                      GROUP BY p.post_id
                                                    ORDER BY post_score DESC
                                                    LIMIT 100; """, (date_q1, date_q2))
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

                    df2['reply_count'] = df2['reply_count'].replace(0, " ")
                    df2['down_votes'] = df2['down_votes'].replace(0, " ")
                    df2['up_votes'] = df2['up_votes'].replace(0, " ")

              
                df = pd.merge(df, df2, on=['post_id'], how='left')
                #Correct Timezone
                to_zone = tz.tzlocal()

                df['creation_time'] = pd.to_datetime(df['creation_time'])
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
                df['user_score_bars_print'] = df['user_score_bars'].apply(lambda x: '■' * x)
                df['user_score_bars_print'] = df['user_score_bars_print'] + df['user_score_bars'].apply(lambda x: '□' * (10 - x))
       
                ##Split into posts and replys
                posts = df[df["reply_to_id"].isnull()]
                posts = posts.sort_values(by=['post_id'], ascending=False)  
                
            else:
                posts = df
 
                

            #Get Photos for all IDs
            if len(posts.index) > 0:
                ids = ', '.join(f'"{w}"' for w in posts.media_id)
                ids = "(" + ids + ")"
                
                with engine.connect() as connection:
                    ResultProxy = connection.execute('SELECT * FROM photos ph WHERE ph.media_id IN %s;' % (ids))

                photos = DataFrame(ResultProxy.fetchall())
                if len(photos.index) > 0:
                    photos.columns = ResultProxy.keys()
                    photos['bottom-padding'] = ((photos['height']/photos['width'])*100) - 5
                else:
                    photos = pd.DataFrame({"media_id": [0]})
            else:
                photos = pd.DataFrame({"media_id": [0]})

            handle = current_user.get_user_handle()

            print(df)

            return render_template('top.html', today = today, date_selected = date_selected, current_user_id = user_id, current_user_handle = handle, current_user_profile_photo = user_profile_photo, posts=posts, photos=photos, camp_id=camp_id)
        except Exception as e:
            # e holds description of the error
            error_text = "<p>The error:<br>" + str(e) + "</p>"
            hed = '<h1>Something is broken.</h1>'
            return hed + error_text
           
    else:
        flash('You are not a member of that camp')
        return redirect('/')



if __name__ == '__main__':
    #Need to make this port 443 in prod
    application.run(port=8080, debug=True, use_reloader = True)