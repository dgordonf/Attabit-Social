from flask import Flask, request, render_template, redirect, url_for, flash, jsonify
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
from datetime import datetime
from dateutil import tz
from colour import Color
import re
import boto3, botocore
from django.utils.crypto import get_random_string
from werkzeug.utils import secure_filename
from PIL import Image

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
        
    def is_authenticated(self):
        """Return True if the user is authenticate#d."""
        return self.authenticated


@application.route('/')
def homepage():
    try:
        try:
            user_id =  current_user.get_user_id()
        except:
            db.session.rollback()
        if user_id is None:
            form = LoginForm(request.form)
            form2 = RegistrationForm(request.form)
            return render_template('login.html', form=form, form2=form2)
        else:
            return redirect("camp/1")
    except:
        form = LoginForm(request.form)
        form2 = RegistrationForm(request.form)
        return render_template('login.html', form=form, form2=form2)

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
    return redirect('/')

@application.route('/login', methods = ['POST'])
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
            return redirect('/')
        
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
                return redirect("camp/1")
            else: 
                print("Nope") 
        else:
            print("Not a user")        

    return redirect("/")

@application.route("/logout")
def logout():
    logout_user()
    return redirect("/")


@application.route('/signup', methods = ['POST'])
def signup(): 
    form = RegistrationForm(request.form)
    if request.method == 'POST' and form.validate() and User.query.filter_by(email=form.email.data).first() is None:
        name = form.name.data
        email = form.email.data
        password = form.password.data.encode('utf-8')

        salt = bcrypt.gensalt()
        password_hash = bcrypt.hashpw(password, salt)
        password_hash = password_hash.decode('utf8')
        
        with engine.connect() as connection:
            connection.execute("INSERT INTO users (first_name, email, password) VALUES (%s, %s, %s);", (name, email, password_hash))
        
        user = User.query.get(email)
        login_user(user, remember=True)
        user_id =  current_user.get_user_id()

        with engine.connect() as connection:
            connection.execute("INSERT INTO camp_directory (camp_id, user_id) VALUES (%s, %s);", (1, user_id))
        
        return redirect("camp/1")
    print("Already a user")    
    return render_template('index.html', form=form)

@application.route('/camp/<int:camp_id>', methods = ['POST', 'GET'])
@login_required
def camp(camp_id):
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
                    with Image.open(media_file) as img:
                        width, height = img.size

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
                with engine.connect() as connection:
                    connection.execute('INSERT INTO post_votes (camp_id, user_id, post_id, value) VALUES (%s, %s, %s, %s);', (camp_id, user_id, post_id, value))
                
            except Exception as e:
                # e holds description of the error
                error_text = "<p>The error:<br>" + str(e) + "</p>"
                hed = '<h1>Something is broken.</h1>'
                return hed + error_text 
        return redirect('/')

    ##Are they in this camp? If yes also grab their color
    with engine.connect() as connection:
        ResultProxy = connection.execute("""SELECT * FROM camp_directory cd 
                                            LEFT JOIN
                                                (	SELECT  u.id, SUM(p1.value) AS user_score
                                                    FROM    users u
                                                    LEFT JOIN posts p ON p.user_id = u.id
                                                    LEFT JOIN post_votes p1 ON p1.post_id = p.post_id
                                                    GROUP   BY u.id
                                                ) b ON b.id = cd.user_id
                                            WHERE cd.camp_id = %s AND cd.user_id = %s; """, (camp_id, user_id))
    df = DataFrame(ResultProxy.fetchall())

    #If yes, load page
    if len(df.index) > 0: 
        try:
            df.columns = ResultProxy.keys()
            if df['user_score'][0] is None:
                user_badge_score = 0
            else:
                user_badge_score = int(round(df['user_score'][0], 0))
            with engine.connect() as connection:
                ResultProxy = connection.execute("""SELECT p.post_id, p.camp_id, p.user_id, p.reply_to_id, p.media_id, p.creation_time, p.post_text, SUM(pv.value) AS post_score, b.user_score, COALESCE(c.current_user_score, 0 ) as current_user_score, u.first_name 
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
                                                    		SELECT p2.post_id, SUM(p2.value) AS current_user_score
																FROM post_votes p2
																WHERE p2.camp_id = %s AND p2.user_id = %s
																GROUP BY p2.post_id
                                                    		) c on c.post_id = p.post_id     
                                                    WHERE p.camp_id = %s
                                                    GROUP BY p.post_id; """, (camp_id, user_id, camp_id))
            df = DataFrame(ResultProxy.fetchall())
            
            if len(df.index) > 0:
                df.columns = ResultProxy.keys()

                
                #Correct Timezone
                to_zone = tz.tzlocal()
                                                
                df['creation_time'] = pd.to_datetime(df['creation_time'])
                df['creation_time'] = df['creation_time'].dt.tz_localize('UTC').dt.tz_convert(to_zone)
                df['creation_time'] = df['creation_time'].dt.strftime('%b %d, %Y')

                #Correct Update Post Score (All posts begin at a score of 0) and round
                df['post_score'] = df['post_score'].fillna(0).astype(int)
                df['user_score'] = df['user_score'].fillna(0).astype(int)
               
                #https://coolors.co/22577a-38a3a5-c7f9cc-f5b768-f69f64-f87c5f
                #5adbf0,#775bec,#e65978, #f6594c,

                teal = Color("#5adbf0")
                purple = Color("#775bec")
                orange = Color("#e65978")
                pink = Color("#f6594c")
                
                distance = 10

                colors = list(teal.range_to(purple, distance)) + list(purple.range_to(orange, distance)) + list(orange.range_to(pink, distance)) + list(pink.range_to(teal, distance)) 
                    
                datalist = []    
                for values in df.user_score:
                    score = int(round(values, 0))
                    if score < 0:
                        score = 0
                    color = colors[score]
                    datalist.append(color)
                            
                df['user_color'] = datalist
                
                ##Get current user color
                user_badge_color = colors[user_badge_score]
                                
                ##Split into posts and replys
                posts = df[df["reply_to_id"].isnull()]
                posts = posts.sort_values(by=['post_id'], ascending=False)  
                
                replys = df[df["reply_to_id"].notnull()]
                replys = replys.sort_values(by=['post_id'], ascending=True)  
                
                #Get iteration id so AJAX knows when data is new
                iteration_id = df['post_score'].sum()/df['post_score'].count()

            else:
                posts = df
                replys = df
                iteration_id = 0

            #Get Photos for all IDs
            if len(posts.index) > 0:
                ids = ', '.join(f'"{w}"' for w in posts.media_id)
                ids = "(" + ids + ")"
                
                with engine.connect() as connection:
                    ResultProxy = connection.execute('SELECT * FROM photos ph WHERE ph.media_id IN %s;' % ids)

                photos = DataFrame(ResultProxy.fetchall())
                if len(photos.index) > 0:
                    photos.columns = ResultProxy.keys()
                    photos['bottom-padding'] = (photos['height']/photos['width'])*100
                else:
                    photos = pd.DataFrame({"media_id": [0]})
            else:
                photos = pd.DataFrame({"media_id": [0]})

            return render_template('camp.html',  iteration_id = iteration_id, posts=posts, photos=photos, replys=replys, camp_id=camp_id, user_badge_color=user_badge_color)
        except Exception as e:
            # e holds description of the error
            error_text = "<p>The error:<br>" + str(e) + "</p>"
            hed = '<h1>Something is broken.</h1>'
            return hed + error_text
           
    else:
        flash('You are not a member of that camp')
        return redirect('/')

@application.route('/camp_load/<int:camp_id>', methods = ['POST', 'GET'])
@login_required
def camp_load(camp_id):
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
                            connection.execute('INSERT INTO photos (media_id, photo_url) VALUES (%s, %s);', (media_id, filename))
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
                with engine.connect() as connection:
                    connection.execute('INSERT INTO post_votes (camp_id, user_id, post_id, value) VALUES (%s, %s, %s, %s);', (camp_id, user_id, post_id, value))
                
            except Exception as e:
                # e holds description of the error
                error_text = "<p>The error:<br>" + str(e) + "</p>"
                hed = '<h1>Something is broken.</h1>'
                return hed + error_text 
        

    ##Are they in this camp? If yes also grab their color
    with engine.connect() as connection:
        ResultProxy = connection.execute("""SELECT * FROM camp_directory cd 
                                            LEFT JOIN
                                                (	SELECT  u.id, SUM(p1.value) AS user_score
                                                    FROM    users u
                                                    LEFT JOIN posts p ON p.user_id = u.id
                                                    LEFT JOIN post_votes p1 ON p1.post_id = p.post_id
                                                    GROUP   BY u.id
                                                ) b ON b.id = cd.user_id
                                            WHERE cd.camp_id = %s AND cd.user_id = %s; """, (camp_id, user_id))
    df = DataFrame(ResultProxy.fetchall())

    #If yes, load page
    if len(df.index) > 0: 
        try:
            df.columns = ResultProxy.keys()
            if df['user_score'][0] is None:
                user_badge_score = 0
            else:
                user_badge_score = int(round(df['user_score'][0], 0))
            with engine.connect() as connection:
                ResultProxy = connection.execute("""SELECT p.post_id, p.camp_id, p.user_id, p.reply_to_id, p.media_id, p.creation_time, p.post_text, SUM(pv.value) AS post_score, b.user_score, COALESCE(c.current_user_score, 0 ) as current_user_score, u.first_name 
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
                                                    		SELECT p2.post_id, SUM(p2.value) AS current_user_score
																FROM post_votes p2
																WHERE p2.camp_id = %s AND p2.user_id = %s
																GROUP BY p2.post_id
                                                    		) c on c.post_id = p.post_id     
                                                    WHERE p.camp_id = %s
                                                    GROUP BY p.post_id; """, (camp_id, user_id, camp_id))
            df = DataFrame(ResultProxy.fetchall())
            
            if len(df.index) > 0:
                df.columns = ResultProxy.keys()

                #Correct Timezone
                to_zone = tz.tzlocal()

                df['creation_time'] = pd.to_datetime(df['creation_time'])
                df['creation_time'] = df['creation_time'].dt.tz_localize('UTC').dt.tz_convert(to_zone)
                df['creation_time'] = df['creation_time'].dt.strftime('%b %d, %Y')

                #Correct Update Post Score (All posts begin at a score of 0) and round
                df['post_score'] = df['post_score'].fillna(0).astype(int)
                df['user_score'] = df['user_score'].fillna(0).astype(int)
               
                #https://coolors.co/22577a-38a3a5-c7f9cc-f5b768-f69f64-f87c5f
                #5adbf0,#775bec,#e65978, #f6594c,

                teal = Color("#5adbf0")
                purple = Color("#775bec")
                orange = Color("#e65978")
                pink = Color("#f6594c")
                
                distance = 10

                colors = list(teal.range_to(purple, distance)) + list(purple.range_to(orange, distance)) + list(orange.range_to(pink, distance)) + list(pink.range_to(teal, distance)) 
                    
                datalist = []    
                for values in df.user_score:
                    score = int(round(values, 0))
                    if score < 0:
                        score = 0
                    color = colors[score]
                    datalist.append(color)
                            
                df['user_color'] = datalist
                
                ##Get current user color
                user_badge_color = colors[user_badge_score]
              
                ##Split into posts and replys
                posts = df[df["reply_to_id"].isnull()]
                posts = posts.sort_values(by=['post_id'], ascending=False)  
                
                replys = df[df["reply_to_id"].notnull()]
                replys = replys.sort_values(by=['post_id'], ascending=True)  
                
                #Get iteration id so AJAX knows when data is new
                iteration_id = df['post_score'].sum()/df['post_score'].count()

            else:
                posts = df
                replys = df
                iteration_id = 0
            
            #Get Photos for all IDs
            if len(posts.index) > 0:
                ids = ', '.join(f'"{w}"' for w in posts.media_id)
                ids = "(" + ids + ")"
                
                with engine.connect() as connection:
                    ResultProxy = connection.execute('SELECT * FROM photos ph WHERE ph.media_id IN %s;' % ids)

                photos = DataFrame(ResultProxy.fetchall())
                if len(photos.index) > 0:
                    photos.columns = ResultProxy.keys()
                    photos['bottom-padding'] = (photos['height']/photos['width'])*100
                else:
                    photos = pd.DataFrame({"media_id": [0]})
            else:
                photos = pd.DataFrame({"media_id": [0]})
            
            return render_template('camp_load.html',  iteration_id = iteration_id, posts=posts, photos=photos, replys=replys, camp_id=camp_id, user_badge_color=user_badge_color)
        except Exception as e:
            # e holds description of the error
            error_text = "<p>The error:<br>" + str(e) + "</p>"
            hed = '<h1>Something is broken.</h1>'
            return hed + error_text
           
    else:
        flash('You are not a member of that camp')
        



if __name__ == '__main__':
    application.run(port=8080, debug=True, use_reloader = True)