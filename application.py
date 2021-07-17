from flask import Flask, request, render_template, redirect, url_for, flash
from string import Template
from flask_sqlalchemy import SQLAlchemy
from numpy import isnan
import sqlalchemy
import pandas as pd
from pandas import DataFrame
import re
from flask_gtts import gtts
from config import Config
from flask_login import LoginManager
from models import LoginForm, RegistrationForm, User
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

# AWS guide: https://medium.com/@rodkey/deploying-a-flask-application-on-aws-a72daba6bb80
# God Man: https://stackoverflow.com/questions/62111066/mysqlclient-installation-error-in-aws-elastic-beanstalk
#Read this: https://stackoverflow.com/questions/53024891/modulenotfounderror-no-module-named-mysqldb/54031440

#Database fix guide: https://docs.sqlalchemy.org/en/14/core/connections.html

# Not the entire world, just your best friends. 
application = Flask(__name__)
application.secret_key = application.config['SECRET_KEY']

application.config.from_object(Config)

#This is for users table
db = SQLAlchemy(application)
db.init_app(application)

##Create SQL Engine
engine = sqlalchemy.create_engine(application.config['SQLALCHEMY_DATABASE_URI'])

### AUTH SECTION ###
login_manager = LoginManager()
login_manager.init_app(application)
login_manager.login_view = 'login'

def cleanup(session):
    """
    This method cleans up the session object and also closes the connection pool using the dispose method.
    """
    session.close()
    engine_container.dispose()

@application.route('/')
def homepage():
    try:
        user_id =  current_user.get_user_id()
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
        return User.query.get(user_id)
    return None

@login_manager.unauthorized_handler
def unauthorized():
    flash('You must be logged in to view that page.')
    return redirect('/')

@application.route('/login', methods = ['POST'])
def login():
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        user = User.query.get(form.email.data)
        if user:
            form_password = form.password.data.encode('utf-8')
            user_password = user.password.encode('utf-8')
            if bcrypt.checkpw(form_password, user_password):
                #user.authenticated = True
                #db.session.add(user)
                #db.session.commit()
                login_user(user, remember=True)
                db.session.close()
                db.engine.dispose()
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
        user_id =  current_user.get_user_id()
    finally:
        db.session.close()
        db.engine.dispose()

    if request.method == 'POST':
        type = request.form.get('update_type')    
        if type == 'post_text':
            try:
                reply_to_id = request.form.get('reply_to_id')
                post_text = request.form.get('post_text')
                with engine.connect() as connection:
                    connection.execute('INSERT INTO posts (camp_id, user_id, reply_to_id, post_text) VALUES (%s, %s, %s, %s);', (camp_id, user_id, reply_to_id, post_text))
                
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
                ResultProxy = connection.execute("""SELECT p.post_id, p.camp_id, p.user_id, p.reply_to_id, p.creation_time, p.post_text, SUM(pv.value) AS post_score, b.user_score, u.id, u.first_name 
                                                    FROM posts p 
                                                    LEFT JOIN users u ON p.user_id = u.id 
                                                    LEFT JOIN post_votes pv ON p.camp_id = pv.camp_id AND p.post_id = pv.post_id 
                                                    LEFT JOIN
                                                            (
                                                                SELECT  u.id, SUM(p1.value) AS user_score
                                                                FROM    users u
                                                                LEFT JOIN posts p ON p.user_id = u.id
                                                                LEFT JOIN post_votes p1 ON p1.post_id = p.post_id
                                                                GROUP   BY u.id
                                                            ) b ON b.id = u.id
                                                    WHERE p.camp_id = %s 
                                                    GROUP BY p.post_id; """, (camp_id))
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
               
                ##Create User Colors
                queen_blue = Color("#577590")
                cadet_blue = Color("#4D908E") 
                zomp = Color("#43AA8B")
                pistachio = Color("#90BE6D")
                maize_crayola = Color("#F9C74F")
                mango_tango = Color("#F9844A")
                yellow_orange = Color("#F8961E")
                orange_red = Color("#F3722C")

                distance = 10

                colors = list(queen_blue.range_to(cadet_blue, distance)) + list(cadet_blue.range_to(zomp, distance)) + list(zomp.range_to(pistachio, distance)) + list(pistachio.range_to(maize_crayola, distance)) + list(maize_crayola.range_to(mango_tango, distance)) + list(mango_tango.range_to(yellow_orange, distance)) + list(yellow_orange.range_to(orange_red,distance))
                    
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
                
                ## Make URLs Clickable
                #datalist = [] 
                #for values in df.post_text:
                    #if values is not None:
                        #print(values)
                        #url = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', values)
                        #if len(url) > 0:
                           # print(url[0])
                           # url_clean = "<a>" + str(url[0]) + "</a>"
                           # print(url_clean)
                           # text = re.sub(str(url[0]), url_clean, values)
                           # datalist.append(text)

                ##Split into posts and replys
                posts = df[df["reply_to_id"].isnull()]
                posts = posts.sort_values(by=['post_id'], ascending=False)  
                
                replys = df[df["reply_to_id"].notnull()]
                replys = replys.sort_values(by=['post_id'], ascending=True)  

            else :
                posts = df
                replys = df
            
            return render_template('camp.html',  posts=posts, replys=replys, camp_id=camp_id, user_badge_color=user_badge_color)
        except Exception as e:
            # e holds description of the error
            error_text = "<p>The error:<br>" + str(e) + "</p>"
            hed = '<h1>Something is broken.</h1>'
            conn.close()
            return hed + error_text
           
    else:
        flash('You are not a member of that camp')
        return redirect('/')
    

if __name__ == '__main__':
    application.run(port=8080, debug=True, use_reloader = True)