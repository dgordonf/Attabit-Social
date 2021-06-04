from flask import Flask, request, render_template, redirect, url_for, flash
from string import Template

from flask_sqlalchemy import SQLAlchemy
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

# AWS guide: https://medium.com/@rodkey/deploying-a-flask-application-on-aws-a72daba6bb80
# God Man: https://stackoverflow.com/questions/62111066/mysqlclient-installation-error-in-aws-elastic-beanstalk
#Read this: https://stackoverflow.com/questions/53024891/modulenotfounderror-no-module-named-mysqldb/54031440

# Not the entire world, just your best friends. 
application = Flask(__name__)
application.secret_key = application.config['SECRET_KEY']

application.config.from_object(Config)

db = SQLAlchemy(application)
db.init_app(application)

### AUTH SECTION ###
login_manager = LoginManager()
login_manager.init_app(application)
login_manager.login_view = 'login'


@application.route('/')
def homepage():
    form = LoginForm(request.form)
    return render_template('login.html', form=form)

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


@application.route('/signup', methods = ['POST', 'GET'])
def signup(): 
    form = RegistrationForm(request.form)
    if request.method == 'POST' and form.validate() and User.query.filter_by(email=form.email.data).first() is None:
        username = form.username.data
        name = form.name.data
        email = form.email.data
        password = form.password.data.encode('utf-8')

        salt = bcrypt.gensalt()
        password_hash = bcrypt.hashpw(password, salt)
        password_hash = password_hash.decode('utf8')
        
        try:
            engine = sqlalchemy.create_engine(application.config['SQLALCHEMY_DATABASE_URI'])
            connection = engine.connect()   
            connection.execute("INSERT INTO users (username, first_name, email, password) VALUES (%s, %s, %s, %s);", (username, name, email, password_hash))
        finally:
            connection.close()
        
        return redirect("camp/1")
    print("Already a user")    
    return render_template('index.html', form=form)
       

@application.route('/camp/<int:camp_id>', methods = ['POST', 'GET'])
@login_required
def camp(camp_id):
    user_id =  current_user.get_user_id()

    try:
        engine = sqlalchemy.create_engine(application.config['SQLALCHEMY_DATABASE_URI'])
        connection = engine.connect()   
        print("connected")
    except:
        print ("I am unable to connect to the database, bro")

    if request.method == 'POST':
        type = request.form.get('update_type')    
        if type == 'post_text':
            try:
                reply_to_id = request.form.get('reply_to_id')
                post_text = request.form.get('post_text')
                connection.execute('INSERT INTO posts (camp_id, user_id, reply_to_id, post_text) VALUES (%s, %s, %s, %s);', (camp_id, user_id, reply_to_id, post_text))
            
            except Exception as e:
                # e holds description of the error
                error_text = "<p>The error:<br>" + str(e) + "</p>"
                hed = '<h1>Something is broken.</h1>'
                return hed + error_text 

        if type == 'post_vote':
            try:
                value = request.form.get('post_vote')
                post_id = request.form.get('post_id')
                connection.execute('INSERT INTO post_votes (camp_id, user_id, post_id, value) VALUES (%s, %s, %s, %s);', (camp_id, user_id, post_id, value))
            
            except Exception as e:
                # e holds description of the error
                error_text = "<p>The error:<br>" + str(e) + "</p>"
                hed = '<h1>Something is broken.</h1>'
                return hed + error_text 

    ##Are they in this camp?
    ResultProxy = connection.execute('SELECT * FROM camp_directory cd WHERE cd.camp_id = %s AND cd.user_id = %s;', (camp_id, user_id))
    df = DataFrame(ResultProxy.fetchall())

    #If yes, load page
    if len(df.index) > 0: 
        try:
            ResultProxy = connection.execute('SELECT p.post_id, p.camp_id, p.user_id, p.reply_to_id, p.creation_time, p.post_text, SUM(pv.value) AS opacity, u.id, u.username, u.first_name FROM posts p LEFT JOIN users u ON p.user_id = u.id LEFT JOIN post_votes pv ON p.camp_id = pv.camp_id AND p.post_id = pv.post_id WHERE p.camp_id = %s GROUP BY p.post_id;', (camp_id))
            df = DataFrame(ResultProxy.fetchall())
            
            if len(df.index) > 0:
                df.columns = ResultProxy.keys()

                #Correct Timezone
                to_zone = tz.tzlocal()

                df['creation_time'] = pd.to_datetime(df['creation_time'])
                df['creation_time'] = df['creation_time'].dt.tz_localize('UTC').dt.tz_convert(to_zone)
                df['creation_time'] = df['creation_time'].dt.strftime('%b %d, %Y')

                posts = df[df["reply_to_id"].isnull()]
                posts = posts.sort_values(by=['creation_time'], ascending=False)  
                
                replys = df[df["reply_to_id"].notnull()]
                replys = replys.sort_values(by=['creation_time'], ascending=True)  
            else :
                posts = df
                replys = df
            
            return render_template('camp.html',  posts=posts, replys=replys, camp_id=camp_id)
        except Exception as e:
            # e holds description of the error
            error_text = "<p>The error:<br>" + str(e) + "</p>"
            hed = '<h1>Something is broken.</h1>'
            return hed + error_text
        finally:
            connection.close()     
    else:
        flash('You are not a member of that camp')
        return redirect('/')
    
@application.teardown_request
def teardown_request(exception):
    if exception:
        db.session.rollback()
    db.session.remove()  

if __name__ == '__main__':
    application.run(port=8080, debug=True, use_reloader = True)