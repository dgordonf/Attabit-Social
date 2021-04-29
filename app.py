from flask import Flask, request, render_template, redirect, url_for, flash
from string import Template
from flask_sqlalchemy import SQLAlchemy
import sqlalchemy
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
from flask_login import login_user, logout_user, login_required

# Not the entire world, just your best friends. 
app = Flask(__name__)
app.secret_key = app.config['SECRET_KEY']
db = SQLAlchemy(app)

gtts(app)
#login = LoginManager(app)
app.config.from_object(Config)

try:
    engine = sqlalchemy.create_engine(app.config['DATABASE'])
    connection = engine.connect()
    print("connected")
except:
    print ("I am unable to connect to the database")


@app.route('/')
def homepage():
    form = LoginForm(request.form)
    return render_template('login.html', form=form)

@app.route('/login', methods = ['POST'])
def login():
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        user = User.query.get(form.email.data)
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                user.authenticated = True
                db.session.add(user)
                db.session.commit()
                login_user(user, remember=True)
                return redirect(url_for("camp/1"))
    return redirect("/")


@app.route('/signup', methods = ['POST'])
def signup(): 
    form = RegistrationForm(request.form)
    if request.method == 'POST' and form.validate():
        username = form.username.data
        name = form.name.data
        email = form.email.data
        password_hash = sha256_crypt.encrypt(form.password.data)
        connection.execute("INSERT INTO users (username, first_name, email, password_hash) VALUES (%s, %s, %s, %s);", (username, name, email, password_hash))
        return redirect("camp/1")
    return render_template('index.html', form=form)
    

@app.route('/camp/<int:camp_id>', methods = ['GET'])
def camp(camp_id):
    try:
        ResultProxy = connection.execute('SELECT * FROM posts WHERE camp_id = %s;', (camp_id))
               
        df = DataFrame(ResultProxy.fetchall())
        df.columns = ResultProxy.keys()

        posts = df[df["reply_to_id"].isnull()]
        posts = posts.sort_values(by=['creation_time'], ascending=False)  

        replys = df[df["reply_to_id"].notnull()]
        replys = replys.sort_values(by=['creation_time'], ascending=True)  

        return render_template('camp.html',  posts=posts, replys=replys, camp_id=camp_id)
    except Exception as e:
        # e holds description of the error
        error_text = "<p>The error:<br>" + str(e) + "</p>"
        hed = '<h1>Something is broken.</h1>'
        return hed + error_text

@app.route('/posts', methods = ['POST'])
def posts():
    if request.method == 'POST':
        try:
            camp_id = request.form.get('camp_id')
            user_id = request.form.get('user_id')
            reply_to_id = request.form.get('reply_to_id')
            post_text = request.form.get('post_text')
            connection.execute('INSERT INTO posts (camp_id, user_id, reply_to_id, post_text) VALUES (%s, %s, %s, %s);', (camp_id, user_id, reply_to_id, post_text))

            return redirect("camp/1")    
        
        except Exception as e:
            # e holds description of the error
            error_text = "<p>The error:<br>" + str(e) + "</p>"
            hed = '<h1>Something is broken.</h1>'
            return hed + error_text        

if __name__ == '__main__':
    app.run(debug=True, use_reloader=True)