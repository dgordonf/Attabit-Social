from flask import Flask, request, render_template, redirect
from string import Template
from flask_sqlalchemy import SQLAlchemy
import sqlalchemy as db
from pandas import DataFrame
import re
from flask_gtts import gtts
from config import Config
from flask_login import LoginManager

## A place to think --  and index for thoughts

app = Flask(__name__)
gtts(app)
login = LoginManager(app)
app.config.from_object(Config)

try:
    engine = db.create_engine(app.config['DATABASE'])
    connection = engine.connect()
    print("connected")
except:
    print ("I am unable to connect to the database")


@app.route('/')
def homepage():
    return render_template('index.html')

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