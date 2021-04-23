from flask import Flask, request, render_template, redirect
from flask import request
from string import Template
from flask_sqlalchemy import SQLAlchemy
import sqlalchemy as db
from pandas import DataFrame
import re
from flask_gtts import gtts

## A place to think --  and index for thoughts

app = Flask(__name__)
gtts(app)
try:
    engine = db.create_engine('mysql://admin:Graceless-Pursuit-Small2@meadow-1-instance-1.c1qv3kvmac8s.us-east-1.rds.amazonaws.com/meadow')
    connection = engine.connect()
    db = SQLAlchemy(app)
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

        df = df.sort_values(by=['creation_time'], ascending=False)   
        
        return render_template('camp.html',  posts=df, camp_id=camp_id)
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
            post_text = request.form.get('post_text')
            connection.execute('INSERT INTO posts (camp_id, user_id, post_text) VALUES (%s, %s, %s);', (camp_id, user_id, post_text))

            return redirect("camp/1")    
        
        except Exception as e:
            # e holds description of the error
            error_text = "<p>The error:<br>" + str(e) + "</p>"
            hed = '<h1>Something is broken.</h1>'
            return hed + error_text        

if __name__ == '__main__':
    app.run(debug=True, use_reloader=True)