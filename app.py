from flask import Flask, request, render_template
from flask import request
from string import Template
from flask_sqlalchemy import SQLAlchemy
import sqlalchemy as db
from pandas import DataFrame
import re
from flask_gtts import gtts

## A place to think -- and index for thoughts

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


@app.route('/camp/<id>')
def camp(id):
    id = int(id)
    try:
        ResultProxy = connection.execute('SELECT * FROM posts WHERE camp_id = %s;', (id))
               
        df = DataFrame(ResultProxy.fetchall())
        df.columns = ResultProxy.keys()
        
        return render_template('camp.html',  data=df)
    except Exception as e:
        # e holds description of the error
        error_text = "<p>The error:<br>" + str(e) + "</p>"
        hed = '<h1>Something is broken.</h1>'
        return hed + error_text

if __name__ == '__main__':
    app.run(debug=True, use_reloader=True)