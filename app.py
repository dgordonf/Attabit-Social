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


@app.route('/search')
def search():
    q = request.args.get('q')
    page = request.args.get('page')
    try:
        query = "%" + q + "%"
        ResultProxy = connection.execute('SELECT ind.key_text, ind.article_title, ind.author_id, au.author, ind.article_id, ind.url, ind.article_date FROM search_index ind LEFT JOIN authors au ON ind.author_id = au.author_id WHERE ind.key_text LIKE %s OR ind.article_title LIKE %s OR au.author LIKE %s LIMIT 10000;', (query,query, query))
        df = DataFrame(ResultProxy.fetchall())
        df.columns = ResultProxy.keys()
        
        #Some algo to sort this correctly
        print(df)
        df.sort_values(by=['author_id'], ascending=False)   
            
        #Pagination
        if isinstance(page, str):
            page = int(page)
            page_end = page + 10
            if (page_end) > len(df.index):
                page_end = len(df.index)
        else: 
            page = int(0)
            page_end = int(10)
        
        df = df.iloc[page:page_end]

        #Get sentences for each Article ID
        ids = ', '.join(f'"{w}"' for w in df.article_id)
        ids = "(" + ids + ")"
        
        ResultProxy = connection.execute('SELECT * FROM sentences WHERE article_id IN %s AND text_color < 5 ORDER BY article_sentence_number;' % ids)
        sen_df = DataFrame(ResultProxy.fetchall())
        sen_df.columns = ResultProxy.keys()
        sen_df.text_color = sen_df.text_color.round()

        #Create sentence_link for next page
        datalist = []    
        for values in sen_df.sentence_text:
            datalist.append(re.sub(" ", "%20",str(values)))
                    
        sen_df['sentence_link'] = datalist
        
        return render_template('search.html',  q=q, data=df, sentences = sen_df)
    except Exception as e:
        # e holds description of the error
        error_text = "<p>The error:<br>" + str(e) + "</p>"
        hed = '<h1>Something is broken.</h1>'
        return hed + error_text

@app.route('/author')
def author():
    id = request.args.get('id')
    try:
        ResultProxy = connection.execute('SELECT ind.article_title, ind.author_id, au.author, ind.article_id, ind.url, ind.article_date FROM search_index ind LEFT JOIN authors au ON ind.author_id = au.author_id WHERE ind.author_id = %s LIMIT 10;', (id))
        df = DataFrame(ResultProxy.fetchall())
        df.columns = ResultProxy.keys()
        
        #Get sentences for each Article ID
        ids = ', '.join(f'"{w}"' for w in df.article_id)
        ids = "(" + ids + ")"
        
        ResultProxy = connection.execute('SELECT * FROM sentences WHERE article_id IN %s AND text_color < 4 ORDER BY article_sentence_number;' % ids)
        sen_df = DataFrame(ResultProxy.fetchall())
        sen_df.columns = ResultProxy.keys()
        sen_df.text_color = sen_df.text_color.round()

        #Create sentence_link
        datalist = []    
        for values in sen_df.sentence_text:
            datalist.append(re.sub(" ", "%20",str(values)))
                    
        sen_df['sentence_link'] = datalist
        
        return render_template('search.html', data=df, sentences = sen_df)
    except Exception as e:
        # e holds description of the error
        error_text = "<p>The error:<br>" + str(e) + "</p>"
        hed = '<h1>Something is broken.</h1>'
        return hed + error_text

if __name__ == '__main__':
    app.run(debug=True, use_reloader=True)