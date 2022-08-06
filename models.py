from flask import Flask
from wtforms import Form, BooleanField, StringField, PasswordField, validators
from flask_sqlalchemy import SQLAlchemy
from config import Config
import sqlalchemy
import os
import boto3, botocore
from config import Config, S3_KEY, S3_SECRET, S3_BUCKET
import pandas as pd
from pandas import DataFrame
from dateutil import tz
import re
from dateutil import tz

##Create SQL Engine Look at this: https://docs.sqlalchemy.org/en/14/core/pooling.html#pool-disconnects
engine = sqlalchemy.create_engine(Config.SQLALCHEMY_DATABASE_URI, pool_recycle=3600,)

class RegistrationForm(Form):
    email = StringField('Email', [validators.DataRequired(message='Email field is required'), validators.Email(message='Please enter a valid email address')])
    name = StringField('Your Name', [validators.DataRequired(message='Please enter an appearance name for your account'), validators.Length(min=1, max=25, message='Name must be between 1 and 25 characters')])
    username = StringField('Username', [validators.DataRequired(message='Please enter a username for your account'), validators.Length(min=1, max=25, message='Username must be between 1 and 25 characters'), validators.Regexp('^[A-Za-z0-9_]+$', message='Username must be alphanumeric with no spaces')])
    password = PasswordField('Password', [
        validators.DataRequired(message='This field cannot be blank'),
        validators.EqualTo('confirm', message='Passwords must match'),
        validators.Length(min=8, max=50, message='Password must be between 8 and 50 characters')
    ])
    confirm = PasswordField('Confirm Password')

class LoginForm(Form):
    email = StringField('Email Address', [validators.DataRequired(message='Email field is required'), validators.Email(message='Please enter a valid email address')])
    password = PasswordField('Password', [validators.DataRequired(message='Please enter your password')])    

class PasswordResetForm(Form):
    email = StringField('Email Address', [validators.DataRequired(message='Email field is required'), validators.Email(message='Please enter the email address you created your account with')])

class PasswordChangeForm(Form):
    password = PasswordField('Password', [
        validators.DataRequired(message='This field cannot be blank'),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Confirm Password')

application = Flask(__name__)
application.secret_key = application.config['SECRET_KEY']

application.config.from_object(Config)

#Enginge options here: https://flask-sqlalchemy.palletsprojects.com/en/2.x/api/
#db = SQLAlchemy(application, engine_options={"pool_recycle": 1800})




#Set up S3
s3 = boto3.client(
   "s3",
   aws_access_key_id = S3_KEY,
   aws_secret_access_key = S3_SECRET
)

def upload_file_to_s3(file, bucket_name, acl="public-read"):
    try:
        s3.upload_fileobj(
            file,
            bucket_name,
            file.filename,
            ExtraArgs={
                "ACL": acl,
                "ContentType": file.content_type
            }
        )
        

    except Exception as e:
        # This is a catch all exception, edit this part to fit your needs.
        print("Something Happened: ", e)
        return e

def time_ago(time=False):
    """
    Get a datetime object or a int() Epoch timestamp and return a
    pretty string like 'an hour ago', 'Yesterday', '3 months ago',
    'just now', etc
    """
    from datetime import datetime
    from dateutil import tz
    to_zone = tz.tzlocal()
    now = datetime.now(to_zone)
    if type(time) is int:
        diff = now - datetime.fromtimestamp(time)
    elif isinstance(time, datetime):
        diff = now - time
    elif not time:
        diff = 0
    second_diff = diff.seconds
    day_diff = diff.days

    if day_diff <= 0:
        if second_diff < 10:
            return "just now"
        if second_diff < 60:
            return str(second_diff) + "sec"
        if second_diff < 3600:
            return str(second_diff // 60) + "min"
        if second_diff < 86400:
            return str(second_diff // 3600) + "hr"
    if day_diff == 1:
        return "1d"
    if day_diff < 7:
        return str(day_diff) + "d"
    if day_diff < 31:
        return str(day_diff // 7) + "w"
    if day_diff < 365:
        return str(day_diff // 30) + "mo"
    return str(day_diff // 365) + "y"

def get_president_user():
    with engine.connect() as connection:
        ResultProxy = connection.execute('''SELECT  u.id, u.profile_photo, SUM(p1.value) AS user_score
                                                FROM users u
                                                LEFT JOIN posts p ON p.user_id = u.id
                                                LEFT JOIN post_votes p1 ON p1.post_id = p.post_id
                                                GROUP BY u.id
                                                ORDER BY user_score DESC
                                                LIMIT 1;''')
        df = DataFrame(ResultProxy.fetchall())
        df.columns = ResultProxy.keys()
        president_user_id = df['id'][0]
        return president_user_id

def is_president(list_of_user_ids):
    president_user_id = get_president_user()
    #retun list of true or false if users are president
    is_president = []
    for user_id in list_of_user_ids:
        if user_id == president_user_id:
            is_president.append(True)
        else:
            is_president.append(False)
    return is_president

def get_feed(user_id, last_post_id):

    #get max post_id if last_post_id is None
    if last_post_id is None:
        with engine.connect() as connection:
            result = connection.execute("SELECT MAX(post_id) FROM posts")
            last_post_id = result.fetchone()[0] + 1

    with engine.connect() as connection:
        ResultProxy = connection.execute("""SELECT p.post_id, p.user_id, u.first_name, u.handle, u.profile_photo, p.reply_to_id, p.creation_time, pv.post_score, p.post_text, b.user_score, COALESCE(c.current_user_vote, 0 ) as current_user_vote 
                                                FROM posts p
                                                LEFT JOIN users u ON u.id = p.user_id 
                                                LEFT JOIN 
                                                    (
                                                        SELECT f.user_id, f.following, f.follow_value
                                                            FROM follows f
                                                            WHERE f.user_id = %s AND f.follow_value = 1
                                                    ) f ON f.following = p.user_id 
                                                LEFT JOIN
                                                    (
                                                        SELECT pv.post_id, SUM(pv.value) AS post_score
                                                            FROM post_votes pv
                                                            GROUP BY pv.post_id
                                                    ) pv ON p.post_id = pv.post_id
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
                                                WHERE p.post_id < %s
                                                AND ((f.follow_value = 1 AND f.user_id = %s) OR p.user_id = %s) AND p.reply_to_id IS NULL AND p.is_deleted = 0
                                                ORDER BY p.post_id DESC
                                                LIMIT 10;""", (user_id, user_id, last_post_id, user_id, user_id))
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
                                                        WHERE p.post_id IN %s; """ % (ids, ids, ids, ids))
            
        df2 = DataFrame(ResultProxy.fetchall())
        df2.columns = ResultProxy.keys()
        
        df = pd.merge(df, df2, on=['post_id'], how='left')

        #check if user is president
        df['is_president'] = is_president(df['user_id'])
        
        return df

def format_feed(df):
    df['reply_count'] = round(df['reply_count'].fillna(0).astype(int), 0)
    df['down_votes'] = round(df['down_votes'].fillna(0).astype(int), 0)
    df['up_votes'] = round(df['up_votes'].fillna(0).astype(int), 0)

    df['reply_count'] = df['reply_count'].replace(0, " ")
    df['down_votes'] = df['down_votes'].replace(0, " ")
    df['up_votes'] = df['up_votes'].replace(0, " ")

    to_zone = tz.tzlocal()

    df['creation_time'] = pd.to_datetime(df['creation_time'])
    
    #Cover to time ago for each post
    df['time_ago'] = ""
    for i in range(len(df.index)):
        df['time_ago'][i] = time_ago(df['creation_time'][i].tz_localize('UTC').tz_convert(to_zone))
    
    df['creation_time'] = df['creation_time'].dt.tz_localize('UTC').dt.tz_convert(to_zone)
    df['creation_time'] = df['creation_time'].dt.strftime('%m-%d-%Y')

    #Correct Update Post Score (All posts begin at a score of 0) and round
    df['post_score'] = df['post_score'].fillna(0).astype(int)
    df['user_score'] = df['user_score'].fillna(0).astype(int)

    #Create User Score bar chart
    df['user_score'] = df['user_score']/10
    df['user_score_bars'] = ((df['user_score'] % 1) * 10).astype(int)
    df['user_score'] = df['user_score'].astype(int)
    
    #Check if post is greater than 400 characters
    df['post_length'] = 0
    df['post_length_flag'] = 0
    for i in range(len(df.index)):
        df['post_length'][i] = len(df['post_text'][i])
        if len(df['post_text'][i]) > 400:
            df['post_length_flag'][i] = 1

    #Cut down any text where post_length_flag is 1
    for i in range(len(df.index)):
        if df['post_length_flag'][i] == 1:
            char_count = 400
            while char_count < 450 and df['post_length'][i] > char_count:
                if df['post_text'][i][char_count] == ' ':
                    break
                char_count += 1
            df['post_text'][i] = df['post_text'][i][:char_count] + "..."

    return df

##Get notifications for this user
def get_notifications(user_id):
    with engine.connect() as connection:
            ResultProxy = connection.execute('''SELECT n.notification_id, n.creation_time, u.profile_photo, u.handle, n.event_type_id, n.reference_post_id, n.seen
                                                FROM notifications n
                                                LEFT JOIN users u ON u.id = n.triggered_by_user_id
                                                WHERE n.user_id = %s
                                                ORDER BY n.creation_time DESC
                                                LIMIT 25;
                                                ''', (user_id ))
            notifications = DataFrame(ResultProxy.fetchall())


    ## format the notifications
    if len(notifications.index) > 0:
        notifications.columns = ResultProxy.keys()

        #fill reference_post_id with 0s if NA
        notifications['reference_post_id'] = notifications['reference_post_id'].fillna(0)
        notifications['reference_post_id'] = notifications['reference_post_id'].astype(int)
        notifications['reference_post_id'] = notifications['reference_post_id'].astype(int)

        notifications['event_type_id'] = notifications['event_type_id'].astype(int)
        notifications['profile_photo'] = notifications['profile_photo'].fillna("")
        
        notifications['text'] = ''
        notifications['redirect'] = ''

        #Correct Timezone
        to_zone = tz.tzlocal()

        notifications['time_ago'] = ''
        #Create text for each notification
        for i in range(len(notifications.index)):
            if (notifications['event_type_id'][i] == 1):
                notifications['text'][i] = "now follows you"    
                notifications['redirect'][i] = "/@" + str(notifications['handle'][i])       

            if (notifications['event_type_id'][i] == 2):
                notifications['text'][i] = "replied to your post"
                notifications['reference_post_id'][i] = str(round(notifications['reference_post_id'][i], 0))
                notifications['redirect'][i] = "/post/" + str(notifications['reference_post_id'][i])

            if (notifications['event_type_id'][i] == 3):
                notifications['text'][i] = "mentioned you"
                notifications['reference_post_id'][i] = str(round(notifications['reference_post_id'][i], 0))
                notifications['redirect'][i] = "/post/" + str(notifications['reference_post_id'][i])    

            notifications['time_ago'][i] = time_ago(notifications['creation_time'][i].tz_localize('UTC').tz_convert(to_zone))
    
    #Sum count of unseen notifications
    unseen_count = 0
    for i in range(len(notifications.index)):
        if notifications['seen'][i] == 0:
            unseen_count += 1
    
    return notifications, unseen_count

def notify_mentionted_users(post_text, current_user):
    if '@' in post_text:
        #Get the list of users that are mentioned
        users = re.findall(r'@([a-zA-Z0-9_]+)', post_text)
        for user in users:
                #Get user_id of follow account
            with engine.connect() as connection:
                ResultProxy = connection.execute('''SELECT u.id 
                                                    FROM users u 
                                                    WHERE u.handle = %s; ''', (user))

            df = DataFrame(ResultProxy.fetchall())
            if len(df) > 0:
                df.columns = ResultProxy.keys()

                mentioned_user_id = df['id'][0]
                print(mentioned_user_id)


                #Get the post_id of the post
                with engine.connect() as connection:
                    ResultProxy = connection.execute('''SELECT p.post_id
                                                        FROM posts p 
                                                        WHERE p.user_id = %s 
                                                        ORDER BY p.post_id DESC
                                                        LIMIT 1; ''', (current_user))
                    df = DataFrame(ResultProxy.fetchall())
                    df.columns = ResultProxy.keys()

                post_id = df['post_id'][0]

                #Notify the user that someone mentioned them
                event_type_id = 3
                with engine.connect() as connection:
                    connection.execute('INSERT INTO notifications (user_id, triggered_by_user_id, event_type_id, reference_post_id) VALUES (%s, %s, %s, %s);',  (mentioned_user_id, current_user, event_type_id, post_id))
    
                                   
            