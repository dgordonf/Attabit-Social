import os

class Config(object):
    SQLALCHEMY_DATABASE_URI = os.environ.get('SQLALCHEMY_DATABASE_URI') or 'mysql+pymysql://admin:Graceless-Pursuit-Small2@meadow-1-instance-1.c1qv3kvmac8s.us-east-1.rds.amazonaws.com/meadow'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    DATABASE = os.environ.get('DATABASE') or 'mysql://admin:Graceless-Pursuit-Small2@meadow-1-instance-1.c1qv3kvmac8s.us-east-1.rds.amazonaws.com/meadow'
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'hJxQNbgptG5VEXtdut4HL5yZJCkpXa5Qa'
    PRESERVE_CONTEXT_ON_EXCEPTION = True
    
S3_BUCKET = os.environ.get('S3_BUCKET') or "hideawayy"
S3_KEY = os.environ.get('S3_KEY') or "AKIA57G5CFWXILLMX2JA"
S3_SECRET = os.environ.get('S3_SECRET') or "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"
S3_LOCATION = 'http://{}.s3.amazonaws.com/media/'.format(S3_BUCKET)

SECRET_KEY  = os.urandom(32)