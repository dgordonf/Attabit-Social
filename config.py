import os

class Config(object):
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'mysql://admin:Graceless-Pursuit-Small2@meadow-1-instance-1.c1qv3kvmac8s.us-east-1.rds.amazonaws.com/meadow'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    DATABASE = os.environ.get('DATABASE') or 'mysql://admin:Graceless-Pursuit-Small2@meadow-1-instance-1.c1qv3kvmac8s.us-east-1.rds.amazonaws.com/meadow'
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'hJxQNbgptG5VEXtdut4HL5yZJCkpXa5Qa'
       