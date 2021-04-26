import os

class Config(object):
    DATABASE = os.environ.get('DATABASE') or 'mysql://admin:Graceless-Pursuit-Small2@meadow-1-instance-1.c1qv3kvmac8s.us-east-1.rds.amazonaws.com/meadow'