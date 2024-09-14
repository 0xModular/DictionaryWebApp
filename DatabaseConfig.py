class Track:
    SQLALCHEMY_TRACK_MODIFICATIONS = False

class Config(Track):
    SQLALCHEMY_DATABASE_URI = 'mysql://users:password@127.0.0.1/worddic' #mydict
