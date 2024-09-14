from extensions import ormmysql

#Define Word model for ORM. Each class represent a table in the database.
class Words(ormmysql.Model):
    id = ormmysql.Column(ormmysql.Integer, primary_key=True)
    word = ormmysql.Column(ormmysql.Text)
    meaning = ormmysql.Column(ormmysql.Text)
    phonetics = ormmysql.Column(ormmysql.String(100))
    soundfile = ormmysql.Column(ormmysql.String(100))
    dateadded = ormmysql.Column(ormmysql.String(100))

class User(ormmysql.Model):
    id = ormmysql.Column(ormmysql.Integer, primary_key=True)
    username = ormmysql.Column(ormmysql.String(100))
    password = ormmysql.Column(ormmysql.String(100))
    encryptedpassword = ormmysql.Column(ormmysql.String(100))
    firstName = ormmysql.Column(ormmysql.String(100))
    lastName = ormmysql.Column(ormmysql.String(100))
    phone = ormmysql.Column(ormmysql.String(100))
    email = ormmysql.Column(ormmysql.String(100))
    isAdmin = ormmysql.Column(ormmysql.Boolean)
    dateAdded = ormmysql.Column(ormmysql.String(100))
    loginDate = ormmysql.Column(ormmysql.String(100))
    APIKEY = ormmysql.Column(ormmysql.String(100))
    keyExpiryDate = ormmysql.Column(ormmysql.String(100))