from __future__ import print_function
from flask import Flask, render_template, request, redirect, url_for, session, abort, jsonify
from flask_wtf import CSRFProtect
from flask_talisman import Talisman
from flask_mysqldb import MySQL
import MySQLdb.cursors
import random
import string
import re
import requests
import bcrypt
from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token
import google.auth.transport.requests
import cachecontrol
import pathlib
import os
import csv
import clicksend_client
from clicksend_client import SmsMessage
from clicksend_client.rest import ApiException
from DatabaseConfig import Config
from extensions import ormmysql
from sqlalchemy import and_
from serializers import *
import pandas as pd

app = Flask(__name__)
csrf = CSRFProtect(app)
mysql = MySQL(app)
app.config.from_object(Config)
ormmysql.init_app(app)
talisman = Talisman(app) # For secure headers

from models import User, Words

# TODO replace MySQL with sqlachemy
app.secret_key = b''

app.config['MYSQL_HOST'] = '127.0.0.1'
app.config['MYSQL_USER'] = 'rocky'
app.config['MYSQL_PASSWORD'] = 'rocky12345678'
app.config['MYSQL_DB'] = 'engdictionary'

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

csp = {
    'default-src': [
        '\'self\'',
        'https://accounts.google.com',
        'https://code.jquery.com',
        'https://cdn.jsdelivr.net',
        'https://google.com',
        'https://www.google.com',
        'https://www.gstatic.com',
        'https://apis.google.com'
    ],
    'script-src': [
        '\'self\'',
        'https://www.google.com/',
        'https://accounts.google.com',
        'https://apis.google.com',
        'https://www.gstatic.com'
    ],
    'frame-src': [
        '\'self\'',
        'https://accounts.google.com',
        'https://www.gstatic.com',
        'https://www.google.com/'
    ]
}

# HTTP Strict Transport Security (HSTS) Header
hsts = {
    'max-age': 31536000,
    'includeSubDomains': True
}

# Enforce HTTPS and other headers
talisman.force_https = False
talisman.force_file_save = True
talisman.x_xss_protection = True
talisman.session_cookie_secure = True
talisman.session_cookie_samesite = 'Lax'
talisman.frame_options_allow_from = 'https://www.google.com'
 
# Add the headers to Talisman
talisman.content_security_policy = csp
talisman.strict_transport_security = hsts

GOOGLE_CLIENT_ID = ''

client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")
flow = Flow.from_client_secrets_file(client_secrets_file=client_secrets_file,
                                     scopes=["https://www.googleapis.com/auth/userinfo.profile",
                                             "https://www.googleapis.com/auth/userinfo.email", "openid"],
                                             redirect_uri="http://127.0.0.1:5000/callback")

@app.route('/callback')
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500) # state does not match!

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )
    name = id_info['name'].split()
    session['firstName'] = name[0]
    session['lastName'] = name[1]
    session['email'] = id_info['email']
    return redirect('/register') 

def verify_recaptcha(response):
    secret_key = '6Ldl3L8pAAAAAC5bfk13CXHUiJtvQzeGKHY7Bz8S'  # Your reCAPTCHA secret key

    data = {
        'secret': secret_key,
        'response': response
    }

    response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=data)
    result = response.json()
    return result['success']

configuration = clicksend_client.Configuration()
configuration.username = '' # personal email
configuration.password = ''

# create an instance of the API class
api_instance = clicksend_client.SMSApi(clicksend_client.ApiClient(configuration))

def create_verification_code():
    return ''.join(random.choices(string.digits, k=6))

Gen_verification_code = create_verification_code()

@app.route('/phone', methods=['POST', 'GET'])
def phone():
    phone_number = request.form.get('phone_number')  # Get the phone number from the form input

    sms_message = SmsMessage(source="flask",
                        body=f"Your verification code is: {Gen_verification_code}",
                        to=phone_number)

    sms_messages = clicksend_client.SmsMessageCollection(messages=[sms_message])

    try:
        # Send sms message(s)
        api_response = api_instance.sms_send_post(sms_messages)
        print(api_response)
    except ApiException as e:
        print("Exception when calling SMSApi->sms_send_post: %s\n" % e)
        return "Failed to send verification code"

    return render_template('phone.html')

@app.route('/verify_phone', methods=['POST'])
def verify_phone():
    # Here you can handle the verification process
    verification_code = request.form.get('verification_code')  # Get the verification code from the form input

    # Perform verification logic here

    # For example, you could compare the verification code entered by the user with the one generated
    if verification_code == Gen_verification_code:  
        # Verification successful
        return render_template('home.html')
    else:
        # Verification failed
        msg = "Verification failed"
        return render_template('phone.html')

@app.route('/home')
def home():
    if "username" in session:
        return render_template('home.html', username=session['username'])
    else:
        #return redirect(url_for('login'))
        return render_template('home.html')
    
@app.route('/register', methods=['POST', 'GET'])
def register():

    email = session.get('email', '')
    firstName = session.get('firstName', '')
    lastName = session.get('lastName', '')

    if request.method == 'POST':
        userID=3
        username = request.form['username']
        password = request.form['password']
        firstName = request.form['firstName']
        lastName = request.form['lastName']
        phone = request.form['phone']
        email = request.form['email']

        user = User.query.filter(User.username == username).first()


        if user:
            msg = 'Account already exists !'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address !'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only characters and numbers !'
        elif not username or not password or not email:
            msg = 'Please fill out the form !'
        else:
            # encrypt the plain password
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            
            new_user = User(username=username, plainPassword=password, encryptedPassword=hashed_password, firstName=firstName, lastName=lastName, phone=phone, email=email)
            ormmysql.session.add(new_user)
            ormmysql.session.commit()

            msg = 'You have successfully registered !'
            return render_template('home.html', msg=msg)
    return render_template('register.html', email=email, firstName=firstName, lastName=lastName)


@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        recaptcha_response = request.form['g-recaptcha-response']

        if not verify_recaptcha(recaptcha_response):
            return render_template('login.html', msg="reCAPTCHA verification failed. Please try again!")

        if len(username) > 24 or len(password) > 24:
            return render_template('login.html', msg='Try again!')

        user = User.query.filter(and_(User.username == username, User.password == password)).first()


        if user:
            session['username'] = username
            return redirect(url_for('home'))
        else:
            return render_template("login.html", msg="Invalid username or password. Try again!")
    else:
        return render_template('login.html')

@app.route('/google')
def google_login():
    authorization_url, state = flow.authorization_url()
    session['state'] = state
    return redirect(authorization_url)

@app.route('/export', methods=['GET', 'POST'])
def export():
    if request.method == 'POST':
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users')
        users = cursor.fetchall()

        fileName = "users.csv"
        file = open(fileName, "w", encoding="utf-8", newline="")
        writer = csv.writer(file)
        writer.writerow(["ID", "username", "password", "encrypted password", "first name"])

        for user in users:
            writer.writerow([user['ID'], user['username'], user['encryptedpassword'], user['firstname'], user['lastname'],
                             user['phone'], user['email'], user['isadmin'], user['dateadded'], user['logindate'],
                             user['APIKEY'], user['keyexpirydate']])
        
    return render_template('export.html')
    
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# API calls
@app.route('/words/<word>', methods=['GET'])
def get_word(word):
    words = Words.query.filter(Words.word == word).all()
    words_json = [dictionary(word) for word in words]
    return jsonify(words_json)

@app.route('/words/count', methods=['GET'])
def word_count():
    count = Words.query.count()
    return jsonify({
        'count of words' : count
    })

@app.route('/words/users', methods=['GET'])
def get_users():
    return

if __name__ == '__main__':
    app.run(debug=True, ssl_context=('cert.pem', 'key.pem'))