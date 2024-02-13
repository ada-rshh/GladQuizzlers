import os
import shutil
import uuid

from flask_mail import Mail, Message
# from flask_wtf import FlaskForm
from flask import Flask, session, render_template, request, Response, redirect, send_from_directory
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash
from flask import Flask, render_template, request, redirect, url_for, session
from flask import session
from flask import Flask, render_template, request, redirect, url_for, flash, abort, g, send_file
from pymongo import MongoClient
import pymongo
from Forms import FeedbackForm, ReportForm, ComposeNewsletterForm, CommentForm, EditForm, Report_c_Form, CourseForm, QuestionForm, ResultForm
from filters import format_object_id
from bson.objectid import ObjectId
import bson
import random
import string
import smtplib
from email.mime.text import MIMEText
from flask import jsonify
from gridfs import GridFS
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from flask import make_response
import atexit
import hashlib
import stripe
from dotenv import load_dotenv
from flask_talisman import Talisman

from flask_wtf import CSRFProtect
import secrets

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from functools import wraps
from flask_login import LoginManager, login_user, current_user, UserMixin

from email_validator import validate_email, EmailNotValidError
import re
import bcrypt as bcrypt

from bson import ObjectId
from datetime import datetime

import io
import tempfile

import logging

import requests

import time

import logging
from requests_html import HTMLSession

import pytz

# load env #
load_dotenv()

#########################       start of application        ######################
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
app.config['SITE_KEY'] = os.environ['SITE_KEY']
app.config['RE_SECRET_KEY'] = os.environ['RE_SECRET_KEY']
app.config['VERIFY_URL'] = os.environ['VERIFY_URL']
app.config['MAIL_SERVER'] = os.environ['MAIL_SERVER']
app.config['MAIL_PORT'] = int(os.environ['MAIL_PORT'])
app.config['MAIL_USE_TLS'] = os.environ['MAIL_USE_TLS'].lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ['MAIL_USERNAME']
app.config['MAIL_PASSWORD'] = os.environ['MAIL_PASSWORD']
app.config['MAIL_DEFAULT_SENDER'] = os.environ['MAIL_DEFAULT_SENDER']
app.config['SESSION_COOKIE_SAMESITE'] = 'None'
app.config['SESSION_COOKIE_SECURE'] = True
# app.config['MONGO_URI'] = os.environ['DATABASE_URL']
app.config['MONGO_URI'] = "mongodb+srv://EnvAware:envaware777#@atlascluster.aej9sme.mongodb.net/?retryWrites=true&w=majority"
app.jinja_env.filters['format_object_id'] = format_object_id
csrf = CSRFProtect(app)

login_manager = LoginManager(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["1000 per day", "50 per minute"],
    storage_uri="memory://",
)

mail = Mail(app)
client = MongoClient(app.config['MONGO_URI'])

# main users #
db = client["Glad"]
users_collection = db["users"]
pfp_collection = db['pfp']
teacher_collection = db['teachers']

# admin side #
report_collection = db["reports"]
feedback_collection = db["feedbacks"]
admin_collection = db["admin"]

# donation #
checkout_collection = db['checkout']
comment_collection = db['comment']

# newsletter content #
newsletter_collection = db["newsletter"]

# collection for quizzes
quiz_collection = db["quiz"]  


# jun wens configs #
# This is your test secret API key.
database_url = os.environ['DATABASE_URL']
stripe.api_key = os.environ['API_KEY']



# csp_policy = {
#     'default-src': "'self'",
#     'script-src': "'self' 'unsafe-inline' js.stripe.com cdn.jsdelivr.net unpkg.com code.jquery.com https://kit.fontawesome.com/your-real-fontawesome-kit.js",
#     'style-src': "'self' 'unsafe-inline' https://cdnjs.cloudflare.com/ https://fonts.googleapis.com/ https://unpkg.com/",
#     'connect-src': "'self' https://unpkg.com/",
#     'img-src': "'self' https://unpkg.com/",
#     'font-src': "'self' https://cdnjs.cloudflare.com/ https://fonts.gstatic.com/ https://unpkg.com/",
#     'frame-src': "'self' https://js.stripe.com/ https://www.google.com/",
# }


# talisman = Talisman(app, content_security_policy=csp_policy)



same_site_cookies = [
    ('SID', '.google.com'),
    ('Secure-1PSID', '.google.com'),
    ('HSID', '.google.com'),
    ('SSID', '.google.com'),
    ('APISID', '.google.com'),
    ('SAPISID', '.google.com'),
    ('Secure-1PAPISID', '.google.com'),
    ('OGPC', '.google.com'),
    ('S', '.google.com'),
    ('1P_JAR', '.google.com'),
    ('Secure-1PSIDTS', '.google.com'),
    ('SIDCC', '.google.com'),
    ('Secure-1PSIDCC', '.google.com'),
]

for cookie_name, domain in same_site_cookies:
    app.config['SESSION_COOKIE_SAMESITE'] = 'None'
    app.config['SESSION_COOKIE_SECURE'] = True


fs = GridFS(db)


try:
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(e)

#logging stuff
# Create a logger object
logger = logging.getLogger()

# Set logging level to DEBUG
logger.setLevel(logging.DEBUG)

s = HTMLSession()
today = datetime.today()
date_save = today.strftime("%Y-%m-%d")
logging.basicConfig(filename="logger.log", level=logging.DEBUG,
                        format="%(asctime)s - %(message)s",datefmt="%d-%b-%y %H:%M:%S")
logging.debug("This is a debug message")
singapore_timezone = pytz.timezone('Asia/Singapore')
timestamp = datetime.now(singapore_timezone).strftime('%d-%b-%Y %H:%M:%S')



###################       Security implementations       ###########################
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return redirect("login")

        return f(*args, **kwargs)

    return decorated

class Admin(UserMixin):
    def __init__(self, admin_data):
        self.admin_data = admin_data
        self.is_admin = True  # Set the is_admin property for admin users

    def get_id(self):
        return str(self.admin_data['_id'])



@login_manager.user_loader
def load_admin(user_id):
    # Implement a function to load the admin from your database and return the admin object
    admin = admin_collection.find_one({"_id": ObjectId(user_id)})
    if admin:
        return Admin(admin)  # Instantiate an Admin object with the admin data
    return None


def admin_login_required(func):
    """
    Custom decorator to protect routes that require admin login.
    If the user is not authenticated or is not an admin, they will be redirected to the admin login page.
    """
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('admin_login'))
        if not current_user.is_admin:
            return redirect(url_for('homeb4login'))  # Redirect to homeb4login page
        next_url = request.args.get('next')
        if next_url:
            redirect_url = url_for('admin_dashboard', next=next_url)
        else:
            redirect_url = url_for('admin_dashboard')
        return func(*args, **kwargs)
    return decorated_view


###################       unlogged user       ######################
@app.route('/', methods=['GET'])
def homeb4login():
    return render_template('newhomeb4login.html', site_key=app.config['SITE_KEY'])

@app.route('/contactb4login')
def contactb4login():
    return render_template(('contact.html'))

@app.route('/index2')
def index2():
    return render_template('newhomeb4login.html')


@app.route('/contact')
@login_required
def contact():
    return render_template(('contact.html'))

@app.route('/form_login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        csrf_token = request.form.get("csrf_token")
        recaptcha_token = request.form.get("g-recaptcha-response")  # Get reCAPTCHA token
        print("Received CSRF Token:", csrf_token)
        print("Received reCAPTCHA Token:", recaptcha_token)

        # Verify reCAPTCHA token
        verify_response = requests.post(url=app.config['VERIFY_URL'], data={
            "secret": app.config['RE_SECRET_KEY'],
            "response": recaptcha_token
        }).json()

        if verify_response["success"]:
            # reCAPTCHA verification successful
            print("reCAPTCHA verification successful")

            # Retrieve the user document based on the username
            user = users_collection.find_one({"username": username})
            

            if user:
                email = user.get("email")
                print("Received username:", username)
                print("Received email:", email)

                # Hash the user-provided password and compare it with the stored hashed password
                hashed_password = user.get("password")
                if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
                    email = user.get("email")
                    # Generate OTP and store it in the session
                    otp = ''.join(random.choices(string.digits, k=6))

                    # Send the OTP to the user's email
                    send_otp_email(email, otp)

                    session["username"] = username  # Store username in the session for future use
                    session["otp"] = otp  # Store the OTP in the session for verification
                    session["_csrf_token"] = csrf_token  # Store the CSRF token in the session

                    return redirect("verify_otp")
                else:
                    return render_template("newhomeb4login.html", error="Invalid password")
            else:
                return render_template("newhomeb4login.html", error="Invalid username")
        else:
            # reCAPTCHA verification failed
            print("reCAPTCHA verification failed")
            return render_template("newhomeb4login.html", error="reCAPTCHA verification failed")

        # Generate a new CSRF token and store it in the session
    print("Before CSRF Token generation")
    csrf_token = secrets.token_hex(32)
    session["_csrf_token"] = csrf_token
    print("After CSRF Token generation")
    return render_template("newhomeb4login.html", site_key=app.config['SITE_KEY'])



@app.route('/teacher_login', methods=["GET", "POST"])
def teacher_login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        csrf_token = request.form.get("csrf_token")
        recaptcha_token = request.form.get("g-recaptcha-response")  # Get reCAPTCHA token
        print("Received CSRF Token:", csrf_token)
        print("Received reCAPTCHA Token:", recaptcha_token)

        # Verify reCAPTCHA token
        verify_response = requests.post(url=app.config['VERIFY_URL'], data={
            "secret": app.config['RE_SECRET_KEY'],
            "response": recaptcha_token
        }).json()

        if verify_response["success"]:
            # reCAPTCHA verification successful
            print("reCAPTCHA verification successful")

            # Your existing authentication logic here...
            # Retrieve the user document based on the username
            teacher = teacher_collection.find_one({"username": username})

            if teacher:
                email = teacher.get("email")
                print("Received username:", username)
                print("Received email:", email)

                # Hash the user-provided password and compare it with the stored hashed password
                hashed_password = teacher.get("password")
                if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
                    email = teacher.get("email")
                    # Generate OTP and store it in the session
                    otp = ''.join(random.choices(string.digits, k=6))

                    # Send the OTP to the user's email
                    send_otp_email(email, otp)

                    session["username"] = username  # Store username in the session for future use
                    session["otp"] = otp  # Store the OTP in the session for verification
                    session["_csrf_token"] = csrf_token  # Store the CSRF token in the session

                    return redirect("teacher_verify_otp")
                else:
                    return render_template("newhomeb4login.html", error="Invalid password")
            else:
                return render_template("newhomeb4login.html", error="Invalid username")
        else:
            # reCAPTCHA verification failed
            print("reCAPTCHA verification failed")
            return render_template("newhomeb4login.html", error="reCAPTCHA verification failed")

        # Generate a new CSRF token and store it in the session
    print("Before CSRF Token generation")
    csrf_token = secrets.token_hex(32)
    session["_csrf_token"] = csrf_token
    print("After CSRF Token generation")
    return render_template("teacher/teacher_login.html", site_key=app.config['SITE_KEY'])



def send_otp_email(recipient_email, otp):
    subject = 'OTP for Account Verification'
    body = f'Your OTP for account verification is: {otp}'

    msg = Message(subject=subject, recipients=[recipient_email], body=body)
    mail.send(msg)


@app.route('/otp_verification')
def verification():
    stored_otp = session.get("otp")
    if not stored_otp:
        return redirect("/")  # Redirect to login if no OTP is stored in the session
    return render_template("otp_verification.html")


@app.route('/verify_otp', methods=["GET", "POST"])  # Updated route to handle both GET and POST
def verify_otp():
    if request.method == "POST":
        entered_otp = request.form.get("otp")
        stored_otp = session.get("otp")
        username = session.get("username")

        if entered_otp == stored_otp:
            session.pop("otp", None)
            return redirect("/home")

        else:
            return render_template("otp_verification.html", error="Invalid OTP", username=username, otp=stored_otp)

    else:  # This part handles the GET request
        stored_otp = session.get("otp")
        if not stored_otp:
            return redirect("/")  # Redirect to login if no OTP is stored in the session
        return render_template("otp_verification.html")
    


@app.route('/teacher_verify_otp', methods=["GET", "POST"])  # Updated route to handle both GET and POST
def teacher_verify_otp():
    if request.method == "POST":
        entered_otp = request.form.get("otp")
        stored_otp = session.get("otp")
        username = session.get("username")

        if entered_otp == stored_otp:
            session.pop("otp", None)
            return redirect("/teacher_dashboard")

        else:
            return render_template("teacher/teacher_otp_verification.html", error="Invalid OTP", username=username, otp=stored_otp)

    else:  # This part handles the GET request
        stored_otp = session.get("otp")
        if not stored_otp:
            return redirect("/")  # Redirect to login if no OTP is stored in the session
        return render_template("teacher/teacher_otp_verification.html")



def validate_csrf_token(csrf_token):
    if csrf_token != session.get("_csrf_token"):
        abort(403)  # Invalid CSRF token, abort the request

@app.route('/forgot')
def forgotpw():
    return render_template("forgot.html")



# Updated Python Function
@app.route('/form_forgot', methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        email_to_check = request.form.get('email')

        # Perform the query to check if the email exists in the database
        user_exists = users_collection.find_one({'email': email_to_check})

        if user_exists:
            otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])

            # Save the OTP and email in the session
            session["otp"] = otp
            session["email_to_check"] = email_to_check  # Store the email to check during OTP verification

            # Send the OTP to the email address
            send_otp_email(email_to_check, otp)
            return render_template("otp_verification_forgot.html", info="OTP has been sent to your email.")

        else:
            # Email does not exist in the database
            return render_template("forgot.html", info="Invalid Email")

    return render_template("forgot.html")




@app.route('/verify_forgot_otp', methods=["GET", "POST"])
def verify_forgot_otp():
    if request.method == "POST":
        entered_otp = request.form.get("otp")
        stored_otp = session.get("otp")
        email_to_check = session.get("email_to_check")

        if entered_otp == stored_otp:
            # Clear the OTP and email_to_check from the session after successful verification
            session.pop("otp", None)
            session.pop("email_to_check", None)
            return render_template("reset_password.html", email=email_to_check)

        else:
            return render_template("otp_verification_forgot.html", error="Invalid OTP")

    else:  # This part handles the GET request
        stored_otp = session.get("otp")
        if not stored_otp:
            return redirect("/")  # Redirect to login if no OTP is stored in the session
        return render_template("otp_verification_forgot.html")



@app.route('/reset_password', methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        confirm_pw = request.form["confirm"]

        if password != confirm_pw:
            return render_template("reset_password.html", email=email, error="Passwords do not match!")
        elif len(password) <= 7:
            return render_template("reset_password.html", error="Password too short!")
        elif len(password) >= 15:
            return render_template("reset_password.html", error="Password too long")

        # Hash and salt the new password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Update the user's password in the database using the email
        user = users_collection.find_one({'email': email})
        if user:
            users_collection.update_one({"email": email}, {"$set": {"password": hashed_password}})
            # Optionally, you can clear the session after password reset to avoid using the same OTP again
            session.clear()
            return redirect("/")
        else:
            # Email does not exist in the database, handle this accordingly
            return render_template("reset_password.html", email=email, error="Invalid Email")

    return render_template("reset_password.html")



@app.route('/login')
def loginpage():
    return render_template('newlogin.html', site_key=app.config['SITE_KEY'])



@app.route('/signup')
def signuppage():
    return render_template('newsignup.html', site_key=app.config['SITE_KEY'])



@app.route('/form_signup', methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        confirm_pw = request.form["confirm"]
        signup_email = request.form["email"]
        subscribe = request.form.get("subscribe")
        csrf_token = request.form.get("csrf_token")
        recaptcha_token = request.form.get("g-recaptcha-response")  # Get reCAPTCHA token
        print("Received CSRF Token:", csrf_token)
        print("Received reCAPTCHA Token:", recaptcha_token)

        # Verify reCAPTCHA token
        verify_response = requests.post(url=app.config['VERIFY_URL'], data={
            "secret": app.config['RE_SECRET_KEY'],
            "response": recaptcha_token
        }).json()

        if verify_response["success"]:
            # reCAPTCHA verification successful
            print("reCAPTCHA verification successful")

            # Validate the email
            try:
                valid_email = validate_email(signup_email)
                signup_email = valid_email.email
            except EmailNotValidError:
                return render_template("newsignup.html", error="Invalid email format", password=password, confirm=confirm_pw)

            # Check email length
            if len(signup_email) > 50:  # Adjust the maximum length as needed
                return render_template("newsignup.html", error="Email address is too long", username=username)

            password_uppercase_regex = re.compile(r'[A-Z]')
            password_lowercase_regex = re.compile(r'[a-z]')
            password_special_regex = re.compile(r'[!@#$%^&*(),.?":{}|<>]')
            # Check email length
            if len(signup_email) > 50:  # Adjust the maximum length as needed
                return render_template("newsignup.html", error="Email address is too long", username=username)

            existing_user = users_collection.find_one({"$or": [{"username": username}, {"email": signup_email}]})
            
            if existing_user:
                return render_template("newsignup.html", error="Username or email already exists", password=password, confirm=confirm_pw)
            elif not password_uppercase_regex.search(password):
                return render_template("newsignup.html", error="Password must contain at least one uppercase letter", username=username, email=signup_email)

            # Check if the password contains at least one lowercase letter
            elif not password_lowercase_regex.search(password):
                return render_template("newsignup.html", error="Password must contain at least one lowercase letter", username=username, email=signup_email)

            # Check if the password contains at least one special character
            elif not password_special_regex.search(password):
                return render_template("newsignup.html", error="Password must contain at least one special character", username=username, email=signup_email)       
            elif re.search(r'[!@#$%^&*(),.?":{}|<>]', username):
                return render_template("newsignup.html", error="Username cannot contain special characters", email=signup_email)
            elif len(password) <= 7:
                return render_template("newsignup.html", error="Password too short!", username=username, email=signup_email)
            elif len(password) >= 15:
                return render_template("newsignup.html", error="Password too long", username=username, email=signup_email)
            elif password != confirm_pw:
                return render_template("newsignup.html", error="Passwords do not match!")
            
            else:
                signup_email = request.form["email"]
                print("Received username:", username)
                print("Received email:", signup_email)
                
                # Hash and salt the password using bcrypt
                hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

                user = {"username": username, "password": hashed_password, "email": signup_email, "subscribed_to_newsletter": bool(subscribe), "createdOn": datetime.utcnow(), "modifiedOn": datetime.utcnow()}
                users_collection.insert_one(user)
                otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])

                # Save the OTP in the session
                session["otp"] = otp

                # Send the OTP to the email address
                send_otp_email(signup_email, otp)

                return render_template("otp_verification.html", info="OTP has been sent to your email.")
        else:
            # reCAPTCHA verification failed
            print("reCAPTCHA verification failed")
            return render_template("newsignup.html", error="reCAPTCHA verification failed")

    return render_template("newsignup.html")



@app.route('/teacher_signup', methods=["GET", "POST"])
def teacher_signup():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        confirm_pw = request.form["confirm"]
        signup_email = request.form["email"]
        csrf_token = request.form.get("csrf_token")
        recaptcha_token = request.form.get("g-recaptcha-response")  # Get reCAPTCHA token
        print("Received CSRF Token:", csrf_token)
        print("Received reCAPTCHA Token:", recaptcha_token)

        # Verify reCAPTCHA token
        verify_response = requests.post(url=app.config['VERIFY_URL'], data={
            "secret": app.config['RE_SECRET_KEY'],
            "response": recaptcha_token
        }).json()

        if verify_response["success"]:
            # reCAPTCHA verification successful
            print("reCAPTCHA verification successful")

        # Validate the email
        try:
            valid_email = validate_email(signup_email)
            signup_email = valid_email.email
        except EmailNotValidError:
            return render_template("teacher/teacher_signup.html", error="Invalid email format", password=password, confirm=confirm_pw)

        # Check email length
        if len(signup_email) > 50:  # Adjust the maximum length as needed
            return render_template("teacher/teacher_signup.html", error="Email address is too long", username=username)

        existing_teacher = teacher_collection.find_one({"$or": [{"username": username}, {"email": signup_email}]})

        if existing_teacher:
            return render_template("teacher/teacher_signup.html", error="Username or email already exists", password=password, confirm=confirm_pw)
        elif re.search(r'[!@#$%^&*(),.?":{}|<>]', username):
            return render_template("teacher/teacher_signup.html", error="Username cannot contain special characters", email=signup_email)
        elif len(password) <= 7:
            return render_template("teacher/teacher_signup.html", error="Password too short!", username=username, email=signup_email)
        elif len(password) >= 15:
            return render_template("teacher/teacher_signup.html", error="Password too long", username=username, email=signup_email)
        elif password != confirm_pw:
            return render_template("teacher/teacher_signup.html", error="Passwords do not match!")

        else:
            signup_email = request.form["email"]
            print("Received username:", username)
            print("Received email:", signup_email)
            # Hash and salt the password using bcrypt
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            teacher = {"username": username, "password": hashed_password, "email": signup_email, "createdOn": datetime.utcnow(), "modifiedOn": datetime.utcnow()}
            teacher_collection.insert_one(teacher)
            otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])

            # Save the OTP in the session
            session["otp"] = otp

            # Send the OTP to the email address
            send_otp_email(signup_email, otp)

            return render_template("otp_verification.html", info="OTP has been sent to your email.")
    
    return render_template("teacher/teacher_signup.html", site_key=app.config['SITE_KEY'])



@app.route("/home")
@login_required
def home():
    if "username" in session:
        return render_template("newhome.html", info=session["username"])  # Updated to pass info instead of username
    # else:
    #     return redirect("/")



@app.route("/editprofile", methods=["GET"])
@login_required
def editprofile():
    profile_picture_url = session.get('profile_picture_url', None)
    # Render the editpfp.html template
    return render_template('editprofile.html', profile_picture_url=profile_picture_url)



@app.route('/edit_profile', methods=["GET", "POST"])
@login_required
def edit_profile():
    global existing_user
    if request.method == "POST":
        old_username = request.form["old_username"]
        new_username = request.form["new_username"]

        new_password = request.form["new_password"]
        confirm_password = request.form["confirm"]

        user = users_collection.find_one({"username": old_username})
        if user:
            # Check if a new username is provided and if it already exists
            if new_username:
                existing_user = users_collection.find_one({"username": new_username})
                if existing_user and new_username == existing_user["username"]:
                    return render_template("editprofile.html", error="Username already exists!")
                elif re.search(r'[!@#$%^&*(),.?":{}|<>]', new_username):
                    return render_template("editprofile.html", error="Username cannot contain special characters")

            # Check if a new password is provided and if passwords match
            if new_password:
                if new_password != confirm_password:
                    return render_template("editprofile.html", error="Passwords do not match!")
                elif len(new_password) <= 7:
                    return render_template("editprofile.html", error="Password too short!")
                elif len(new_password) >= 15:
                    return render_template("editprofile.html", error="Password too long")

            # Update the session variable with the new username
            if new_username and new_username != old_username:
                session["username"] = new_username

            # Prepare the updates dictionary
            update_query = {"username": old_username}
            update_statement = {"$set": {}}

            if new_username and new_username != old_username:
                update_statement["$set"]["username"] = new_username

            if new_password:
                hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
                update_statement["$set"]["password"] = hashed_password

            update_statement["$set"]["modifiedOn"] = datetime.now(singapore_timezone)

            # Update the user document with new values using update_one()
            users_collection.update_one(update_query, update_statement)

            # Save the session after making the changes
            session.modified = True

            return redirect("home")

    return render_template("editprofile.html")



def scan_file(file: object) -> tuple:
    # upload endpoint
    files_url = "https://www.virustotal.com/api/v3/files"

    # specify post payload
    files = {"file": (file.filename, file, file.content_type)}
    files_headers = {
        "accept": "application/json",
        "x-apikey": os.getenv('VT_API_KEY')
    }

    # post
    files_response = requests.post(files_url, files=files, headers=files_headers)

    # get response
    if files_response.status_code == 200:
        # if response is ok
        files_response_data = files_response.json()
        # get the id from json response
        analysis_id = files_response_data["data"]["id"]

    else:
        return 'UploadError', 'Error'

    # analysis endpoint with file id
    analysis_url = "https://www.virustotal.com/api/v3/analyses/" + analysis_id

    # specify headers
    analysis_headers = {
        "accept": "application/json",
        "x-apikey": os.getenv('VT_API_KEY')
    }

    # post
    analysis_response = requests.get(analysis_url, headers=analysis_headers)

    # declare attempts count
    attempts = 1

    # retry getting analysis response for max 120 times in 2 minutes if virustotal slow like snorlax
    while attempts < 120 and analysis_response.status_code == 200 and analysis_response.json()["data"]["attributes"]["status"] in ['queued', 'in-progress']:
        time.sleep(1)
        analysis_response = requests.get(analysis_url, headers=analysis_headers)
        attempts += 1
        # if attempts more than 30 just timeout
        if attempts >= 30:
            return 'File timed out.', 'Timeout'

    # get response
    if analysis_response.status_code == 200:
        # if response is ok
        analysis_response_data = analysis_response.json()
        amogusus = analysis_response_data["data"]["attributes"]["stats"]["suspicious"]
        malicious = analysis_response_data["data"]["attributes"]["stats"]["malicious"]

        # if got sussy
        if amogusus > 0 or malicious > 0:
            return "The file is potentially unsafe.", 'Unsafe'

        # if no sussy
        elif amogusus == 0 and malicious == 0:
            file.seek(0)
            return "The file is safe. No antivirus engines detected any threats.", 'Safe'

        else:
            return "Error occurred during file scanning.", 'Scan'

    else:
        # handle errors
        return "Error occurred during file scanning.", 'Scan'




@app.route('/get_image/<file_id>')
def get_image(file_id):
    file = fs.get(ObjectId(file_id))
    if file is not None:
        data = file.read()
        response = make_response(data)
        response.headers.set('Content-Type', file.content_type)
        response.headers.set('Content-Disposition', 'inline')
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    else:
        return 'Image not found'



@app.route('/edit_pfp', methods=["GET", "POST"])
@login_required
def edit_pfp():
    if request.method == 'POST':
        photo = request.files['photo']
        current_user_id = session.get('username')

        # Save the photo to GridFS
        if photo and len(photo.read()) <= MAX_FILE_SIZE:
            photo.seek(0)  # Reset file pointer after reading
            filename = secure_filename(photo.filename)
            file_id = fs.put(photo, filename=filename)

            print(f"{current_user_id} is uploading, {filename}")

            print("Performing file scan...")  # Debugging statement
            # Call the scan_file function
            _, scan_status = scan_file(photo)
            print("File scan completed.")  # Debugging statement

            if scan_status == 'Safe':
                # Proceed with saving the profile picture

                # Obtain the current user's ID from the session
                current_user_id = session.get('username')

                # Check if the user already has a profile picture
                existing_pfp = pfp_collection.find_one({'author_id': current_user_id})

                if existing_pfp:
                    # Delete the old profile picture from GridFS
                    old_file_id = existing_pfp['image_file_id']
                    fs.delete(ObjectId(old_file_id))

                    # Update the existing profile picture with the new one
                    pfp_collection.update_one({'author_id': current_user_id}, {'$set': {'image_file_id': file_id}})
                else:
                    # Insert the new profile picture into the database
                    pfp = {
                        'author_id': current_user_id,
                        'image_file_id': file_id,
                    }
                    pfp_collection.insert_one(pfp)

                # Update the session with the profile picture URL
                profile_picture_url = url_for('get_image', file_id=file_id)
                session['profile_picture_url'] = profile_picture_url

                # Debugging: Print the profile picture URL
                print("Profile Picture URL:", profile_picture_url)

                # Return success message and profile picture URL in JSON format
                return jsonify({"success": True, "profile_picture_url": profile_picture_url})

            elif scan_status == 'Unsafe':
                # Handling unsafe files
                flash("The uploaded file is potentially unsafe. Please upload a different image.", "error")
                return jsonify({"success": False, "error": "Unsafe file"}), 400

            elif scan_status == 'UploadError':
                # Handling upload errors
                flash("Error occurred during file upload. Please try again later.", "error")
                return jsonify({"success": False, "error": "Upload error"}), 500

            elif scan_status == 'Timeout':
                # Handling scan timeout
                flash("File scan timed out. Please try again later.", "error")
                return jsonify({"success": False, "error": "Scan timeout"}), 500

            else:
                # Handling other scan errors
                flash("Error occurred during file scanning. Please try again later.", "error")
                return jsonify({"success": False, "error": "Scan error"}), 500

        else:
            flash("Invalid file. Please upload a valid image (up to 1.5 MB).", "error")
            return jsonify({"success": False, "error": "Invalid file"}), 400

    # This part will be executed only if the request method is not POST,
    # which means someone accessed /edit_pfp directly in the browser.
    # Redirect them back to the edit profile page.
    return jsonify({"success": False, "error": "Method not allowed"}), 405




@app.route("/logout")
@login_required
def logout():
    # Clear the session and log the user out
    session.clear()
    return redirect("/")



@app.route("/deleteacc")
@login_required
def deleteprofile():
    return render_template("deleteacc.html")



@app.route("/form_delete", methods=["GET", "POST"])
@login_required
def delete_acc():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = users_collection.find_one({"username": username})
        if user:
            hashed_password = user.get("password")
            if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
                users_collection.delete_one(user)  # Use the _id field for deletion
                return redirect("/")

        return render_template("deleteacc.html", error="Invalid username or password")

    return render_template("deleteacc.html")



#####################################   adarsh - codes       ######################################
def send_newsletter_email(email, content, username):
    try:
        with app.app_context():
            msg = Message("Newsletter from WildVine", recipients=[email])
            msg.body = f"Hi {username}!\n\n{content}"
            # Send the email
            mail.send(msg)
            print(f"Newsletter email sent to: {email}")
    except Exception as e:
        print(f"Error sending newsletter email to {email}: {str(e)}")



def send_newsletter():
    # Get the latest newsletter content
    latest_newsletter = newsletter_collection.find().sort([('$natural', -1)]).limit(1).next()

    subscribed_users = users_collection.find({"subscribed_to_newsletter": True})

    for user in subscribed_users:
        # Send the newsletter to the user's email
        send_newsletter_email(user["email"], latest_newsletter["content"], user["username"])



@app.route('/compose_newsletter', methods=['GET', 'POST'])
@admin_login_required
def compose_newsletter():
    compose_form = ComposeNewsletterForm()

    if compose_form.validate_on_submit():
        newsletter_content = compose_form.newsletter_content.data

        # Save the newsletter content in the newsletter collection
        newsletter_collection.insert_one({"content": newsletter_content})

        flash('Newsletter content saved.')
        return redirect('/admin_home')

    return render_template('admin/compose_newsletter.html', compose_form=compose_form)



#####################################   feed          ######################################

@app.route('/forum')
@login_required
def forum():
    # Get all posts from the database
    posts = pfp_collection.find()
    edit_form = EditForm()
    comment_form = CommentForm()


    current_user_id = session.get('username')
    return render_template('forum.html', posts=posts, username=current_user_id, edit_form=edit_form, comment_form=comment_form)



@app.route('/admin_forum')
@admin_login_required
def admin_forum():
    # Get all posts from the database
    posts = pfp_collection.find()
    edit_form = EditForm()
    comment_form = CommentForm()


    current_user_id = session.get('username')
    return render_template('admin_forum.html', posts=posts, username=current_user_id, edit_form=edit_form, comment_form=comment_form)



@app.route('/search_by_author')
@admin_login_required
def search_by_author():
    edit_form = EditForm()
    comment_form = CommentForm()
    author_id = request.args.get('author_id')

    if author_id:
        posts = pfp_collection.find({'author_id': author_id})
    else:
        posts = []

    return render_template('search_results.html', posts=posts, edit_form=edit_form, comment_form=comment_form)



################################################## Add questions for quizzes #######################################################################################################



ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'pdf', 'txt'}
MAX_FILE_SIZE = 1.5 * 1024 * 1024  # 1.5 MB in bytes



def allowed_file(filename):
    # ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'txt'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS



@app.route('/admin_dashboard')
@admin_login_required
def admin_dashboard_view():
    total_course = quiz_collection.count_documents({})
    total_users = users_collection.count_documents({})
    total_teachers = teacher_collection.count_documents({}) 

    context = {
        'total_course': total_course,
        'total_users': total_users,
        'total_teachers': total_teachers,
    }
    return render_template('admin/admin_dashboard.html', **context)



@app.route('/admin_view-exam')
@admin_login_required
def admin_view_exam_view():
    courses = quiz_collection.find()
    return render_template('admin/admin_view_exam.html', courses=courses)



@app.route('/admin_delete-exam/<string:course_id>')
@admin_login_required
def admin_delete_exam_view(course_id):
    try:
        course_id_obj = ObjectId(course_id)  # Convert course_id to ObjectId
        result = quiz_collection.delete_one({'_id': course_id_obj})

        if result.deleted_count > 0:
            # Exam successfully deleted
            flash('Quiz has been successfully deleted', 'success')
            return redirect(url_for('admin_view_exam_view'))
        else:
            # Exam not found or not deleted
            flash('Quiz not found or could not be deleted', 'error')
            return render_template('error.html', message='Quiz not found')
    except Exception as e:
        print(f"Error deleting quiz: {e}")
        flash('Error deleting quiz', 'error')
        return render_template('error.html', message='Invalid course ID')



@app.route('/admin_view-question')
@admin_login_required
def admin_view_question_view():
    courses = quiz_collection.find()
    return render_template('admin/admin_view_question.html', courses=courses)



@app.route('/admin_see-question/<string:course_id>')
@admin_login_required
def admin_see_question_view(course_id):
    if ObjectId.is_valid(course_id):
        print(f"Received course_id: {course_id}")
        course = quiz_collection.find_one({'_id': ObjectId(course_id)})
        print(f"Found course: {course}")
        if course:
            questions = course.get('questions', [])
            course_name = course.get('course_name', 'Unknown Course')
            return render_template('admin/admin_see_question.html', questions=questions, course_id=course_id, course_name=course_name)
        else:
            return render_template('error.html', message='Course not found')
    else:
        flash('Invalid course ID', 'error')
        return redirect(url_for('admin_view_question_view'))
    


from flask import flash

@app.route('/admin_remove-question/<string:course_id>/<string:question_id>')
@admin_login_required
def admin_remove_question_view(course_id, question_id):
    result = quiz_collection.update_one(
        {'_id': ObjectId(course_id)},
        {'$pull': {'questions': {'_id': ObjectId(question_id)}}}
    )
    if result.modified_count > 0:
        flash('Question has been successfully deleted', 'success')
    else:
        flash('Failed to delete question', 'error')
    return redirect(url_for('admin_view_question_view'))




####################### Teacher Codes for quiz ###################################



@app.route('/teacher_dashboard')
def teacher_dashboard_view():
    total_course = quiz_collection.count_documents({})
    total_users = users_collection.count_documents({})  # Assuming you want to count the number of users
    total_teachers = teacher_collection.count_documents({}) 

    context = {
        'total_course': total_course,
        'total_teachers': total_teachers,
        'total_users': total_users  # Change to total_users
    }
    if "username" in session:
        return render_template('teacher/teacher_dashboard.html', **context, info=session["username"]) # Updated to pass info instead of username



@app.route('/teacher_exam', methods=['GET', 'POST'])
def teacher_exam():
    return render_template('teacher/teacher_exam.html')



@app.route('/teacher_add-exam', methods=['GET', 'POST'])
def teacher_add_exam_view():
    courseForm = CourseForm()

    if courseForm.validate_on_submit():
        course_name = courseForm.course_name.data
        question_number = courseForm.question_number.data
        total_marks = courseForm.total_marks.data
        current_user_id = session.get('username')

        course_data = {
            'course_name': course_name,
            'author_id': current_user_id,
            'question_number': question_number,
            'total_marks': total_marks
        }

        quiz_collection.insert_one(course_data)
        return redirect('/teacher_view-exam')

    return render_template('teacher/teacher_add_exam.html', courseForm=courseForm)



@app.route('/teacher_view-exam')
def teacher_view_exam_view():
    courses = quiz_collection.find()
    return render_template('teacher/teacher_view_exam.html', courses=courses)



@app.route('/teacher_delete-exam/<string:course_id>')
def delete_exam_view(course_id):
    try:
        course_id_obj = ObjectId(course_id)  # Convert course_id to ObjectId
        result = quiz_collection.delete_one({'_id': course_id_obj})

        if result.deleted_count > 0:
            # Exam successfully deleted
            flash('Quiz has been successfully deleted', 'success')
            return redirect(url_for('teacher_view_exam_view'))
        else:
            # Exam not found or not deleted
            flash('Quiz not found or could not be deleted', 'error')
            return render_template('error.html', message='Quiz not found')
    except Exception as e:
        print(f"Quiz deleting exam: {e}")
        flash('Quiz deleting exam', 'error')
        return render_template('error.html', message='Invalid course ID')


@app.route('/teacher_question', methods=['GET', 'POST'])
def teacher_question():
    return render_template('teacher/teacher_question.html')



@app.route('/teacher_add-question', methods=['GET', 'POST'])
def teacher_add_question_view():
    question_form = QuestionForm()
    course_form = CourseForm()

    if request.method == 'POST':
        if question_form.validate_on_submit():
            # Process question form data
            marks = question_form.marks.data
            question_text = question_form.question.data
            option1 = question_form.option1.data
            option2 = question_form.option2.data
            option3 = question_form.option3.data
            option4 = question_form.option4.data
            answer = question_form.answer.data

            # Generate a unique ID for the question
            question_id = ObjectId()

            # Retrieve selected course ID from the form
            course_id = course_form.course_id.data

            # Create a new question dictionary with the generated ID
            question = {
                '_id': question_id,  # Assign the generated ID
                'marks': marks,
                'question': question_text,
                'option1': option1,
                'option2': option2,
                'option3': option3,
                'option4': option4,
                'answer': answer,
            }

            # Update the course with the new question
            quiz_collection.update_one({'_id': ObjectId(course_id)}, {'$push': {'questions': question}})

            return redirect('/teacher_view-question')

    # Load the existing courses for the form
    courses = quiz_collection.find()
    
    return render_template('teacher/teacher_add_question.html', question_form=question_form, course_form=course_form, courses=courses)


@app.route('/teacher_view-question')
def teacher_view_question_view():
    courses = quiz_collection.find()
    return render_template('teacher/teacher_view_question.html', courses=courses)



@app.route('/teacher_see-question/<string:course_id>')
def see_question_view(course_id):
    if ObjectId.is_valid(course_id):
        print(f"Received course_id: {course_id}")
        course = quiz_collection.find_one({'_id': ObjectId(course_id)})
        print(f"Found course: {course}")
        if course:
            questions = course.get('questions', [])
            course_name = course.get('course_name', 'Unknown Course')
            return render_template('teacher/see_question.html', questions=questions, course_id=course_id, course_name=course_name)
        else:
            return render_template('error.html', message='Course not found')
    else:
        flash('Invalid course ID', 'error')
        return redirect(url_for('teacher_view_question_view'))
    


@app.route('/teacher_remove-question/<string:course_id>/<string:question_id>')
def remove_question_view(course_id, question_id):
    try:
        quiz_collection.update_one(
            {'_id': ObjectId(course_id)},
            {'$pull': {'questions': {'_id': ObjectId(question_id)}}}
        )
        flash('Question successfully deleted', 'success')
    except Exception as e:
        print(f"Error deleting question: {e}")
        flash('Failed to delete question', 'error')
    return redirect(url_for('teacher_view_question_view'))



######################################### user codes for quiz ##########################################################



@app.route("/quiz")
@login_required
def quiz():
    quizzes = quiz_collection.find()
    return render_template("quiz.html", quizzes=quizzes)



@app.route("/attempt_quiz/<quiz_id>")
@login_required
def attempt_quiz(quiz_id):
    quiz = quiz_collection.find_one({'_id': ObjectId(quiz_id)})
    if quiz:
        return render_template("quiz2.html", quiz=quiz)
    else:
        # Handle the case where the quiz with the given ID is not found
        return render_template("quiz_not_found.html")



@app.route("/submit_attempt/<quiz_id>", methods=['POST'])
@login_required
def submit_attempt(quiz_id):
    quiz = quiz_collection.find_one({'_id': ObjectId(quiz_id)})
    user_answers = request.form.to_dict(flat=False)
    correct_answers = {}

    # Extract correct answers from the quiz
    for question in quiz['questions']:
        correct_answers[str(question['_id'])] = question['answer']

    # Compare user's answers with correct answers
    wrong_answers = {}
    for question_id, user_answer in user_answers.items():
        if question_id.startswith('answer_'):
            question_id = question_id[len('answer_'):]
            if user_answer[0] != correct_answers.get(question_id):
                wrong_answers[question_id] = user_answer[0]

    return render_template("quiz_results.html", quiz=quiz, wrong_answers=wrong_answers, str=str)



@app.route('/search_by_teacher')
@login_required
def search_by_teacher():
    query = request.args.get('query')
    quizzes = []

    if query:
        # Search by both author ID and course name
        query_filter = {
            '$or': [
                {'author_id': {'$regex': query, '$options': 'i'}},  # Case-insensitive regex search for author ID
                {'course_name': {'$regex': query, '$options': 'i'}}  # Case-insensitive regex search for course name
            ]
        }
        quizzes = quiz_collection.find(query_filter)

    return render_template('quiz.html', quizzes=quizzes)
    


#####################################   lionel - codes       ######################################
######   feedback codes       ######



# @app.route('/feedback', methods=['GET', 'POST'])
# @login_required
# def feedback():
#     feedback = FeedbackForm()
#     success_message = None  # Initialize the success message as None

#     if feedback.validate_on_submit():
#         form_data = {
#             "first_name": feedback.first_name.data,
#             "last_name": feedback.last_name.data,
#             "email": feedback.email.data,
#             "title": feedback.title.data,
#             "remarks": feedback.remarks.data,
#         }
#         result = store_feedback_to_mongodb(form_data)
#         success_message = result  # Set the success message
#         flash(result)  # Optionally show a success message to the user
#         return redirect("home")  # Redirect the user to the home page after submission
#     else:
#         print("Form validation errors:", feedback.errors)

#     return render_template('feedback.html', form=feedback, success_message=success_message)



# def store_feedback_to_mongodb(form_data):
#     # Access the desired collection in the wildvine database
#     collection = db["feedbacks"]

#     # Insert the form data into the collection
#     insert_result = collection.insert_one(form_data)
#     print("Data inserted with ID:", insert_result.inserted_id)

#     return "Feedback submitted successfully!"


@app.route('/feedback', methods=['GET', 'POST'])
@login_required
def feedback():
    form = FeedbackForm()  # Instantiate the FeedbackForm class
    filename = None  # Initialize filename variable

    if request.method == 'POST':
        # Handle file upload
        if 'screenshot' in request.files:
            file = request.files['screenshot']
            if file:
                filename = secure_filename(file.filename)
                print("Received file:", filename)  # Debugging line
                # Save the uploaded file to MongoDB
                save_screenshot_to_mongodb(file, filename)
                
                # Scan the uploaded file using VirusTotal API
                scan_result, scan_status = scan_file(file)
                if scan_status == 'Safe':
                    flash("Screenshot uploaded and scanned. It's safe.")
                elif scan_status == 'Unsafe':
                    flash("Screenshot uploaded and scanned. It's potentially unsafe. Please review.")
                elif scan_status == 'Timeout':
                    flash("Screenshot upload successful but scanning timed out. Please try again later.")
                else:
                    flash("Screenshot upload successful but scanning encountered an error. Please try again later.")

        # Handle other form data
        # Access form fields using request.form['field_name']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        title = request.form['title']
        remarks = request.form['remarks']

        # Store feedback data in MongoDB
        store_feedback_to_mongodb(first_name, last_name, email, title, remarks, filename)

        flash("Feedback submitted successfully!")
        return redirect("home")

    return render_template('feedback.html', form=form)


def save_screenshot_to_mongodb(file, filename):
    # Access the desired collection in MongoDB
    fs = GridFS(db)

    # Store the file in MongoDB
    with fs.new_file(filename=filename) as fp:
        fp.write(file.read())
        fp.close()


def store_feedback_to_mongodb(first_name, last_name, email, title, remarks, filename):
    # Access the desired collection in MongoDB
    collection = db["feedbacks"]

    # Prepare feedback data including the filename of the screenshot
    form_data = {
        "first_name": first_name,
        "last_name": last_name,
        "email": email,
        "title": title,
        "remarks": remarks,
        "screenshot": filename  # Include the filename of the uploaded screenshot
    }

    # Insert the form data into the collection
    collection.insert_one(form_data)



@app.route('/feedback/screenshot/<filename>')
def get_screenshot(filename):
    # Retrieve the screenshot file from MongoDB GridFS
    fs = GridFS(db)
    screenshot_file = fs.find_one({"filename": filename})

    if screenshot_file:
        # Return the file as a response
        return send_file(io.BytesIO(screenshot_file.read()), mimetype='image/*')
    else:
        # Return a placeholder image or handle the case when the file is not found
        pass  # Implement your logic here



@app.route('/feedback_log')
@admin_login_required
def feedback_log():
    feedback_data = fetch_feedback_data_from_mongodb()  # Fetch feedback data from MongoDB
    return render_template('admin/admin_feedback.html', feedback_data=feedback_data)



def fetch_feedback_data_from_mongodb():
    collection = db["feedbacks"]
    feedback_data = list(collection.find())  # Retrieve all feedback documents from the collection
    return feedback_data



###################################        report for posts - took lionels report codes and modified to suit report of posts - adarsh        ####################################
# @app.route('/report_form', methods=['POST', 'GET'])
# @login_required
# def report_form():
#     report_form = ReportForm()  # Create an instance of the ReportForm class

#     if request.method == 'POST':
#         if report_form.validate_on_submit():  # Validate the form data
#             report_reason = report_form.title.data  # Get the selected reason from the form
#             remarks = report_form.remarks.data  # Get the remarks from the form

#             quiz_course_name = request.args.get('quiz_course_name')  # Get post_id from query parameter
#             quiz_author_id = request.args.get('quiz_author_id')  # Get post_author_id from query parameter

#             reporting_user_id = session.get('username')

#             # Store the report data in your reports_collection or database
#             report_collection.insert_one({
#                 "reported_quiz_name": quiz_course_name,
#                 "reporting_user_id": reporting_user_id,  # Store the reporting user's ID
#                 "reported_quiz_author_id": quiz_author_id,  # Store post_author_id
#                 "report_reason": report_reason,
#                 "remarks": remarks  # Store the remarks in the report
#             })

#             return redirect(url_for('home'))
#         else:
#             return jsonify({"success": False, "error": "Form validation failed"})

#     else:
#         return render_template('report.html', report_form=report_form)  # Render the form initially


@app.route('/report_form', methods=['POST', 'GET'])
@login_required
def report_form():
    report_form = ReportForm()

    if request.method == 'POST':
        if report_form.validate_on_submit():
            report_reason = report_form.title.data
            remarks = report_form.remarks.data

            quiz_course_name = request.form.get('quiz_course_name')
            quiz_author_id = request.form.get('quiz_author_id')

            print("quiz_course_name:", quiz_course_name)
            print("quiz_author_id:", quiz_author_id)

            reporting_user_id = session.get('username')

            # Handle file upload
            screenshot = report_form.screenshot.data
            if screenshot:
                # Save the file to GridFS
                filename = secure_filename(screenshot.filename)
                file_id = fs.put(screenshot, filename=filename)

                # Scan the uploaded file
                scan_result, scan_status = scan_file(screenshot)

                # Check scan status
                if scan_status == 'Safe':
                    # Store the report data along with the GridFS file ID
                    report_collection.insert_one({
                        "reported_quiz_name": quiz_course_name,
                        "reporting_user_id": reporting_user_id,
                        "reported_quiz_author_id": quiz_author_id,
                        "report_reason": report_reason,
                        "remarks": remarks,
                        "screenshot_id": file_id,  # Store the GridFS file ID
                    })
                    return redirect(url_for('home'))
                else:
                    # If the file is not safe, delete it from GridFS
                    fs.delete(file_id)
                    return jsonify({"success": False, "error": "File scanning failed. The file is potentially unsafe."})
            else:
                return jsonify({"success": False, "error": "No file uploaded"})
        else:
            return jsonify({"success": False, "error": "Form validation failed"})
    else:
        return render_template('report.html', report_form=report_form)



@app.route('/report_log')
@admin_login_required
def report_log():
    report_data = fetch_report_data_from_mongodb()  # Fetch report data from MongoDB
    return render_template('admin/admin_report.html', report_data=report_data)



def fetch_report_data_from_mongodb():
    collection = db["reports"]
    report_data = list(collection.find())  # Retrieve all report documents from the collection
    print("Fetched Report Data:", report_data)  # Add this line for debugging
    return report_data



@app.route('/get_r_screenshot/<screenshot_id>')
def get_r_screenshot(screenshot_id):
    # Retrieve the file from GridFS using the ObjectId
    file = fs.get(ObjectId(screenshot_id))

    if file:
        # Serve the file using send_file
        return send_file(file, mimetype='image/jpeg')
    else:
        # Return a 404 Not Found error if the file is not found
        return "File not found", 404




@app.route("/admin_signup", methods=["GET", "POST"])
def admin_signup():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        confirm_pw = request.form["confirm"]


        existing_user = admin_collection.find_one({"$or": [{"username": username}]})

        if existing_user:
            return render_template("admin/admin_signup.html", error="Username or email already exists")
        elif password != confirm_pw:
            return render_template("admin/admin_signup.html", error="Passwords do not match!")

        else:
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            user = {"username": username, "password": hashed_password, "createdOn": datetime.utcnow(), "modifiedOn": datetime.utcnow()}
            admin_collection.insert_one(user)

            return redirect(url_for('homeb4login'))

    return render_template("admin/admin_signup.html")



@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the username exists in the admin database
        admin = admin_collection.find_one({'username': username})

        if admin and bcrypt.checkpw(password.encode('utf-8'), admin['password']):
            admin_user = Admin(admin)  # Instantiate the Admin class with admin data
            login_user(admin_user)      # Login the admin using Flask-Login
            session['admin_username'] = admin['username']  # Set the admin_username in the session
            next_url = request.form.get('next')
            if next_url:
                return redirect(next_url)
            else:
                return redirect('/admin_dashboard')  # Redirect to the admin dashboard page after successful login

        else:
            error = "Invalid username or password. Please try again."
            return render_template('admin/adminlogin.html', error=error)

    return render_template('admin/adminlogin.html', error='')



@app.route('/admin_home')
@admin_login_required
def admin_dashboard():
    next_url = request.args.get('next')
    if next_url:
        redirect_url = url_for('admin_dashboard', next=next_url)
    else:
        redirect_url = url_for('admin_dashboard')
    admin_user = current_user
    return render_template('admin/adminhome.html', admin_username=session['admin_username'], admin_user=admin_user)



@app.route('/admin_logout')
@admin_login_required
def admin_logout():
    # Clear the admin_username from the session to log out the admin
    session.pop('admin_username', None)
    return redirect('/admin_login')



@app.route('/logging')
@admin_login_required
def logging():
    username = request.form.get('username')
    logger.debug(f"{username} tried to access logger")
    users = db.users.find()
    teachers = db.teachers.find()
    admins = db.admin.find()
    return render_template('logging.html', users=users, teachers=teachers, admins=admins)

@app.route('/loggingdebug')
def loggingdebug():
    username = request.form.get('username')
    logger.debug(f"{username} tried to access logger")
    with open('logger.log', 'r') as log_file:
        log_content = log_file.read()

    return render_template('loggingdebug.html',  log_content=log_content)

@app.route('/loggingwarning')
def loggingwarning():
    username = request.form.get('username')
    logger.debug(f"{username} tried to access logger")
    with open('loggerwarning.log', 'r') as log_file:
        log_content = log_file.read()

    return render_template('loggingwarning.html',  log_content=log_content)



# Function to create the 'admin' collection and insert admin details
def create_admin_collection():
    admin_collection = db["admin"]

    if 'admin' not in db.list_collection_names():
        admin_details = {
            "username": "Jiggy",
            "password": "ABC@123",
        }
        admin_collection.insert_one(admin_details)
        print("Admin collection created and admin details inserted.")

def check_role(username):
    user = users_collection.find_one({'username': username})
    
    if user:
        role = user.get('role')
        log_action(f"Checked role for user '{username}'. Role: {role}")
        return role 
    
    return 'user'

#####   Add to app.run if need to make another admin account   #####
# create_admin_collection()



# scheduler = BackgroundScheduler()

# # Add the job to the scheduler
# scheduler.add_job(send_newsletter, trigger=IntervalTrigger(minutes=5))  # Send every 5 minutes

# # Start the scheduler
# scheduler.start()

# # Ensure the scheduler shuts down gracefully when the app exits
# atexit.register(lambda: scheduler.shutdown())

if __name__ == '__main__':
    # schedule_newsletter()
    create_admin_collection()
    app.run(debug=True)



##########################################       File logs       #################################################

##### esther files ####

## HTMLS ##

# deleteacc.html
# editprofile.html
# home.html
# homeb4login.html (ignore homeb4login(esther) - not in use)
# login.html
# otp_verification.html
# otp_verification_forgot.html
# profile preview (not in use)
# forgot.html
# reset_password.html
# signup.html
# verify.html (not in use - i think)

## CSS and JS ##

# forgot.css
# dropdown.css
# editprofile.css
# login.css
# profilepic.css
# script(esther).css
# suandforgot.css

# profilepic.js
# script.js


#### adarsh files ####

## HTMLS ##

# admin_forum.html
# admin_signup.html
# compose_newsletter.html
# error.html (i dont think in use)
# forum.html
# forum_test.html (not in use)
# newsletter.html (not in use)
# search_results.html
# upload_post.html

## CSS and JS ##

# admin_forum.css
# forum.css
# forum_test.css(not in use)
# news.css
# upload.css

# admin_forum.js
# forum.js
# report.js
# script.js


#### lionel files ####

## HTMLS ##

# adminhome.html
# admin_login.html
# feedback.html
# feedback_log.html
# report.html
# report_log.html

## CSS and JS ##

# style(lionel).css
# uses esthers css for the admin home page same with adarsh. but essentially just this file

# script.js

##########################################       File logs       #################################################
