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
from flask import Flask, render_template, request, redirect, url_for, flash, abort, g
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
import datetime

import io
import tempfile

import logging

# load env #
load_dotenv()

#########################       start of application        ######################
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
app.config['MAIL_SERVER'] = os.environ['MAIL_SERVER']
app.config['MAIL_PORT'] = int(os.environ['MAIL_PORT'])
app.config['MAIL_USE_TLS'] = os.environ['MAIL_USE_TLS'].lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ['MAIL_USERNAME']
app.config['MAIL_PASSWORD'] = os.environ['MAIL_PASSWORD']
app.config['MAIL_DEFAULT_SENDER'] = os.environ['MAIL_DEFAULT_SENDER']
# app.config['MONGO_URI'] = os.environ['DATABASE_URL']
<<<<<<< HEAD
app.config['MONGO_URI'] = "mongodb+srv://EnvAware:envaware777#@atlascluster.aej9sme.mongodb.net/?retryWrites=true&w=majority"
=======
app.config['MONGO_URI'] = "mongodb+srv://EnvAware:envaware777%23@atlascluster.aej9sme.mongodb.net/?retryWrites=true&w=majority"
>>>>>>> 0f720327510c5525fb35d459379cddb4d2b00e89
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
db = client["venv"]
users_collection = db["users"]
posts_collection = db['posts']

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

# #logging stuff
# logging.basicConfig(level=logging.DEBUG, filename="C:/Users/User/Downloads/Glad/example.log", filemode="w",
#             format="%(asctime)s - %(levelname)s - %(message)s",
#             datefmt="%Y-%m-%d %H:%M:%S")

# def log_action(message):
#     """Helper function to log actions."""
#     logger.info(message)

# logger = logging.getLogger(__name__)
# logger.info("test the custom logger")

# #end of logging stuff   

###################       Security implementations       ###########################
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return redirect("/")

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
@app.route('/')
def homeb4login():
    return render_template('homeb4login.html')

@app.route('/contactb4login')
def contactb4login():
    return render_template(('contact.html'))

@app.route('/index2')
def index2():
    return render_template('homeb4login.html')


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
        print("Received CSRF Token:", csrf_token)

        # Retrieve the user document based on the username
        user = users_collection.find_one({"username": username})

        if user:
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
                return render_template("homeb4login.html", error="Invalid password")

        else:
            return render_template("homeb4login.html", error="Invalid username")

        # Generate a new CSRF token and store it in the session
    print("Before CSRF Token generation")
    csrf_token = secrets.token_hex(32)
    session["_csrf_token"] = csrf_token
    print("After CSRF Token generation")
    return render_template("homeb4login.html")



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



@app.route('/signup')
def signuppage():
    return render_template('signup.html')



@app.route('/form_signup', methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        confirm_pw = request.form["confirm"]
        signup_email = request.form["email"]
        subscribe = request.form.get("subscribe")

        # Validate the email
        try:
            valid_email = validate_email(signup_email)
            signup_email = valid_email.email
        except EmailNotValidError:
            return render_template("signup.html", error="Invalid email format", password=password, confirm=confirm_pw)

        # Check email length
        if len(signup_email) > 50:  # Adjust the maximum length as needed
            return render_template("signup.html", error="Email address is too long", username=username)

        existing_user = users_collection.find_one({"$or": [{"username": username}, {"email": signup_email}]})

        if existing_user:
            return render_template("signup.html", error="Username or email already exists", password=password, confirm=confirm_pw)
        elif re.search(r'[!@#$%^&*(),.?":{}|<>]', username):
            return render_template("signup.html", error="Username cannot contain special characters", email=signup_email)
        elif len(password) <= 7:
            return render_template("signup.html", error="Password too short!", username=username, email=signup_email)
        elif len(password) >= 15:
            return render_template("signup.html", error="Password too long", username=username, email=signup_email)
        elif password != confirm_pw:
            return render_template("signup.html", error="Passwords do not match!")

        else:
            # Hash and salt the password using bcrypt
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            user = {"username": username, "password": hashed_password, "email": signup_email, "subscribed_to_newsletter": bool(subscribe)}
            users_collection.insert_one(user)
            otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])

            # Save the OTP in the session
            session["otp"] = otp

            # Send the OTP to the email address
            send_otp_email(signup_email, otp)

            return render_template("otp_verification.html", info="OTP has been sent to your email.")



@app.route("/home")
@login_required
def home():
    if "username" in session:
        return render_template("home.html", info=session["username"])  # Updated to pass info instead of username
    # else:
    #     return redirect("/")



@app.route("/editprofile")
@login_required
def editprofile():
    return render_template('editprofile.html')



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

            # Update the user document with new values using update_one()
            users_collection.update_one(update_query, update_statement)

            # Save the session after making the changes
            session.modified = True

            return redirect("home")

    return render_template("editprofile.html")



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
    posts = posts_collection.find()
    edit_form = EditForm()
    comment_form = CommentForm()


    current_user_id = session.get('username')
    return render_template('forum.html', posts=posts, username=current_user_id, edit_form=edit_form, comment_form=comment_form)



@app.route('/admin_forum')
@admin_login_required
def admin_forum():
    # Get all posts from the database
    posts = posts_collection.find()
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
        posts = posts_collection.find({'author_id': author_id})
    else:
        posts = []

    return render_template('search_results.html', posts=posts, edit_form=edit_form, comment_form=comment_form)



################################################## Add questions for quizzes #######################################################################################################



ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'pdf', 'txt'}
MAX_FILE_SIZE = 1.5 * 1024 * 1024  # 1.5 MB in bytes



def allowed_file(filename):
    # ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'txt'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# def extract_questions_from_pdf(pdf_content):
#     questions = []

#     try:
#         # Create a temporary directory
#         temp_dir = tempfile.mkdtemp()

#         # Save the PDF content to a temporary file in the created directory
#         temp_pdf_path = os.path.join(temp_dir, "temp_pdf.pdf")
#         with open(temp_pdf_path, "wb") as temp_pdf:
#             temp_pdf.write(pdf_content)

#         # Open the temporary file with PyMuPDF
#         doc = fitz.open(temp_pdf_path)

#         for page_num in range(doc.page_count):
#             page = doc[page_num]
#             text = page.get_text()

#             # Split text into lines
#             lines = text.split('\n')

#             # Extract lines starting with "question" (case-insensitive)
#             for line in lines:
#                 if line.strip().lower().startswith("question"):
#                     questions.append(line.strip())

#         # Check if any valid questions were found
#         if not questions:
#             raise ValueError("No valid questions found in the PDF")

#         return questions

#     except Exception as e:
#         # Handle exceptions (print or log the error, and consider raising a custom exception)
#         print(f"Error extracting questions: {e}")
#         return []

#     finally:
#         # Close the PyMuPDF document and delete the temporary directory
#         doc.close()
#         shutil.rmtree(temp_dir, ignore_errors=True)

# def save_questions_to_mongodb(caption, questions, file_content):
#     # Save the file to GridFS
#     fs = GridFS(db)
#     file_id = fs.put(file_content, filename=caption)

#     # Insert questions and file_id into the collection
#     quiz_collection.insert_one({'caption': caption, 'questions': questions, 'file_id': file_id})

# @app.route('/upload_quiz', methods=['GET', 'POST'])
# def upload_quiz():
#     questions = []  # Initialize questions here
#     if request.method == 'POST':
#         caption = request.form['caption']
#         file = request.files['file']

#         if file and allowed_file(file.filename) and len(file.read()) <= MAX_FILE_SIZE:
#             file.seek(0)  # Reset file pointer after reading
#             file_extension = file.filename.rsplit('.', 1)[1].lower()

#             if file_extension == 'pdf':
#                 file_content = file.read()
#                 questions = extract_questions_from_pdf(file_content)
#                 save_questions_to_mongodb(caption, questions, file_content)

#             elif file_extension == 'txt':
#                 # Handle text file extraction here if needed
#                 pass

#             return render_template('quiz.html', caption=caption, questions=questions)

#     return render_template('upload_quiz.html')




# def extract_quiz_data(pdf_path):
#     with fitz.open(pdf_path) as pdf_document:
#         num_pages = pdf_document.page_count

#         quiz_data = []

#         for page_num in range(num_pages):
#             page = pdf_document[page_num]
#             text = page.get_text()

#             # Use regular expressions to identify questions and answers
#             question_pattern = re.compile(r'Question (\d+):(.+?)(?=(\nAnswer|\nCorrect)|$)', re.DOTALL)
#             answer_pattern = re.compile(r'Answer:(.+?)(?=(\nCorrect|$))', re.DOTALL)
#             correct_answer_pattern = re.compile(r'Correct:(.+?)(?=\n|$)', re.DOTALL)

#             questions = question_pattern.findall(text)
#             answers = answer_pattern.findall(text)
#             correct_answers = correct_answer_pattern.findall(text)

#             # Add data to the quiz_data list
#             for question in questions:
#                 q_num, q_text = question
#                 quiz_data.append({
#                     'question': f"{q_num}: {q_text.strip()}",
#                     'answers': [ans.strip() for ans in answers[i].split(',')],
#                     'correct_answer': correct_answers[i].strip()
#                 })

#     print("Extracted Quiz Data:", quiz_data)
#     return quiz_data




# @app.route('/upload_quiz', methods=['GET', 'POST'])
# def upload_quiz():
#     if request.method == 'POST':
#         if 'file' not in request.files:
#             flash('No file part', 'error')
#             return redirect(request.url)

#         file = request.files['file']

#         if file.filename == '':
#             flash('No selected file', 'error')
#             return redirect(request.url)

#         if file:
#             # Save the uploaded file to the 'uploads' directory
#             upload_directory = 'uploads'
#             os.makedirs(upload_directory, exist_ok=True)
#             file_path = os.path.join(upload_directory, file.filename)
#             file.save(file_path)

#             # Save file path and quiz data to MongoDB
#             quiz_data = extract_quiz_data(file_path)
#             print("Extracted Quiz Data:", quiz_data)  # Add this line for debugging
#             quiz_document = {'file_path': file_path, 'quiz_data': quiz_data}
#             quiz_collection.insert_one(quiz_document)

#             flash('Quiz uploaded successfully', 'success')
#             return render_template('upload_quiz.html', quiz_data=quiz_data)

#     return render_template('upload_quiz.html')



# @app.route('/quiz')
# def quiz():
#     # Retrieve quiz data from MongoDB
#     quiz_data = quiz_collection.find()

#     return render_template('quiz.html', quiz_data=quiz_data)



# @app.route('/submit_quiz', methods=['POST'])
# def submit_quiz():
#     # Handle user-submitted answers
#     user_answers = request.form.to_dict()
    
#     # Compare user answers with correct answers
#     for question_id, user_answer in user_answers.items():
#         correct_answer = quiz_collection.find_one({'_id': ObjectId(question_id)})['correct_answer']
#         if user_answer == correct_answer:
#             feedback = "Correct!"
#         else:
#             feedback = "Incorrect."

#         # You can update a user's feedback in MongoDB or do other actions as needed.

#     return render_template('feedback.html', feedback=feedback)



################################################## Add questions for quizzes #######################################################################################################



# @app.route('/add_post', methods=['GET', 'POST'])
# @login_required
# def add_post():
#     if request.method == 'POST':
#         # Get the data from the form
#         caption = request.form['caption']
#         if any(char in '<>/\\' for char in caption):
#             flash("Invalid characters in the caption. Please avoid using <, >, /, or \\ characters.")
#             return redirect(url_for('add_post'))

#         photo = request.files['photo']

#         # Save the photo to GridFS
#         if photo and allowed_file(photo.filename) and len(photo.read()) <= MAX_FILE_SIZE:
#             photo.seek(0)  # Reset file pointer after reading
#             filename = secure_filename(photo.filename)
#             file_id = fs.put(photo, filename=filename)

#             # Obtain the current user's ID from the session
#             current_user_id = session.get('username')  # Replace 'user_id' with the actual key you use to store user ID in session

#             # Insert the new post into the database with 'author_id' field
#             post = {
#                 'author_id': current_user_id,
#                 'image_file_id': file_id,
#                 'caption': caption,
#                 'comments': []
#             }
#             posts_collection.insert_one(post)

#             return redirect(url_for('forum'))


#         else:
#             flash("Invalid file. Please upload a valid image (up to 1.5 MB) with allowed extensions: jpg, jpeg, png, gif.","error")
#             return redirect(url_for('add_post'))

#     return render_template('upload_post.html')



# def get_current_user_id():
#     return session.get('username')



# @app.route('/add_comment', methods=['POST'])
# def add_comment():
#     # Get the data from the form
#     post_id = request.form['post_id']
#     comment_text = request.form['comment_text']
#     if any(char in '<>/\\' for char in comment_text):
#         flash("Invalid characters in the caption. Please avoid using <, >, /, or \\ characters.")
#         return redirect(url_for('forum'))

#     # Find the post in the database
#     post = posts_collection.find_one({'_id': ObjectId(post_id)})

#     if post:
#         # Add the comment to the post with user information
#         current_user_id = session.get('username')  # Replace 'user_id' with the actual key you use to store user ID in session
#         comment_data = {
#             'username': current_user_id,
#             'comment_text': comment_text
#         }
#         post['comments'].append(comment_data)
#         posts_collection.update_one({'_id': ObjectId(post_id)}, {'$set': post})

#         # Return the added comment as part of the JSON response
#         return jsonify({'comment': comment_text}), 200

#     # If the post is not found, return an error response
#     return jsonify({'error': 'Post not found'}), 404



# @app.route('/edit_post/<post_id>', methods=['GET', 'POST'])
# def edit_post(post_id):
#     # Retrieve the post from the database based on the provided 'post_id'
#     post = posts_collection.find_one({'_id': ObjectId(post_id)})

#     # Check if the post is not found or the user is not authorized to edit it
#     if not post or post['author_id'] != session.get('username'):
#         flash("You are not authorized to edit this post", "error")
#         return redirect(url_for('forum'))

#     # Process the POST request (when the form is submitted)
#     if request.method == 'POST':
#         # Get the new caption from the form
#         new_caption = request.form['caption']
#         if any(char in '<>/\\' for char in new_caption):
#             flash("Invalid characters in the caption. Please avoid using <, >, /, or \\ characters.")
#             return redirect(url_for('forum'))

#         # Update the 'caption' field of the post in the database
#         posts_collection.update_one({'_id': ObjectId(post_id)}, {'$set': {'caption': new_caption}})

#         # Redirect to the 'forum' route after the post is edited
#         return redirect(url_for('forum'))


#     return render_template('edit_post.html', post=post)



# @app.route('/delete_post/<post_id>', methods=['POST'])
# @csrf.exempt  # Since you're validating CSRF token manually, exempt this route
# def delete_post(post_id):
#     try:
#         post = posts_collection.find_one({"_id": ObjectId(post_id)})

#         if post:
#             # Check if the current user's username matches the post's creator username
#             if post["author_id"] == session.get('username'):
#                 # Delete post document
#                 posts_collection.delete_one({"_id": post["_id"]})
#                 # Delete associated image
#                 fs.delete(post["image_file_id"])
#                 return jsonify({"message": "Post deleted successfully"}), 200
#             else:
#                 return jsonify({"message": "You are not authorized to delete this post"}), 403
#         else:
#             return jsonify({"message": "Post not found"}), 404

#     except Exception as e:
#         return jsonify({"message": str(e)}), 500



# @app.route('/admin_delete_post/<post_id>', methods=['POST'])
# @admin_login_required
# @csrf.exempt  # Since you're validating CSRF token manually, exempt this route
# def admin_delete_post(post_id):
#     try:
#         # Delete the post and its associated image from MongoDB
#         post = posts_collection.find_one({"_id": ObjectId(post_id)})
#         if post:
#             # Delete post document
#             posts_collection.delete_one({"_id": post["_id"]})
#             # Delete associated image
#             fs.delete(post["image_file_id"])
#             return jsonify({"message": "Post deleted successfully"}), 200
#         else:
#             return jsonify({"message": "Post not found"}), 404

#     except Exception as e:
#         return jsonify({"message": str(e)}), 500

####################### Admin Codes for quiz ###################################



@app.route('/admin_dashboard')
def admin_dashboard_view():
    total_course = quiz_collection.count_documents({})
    total_users = users_collection.count_documents({})

    context = {
        'total_course': total_course,
        'total_users': total_users
    }
    return render_template('admin/admin_dashboard.html', **context)



@app.route('/admin_view-exam')
def admin_view_exam_view():
    courses = quiz_collection.find()
    return render_template('admin/admin_view_exam.html', courses=courses)



@app.route('/admin_delete-exam/<string:course_id>')
def admin_delete_exam_view(course_id):
    try:
        course_id_obj = ObjectId(course_id)  # Convert course_id to ObjectId
        result = quiz_collection.delete_one({'_id': course_id_obj})

        if result.deleted_count > 0:
            # Exam successfully deleted
            return redirect(url_for('admin_view_exam_view'))
        else:
            # Exam not found or not deleted
            return render_template('error.html', message='Exam not found')
    except Exception as e:
        print(f"Error deleting exam: {e}")
        return render_template('error.html', message='Invalid course ID')



@app.route('/admin_view-question')
def admin_view_question_view():
    courses = quiz_collection.find()
    return render_template('admin/admin_view_question.html', courses=courses)



@app.route('/admin_see-question/<string:course_id>')
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
    


@app.route('/admin_remove-question/<string:course_id>/<string:question_id>')
def admin_remove_question_view(course_id, question_id):
    quiz_collection.update_one(
        {'_id': ObjectId(course_id)},
        {'$pull': {'questions': {'_id': ObjectId(question_id)}}}
    )
    return redirect(url_for('admin_view_question_view'))



####################### Teacher Codes for quiz ###################################



@app.route('/teacher_dashboard')
def teacher_dashboard_view():
    total_course = quiz_collection.count_documents({})
    # total_question = quiz_collection.aggregate([
    #     {"$group": {"_id": None, "total": {"$sum": "$question_number"}}}
    # ]).next()['total']
    total_users = users_collection.count_documents({})  # Assuming you want to count the number of users

    context = {
        'total_course': total_course,
        # 'total_question': total_question,
        'total_users': total_users  # Change to total_users
    }
    return render_template('teacher/teacher_dashboard.html', context=context)



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

        course_data = {
            'course_name': course_name,
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
            return redirect(url_for('teacher_view_exam_view'))
        else:
            # Exam not found or not deleted
            return render_template('error.html', message='Exam not found')
    except Exception as e:
        print(f"Error deleting exam: {e}")
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

            # Retrieve selected course ID from the form
            course_id = course_form.course_id.data

            # Create a new question dictionary
            question = {
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
    quiz_collection.update_one(
        {'_id': ObjectId(course_id)},
        {'$pull': {'questions': {'_id': ObjectId(question_id)}}}
    )
    return redirect(url_for('teacher_view_question_view'))



@app.route('/image/<file_id>')
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
    


#####################################   lionel - codes       ######################################
######   feedback codes       ######



@app.route('/feedback', methods=['GET', 'POST'])
@login_required
def feedback():
    feedback = FeedbackForm()
    success_message = None  # Initialize the success message as None

    if feedback.validate_on_submit():
        form_data = {
            "first_name": feedback.first_name.data,
            "last_name": feedback.last_name.data,
            "email": feedback.email.data,
            "title": feedback.title.data,
            "remarks": feedback.remarks.data,
        }
        result = store_feedback_to_mongodb(form_data)
        success_message = result  # Set the success message
        flash(result)  # Optionally show a success message to the user
        return redirect("home")  # Redirect the user to the home page after submission
    else:
        print("Form validation errors:", feedback.errors)

    return render_template('feedback.html', form=feedback, success_message=success_message)



def store_feedback_to_mongodb(form_data):
    # Access the desired collection in the wildvine database
    collection = db["feedbacks"]

    # Insert the form data into the collection
    insert_result = collection.insert_one(form_data)
    print("Data inserted with ID:", insert_result.inserted_id)

    return "Feedback submitted successfully!"



@app.route('/feedback_log')
@admin_login_required
def feedback_log():
    feedback_data = fetch_feedback_data_from_mongodb()  # Fetch feedback data from MongoDB
    return render_template('feedback_log.html', feedback_data=feedback_data)



def fetch_feedback_data_from_mongodb():
    collection = db["feedbacks"]
    feedback_data = list(collection.find())  # Retrieve all feedback documents from the collection
    return feedback_data



######   report codes       ######
####################################################################                  report for comments - lionel and jun wen                ###################################################
@app.route('/report', methods=['GET', 'POST'])
@login_required
def report():
    report_c = Report_c_Form()
    if report_c.validate_on_submit():
        form_data = {
            "title": report_c.title.data,
            "remarks": report_c.remarks.data,
        }
        result = store_report_to_mongodb(form_data)
        flash(result)
        return redirect("home")
    return render_template('report_c.html', form=report_c)

def store_report_to_mongodb(form_data):
    # Access the desired collection in the wildvine database
    collection = db["reports_c"]

    # Insert the form data into the collection
    insert_result = collection.insert_one(form_data)
    print("Data inserted with ID:", insert_result.inserted_id)

    return "Report submitted successfully!"



@app.route('/report_c_log')
@admin_login_required
def report_c_log():
    report_data = fetch_report_data_from_mongodb_c()
    return render_template('report_c_log.html', report_data=report_data)



def fetch_report_data_from_mongodb_c():
    collection = db["reports_c"]
    report_data = list(collection.find())  # Retrieve all report documents from the collection
    print("Fetched Report Data:", report_data)  # Add this line for debugging
    return report_data


###################################        report for posts - took lionels report codes and modified to suit report of posts - adarsh        ####################################
@app.route('/report_form', methods=['POST', 'GET'])
@login_required
def report_form():
    report_form = ReportForm()  # Create an instance of the ReportForm class

    if request.method == 'POST':
        if report_form.validate_on_submit():  # Validate the form data
            report_reason = report_form.title.data  # Get the selected reason from the form
            remarks = report_form.remarks.data  # Get the remarks from the form

            post_id = request.args.get('post_id')  # Get post_id from query parameter
            post_author_id = request.args.get('post_author_id')  # Get post_author_id from query parameter

            reporting_user_id = session.get('username')

            # Store the report data in your reports_collection or database
            report_collection.insert_one({
                "reported_post_id": post_id,
                "reporting_user_id": reporting_user_id,  # Store the reporting user's ID
                "reported_post_author_id": post_author_id,  # Store post_author_id
                "report_reason": report_reason,
                "remarks": remarks  # Store the remarks in the report
            })

            return redirect(url_for('home'))
        else:
            return jsonify({"success": False, "error": "Form validation failed"})

    else:
        return render_template('report.html', report_form=report_form)  # Render the form initially



@app.route('/report_log')
@admin_login_required
def report_log():
    report_data = fetch_report_data_from_mongodb()  # Fetch report data from MongoDB
    return render_template('report_log.html', report_data=report_data)



def fetch_report_data_from_mongodb():
    collection = db["reports"]
    report_data = list(collection.find())  # Retrieve all report documents from the collection
    print("Fetched Report Data:", report_data)  # Add this line for debugging
    return report_data



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
            user = {"username": username, "password": hashed_password}
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
                return redirect('/admin_home')  # Redirect to the admin dashboard page after successful login

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



scheduler = BackgroundScheduler()

# Add the job to the scheduler
scheduler.add_job(send_newsletter, trigger=IntervalTrigger(minutes=5))  # Send every 5 minutes

# Start the scheduler
scheduler.start()

# Ensure the scheduler shuts down gracefully when the app exits
atexit.register(lambda: scheduler.shutdown())

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
