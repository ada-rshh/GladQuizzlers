import os
import uuid

from flask_mail import Mail, Message
# from flask_wtf import FlaskForm
from flask import Flask, session, render_template, request, Response, redirect, send_from_directory
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash
from flask import Flask, render_template, request, redirect, url_for, session
from flask import session
from flask import Flask, render_template, request, redirect, url_for, flash
from pymongo import MongoClient
import random
import string
import smtplib
from email.mime.text import MIMEText

app = Flask(__name__)
app.config['SECRET_KEY'] = 'e58984a365380c9920f48c1b589f9466'  # Replace with your own secret key
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'environmentalawareness.nyp@gmail.com'
app.config['MAIL_PASSWORD'] = 'huahquvjovplgrtw'
app.config['MAIL_DEFAULT_SENDER'] = 'environmentalawareness.nyp@gmail.com'
app.config['MONGO_URI'] = 'mongodb://localhost:27017/social_media'
# app.jinja_env.filters['format_object_id'] = format_object_id

uri = "mongodb+srv://EnvAware:envaware777#@atlascluster.aej9sme.mongodb.net/?retryWrites=true&w=majority"
mail = Mail(app)
client = MongoClient(uri)

db = client["wildvine"]
users_collection = db["users"]

try:
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(e)


@app.route('/')
def homeb4login():
    return render_template('homeb4login.html')


@app.route('/homeb4login')
def homeb4loginn():
    return render_template('homeb4login.html')


@app.route('/form_login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Check if the username and password match in the database
        user = users_collection.find_one({"username": username, "password": password})

        if user:

            email = user.get("email")
            # Generate OTP and store it in the session
            otp = ''.join(random.choices(string.digits, k=6))


            # Send the OTP to the user's email
            send_otp_email(email, otp)

            return render_template("otp_verification.html", username=username, otp=otp)

        else:
            return render_template("homeb4login.html", error="Invalid username or password")

    return render_template("homeb4login.html")


def send_otp_email(recipient_email, otp):
    subject = 'OTP for Account Verification'
    body = f'Your OTP for account verification is: {otp}'

    msg = Message(subject=subject, recipients=[recipient_email], body=body)
    mail.send(msg)


@app.route('/otp_verification.html')
def verification():
    return render_template("otp_verification.html")


@app.route('/verify_otp', methods=["POST"])
def verify_otp():
    entered_otp = request.form.get("otp")
    stored_otp = request.form.get("stored_otp")
    username = request.form.get("username")

    if entered_otp == stored_otp:
        session.pop("otp", None)
        return render_template("home.html", info=username)

    else:
        return render_template("otp_verification.html", error="Invalid OTP", username=username, otp=stored_otp)


@app.route('/forgot.html')
def forgotpw():
    return render_template("forgot.html")


@app.route('/form_forgot', methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        email_to_check = request.form.get('email')  # Assuming the email is passed as a form parameter named 'email'

        # Perform the query to check if the email exists in the database
        email_exists = users_collection.find_one({'email': email_to_check})

        if email_exists:
            otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])

            # Save the OTP in the database or generate a unique token to track the OTP verification process

            # Send the OTP to the email address
            send_otp_email(email_to_check, otp)
            return render_template("otp_verification.html", info="OTP has been sent to your email.")

        else:
            # Email does not exist in the database
            return render_template("forgot.html", info="Invalid Email")


@app.route('/signup.html')
def signuppage():
    return render_template('signup.html')


@app.route("/form_signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        confirm_pw = request.form["confirm"]
        email = request.form["email"]

        existing_user = users_collection.find_one({"$or": [{"username": username}, {"email": email}]})

        if existing_user:
            return render_template("signup.html", error="Username or email already exists")
        elif password != confirm_pw:
            return render_template("signup.html", error="Passwords do not match!")

        else:
            user = {"username": username, "password": password, "email": email}
            users_collection.insert_one(user)
            otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])

            # Save the OTP in the database or generate a unique token to track the OTP verification process

            # Send the OTP to the email address
            send_otp_email(email, otp)
            return render_template("otp_verification.html", info="OTP has been sent to your email.")

        # otp = generate_otp(

        # Send the OTP to the user's email (implementation not included here

    return render_template("signup.html")


@app.route("/home")
def home():
    if "username" in session:
        return render_template("home.html", username=session["username"])
    else:
        return redirect("/home.html")


@app.route("/editprofile")
def editprofile():
    return render_template('editprofile.html')


@app.route('/edit_profile', methods=["GET", "POST"])
def edit_profile():
    if request.method == "POST":
        username = request.form["username"]
        bio = request.form["bio"]
        password = request.form["password"]

        user = {"username": username, "password": password}

        return render_template("/home.html", info=username)


@app.route("/logout")
def logout():
    # Clear the session and log the user out
    session.clear()
    return redirect("/")


if __name__ == '__main__':
    app.run(debug=True)