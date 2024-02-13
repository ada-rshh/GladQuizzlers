###################     unlogged user       ######################
@app.route('/')
def homeb4login():
    return render_template('homeb4login.html')


# @app.route('/homeb4login')
# def homeb4loginn():
#     return render_template('homeb4login.html')


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


@app.route('/verify_otp', methods=["POST"])
def verify_otp():
    entered_otp = request.form.get("otp")
    stored_otp = request.form.get("stored_otp")
    username = request.form.get("username")

    # print("Entered OTP:", entered_otp)
    # print("Stored OTP:", stored_otp)

    if entered_otp == stored_otp:
        session.pop("otp", None)
        # Redirect to the home.html page with the username as a query parameter
        return redirect(url_for('home', username=username))
    else:
        return render_template("otp_verification.html", error="Invalid OTP", username=username, otp=stored_otp)




@app.route('/signup.html')
def signuppage():
    return render_template('signup.html')


@app.route("/form_signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        confirm_pw = request.form["confirm"]
        signup_email = request.form["email"]

        existing_user = users_collection.find_one({"$or": [{"username": username}, {"email": signup_email}]})

        if existing_user:
            return render_template("signup.html", error="Username or email already exists")
        elif password != confirm_pw:
            return render_template("signup.html", error="Passwords do not match!")

        else:
            user = {"username": username, "password": password, "email": signup_email}
            users_collection.insert_one(user)
            signup_email = user.get("email")
            otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])

            # Save the OTP in the database or generate a unique token to track the OTP verification process

            # Send the OTP to the email address
            send_otp_email(signup_email, otp)
            return render_template("otp_verification.html", info="OTP has been sent to your email.", username=username, otp=otp)

        # otp = generate_otp(

        # Send the OTP to the user's email (implementation not included here

    return render_template("signup.html")













@app.route('/add_post', methods=['GET', 'POST'])
def add_post():
    if request.method == 'POST':
        # Get the data from the form
        caption = request.form['caption']
        photo = request.files['photo']

        # Save the photo to GridFS
        if photo and allowed_file(photo.filename):
            filename = secure_filename(photo.filename)
            file_id = fs.put(photo, filename=filename)

            # Obtain the current user's ID from the session
            current_user_id = session.get('user_id')  # Replace 'user_id' with the actual key you use to store user ID in session

            # Insert the new post into the database with 'author_id' field
            post = {
                'author_id': current_user_id,
                'image_file_id': file_id,
                'caption': caption,
                'comments': []
            }
            posts_collection.insert_one(post)

            return redirect(url_for('forum'))  # Replace 'forum' with the route where you want to redirect after adding the post

    return render_template('upload_post.html')




@app.route('/add_comment', methods=['POST'])
def add_comment():
    # Get the data from the form
    post_id = request.form['post_id']
    comment_text = request.form['comment_text']

    # Find the post in the database
    post = posts_collection.find_one({'_id': ObjectId(post_id)})

    if post:
        # Add the comment to the post with user information
        current_user_id = session.get('user_id')  # Replace 'user_id' with the actual key you use to store user ID in session
        comment_data = {
            'user_id': current_user_id,
            'comment_text': comment_text
        }
        post['comments'].append(comment_data)
        posts_collection.update_one({'_id': ObjectId(post_id)}, {'$set': post})

        # Return the added comment as part of the JSON response
        return jsonify({'comment': comment_text}), 200

    # If the post is not found, return an error response
    return jsonify({'error': 'Post not found'}), 404


@app.route('/edit_post/<post_id>', methods=['GET', 'POST'])
def edit_post(post_id):
    post = posts_collection.find_one({'_id': ObjectId(post_id)})

    if not post or post['author_id'] != session.get('user_id'):
        return 'Post not found or unauthorized', 404

    if request.method == 'POST':
        new_caption = request.form['caption']
        posts_collection.update_one({'_id': ObjectId(post_id)}, {'$set': {'caption': new_caption}})
        return redirect(url_for('forum'))

    return render_template('edit_post.html', post=post)



@app.route('/delete_post/<post_id>', methods=['POST', 'DELETE'])
def delete_post(post_id):
    post = posts_collection.find_one({'_id': ObjectId(post_id)})

    if request.method in ['POST', 'DELETE']:
        if not post or post['author_id'] != session.get('user_id'):
            return jsonify({'error': 'You are not authorized to delete this post.'}), 401

        posts_collection.delete_one({'_id': ObjectId(post_id)})
        # You may also want to delete the image from GridFS if needed

        return jsonify({'message': 'Post deleted'}), 200

    # If the method is neither POST nor DELETE, return a 405 Method Not Allowed response
    return jsonify({'error': 'Method Not Allowed'}), 405



######################## forum html
#
# <center>
#     <div id="posts-container">
#         {% for post in posts %}
#             <div class="post-card" id="post-{{ post._id }}">
#                 <img src="{{ url_for('get_image', file_id=post.image_file_id|format_object_id) }}" alt="Post Image" width="300">
#                 <div class="post-actions">
#                     <!-- Dropdown menu for editing post -->
#                     <div class="dropdown">
#                         <span class="post-options" onclick="toggleDropdown('{{ post._id }}')">
#                             <i class="fas fa-ellipsis-v"></i>
#                         </span>
#                         <div class="dropdown-content" id="dropdown-{{ post._id }}">
#                             <a class="dropdown-item" href="#" onclick="toggleEditForm('{{ post._id }}')">Edit Caption</a>
#                             <a class="dropdown-item" href="#" onclick="deletePost('{{ post._id }}')">Delete Post</a>
#                         </div>
#                     </div>
#                 </div>
#                 <p>{{ post.caption }}</p>
#                 <div id="edit-form-{{ post._id }}" style="display: none;">
#                     <form class="edit-form" method="POST" action="{{ url_for('edit_post', post_id=post._id) }}">
#                         <input type="text" name="caption" value="{{ post.caption }}" required>
#                         <input type="submit" value="Save">
#                     </form>
#                 </div>
#                 <div class="comments-section">
#                     <ul class="comments-list" id="comments-list-{{ post._id }}" style="display: none;">
#                         {% for comment in post.comments %}
#                         <li>{{ comment.username }}: {{ comment.comment_text }}</li>
#                         {% endfor %}
#                     </ul>
#                     <span class="comment-icon" data-post-id="{{ post._id }}" onclick="toggleComments('{{ post._id }}')">
#                         <i class="fas fa-chevron-down"></i> Show Comments
#                     </span>
#                     <form class="comment-form" method="POST" data-post-id="{{ post._id }}" onsubmit="addComment(event, '{{ post._id }}')">
#                         <input type="hidden" name="post_id" value="{{ post._id }}">
#                         <input type="text" name="comment_text" required>
#                         <input type="submit" value="Add Comment">
#                     </form>
#                 </div>
#                 <hr>
#             </div>
#         {% endfor %}
#     </div>
# </center>





#####################################   news letter          ######################################

# def send_newsletter():
#     with app.app_context():  # Enter the application context
#         mail = Mail(app)  # Initialize the mail object
#         subscribers = db.subscribers.find()
#         for subscriber in subscribers:
#             email = subscriber['email']
#             send_email = subscriber.get('sendEmail', False)  # Get the checkbox value
#
#             if send_email:
#                 # Code to send emails to the user
#                 message = Message('Newsletter', recipients=[email])
#                 message.body = 'Hello, this is your newsletter!'
#                 print(f"Sending newsletter to {email}")
#                 try:
#                     mail.send(message)
#                     print(f"Sent newsletter to {email}")
#                 except Exception as e:
#                     print(f"Failed to send newsletter to {email}. Error: {e}")
#             else:
#                 # Code to handle non-email sending case (optional)
#                 print(f"Not sending email to {email}")



# @app.route("/form_signup", methods=["GET", "POST"])
# def signup():
#     if request.method == "POST":
#         username = request.form["username"]
#         password = request.form["password"]
#         confirm_pw = request.form["confirm"]
#         signup_email = request.form["email"]
#
#         existing_user = users_collection.find_one({"$or": [{"username": username}, {"email": signup_email}]})
#
#         if existing_user:
#             return render_template("signup.html", error="Username or email already exists")
#         elif password != confirm_pw:
#             return render_template("signup.html", error="Passwords do not match!")
#
#         else:
#             user = {"username": username, "password": password, "email": signup_email, "subscribed_to_newsletter": True}
#             users_collection.insert_one(user)
#             otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])
#
#             # Save the OTP in the session
#             session["otp"] = otp
#
#             send_newsletter()
#
#             # Send the OTP to the email address
#             send_otp_email(signup_email, otp)
#             return render_template("otp_verification.html", info="OTP has been sent to your email.")

# @app.route("/form_signup", methods=["GET", "POST"])
# def signup():
#     if request.method == "POST":
#         username = request.form["username"]
#         password = request.form["password"]
#         confirm_pw = request.form["confirm"]
#         signup_email = request.form["email"]
#         subscribe_newsletter = request.form.get("subscribe", False)  # Get the checkbox value
#
#         existing_user = users_collection.find_one({"$or": [{"username": username}, {"email": signup_email}]})
#
#         if existing_user:
#             return render_template("signup.html", error="Username or email already exists")
#         elif password != confirm_pw:
#             return render_template("signup.html", error="Passwords do not match!")
#
#         else:
#             user = {
#                 "username": username,
#                 "password": password,
#                 "email": signup_email,
#                 "subscribed_to_newsletter": subscribe_newsletter,
#             }
#             users_collection.insert_one(user)
#             otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])
#
#             # Save the OTP in the session
#             session["otp"] = otp
#
#             # Save email to send newsletter if user subscribed
#             if subscribe_newsletter:
#                 save_to_mongodb(signup_email, send_email=True)
#
#             # Send the OTP to the email address
#             send_otp_email(signup_email, otp)
#             return render_template("otp_verification.html", info="OTP has been sent to your email.")
#
#
# def send_newsletter():
#     with app.app_context():  # Enter the application context
#         mail = Mail(app)  # Initialize the mail object
#         subscribers = db.subscribers.find({"subscribed_to_newsletter": True})
#         for subscriber in subscribers:
#             signup_email = subscriber['email']
#             send_email = subscriber.get('sendEmail', False)  # Get the checkbox value
#
#             if send_email:
#                 try:
#                     # Code to send emails to the user
#                     message = Message('Newsletter', recipients=[signup_email])
#                     message.body = 'Hello, this is your newsletter!'
#                     print(f"Sending newsletter to {signup_email}")
#                     mail.send(message)
#                     print(f"Sent newsletter to {signup_email}")
#                 except Exception as e:
#                     print(f"Failed to send newsletter to {signup_email}. Error: {e}")
#             else:
#                 # Code to handle non-email sending case (optional)
#                 print(f"Not sending email to {signup_email}")
#
#
#
# @app.route('/news')
# def news():
#     return render_template('newsletter.html')
#
#
# @app.route('/subscribe', methods=['POST'])
# def subscribe():
#     signup_email = request.form['email']
#     send_email = request.form.get('sendEmail', False)  # Get the checkbox value
#     save_to_mongodb(signup_email, send_email)
#     return 'Thank you for subscribing!'
#
#
# def save_to_mongodb(signup_email, send_email):
#     subscriber = {'email': signup_email, 'sendEmail': send_email}
#     db.subscribers.insert_one(subscriber)
#
#
# def schedule_newsletter():
#     scheduler = BackgroundScheduler()
#     scheduler.add_job(send_newsletter, 'interval', minutes=1)  # Send newsletters every day
#     scheduler.start()
#     atexit.register(lambda: scheduler.shutdown())  # Shut down the scheduler when the Flask app is exited
#     print("Scheduler started.")




<form>
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  </form>

      <div class="header-action">
        <a href="/add_post" class="button search-btn" aria-label="Add Post">
          <i class="fa-solid fa-arrow-up-from-bracket"></i>
        </a>
        </div>

      <div class="h-icons">
			<a href="#"><i class="bx bx-user-circle" class="account" style="font-size: 1.73em;" onclick="toggleMenu()"></i></a>
			<div class="sub-menu-wrap" id="subMenu">
				<div class="sub-menu">
					<div class="user-info">
                        <h2>{{info}}</h2>  <!-- Updated to use {{info}} instead of {{username}} -->
                    </div>
					<hr>
					<a href="/editprofile" class="sub-menu-link">
						<i class='bx bxs-edit-alt'></i>
						<p>edit profile</p>
						<span>></span>
					</a>
					<a href="/logout" class="sub-menu-link">
						<i class='bx bx-log-out' ></i>
						<p>logout</p>
						<span>></span>
					</a>
					<a href="/deleteacc" class="sub-menu-link">
						<i class='bx bx-trash'></i>
						<p>delete account</p>
						<span>></span>
					</a>
				</div>
			</div>
		</div>
        <script>
		let subMenu = document.getElementById("subMenu");

		function toggleMenu(){
			subMenu.classList.toggle("open-menu");
		}
	</script>

    </div>
  </header>





  <main>
    <article>

      <!--
        - #HERO
      -->

      <section class="hero" id="home">
        <div class="container">

          <p class="section-subtitle">
            <img src="./static/images/subtitle-img-white.png" width="32" height="7" alt="Wavy line">

            <span>Welcome, {{ info }}!</span>
          </p>

          <h2 class="h1 hero-title">
            Give Love for Saving <strong>World Animals</strong>
          </h2>

          <p class="hero-text">
            Sit amet consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua
            suspendisse
            ultrices gravida.
          </p>

          <button class="btn btn-primary">
            <span>Donation</span>

            <ion-icon name="heart-outline" aria-hidden="true"></ion-icon>
          </button>

        </div>


################################################################################## old social media forum codes #########################################################################
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


################################################################# old pfp codes #############################################################################################
# @app.route('/add_pfp', methods=['POST'])
# @login_required
# def add_pfp():
#     if request.method == 'POST':
#         photo = request.files['photo']

#         # Save the photo to GridFS
#         if photo and len(photo.read()) <= MAX_FILE_SIZE:
#             photo.seek(0)  # Reset file pointer after reading
#             filename = secure_filename(photo.filename)
#             file_id = fs.put(photo, filename=filename)

#             # Obtain the current user's ID from the session
#             current_user_id = session.get('username')

#             # Check if the user already has a profile picture
#             existing_pfp = pfp_collection.find_one({'author_id': current_user_id})

#             if existing_pfp:
#                 # Delete the old profile picture from GridFS
#                 old_file_id = existing_pfp['image_file_id']
#                 fs.delete(ObjectId(old_file_id))

#                 # Update the existing profile picture with the new one
#                 pfp_collection.update_one({'author_id': current_user_id}, {'$set': {'image_file_id': file_id}})
#             else:
#                 # Insert the new profile picture into the database
#                 pfp = {
#                     'author_id': current_user_id,
#                     'image_file_id': file_id,
#                 }
#                 pfp_collection.insert_one(pfp)

#             # Update the session with the profile picture URL
#             profile_picture_url = url_for('get_image', file_id=file_id)
#             session['profile_picture_url'] = profile_picture_url

#             # Debugging: Print the profile picture URL
#             print("Profile Picture URL:", profile_picture_url)

#             # Return success message and profile picture URL in JSON format
#             return jsonify({"success": True, "profile_picture_url": profile_picture_url})

#         else:
#             flash("Invalid file. Please upload a valid image (up to 1.5 MB).", "error")
#             return jsonify({"success": False, "error": "Invalid file"}), 400

#     # This part will be executed only if the request method is not POST,
#     # which means someone accessed /add_pfp directly in the browser.
#     # Redirect them back to the edit profile page.
#     return jsonify({"success": False, "error": "Method not allowed"}), 


# # Modify the edit_profile route to retrieve the profile picture URL from the session
# @app.route('/edit_profile', methods=["GET", "POST"])
# @login_required
# def edit_profile():
#     if request.method == "POST":
#         # Handle form submission to update user information
#         old_username = request.form["old_username"]
#         new_username = request.form["new_username"]
#         new_password = request.form["new_password"]
#         confirm_password = request.form["confirm"]

#         user = users_collection.find_one({"username": old_username})
#         if user:
#             # Check if a new username is provided and if it already exists
#             if new_username:
#                 existing_user = users_collection.find_one({"username": new_username})
#                 if existing_user and new_username == existing_user["username"]:
#                     return render_template("editprofile.html", error="Username already exists!")
#                 elif re.search(r'[!@#$%^&*(),.?":{}|<>]', new_username):
#                     return render_template("editprofile.html", error="Username cannot contain special characters")

#             # Check if a new password is provided and if passwords match
#             if new_password:
#                 if new_password != confirm_password:
#                     return render_template("editprofile.html", error="Passwords do not match!")
#                 elif len(new_password) <= 7:
#                     return render_template("editprofile.html", error="Password too short!")
#                 elif len(new_password) >= 15:
#                     return render_template("editprofile.html", error="Password too long")

#             # Update the session variable with the new username
#             if new_username and new_username != old_username:
#                 session["username"] = new_username

#             # Prepare the updates dictionary
#             update_query = {"username": old_username}
#             update_statement = {"$set": {}}

#             if new_username and new_username != old_username:
#                 update_statement["$set"]["username"] = new_username

#             if new_password:
#                 hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
#                 update_statement["$set"]["password"] = hashed_password

#             # Update the user document with new values using update_one()
#             users_collection.update_one(update_query, update_statement)

#             # Save the session after making the changes
#             session.modified = True

#             return redirect(url_for("home"))  # Redirect to home page after successful update

#      # Retrieve the current user's profile picture URL from the session
#     profile_picture_url = session.get('profile_picture_url', None)


#     return render_template("editprofile.html", profile_picture_url=profile_picture_url)


# # Add this route to handle editing profile pictures
# @app.route('/edit_pfp', methods=["GET", "POST"])
# @login_required
# def edit_pfp():
#     if request.method == 'POST':
#         photo = request.files['photo']

#         # Save the photo to GridFS
#         if photo and len(photo.read()) <= MAX_FILE_SIZE:
#             photo.seek(0)  # Reset file pointer after reading
#             filename = secure_filename(photo.filename)
#             file_id = fs.put(photo, filename=filename)

#             # Obtain the current user's ID from the session
#             current_user_id = session.get('username')

#             # Check if the user already has a profile picture
#             existing_pfp = pfp_collection.find_one({'author_id': current_user_id})

#             if existing_pfp:
#                 # Delete the old profile picture from GridFS
#                 old_file_id = existing_pfp['image_file_id']
#                 fs.delete(ObjectId(old_file_id))

#                 # Update the existing profile picture with the new one
#                 pfp_collection.update_one({'author_id': current_user_id}, {'$set': {'image_file_id': file_id}})
#             else:
#                 # Insert the new profile picture into the database
#                 pfp = {
#                     'author_id': current_user_id,
#                     'image_file_id': file_id,
#                 }
#                 pfp_collection.insert_one(pfp)

#             # Update the session with the profile picture URL
#             profile_picture_url = url_for('get_image', file_id=file_id)
#             session['profile_picture_url'] = profile_picture_url

#             # Debugging: Print the profile picture URL
#             print("Profile Picture URL:", profile_picture_url)

#             # Return success message and profile picture URL in JSON format
#             return jsonify({"success": True, "profile_picture_url": profile_picture_url})

#         else:
#             flash("Invalid file. Please upload a valid image (up to 1.5 MB).", "error")
#             return jsonify({"success": False, "error": "Invalid file"}), 400

#     # This part will be executed only if the request method is not POST,
#     # which means someone accessed /edit_pfp directly in the browser.
#     # Redirect them back to the edit profile page.
#     return jsonify({"success": False, "error": "Method not allowed"}), 405





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

            existing_user = users_collection.find_one({"$or": [{"username": username}, {"email": signup_email}]})

            if existing_user:
                return render_template("newsignup.html", error="Username or email already exists", password=password, confirm=confirm_pw)
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

                user = {"username": username, "password": hashed_password, "email": signup_email, "subscribed_to_newsletter": bool(subscribe)}
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