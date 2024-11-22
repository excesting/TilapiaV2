import argparse
import io
from PIL import Image
import tensorflow as tf
import torch
import cv2
import numpy as np
from re import DEBUG, sub
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    send_file,
    url_for,
    Response,
    flash,
    session
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from flask_migrate import Migrate
from werkzeug.utils import secure_filename, send_from_directory
from werkzeug.security import check_password_hash
import os
import subprocess
from subprocess import Popen
import re
import requests
import shutil
import time
import glob
import datetime
import os
import random
from flask import flash
from werkzeug.security import generate_password_hash
from ultralytics import YOLO
from flask_mail import Mail, Message
import string


app = Flask(__name__, static_folder='static')


# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///./aquadetect.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'  # Needed for session management
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'aquadetect001@gmail.com'  # Replace with your email
app.config['MAIL_PASSWORD'] = 'mkaa yluz sqqa pvgk'  # Replace with your email password or app-specific password
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

# Initialize Database and Migrate
# Initialize Flask-Mail and SQLAlchemy
mail = Mail(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Define User Model
class UserLogin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), nullable = False)

# Define LocationInfo Model
class LocationInfo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    location = db.Column(db.String(120), nullable=False)
    disease = db.Column(db.String(120), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Card(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    image_path = db.Column(db.String(120), nullable=False)  # Path to the image
    description = db.Column(db.Text, nullable=False)  # Description text for the card

class PasswordReset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    code = db.Column(db.String(6), nullable=False)  # 6-digit code
    expires_at = db.Column(db.DateTime, nullable=False)

# User Model for the database
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120))
    hashCode = db.Column(db.String(120))

#password reset
@app.route("/password-reset-request", methods=["POST", "GET"])
def password_reset_request():
    if request.method == "POST":
        email = request.form['email']
        user = User.query.filter_by(email=email).first()

        if user:
            # Generate a random hash code for password reset link
            hashCode = ''.join(random.choices(string.ascii_letters + string.digits, k=24))
            user.hashCode = hashCode
            db.session.commit()

            # Send password reset email
            msg = Message('Reset Your Password', sender='aquadetect001@gmail.com', recipients=[email])
            msg.body = f"Hello,\n\nWe received a request to reset your password. If it was you, click the link below to reset your password:\n\nhttp://localhost:5000/reset/{hashCode}\n\nIf you did not request a password reset, please ignore this message."
            mail.send(msg)
            flash('Password reset link sent to your email.', 'success')

            return redirect(url_for('password_reset_request'))

        flash('Email not found in our system.', 'danger')
        return redirect(url_for('password_reset_request'))

    return render_template('password_reset_request.html')

from werkzeug.security import generate_password_hash

@app.route("/reset/<string:hashCode>", methods=["GET", "POST"])
def reset_password(hashCode):
    user = User.query.filter_by(hashCode=hashCode).first()

    if user:
        if request.method == "POST":
            new_password = request.form['password']
            confirm_password = request.form['confirm_password']

            if new_password == confirm_password:
                # Hash the new password
                hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')

                user.password = hashed_password
                user.hashCode = None  # Clear the hashCode after password reset
                db.session.commit()

                flash('Your password has been updated!', 'success')
                return redirect(url_for('password_reset_request'))
            else:
                flash('Passwords do not match.', 'danger')
                return redirect(url_for('reset_password', hashCode=hashCode))

        return render_template('reset_password.html', hashCode=hashCode)

    flash('Invalid password reset link.', 'danger')
    return redirect(url_for('password_reset_request'))


# Function to initialize default cards in the database
def initialize_cards():
    with app.app_context():  # Ensure the application context is available
        # Check if the CardInfo table is empty
        if Card.query.count() == 0:
            # Define default card data
            card1 = Card(image_path='static/images/image-45.png', description='To aid fishermen in discerning the health status of Nile Tilapia, distinguishing between vitality and potential pathogenic conditions.')
            card2 = Card(image_path='static/images/image-43.png', description='To Ensure the provision of high-quality Nile Tilapia fish to consumers.')
            card3 = Card(image_path='static/images/image-44.png', description='To minimize production losses in aquaculture.')

            # Add all cards to the session
            db.session.add_all([card1, card2, card3])
            # Commit the session to write data to the database
            db.session.commit()

            print("Default cards added to CardInfo table.")
        else:
            print("CardInfo table already contains data.")

# Create Database Tables
with app.app_context():
    db.create_all()
    initialize_cards()


# SendGrid API key (ensure this is stored securely)
SENDGRID_API_KEY = os.getenv('SENDGRID_API_KEY')


@app.route("/")
def hello_world():
    if 'logged_in' not in session or not session['logged_in']:
        return redirect(url_for('landing'))

    # Fetch all card information from the database
    cards = Card.query.all()
    return render_template('landing.html', cards=cards)

@app.route('/detect')
def detect():
    # return render_template("index.html")
    if "image_path" in request.args:
        image_path = request.args["image_path"]
        return render_template("index.html", image_path=image_path)
    return render_template("index.html")


@app.route("/contact")
def contact():
    # return render_template("index.html")
    return render_template('contact.html')

from werkzeug.security import check_password_hash

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']

        # Query the user from the 'User' table
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):  # Verify the hashed password
            flash('Login successful!', 'success')
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('landing'))
        else:
            flash('Invalid credentials. Please try again.', 'danger')

    return render_template('login.html')


@app.route("/test")
def test():
        # Check if the user is logged in
    if 'logged_in' not in session or not session['logged_in']:
        # If not logged in, redirect to login page
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('login'))

    # Get filter parameters from the query string
    filter_location = request.args.get('location', '')
    filter_disease = request.args.get('disease', '')

    # Get pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Number of records per page
    offset = (page - 1) * per_page

    # Build the query with filters
    query = db.session.query(LocationInfo)

    if filter_location:
        query = query.filter(LocationInfo.location.ilike(f"%{filter_location}%"))

    if filter_disease:
        query = query.filter(LocationInfo.disease.ilike(f"%{filter_disease}%"))

    # Sort by timestamp in descending order (LIFO)
    query = query.order_by(LocationInfo.timestamp.desc())

    # Paginate the results
    total = query.count()
    location_info_records = query.offset(offset).limit(per_page).all()

    # Determine URLs for pagination
    base_url = url_for('test', location=filter_location, disease=filter_disease)
    prev_url = url_for('test', location=filter_location, disease=filter_disease, page=page-1) if page > 1 else None
    next_url = url_for('test', location=filter_location, disease=filter_disease, page=page+1) if (page * per_page) < total else None

    return render_template('test.html',
                           location_info_records=location_info_records,
                           filter_location=filter_location,
                           filter_disease=filter_disease,
                           prev_url=prev_url,
                           next_url=next_url)


@app.route("/logout")
def logout():
    # Clear the session to log out the user
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/landing')
def landing():
    # Fetch all card information from the database
    cards = Card.query.all()
    return render_template('landing.html', cards=cards)

app.config['UPLOAD_FOLDER'] = 'static/images'

@app.route('/edit_cards', methods=['GET', 'POST'])
def edit_cards():
    # Check if the user is logged in
    if 'logged_in' not in session or not session['logged_in']:
        flash("Please log in to access this page.", "warning")
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Get form data
        card_id = int(request.form['card_id'])
        description = request.form['description']
        image_file = request.files['image']

        # Find the card to update
        card = Card.query.get(card_id)
        if card:
            # Update the card's description
            card.description = description

            if image_file:
                # Save the new image file
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(image_file.filename))
                image_file.save(image_path)
                card.image_path = image_path

            # Save changes to the database
            db.session.commit()
            flash('Card updated successfully!', 'success')
        else:
            flash('Card not found.', 'danger')

        # Redirect to the landing page after the update
        return redirect(url_for('landing'))

    # Fetch current cards for the form
    cards = Card.query.all()
    return render_template('edit_cards.html', cards=cards)


@app.route("/detect", methods=["GET", "POST"])
def predict_img():
    if request.method == "POST":
        if 'file' in request.files:
            f = request.files['file']
            basepath = os.path.dirname(__file__)
            filepath = os.path.join(basepath, 'uploads', f.filename)
            print("upload folder is ", filepath)
            f.save(filepath)
            predict_img.imgpath = f.filename
            print("printing predict_img :::::: ", predict_img)

            file_extension = f.filename.rsplit('.', 1)[1].lower()

            # Fetch form data
            location = request.form.get('location')  # Fetch the location from the form
            timestamp = request.form.get('timestamp')  # Fetch the timestamp from the form

            # Convert the date from the form to a datetime object if needed
            try:
                timestamp = datetime.datetime.strptime(timestamp, '%Y-%m-%d')
            except (ValueError, TypeError):
                timestamp = datetime.datetime.now()  # Fallback to current time

            if file_extension == 'jpg' or file_extension == 'jpeg' :
                # Handle image upload
                img = cv2.imread(filepath)

                # Perform the detection
                model = YOLO('best.pt')
                detections = model(img, save=True)

                # Find the latest subdirectory in the 'runs/detect' folder
                folder_path = os.path.join(basepath, 'runs', 'detect')  # Define the folder path here
                subfolders = [f for f in os.listdir(folder_path) if os.path.isdir(os.path.join(folder_path, f))]
                latest_subfolder = max(subfolders, key=lambda x: os.path.getctime(os.path.join(folder_path, x)))

                # Construct the relative path to the detected image file
                detected_files = glob.glob(os.path.join(folder_path, latest_subfolder, "*.jpg"))
                if detected_files:
                    detected_image_path = detected_files[0]  # Use the first detected image
                    relative_image_path = os.path.relpath(detected_image_path, basepath)  # Relative path
                    relative_image_path = relative_image_path.replace("\\", "/")  # Replace backslashes with forward slashes
                else:
                    relative_image_path = ""  # Handle cases where no images are found

                # Debug output
                print("Detected image path:", detected_image_path)  # Absolute path for debugging
                print("Relative image path:", relative_image_path)  # Relative path for template

                # Extract object classes and their labels
                object_classes = detections[0].boxes.cls.to('cpu').tolist()
                # Example class names, you should replace this with your actual class names
                class_names = ['Columnaris Disease','Motile Aeromonad Septicemia','Normal Nile Tilapia','Parasitic Diseases','Streptococcosis','Tilapia Lake virus']
                detected_labels = [class_names[int(cls)] for cls in object_classes]

                # Save the data only if it hasn't been saved already during this request
                if 'data_saved' not in session:
                    for disease in detected_labels:
                        if location and disease:
                            location_info = LocationInfo(location=location, disease=disease, timestamp=timestamp)
                            db.session.add(location_info)
                    db.session.commit()  # Commit the changes to the database

                    # Mark the data as saved in the session
                    session['data_saved'] = True

                # Debug output
                print("Detected Object Classes:", object_classes)
                print("Detected Labels:", detected_labels)

                return render_template('result.html', image_path=relative_image_path, media_type='image', detected_labels=detected_labels)

    # If no file uploaded or GET request, return the template with default values
    return render_template("result.html", image_path="", media_type='image')


@app.route("/<path:filename>")
def display(filename):
    # Folder path to the predicted results
    folder_path = "runs/detect"

    # Check if the directory exists
    if not os.path.isdir(folder_path):
        return render_template('404.html'), 404

    # Search for the file in the latest prediction directory
    subfolders = [
        f for f in os.listdir(folder_path)
        if os.path.isdir(os.path.join(folder_path, f))
    ]

    if not subfolders:
        return render_template('404.html'), 404

    latest_subfolder = max(
        subfolders, key=lambda x: os.path.getctime(os.path.join(folder_path, x))
    )
    directory = os.path.join(folder_path, latest_subfolder)
    files = os.listdir(directory)

    if filename not in files:
        return render_template('404.html'), 404

    # Serve the file if it exists
    image_path = os.path.join(directory, filename)
    file_extension = filename.rsplit(".", 1)[1].lower()

    if file_extension == "jpg":
        return send_file(image_path, mimetype="image/jpeg")
    elif file_extension == "mp4":
        return send_file(image_path, mimetype="video/mp4")
    else:
        return "Invalid file format", 400

@app.errorhandler(404)
def page_not_found(error):
    app.logger.error(f"404 error: {request.url}")  # Optional logging
    return render_template('404.html'), 404




if __name__ == "__main__":
    # Remove the argparse logic since AWS App Runner will manage the port dynamically.
    # You can still use argparse if you want to set a default port for local development.

    # Get the port from the environment, default to 8080 if not found
    port = int(os.environ.get("PORT", 8080))  # AWS App Runner sets the PORT env variable

    # Initialize the YOLO model
    model = YOLO("best.pt")

    # Run the Flask app on all available IPs (0.0.0.0) and the dynamically assigned port
    app.run(host="0.0.0.0", port=port, debug=True)
