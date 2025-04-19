from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
import os
import smtplib
from email.message import EmailMessage
import random
import string
from uuid import uuid4
from authlib.integrations.flask_client import OAuth
from werkzeug.utils import secure_filename
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import json

# === JSON LOAD/SAVE UTILS ===
def load_data():
    global users_db, emails_db, patient_records
    try:
        with open('data/users.json') as f:
            users_db = json.load(f)
        with open('data/emails.json') as f:
            emails_db = json.load(f)
        with open('data/patients.json') as f:
            patient_records = json.load(f)
    except Exception as e:
        print("Error loading data:", e)

def save_users():
    with open('data/users.json', 'w') as f:
        json.dump(users_db, f, indent=2)
    with open('data/emails.json', 'w') as f:
        json.dump(emails_db, f, indent=2)

def save_patients():
    with open('data/patients.json', 'w') as f:
        json.dump(patient_records, f, indent=2)


app = Flask(__name__)
app.secret_key = os.urandom(24)
bcrypt = Bcrypt(app)

# Configuration
EMAIL_ADDRESS = os.getenv('EMAIL_ADDRESS')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')

# Simulated databases
users_db = {}
emails_db = {}
otp_storage = {}
patient_records = []

# Google OAuth Setup
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    client_kwargs={'scope': 'openid email profile'},
    redirect_uri='http://127.0.0.1:5000/auth/google/callback',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs'
)

# Helper functions
def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def send_otp_email(receiver_email, otp):
    try:
        msg = EmailMessage()
        msg['Subject'] = 'Your OTP Verification Code'
        msg['From'] = f"Health App <{EMAIL_ADDRESS}>"
        msg['To'] = receiver_email
        msg.set_content(f"""
        Hello,

        Your One-Time Password (OTP) is: {otp}
        It will expire in 5 minutes.

        If you did not request this, please ignore this message.

        Thanks,
        Health App Team
        """)
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)
    except Exception as e:
        print(f"❌ Failed to send email to {receiver_email}: {e}")
def send_patient_id_email(receiver_email, name, patient_id):
    try:
        msg = EmailMessage()
        msg['Subject'] = 'Your Patient Registration ID'
        msg['From'] = f"HealthCare App <{EMAIL_ADDRESS}>"
        msg['To'] = receiver_email
        msg.set_content(f"""
        Hello {name},

        Thank you for registering with our health system.

        Your Patient ID is: {patient_id}

        Please keep this ID for future check-ins and accessing your medical records.

        Best regards,
        HealthCare Team
        """)
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)
    except Exception as e:
        print(f"❌ Failed to send patient ID email to {receiver_email}: {e}")

# === ROS JSON UTILS ===
def load_ros():
    try:
        with open('data/ros_records.json') as f:
            return json.load(f)
    except:
        return {}

def save_ros(data):
    with open('data/ros_records.json', 'w') as f:
        json.dump(data, f, indent=4)

# ========== AUTH ROUTES ==========

@app.route('/')
def home():
    if 'user_id' in session:
        user = users_db.get(session['user_id'])
        if user:
            return render_template('welcome.html', 
                                   name=user['name'],
                                   email=user['email'],
                                   provider=user.get('oauth_provider'),
                                   picture=user.get('picture'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if email in emails_db:
            user_id = emails_db[email]
            user = users_db[user_id]
            if user['password'] and bcrypt.check_password_hash(user['password'], password):
                session['user_id'] = user_id
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))

        flash('Invalid email or password', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        name = request.form['name']
        password = request.form['password']

        if email in emails_db:
            flash('Email already registered!', 'danger')
        elif len(password) < 6:
            flash('Password must be at least 6 characters', 'danger')
        else:
            otp = generate_otp()
            otp_storage[email] = otp
            send_otp_email(email, otp)
            session['temp_user'] = {'email': email, 'name': name, 'password': password}
            return redirect(url_for('verify_otp'))
    return render_template('register.html')

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if 'temp_user' not in session:
        return redirect(url_for('register'))

    if request.method == 'POST':
        user_otp = request.form['otp']
        email = session['temp_user']['email']

        if otp_storage.get(email) == user_otp:
            user_id = str(uuid4())
            users_db[user_id] = {
                'email': email,
                'password': bcrypt.generate_password_hash(session['temp_user']['password']).decode('utf-8'),
                'name': session['temp_user']['name'],
                'oauth_provider': None
            }
            emails_db[email] = user_id
            save_users()
            del otp_storage[email]
            del session['temp_user']
            flash('Registration successful! Please login', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid OTP', 'danger')
    return render_template('verify_otp.html')

# ========== GOOGLE AUTH ==========

@app.route('/auth/google')
def google_auth():
    session.clear()
    session['auth_action'] = request.args.get('action', 'login')
    return google.authorize_redirect(url_for('google_callback', _external=True))

@app.route('/auth/google/callback')
def google_callback():
    try:
        token = google.authorize_access_token()
        if not token:
            flash('Authorization failed: No token received', 'danger')
            return redirect(url_for('login'))

        id_info = id_token.verify_oauth2_token(
            token['id_token'],
            google_requests.Request(),
            os.getenv('GOOGLE_CLIENT_ID'),
            clock_skew_in_seconds=10
        )
        if id_info['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            raise ValueError("Invalid token issuer")

        email = id_info['email']
        name = id_info.get('name', email.split('@')[0])
        picture = id_info.get('picture')

        if email in emails_db:
            if session.get('auth_action') == 'register':
                flash('This email is already registered', 'warning')
                return redirect(url_for('register'))

            user_id = emails_db[email]
            session['user_id'] = user_id
            flash('Login successful!', 'success')
        else:
            if session.get('auth_action') == 'login':
                flash('No account found. Please register first.', 'warning')
                return redirect(url_for('register'))

            user_id = str(uuid4())
            users_db[user_id] = {
                'email': email,
                'name': name,
                'password': None,
                'oauth_provider': 'google',
                'picture': picture
            }
            emails_db[email] = user_id
            session['user_id'] = user_id
            flash('Registration complete!', 'success')

        return redirect(url_for('dashboard'))

    except ValueError as e:
        flash(f'Authentication failed: {str(e)}', 'danger')
        return redirect(url_for('login'))
    except Exception as e:
        flash(f'An unexpected error occurred: {str(e)}', 'danger')
        return redirect(url_for('login'))

# ========== PASSWORD RESET ==========

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        if email in emails_db:
            otp = generate_otp()
            otp_storage[email] = otp
            send_otp_email(email, otp)
            session['reset_email'] = email
            flash('OTP has been sent to your email.', 'success')
            return redirect(url_for('reset_password'))
        else:
            flash('Email not found.', 'danger')
    return render_template('forgot_password.html')

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if 'reset_email' not in session:
        return redirect(url_for('forgot_password'))

    email = session['reset_email']
    if request.method == 'POST':
        otp = request.form['otp']
        new_password = request.form['new_password']

        if otp_storage.get(email) == otp:
            user_id = emails_db.get(email)
            if user_id:
                users_db[user_id]['password'] = bcrypt.generate_password_hash(new_password).decode('utf-8')
                save_users()
                del otp_storage[email]
                del session['reset_email']
                flash('Password reset successfully! Please login.', 'success')
                return redirect(url_for('login'))
        else:
            flash('Invalid OTP', 'danger')

    return render_template('reset_password.html')

# ========== DASHBOARD + PATIENT MGMT ==========

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    selected_patient = None

    if request.method == 'POST':
        if 'register' in request.form:
            name = request.form['name']
            email = request.form['email']
            phone = request.form['phone']

            for p in patient_records:
                if p['email'].lower() == email.lower() or p['phone'] == phone:
                    flash('⚠️ Patient with this email or phone already exists.', 'danger')
                    break
            else:
                patient_id = f"PT-{random.randint(100000, 999999)}"
                patient = {
                    'id': patient_id,
                    'name': name,
                    'email': email,
                    'phone': phone,
                    'address': request.form['address'],
                    'state': request.form['state'],
                    'country': request.form['country'],
                    'next_of_kin': request.form['next_of_kin'],
                    'blood_group': request.form['blood_group']
                }
                patient_records.append(patient)
                save_patients()
                send_patient_id_email(email, name, patient_id)
                flash(f"✅ Patient {patient['name']} registered!", 'success')

        elif 'search' in request.form:
            query = request.form['search_query'].lower()
            for p in patient_records:
                if query in p['name'].lower() or query in p['email'].lower() or query in p['id'].lower():
                    selected_patient = p
                    break
            if not selected_patient:
                flash('❌ No patient found.', 'warning')

    return render_template('dashboard.html',
                           users_db=users_db,
                           selected=selected_patient,
                           patients=patient_records)

# ========== PROFILE PICTURE UPLOAD ==========

@app.route('/upload-profile', methods=['POST'])
def upload_profile():
    file = request.files.get('profile_pic')
    if file:
        filename = secure_filename(file.filename)
        file.save(os.path.join('static', 'images', 'default-profile.png'))  # Overwrite
        flash("Profile picture updated!", "success")
    return redirect(request.referrer or url_for('dashboard'))

# ========== MISC DEBUG ROUTES ==========

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/debug-auth')
def debug_auth():
    return {
        'client_id': os.getenv('GOOGLE_CLIENT_ID'),
        'issuers': ['accounts.google.com', 'https://accounts.google.com'],
        'metadata_url': 'https://accounts.google.com/.well-known/openid-configuration'
    }

@app.route('/debug-logo')
def debug_logo():
    logo_path = os.path.join(app.static_folder, 'images', 'google-logo.svg')
    exists = os.path.exists(logo_path)
    return f"Logo exists: {exists}<br>Path: {logo_path}"

@app.route('/hpi/<patient_id>')
def hpi_form(patient_id):
    patient = next((p for p in patient_records if p['id'] == patient_id), None)
    if not patient:
        flash('Patient not found for HPI form', 'danger')
        return redirect(url_for('dashboard'))
    return render_template('hpi_form.html', patient=patient)


@app.route('/view-logo')
def view_logo():
    with open(os.path.join(app.static_folder, 'images', 'google-logo.svg'), 'r') as f:
        return f.read(), 200, {'Content-Type': 'image/svg+xml'}

@app.route('/upload-patient-photo/<patient_id>', methods=['POST'])
def upload_patient_photo(patient_id):
    file = request.files.get('photo')
    if not file:
        flash('No file uploaded.', 'danger')
        return redirect(url_for('dashboard'))

    filename = f"{patient_id}.jpg"
    save_path = os.path.join('static', 'patient_photos', filename)
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    file.save(save_path)

    flash('Patient photo updated!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/ros/<patient_id>', methods=['GET', 'POST'])
def ros_form(patient_id):
    systems = [
        "Constitutional", "Eyes", "Ears, Nose, Mouth, Throat",
        "Cardiovascular", "Respiratory", "Gastrointestinal", "Genitourinary",
        "Musculoskeletal", "Neurological", "Skin", "Endocrine",
        "Hematologic/Lymphatic", "Allergic/Immunologic", "Other"
    ]

    ros_data = load_ros()
    ros = ros_data.get(patient_id, {})

    # ✅ Find the patient object by ID
    patient = next((p for p in patient_records if p['id'] == patient_id), None)
    if not patient:
        flash('Patient not found.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        entry = {sys: request.form[sys] for sys in systems}
        entry['notes'] = request.form['notes']
        ros_data[patient_id] = entry
        save_ros(ros_data)
        flash('ROS saved successfully!', 'success')
        return redirect(url_for('dashboard'))

    # ✅ PASS the patient into the template
    return render_template('ros_form.html',
                           systems=systems,
                           ros=ros,
                           patient=patient,
                           users_db=users_db,
                           patient_id=patient_id)

load_data()
# ========== MAIN ==========
if __name__ == '__main__':
    app.run(debug=True)
