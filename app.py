from dotenv import load_dotenv
load_dotenv()  # Loads variables from .env
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
import os
import smtplib
from email.message import EmailMessage
import random
import string
from authlib.integrations.flask_client import OAuth
from uuid import uuid4
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

app = Flask(__name__)
app.secret_key = os.urandom(24)
bcrypt = Bcrypt(app)

# Configuration
EMAIL_ADDRESS = os.getenv('EMAIL_ADDRESS')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')

# Database simulation
users_db = {}
emails_db = {}
otp_storage = {}

# Corrected Google OAuth setup
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    client_kwargs={
        'scope': 'openid email profile',
        'token_endpoint_auth_method': 'client_secret_post'
    },
    redirect_uri='http://127.0.0.1:5000/auth/google/callback',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs'  # Added for proper token validation
)

# Helper functions
def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def send_otp_email(receiver_email, otp):
    msg = EmailMessage()
    msg['Subject'] = 'Your Verification OTP'
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = receiver_email
    msg.set_content(f'Your OTP is: {otp}\nValid for 5 minutes')
    
    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
        smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        smtp.send_message(msg)

# Routes
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
                return redirect(url_for('home'))
        
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
            del otp_storage[email]
            del session['temp_user']
            flash('Registration successful! Please login', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid OTP', 'danger')
    return render_template('verify_otp.html')

# Google Auth Routes
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
        
        # Verify ID token with issuer check
        id_info = id_token.verify_oauth2_token(
            token['id_token'],
            google_requests.Request(),
            os.getenv('GOOGLE_CLIENT_ID'),
            clock_skew_in_seconds=10
        )
        
        # Explicit issuer verification
        if id_info['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            raise ValueError("Invalid token issuer")
        
        email = id_info['email']
        name = id_info.get('name', email.split('@')[0])
        picture = id_info.get('picture')
        
        # Check if user exists
        if email in emails_db:
            if session.get('auth_action') == 'register':
                flash('This email is already registered', 'warning')
                return redirect(url_for('register'))
            
            # Login existing user
            user_id = emails_db[email]
            session['user_id'] = user_id
            flash('Login successful!', 'success')
        else:
            if session.get('auth_action') == 'login':
                flash('No account found. Please register first.', 'warning')
                return redirect(url_for('register'))
            
            # Register new user
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
        
        return redirect(url_for('home'))
    
    except ValueError as e:
        flash(f'Authentication failed: {str(e)}', 'danger')
        return redirect(url_for('login'))
    except Exception as e:
        flash(f'An unexpected error occurred: {str(e)}', 'danger')
        return redirect(url_for('login'))

# Debug route
@app.route('/debug-auth')
def debug_auth():
    return {
        'client_id': os.getenv('GOOGLE_CLIENT_ID'),
        'issuers': ['accounts.google.com', 'https://accounts.google.com'],
        'metadata_url': 'https://accounts.google.com/.well-known/openid-configuration'
    }

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))


@app.route('/debug-logo')
def debug_logo():
    import os
    logo_path = os.path.join(app.static_folder, 'images', 'google-logo.svg')
    exists = os.path.exists(logo_path)
    return f"Logo exists: {exists}<br>Path: {logo_path}"

@app.route('/view-logo')
def view_logo():
    with open(os.path.join(app.static_folder, 'images', 'google-logo.svg'), 'r') as f:
        return f.read(), 200, {'Content-Type': 'image/svg+xml'}

if __name__ == '__main__':
    app.run(debug=True)