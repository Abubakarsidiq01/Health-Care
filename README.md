# HealthCare Management System

A comprehensive web-based healthcare management system built with Flask that allows healthcare providers to manage patient records, conduct medical assessments, and maintain detailed medical histories.

## 🚀 Features

### Authentication & Authorization
- **User Registration & Login** with email verification via OTP
- **Google OAuth Integration** for seamless authentication
- **Password Reset** functionality with OTP verification
- **Admin Role Management** with secure promotion system
- **Session Management** with secure logout

### Patient Management
- **Patient Registration** with comprehensive demographic information
- **Patient Search** by name, email, or patient ID
- **Patient Photo Upload** for visual identification
- **Unique Patient ID Generation** for tracking

### Medical Documentation
- **Review of Systems (ROS)** - Comprehensive 14-system medical review
- **History of Present Illness (HPI)** - Detailed symptom documentation
- **Medical History Tracking** with audit trails
- **Multi-user Access** with user attribution for all entries

### Administrative Features
- **Admin Dashboard** with patient overview and statistics
- **User Promotion System** with OTP verification
- **Audit Trails** for all medical entries
- **Data Export** capabilities

## 🛠️ Technology Stack

- **Backend**: Python Flask
- **Authentication**: Flask-Bcrypt, Google OAuth 2.0
- **Data Storage**: JSON file-based storage
- **Email Service**: SMTP with Gmail integration
- **Frontend**: HTML, CSS, JavaScript (Jinja2 templates)
- **Security**: Session management, OTP verification, password hashing

## 📋 Prerequisites

- Python 3.7+
- Gmail account for SMTP services
- Google Cloud Console project (for OAuth)

## ⚙️ Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/Abubakarsidiq01/Health-Care.git
   cd Health-Care
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Environment Setup**
   Create a `.env` file in the root directory:
   ```env
   EMAIL_ADDRESS=your-gmail@gmail.com
   EMAIL_PASSWORD=your-app-password
   GOOGLE_CLIENT_ID=your-google-client-id
   GOOGLE_CLIENT_SECRET=your-google-client-secret
   ```

4. **Gmail App Password Setup**
   - Enable 2-factor authentication on your Gmail account
   - Generate an App Password for the application
   - Use this App Password in the `EMAIL_PASSWORD` field

5. **Google OAuth Setup**
   - Go to [Google Cloud Console](https://console.cloud.google.com/)
   - Create a new project or select existing one
   - Enable Google+ API
   - Create OAuth 2.0 credentials
   - Add authorized redirect URIs:
     - `http://127.0.0.1:5000/auth/google/callback` (development)
     - `https://yourdomain.com/auth/google/callback` (production)

## 🚀 Running the Application

### Development
```bash
python app.py
```
The application will be available at `http://127.0.0.1:5000`

### Production (using Gunicorn)
```bash
gunicorn app:app
```

## 📁 Project Structure

```
Health-Care/
├── app.py                 # Main application file
├── requirements.txt       # Python dependencies
├── .env                  # Environment variables (create this)
├── data/                 # JSON data storage
│   ├── users.json        # User accounts
│   ├── emails.json       # Email to user ID mapping
│   ├── patients.json     # Patient records
│   ├── ros_records.json  # Review of Systems data
│   └── hpi.json         # History of Present Illness data
├── static/               # Static files
│   ├── images/          # Profile pictures, logos
│   └── patient_photos/  # Patient photographs
└── templates/           # HTML templates
    ├── login.html
    ├── register.html
    ├── dashboard.html
    ├── ros_form.html
    ├── hpi_form.html
    └── admin_dashboard.html
```

## 🔐 Security Features

- **Password Hashing**: Uses bcrypt for secure password storage
- **OTP Verification**: 6-digit OTP for email verification and admin promotion
- **Session Management**: Secure session handling with Flask sessions
- **Input Validation**: Form validation and sanitization
- **Admin Protection**: Role-based access control for sensitive operations

## 📊 Medical Forms

### Review of Systems (ROS)
Comprehensive 14-system review including:
- Constitutional, Eyes, ENT, Cardiovascular
- Respiratory, Gastrointestinal, Genitourinary
- Musculoskeletal, Neurological, Skin
- Endocrine, Hematologic/Lymphatic, Allergic/Immunologic

### History of Present Illness (HPI)
Detailed symptom documentation with:
- Onset, Location, Duration, Characteristics
- Severity, Timing, Context, Modifying Factors
- Associated Symptoms, Narrative Summary

## 👥 User Roles

### Regular Users
- Register and manage patients
- Complete medical forms (ROS, HPI)
- View patient information
- Upload patient photos

### Administrators
- All regular user permissions
- Access admin dashboard
- View all patient records with audit information
- Promote users to admin status
- System-wide patient management

## 🔧 Configuration

### Email Configuration
The system uses Gmail SMTP for sending OTP emails. Configure your Gmail account:
1. Enable 2-factor authentication
2. Generate an App Password
3. Use the App Password in your `.env` file

### Admin Setup
- The super admin email is hardcoded as `abolakal@gsumailgram.edu`
- Admin promotion requires OTP verification sent to the super admin
- First admin must be manually promoted or configured

## 🚀 Deployment

### Render.com Deployment
1. Connect your GitHub repository to Render
2. Set environment variables in Render dashboard
3. Use the following build command: `pip install -r requirements.txt`
4. Start command: `gunicorn app:app`

### Environment Variables for Production
```env
EMAIL_ADDRESS=your-production-email@gmail.com
EMAIL_PASSWORD=your-app-password
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
```

## 📝 API Endpoints

### Authentication
- `GET /` - Home page (redirects based on auth status)
- `GET/POST /login` - User login
- `GET/POST /register` - User registration
- `GET/POST /verify-otp` - OTP verification
- `GET /auth/google` - Google OAuth login
- `GET /logout` - User logout

### Patient Management
- `GET/POST /dashboard` - Main dashboard with patient registration/search
- `POST /upload-patient-photo/<patient_id>` - Upload patient photo

### Medical Forms
- `GET/POST /ros/<patient_id>` - Review of Systems form
- `GET /ros-history/<patient_id>` - ROS history
- `GET/POST /hpi/<patient_id>` - History of Present Illness form

### Admin Routes
- `GET /admin-dashboard` - Admin dashboard
- `POST /promote-user` - Promote user to admin
- `POST /request-admin/<email>` - Request admin promotion

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🐛 Known Issues

- JSON file-based storage (consider migrating to a proper database for production)
- Limited file upload validation
- No data backup mechanism

## 🔮 Future Enhancements

- [ ] Database integration (PostgreSQL/MySQL)
- [ ] Advanced search and filtering
- [ ] Report generation and export
- [ ] Mobile responsive design improvements
- [ ] API documentation with Swagger
- [ ] Automated testing suite
- [ ] Data backup and recovery system
- [ ] Multi-language support

## 📞 Support

For support and questions, please open an issue on GitHub or contact the development team.

## 🙏 Acknowledgments

- Flask community for the excellent framework
- Google for OAuth integration
- Contributors and testers

---

**Note**: This is a healthcare management system intended for educational and development purposes. Ensure compliance with healthcare regulations (HIPAA, etc.) before using in production environments.

## 🌐 Live Demo
**Deployed Application**: https://health-care-g7dj.onrender.com
