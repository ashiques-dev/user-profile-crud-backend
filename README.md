# Django User Profile CRUD Project

## Overview
This Django project provides a complete user authentication and profile management system with the following features:

- User Signup
- User Sign In
- OTP Verification
- Forgot Password
- Reset Password
- Profile Management (Change Profile Picture, Update Password)

## Features

### 1. User Authentication
- **Signup**: Users can create an account with their email and password.
- **Sign In**: Users can log in using their credentials.
- **OTP Verification**: Users receive an OTP for email verification.
- **Forgot Password**: Users can request a password reset link via email.
- **Reset Password**: Users can reset their password using the provided link.

### 2. User Profile Management
- **Update Profile**: Users can update their name and other details.
- **Change Profile Picture**: Users can upload a new profile picture.
- **Update Password**: Users can change their password.

## Installation & Setup

### Prerequisites
Ensure you have the following installed:
- Python (>=3.10)
- Django (>=5.0)
- PostgreSQL/MySQL/SQLite (Choose based on preference)

### Step 1: Clone the Repository
```bash
git clone https://github.com/ashiques-dev/user-profile-crud-backend.git
cd user-profile-crud-backend
```

### Step 2: Create and Activate a Virtual Environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Configure Environment Variables
Create a `.env` file and set the following environment variables:
```env
SECRET_KEY = 
DEBUG=
ALLOWED_HOSTS = 

EMAIL_BACKEND = 
EMAIL_HOST = 
EMAIL_PORT = 
EMAIL_USE_TLS = 
EMAIL_HOST_USER =
EMAIL_HOST_PASSWORD =

CORS_ALLOWED_ORIGINS = 

REDIS_URL =
```

### Step 5: Apply Migrations
```bash
python manage.py migrate
```

### Step 6: Run the Server
```bash
python manage.py runserver
```

## API Endpoints

### Authentication Endpoints
| Method | Endpoint                 | Description         |
|--------|--------------------------|---------------------|
| POST   | /auth/sign-up/<str:role>/ | User Signup        |
| POST   | /auth/sign-in/<str:role>/ | User Sign In       |
| POST   | /auth/verify-otp/<str:uid>/<str:token>/ | OTP Verification   |
| POST   | /auth/resend-otp/<str:uid>/<str:token>/ | Resend OTP        |
| POST   | /auth/forgot-password/   | Forgot Password    |
| POST   | /auth/reset-password/<str:uid>/<str:token>/ | Reset Password     |
| POST   | /auth/refresh/           | Token Refresh      |

### Profile Endpoints
| Method | Endpoint                     | Description                |
|--------|------------------------------|----------------------------|
| GET    | /user-profile/                | Get User Profile          |
| PUT    | /user-profile/update/         | Update Name/Profile Info  |
| PUT    | /user-profile/change-picture/ | Change Profile Picture    |
| PUT    | /user-profile/update-password/| Update Password          |

## Technologies Used
- Django & Django REST Framework (DRF)
- PostgreSQL/MySQL/SQLite
- Redis & Celery (for async tasks like email sending)

