# Secure File Sharing System

A Flask-based secure file sharing system with user roles, email verification and encrypted download URLs.

## Features
- Two user types: Operations (Ops) and Client
- Secure file upload/download system
- Email verification for new users
- JWT-based authentication
- Encrypted download URLs
- File type validation
- Role-based access control

## Installation

- Download the ZIP file or clone the repository.

1. Create and activate virtual environment:
```
python -m venv venv
venv\Scripts\activate  # Windows
```

2. Install dependencies:
```
pip install -r requirements.txt
```

## Configuration
1. Create .env file in project root:
```
(Dummy env file)
SECRET_KEY=your-secret-key
JWT_SECRET_KEY=your-jwt-secret-key
MAIL_USERNAME=your-gmail@gmail.com
MAIL_PASSWORD=your-gmail-app-password
```

2. Gmail Setup: (Setting up the mail id to be used to send verification mail for new client user sign up)
- Enable 2-factor authentication
- Generate App Password
- Use App Password in .env file


## Database Setup
The application automatically:

- Creates SQLite database
- Initializes required tables
- Creates default ops user:
    - Email: opsuser@example.com
    - Password: opspass123

## Running the Application
```
python app.py
```

# Testing Sequence with Postman

### 1. Client User Signup
```
POST http://localhost:5000/signup
Headers:
Content-Type: application/json

Body:
{
    "email": "client@example.com",
    "password": "clientpass123"
}
```

### 2. Verify Email
- Check email for verification link
- Click or copy URL: `http://localhost:5000/verify/{token}`

### 3. Client Login
```
POST http://localhost:5000/login
Headers:
Content-Type: application/json

Body:
{
    "email": "client@example.com",
    "password": "clientpass123"
}
Response: "<token>"  # Save this token - client_user_token
```

### 4. Ops User Login
```
POST http://localhost:5000/login
Headers:
Content-Type: application/json

Body:
{
    "email": "ops@example.com",
    "password": "opspass123"
}
Response: "<token>"  # Save this token - ops_user_token
```

### 5. Upload File (Ops User)
```
POST http://localhost:5000/upload
Headers:
Authorization: <ops_user_token>

Body:
Form-data:
key: file
value: [select file] (.xlsx, .docx, or .pptx)
```

### 6. List Files (Client User)
```
GET http://localhost:5000/files
Headers:
Authorization: <client_user_token>
```

### 7. Get Download Link (Client User)
```
GET http://localhost:5000/download-file/1
Headers:
Authorization: <client_user_token>
```

### 8. Download File (Client User)
```
GET http://localhost:5000/download-file/<token>
Headers:
Authorization: <client_user_token>
```



## Testing Instructions
- Start the server
- Create client account
- Verify email
- Login as ops user
- Upload test files
- Login as client
- List and download files

## Postman Collection
Import the provided Postman collection for testing


### Error Codes
- 400: Bad Request
- 401: Unauthorized
- 403: Forbidden
- 404: Not Found
- 500: Server Error

