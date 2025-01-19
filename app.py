from flask import Flask, request, jsonify, send_from_directory
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename
import os
import jwt
import uuid
from datetime import datetime, timedelta
import magic

from models import db, User, File
from config import Config

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
mail = Mail(app)

def send_verification_email(user_email, token):
    msg = Message('Email Verification',
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[user_email])
    verification_url = f"http://localhost:5000/verify/{token}"
    msg.body = f'Please click the link to verify your email: {verification_url}'
    msg.html = f'''
        <h1>Email Verification</h1>
        <p>Please click the link below to verify your email address:</p>
        <p><a href="{verification_url}">Verify Email</a></p>
        <p>If the button doesn't work, copy and paste this link in your browser:</p>
        <p>{verification_url}</p>
    '''
    mail.send(msg)

def generate_download_url(file_id, user_id):
    payload = {
        'file_id': file_id,
        'user_id': user_id,
        'nonce': str(uuid.uuid4()),  # Add nonce for additional security
        'exp': datetime.utcnow() + timedelta(minutes=30)
    }
    token = jwt.encode(payload, app.config['JWT_SECRET_KEY'], algorithm='HS256')
    return f"/download-file/{token}"

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'Email already registered'}), 400
    
    verification_token = str(uuid.uuid4())
    user = User(
        email=data['email'],
        user_type='client',
        verification_token=verification_token
    )
    user.set_password(data['password'])
    
    db.session.add(user)
    db.session.commit()
    
    send_verification_email(data['email'], verification_token)
    return jsonify({'message': 'Please check your email for verification'}), 201

@app.route('/verify/<token>', methods=['GET'])
def verify_email(token):
    user = User.query.filter_by(verification_token=token).first()
    if not user:
        return jsonify({'message': 'Invalid verification token'}), 400
    
    user.is_verified = True
    user.verification_token = None
    db.session.commit()
    return jsonify({'message': 'Email verified successfully'}), 200

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    
    if not user or not user.check_password(data['password']):
        return jsonify({'message': 'Invalid credentials'}), 401
    
    if not user.is_verified and user.user_type == 'client':
        return jsonify({'message': 'Please verify your email first'}), 401
    
    token = jwt.encode(
        {'user_id': user.id, 'user_type': user.user_type},
        app.config['JWT_SECRET_KEY'],
        algorithm='HS256'
    )
    return jsonify({'token': token}), 200

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/upload', methods=['POST'])
def upload_file():
    # Get user from token
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'No token provided'}), 401
    
    try:
        payload = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        if payload['user_type'] != 'ops':
            return jsonify({'message': 'Only ops users can upload files'}), 403
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401
    
    if 'file' not in request.files:
        return jsonify({'message': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'message': 'No selected file'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'message': 'File type not allowed'}), 400
    
    filename = secure_filename(file.filename)
    unique_filename = f"{uuid.uuid4()}_{filename}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
    
    # Check file type before saving
    file_content = file.read()
    mime = magic.Magic(mime=True)
    file_type = mime.from_buffer(file_content)  # Check before saving
    
    allowed_mime_types = {
        'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    }
    
    if file_type not in allowed_mime_types:
        return jsonify({'message': 'Invalid file type'}), 400
    
    # Reset file pointer and save
    file.seek(0)
    file.save(file_path)
    
    try:
        new_file = File(
            filename=unique_filename,
            original_filename=filename,
            uploaded_by=payload['user_id'],
            upload_date=datetime.utcnow(),
            file_type=file.filename.rsplit('.', 1)[1].lower()
        )
        db.session.add(new_file)
        db.session.commit()
    except Exception as e:
        # Clean up file if database operation fails
        if os.path.exists(file_path):
            os.remove(file_path)
        return jsonify({'message': 'Error saving file information'}), 500
    
    return jsonify({'message': 'File uploaded successfully'}), 201

@app.route('/files', methods=['GET'])
def list_files():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'No token provided'}), 401
    
    try:
        payload = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        if payload['user_type'] != 'client':
            return jsonify({'message': 'Access denied'}), 403
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401
    
    files = File.query.all()
    file_list = [{
        'id': file.id,
        'filename': file.original_filename,
        'upload_date': file.upload_date.strftime('%Y-%m-%d %H:%M:%S'),
        'file_type': file.file_type
    } for file in files]
    
    return jsonify({'files': file_list}), 200

@app.route('/download-file/<int:file_id>', methods=['GET'])
def get_download_link(file_id):
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'No token provided'}), 401
    
    try:
        payload = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        if payload['user_type'] != 'client':
            return jsonify({'message': 'Access denied'}), 403
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401
    
    file = File.query.get_or_404(file_id)
    download_url = generate_download_url(file_id, payload['user_id'])
    
    return jsonify({
        'download_link': download_url,
        'message': 'success'
    }), 200

@app.route('/download-file/<token>', methods=['GET'])
def download_file(token):
    # Add client authentication check
    auth_token = request.headers.get('Authorization')
    if not auth_token:
        return jsonify({'message': 'No authentication token provided'}), 401
    
    try:
        auth_payload = jwt.decode(auth_token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        if auth_payload['user_type'] != 'client':
            return jsonify({'message': 'Access denied'}), 403
        
        payload = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        user = User.query.get(payload['user_id'])
        if not user or user.user_type != 'client':
            return jsonify({'message': 'Access denied'}), 403
        
        file = File.query.get(payload['file_id'])
        if not file:
            return jsonify({'message': 'File not found'}), 404
        
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        if not os.path.exists(file_path):
            return jsonify({'message': 'File not found'}), 404
            
        return send_from_directory(
            app.config['UPLOAD_FOLDER'],
            file.filename,
            as_attachment=True,
            download_name=file.original_filename  # Updated parameter name
        )
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Download link expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid download link'}), 401
    except Exception as e:
        return jsonify({'message': 'Error processing download'}), 500

if __name__ == '__main__':
    with app.app_context():
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])
        db.create_all()
        
        # Check if ops user exists
        existing_ops = User.query.filter_by(email="opsuser@example.com").first()
        if not existing_ops:
            ops_user = User(
                email="opsuser@example.com",
                user_type="ops",
                is_verified=True
            )
            ops_user.set_password("opspass123")
            db.session.add(ops_user)
            db.session.commit()
            print("Ops user created successfully")
        else:
            print("Ops user already exists")
        
    app.run(debug=True)