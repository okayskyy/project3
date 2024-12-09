from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from argon2 import PasswordHasher
import uuid
import os
from encryption import encrypt_private_key, decrypt_private_key
from models import db, User, AuthLog
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Initialize the app and the database
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///auth.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  
db.init_app(app)

# Password hasher instance
ph = PasswordHasher()

# Rate limiter
limiter = Limiter(key_func=get_remote_address, app=app)  # Ensuring app is passed here

# Ensure the database tables are created before making requests
@app.before_request
def create_tables():
    db.create_all()

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    
    # Ensure the necessary fields are provided
    username = data.get('username')
    email = data.get('email', '')
    if not username:
        return jsonify({"error": "Username is required"}), 400
    
    
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({"error": "Username already taken"}), 400

    # Generate a secure UUID as a password
    password = str(uuid.uuid4())
    
    # Hash the password using Argon2
    password_hash = ph.hash(password)
    
    # Store the user details in the database
    user = User(username=username, password_hash=password_hash, email=email)
    db.session.add(user)
    db.session.commit()

    
    return jsonify({"password": password}), 201

@app.before_request
def log_request():
   
    if request.endpoint == 'auth':
        ip_address = request.remote_addr
        user_id = None  
        log_entry = AuthLog(request_ip=ip_address, user_id=user_id)
        db.session.add(log_entry)
        db.session.commit()

@app.route('/auth', methods=['POST'])
@limiter.limit("5 per minute")  # Adjusted to a more practical rate limit
def auth():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Check password validity
    try:
        ph.verify(user.password_hash, password)
    except:
        return jsonify({"error": "Invalid password"}), 401

    # Successful authentication (logic here to track the user)
    user_id = user.id  # Assuming user has an 'id' field
    ip_address = request.remote_addr
    log_entry = AuthLog(request_ip=ip_address, user_id=user_id)
    db.session.add(log_entry)
    db.session.commit()

    return jsonify({"message": "Authenticated successfully"}), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8080)  
