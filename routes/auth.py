from flask import Blueprint, request, jsonify, session
from models.user import User, db
from services.auth_service import AuthService
from flask_login import login_user, logout_user, login_required
from email_validator import validate_email, EmailNotValidError

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.json
    
    try:
        # Validate email
        validate_email(data['email'])
    except EmailNotValidError:
        return jsonify({'error': 'Invalid email'}), 400
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already registered'}), 400
    
    user = User(
        email=data['email'],
        password=AuthService.hash_password(data['password']).decode('utf-8'),
        name=data.get('name', '')
    )
    
    db.session.add(user)
    db.session.commit()
    
    token = AuthService.generate_token(user.id)
    return jsonify({'token': token, 'user': user.to_dict()})

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(email=data['email']).first()
    
    if not user or not AuthService.check_password(data['password'], user.password.encode('utf-8')):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    login_user(user)
    token = AuthService.generate_token(user.id)
    return jsonify({'token': token, 'user': user.to_dict()})

@auth_bp.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logged out successfully'})