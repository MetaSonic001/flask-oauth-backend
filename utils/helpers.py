import random
import string
from functools import wraps
from flask import request, jsonify
from services.auth_service import AuthService

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(' ')[1]
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        user_id = AuthService.verify_token(token)
        if not user_id:
            return jsonify({'error': 'Token is invalid'}), 401
        
        return f(*args, **kwargs)
    return decorated

def generate_random_string(length=32):
    """Generate a random string for CSRF tokens or session keys"""
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))
