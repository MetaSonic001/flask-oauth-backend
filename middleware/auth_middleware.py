from functools import wraps
from flask import request, jsonify, g
from utils.token_manager import TokenManager
from models.user import User

def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'No token provided'}), 401
        
        token = auth_header.split(' ')[1]
        user_id = TokenManager.verify_token(token)
        
        if user_id == 'expired':
            return jsonify({'error': 'Token expired', 'code': 'TOKEN_EXPIRED'}), 401
        if not user_id:
            return jsonify({'error': 'Invalid token'}), 401
            
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 401
            
        g.user = user
        return f(*args, **kwargs)
    return decorated
