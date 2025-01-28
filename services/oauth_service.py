import bcrypt
import jwt
from datetime import datetime
from flask import current_app
from models.user import User, db

class AuthService:
    @staticmethod
    def create_tokens(user_id):
        """Create access and refresh tokens"""
        access_token = jwt.encode({
            'user_id': user_id,
            'exp': datetime.utcnow() + current_app.config['ACCESS_TOKEN_LIFETIME'],
            'type': 'access'
        }, current_app.config['SECRET_KEY'], algorithm='HS256')
        
        refresh_token = jwt.encode({
            'user_id': user_id,
            'exp': datetime.utcnow() + current_app.config['REFRESH_TOKEN_LIFETIME'],
            'type': 'refresh'
        }, current_app.config['SECRET_KEY'], algorithm='HS256')
        
        return access_token, refresh_token
    
    @staticmethod
    def verify_token(token, token_type='access'):
        try:
            payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
            if payload.get('type') != token_type:
                return None
            return payload.get('user_id')
        except jwt.ExpiredSignatureError:
            return 'expired'
        except jwt.InvalidTokenError:
            return None
    
    @staticmethod
    def hash_password(password):
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    @staticmethod
    def verify_password(password, password_hash):
        return bcrypt.checkpw(password.encode('utf-8'), password_hash)
