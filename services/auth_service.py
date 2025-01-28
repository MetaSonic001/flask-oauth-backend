import bcrypt
import jwt
from datetime import datetime, timedelta
from models.user import User, db
from flask import current_app

class AuthService:
    @staticmethod
    def hash_password(password):
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    @staticmethod
    def check_password(password, hashed):
        return bcrypt.checkpw(password.encode('utf-8'), hashed)
    
    @staticmethod
    def generate_token(user_id):
        payload = {
            'user_id': user_id,
            'exp': datetime.utcnow() + timedelta(days=1)
        }
        return jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')
    
    @staticmethod
    def verify_token(token):
        try:
            payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
            return payload['user_id']
        except:
            return None