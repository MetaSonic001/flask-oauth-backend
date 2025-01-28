from datetime import datetime, timedelta
import jwt
from flask import current_app
from models.user import UserToken, db

class TokenManager:
    @staticmethod
    def generate_and_store_tokens(user_id):
        """Generate and store both access and refresh tokens in the database"""
        # Generate tokens
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
        
        # Deactivate old tokens
        UserToken.query.filter_by(user_id=user_id, is_active=True).update({'is_active': False})
        
        # Store new tokens
        token = UserToken(
            user_id=user_id,
            access_token=access_token,
            refresh_token=refresh_token,
            expires_at=datetime.utcnow() + current_app.config['REFRESH_TOKEN_LIFETIME']
        )
        db.session.add(token)
        db.session.commit()
        
        return access_token, refresh_token
    
    @staticmethod
    def verify_token(token, token_type='access'):
        """Verify token and return user_id if valid"""
        try:
            payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
            if payload.get('type') != token_type:
                return None
                
            # Check if token exists and is active in database
            stored_token = UserToken.query.filter_by(
                user_id=payload.get('user_id'),
                is_active=True
            ).first()
            
            if not stored_token:
                return None
                
            return payload.get('user_id')
        except jwt.ExpiredSignatureError:
            return 'expired'
        except jwt.InvalidTokenError:
            return None
