from flask import Blueprint, jsonify, g, request
from middleware.auth_middleware import auth_required
from utils.token_manager import TokenManager
from models.user import User, db

profile_bp = Blueprint('profile', __name__)

@profile_bp.route('/me', methods=['GET'])
@auth_required
def get_profile():
    """Get current user's profile"""
    return jsonify(g.user.to_dict())

@profile_bp.route('/refresh-token', methods=['POST'])
def refresh_token():
    """Generate new access token using refresh token"""
    refresh_token = request.json.get('refresh_token')
    if not refresh_token:
        return jsonify({'error': 'Refresh token required'}), 400
        
    user_id = TokenManager.verify_token(refresh_token, 'refresh')
    if not user_id or user_id == 'expired':
        return jsonify({'error': 'Invalid or expired refresh token'}), 401
        
    access_token, _ = TokenManager.generate_tokens(user_id)
    return jsonify({'access_token': access_token})