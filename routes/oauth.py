# routes/oauth.py
from flask import Blueprint, request, jsonify, current_app, url_for, redirect, session
from flask_oauthlib.client import OAuth
from models.user import User, UserOAuthProvider, db  # Import UserOAuthProvider here
from services.auth_service import AuthService
from datetime import datetime
from utils.token_manager import TokenManager


oauth = OAuth()
oauth_bp = Blueprint('oauth', __name__)

def init_oauth(app):
    """Initialize OAuth providers with the app context"""
    
    # Google OAuth setup
    google = oauth.remote_app(
        'google',
        consumer_key=app.config.get('GOOGLE_CLIENT_ID'),
        consumer_secret=app.config.get('GOOGLE_CLIENT_SECRET'),
        request_token_params={'scope': 'email profile'},
        base_url='https://www.googleapis.com/oauth2/v1/',
        request_token_url=None,
        access_token_method='POST',
        access_token_url='https://accounts.google.com/o/oauth2/token',
        authorize_url='https://accounts.google.com/o/oauth2/auth'
    )

    # Facebook OAuth setup
    facebook = oauth.remote_app(
        'facebook',
        consumer_key=app.config.get('FACEBOOK_CLIENT_ID'),
        consumer_secret=app.config.get('FACEBOOK_CLIENT_SECRET'),
        request_token_params={'scope': 'email'},
        base_url='https://graph.facebook.com/',
        request_token_url=None,
        access_token_url='/oauth/access_token',
        access_token_method='GET',
        authorize_url='https://www.facebook.com/dialog/oauth'
    )

    # GitHub OAuth setup
    github = oauth.remote_app(
        'github',
        consumer_key=app.config.get('GITHUB_CLIENT_ID'),
        consumer_secret=app.config.get('GITHUB_CLIENT_SECRET'),
        request_token_params={'scope': 'user:email'},
        base_url='https://api.github.com/',
        request_token_url=None,
        access_token_method='POST',
        access_token_url='https://github.com/login/oauth/access_token',
        authorize_url='https://github.com/login/oauth/authorize'
    )

    # LinkedIn OAuth setup
    linkedin = oauth.remote_app(
        'linkedin',
        consumer_key=app.config.get('LINKEDIN_CLIENT_ID'),
        consumer_secret=app.config.get('LINKEDIN_CLIENT_SECRET'),
        request_token_params={'scope': 'r_liteprofile r_emailaddress'},
        base_url='https://api.linkedin.com/v2/',
        request_token_url=None,
        access_token_method='POST',
        access_token_url='https://www.linkedin.com/oauth/v2/accessToken',
        authorize_url='https://www.linkedin.com/oauth/v2/authorization'
    )

    # Token getters
    @google.tokengetter
    def get_google_oauth_token():
        return session.get('google_token')

    @facebook.tokengetter
    def get_facebook_oauth_token():
        return session.get('facebook_token')

    @github.tokengetter
    def get_github_oauth_token():
        return session.get('github_token')

    @linkedin.tokengetter
    def get_linkedin_oauth_token():
        return session.get('linkedin_token')

    # Store providers in app context
    app.google = google
    app.facebook = facebook
    app.github = github
    app.linkedin = linkedin

# OAuth routes
from flask import request, session, url_for, jsonify, current_app
from flask_oauthlib.client import OAuth

# Assuming OAuth setup has been done previously for all providers (Google, LinkedIn, Facebook, GitHub)

@oauth_bp.route('/login/<provider>')
def oauth_login(provider):
    """
    Initiates the OAuth login flow for the specified provider.
    The 'next' parameter is stored in the session to redirect the user after successful authentication.
    """
    next_url = request.args.get('next')
    if next_url:
        session['next_url'] = next_url
    
    if provider == 'google':
        return current_app.google.authorize(callback=url_for('oauth.google_callback', _external=True))
    elif provider == 'linkedin':
        return current_app.linkedin.authorize(callback=url_for('oauth.linkedin_callback', _external=True))
    elif provider == 'facebook':
        return current_app.facebook.authorize(callback=url_for('oauth.facebook_callback', _external=True))
    elif provider == 'github':
        return current_app.github.authorize(callback=url_for('oauth.github_callback', _external=True))
    else:
        return jsonify({'error': 'Provider not supported'}), 400

@oauth_bp.route('/login/google/callback')
def google_callback():
    """
    Handles the callback from Google OAuth.
    Retrieves user info and processes the user data, then redirects accordingly.
    """
    resp = current_app.google.authorized_response()
    if resp is None or resp.get('access_token') is None:
        return jsonify({'error': 'Access denied'}), 401
    
    session['google_token'] = (resp['access_token'], '')
    me = current_app.google.get('userinfo')
    
    next_url = session.pop('next_url', None)
    return handle_oauth_user(
        email=me.data['email'],
        name=me.data['name'],
        provider='google',
        provider_id=me.data['id'],
        next_url=next_url
    )

@oauth_bp.route('/login/linkedin/callback')
def linkedin_callback():
    """
    Handles the callback from LinkedIn OAuth.
    Retrieves user info and processes the user data, then redirects accordingly.
    """
    resp = current_app.linkedin.authorized_response()
    if resp is None or resp.get('access_token') is None:
        return jsonify({'error': 'Access denied'}), 401
    
    session['linkedin_token'] = (resp['access_token'], '')
    me = current_app.linkedin.get('people/~')
    
    next_url = session.pop('next_url', None)
    return handle_oauth_user(
        email=me.data['emailAddress'],
        name=me.data['formattedName'],
        provider='linkedin',
        provider_id=me.data['id'],
        next_url=next_url
    )

@oauth_bp.route('/login/facebook/callback')
def facebook_callback():
    """
    Handles the callback from Facebook OAuth.
    Retrieves user info and processes the user data, then redirects accordingly.
    """
    resp = current_app.facebook.authorized_response()
    if resp is None or resp.get('access_token') is None:
        return jsonify({'error': 'Access denied'}), 401
    
    session['facebook_token'] = (resp['access_token'], '')
    me = current_app.facebook.get('me?fields=id,name,email')
    
    next_url = session.pop('next_url', None)
    return handle_oauth_user(
        email=me.data['email'],
        name=me.data['name'],
        provider='facebook',
        provider_id=me.data['id'],
        next_url=next_url
    )

@oauth_bp.route('/login/github/callback')
def github_callback():
    """
    Handles the callback from GitHub OAuth.
    Retrieves user info and processes the user data, then redirects accordingly.
    """
    resp = current_app.github.authorized_response()
    if resp is None or resp.get('access_token') is None:
        return jsonify({'error': 'Access denied'}), 401
    
    session['github_token'] = (resp['access_token'], '')
    me = current_app.github.get('user')
    
    next_url = session.pop('next_url', None)
    return handle_oauth_user(
        email=me.data['email'],
        name=me.data['name'],
        provider='github',
        provider_id=me.data['id'],
        next_url=next_url
    )


def handle_oauth_user(email, name, provider, provider_id, next_url=None):
    """Enhanced OAuth user handling with multiple providers support"""
    user = User.query.filter_by(email=email).first()
            
    if user:
        # Check if this provider is already linked
        existing_provider = UserOAuthProvider.query.filter_by(
            user_id=user.id,
            provider=provider
        ).first()
                
        if not existing_provider:
            # Add new provider to existing user
            new_provider = UserOAuthProvider(
                user_id=user.id,
                provider=provider,
                provider_user_id=provider_id
            )
            db.session.add(new_provider)
    else:
        # Create new user
        user = User(
            email=email,
            name=name
        )
        db.session.add(user)
        db.session.flush()  # Get user.id
                
        # Add OAuth provider
        oauth_provider = UserOAuthProvider(
            user_id=user.id,
            provider=provider,
            provider_user_id=provider_id
        )
        db.session.add(oauth_provider)
            
    # Update last login
    user.last_login = datetime.utcnow()
    db.session.commit()
            
    # Generate and store tokens
    access_token, refresh_token = TokenManager.generate_and_store_tokens(user.id)
            
    # Return user info and tokens as JSON
    response_data = {
        'user': {
            'id': user.id,
            'email': user.email,
            'name': user.name,
            'last_login': user.last_login.isoformat()
        },
        'tokens': {
            'access_token': access_token,
            'refresh_token': refresh_token
        }
    }
    return jsonify(response_data)
