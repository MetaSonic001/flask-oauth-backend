import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Basic Flask config
    SECRET_KEY = os.getenv('SECRET_KEY') or 'dev-key-please-change'
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Session configuration
    SESSION_TYPE = 'filesystem'
    PERMANENT_SESSION_LIFETIME = timedelta(days=30)
    
    # Frontend URL for redirects
    FRONTEND_URL = os.getenv('FRONTEND_URL', 'http://localhost:3000')
    
    # Token settings
    ACCESS_TOKEN_LIFETIME = timedelta(minutes=30)
    REFRESH_TOKEN_LIFETIME = timedelta(days=30)
    
    # OAuth Configs
    GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
    GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
    FACEBOOK_CLIENT_ID = os.getenv('FACEBOOK_CLIENT_ID')
    FACEBOOK_CLIENT_SECRET = os.getenv('FACEBOOK_CLIENT_SECRET')
    GITHUB_CLIENT_ID = os.getenv('GITHUB_CLIENT_ID')
    GITHUB_CLIENT_SECRET = os.getenv('GITHUB_CLIENT_SECRET')
    LINKEDIN_CLIENT_ID = os.getenv('LINKEDIN_CLIENT_ID')
    LINKEDIN_CLIENT_SECRET = os.getenv('LINKEDIN_CLIENT_SECRET')