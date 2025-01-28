from flask import Blueprint
from .auth import auth_bp
from .oauth import oauth_bp

# You can add any shared route utilities here if needed
def init_routes(app):
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(oauth_bp, url_prefix='/oauth')