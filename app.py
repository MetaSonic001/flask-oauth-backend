from flask import Flask
from flask_login import LoginManager
from flask_session import Session
from models.user import db, User
from routes.auth import auth_bp
from routes.oauth import oauth_bp, oauth, init_oauth
from config.config import Config

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Initialize extensions
    db.init_app(app)
    oauth.init_app(app)
    Session(app)
    
    login_manager = LoginManager()
    login_manager.init_app(app)
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    # Initialize OAuth providers
    init_oauth(app)
    
    # Register blueprints
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(oauth_bp, url_prefix='/oauth')
    
    # Create database tables
    with app.app_context():
        db.create_all()
    
    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, port=5000)