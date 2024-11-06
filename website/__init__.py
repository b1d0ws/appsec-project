from flask import Flask, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from os import path
from flask_login import LoginManager
from dotenv import load_dotenv
import os
from werkzeug.exceptions import RequestEntityTooLarge
from datetime import timedelta

db = SQLAlchemy()
DB_NAME = "database.db"

# This will start our application
def create_app():
    app = Flask(__name__)

    load_dotenv()

    # Limiting file size
    app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2 MB in bytes

    # Register error handler
    @app.errorhandler(RequestEntityTooLarge)
    def handle_file_size_error(e):
        return jsonify({"error": "File is too large!"}), 413

    # Secret Key will be used to generate the tokens
    app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")

    
    @app.before_request
    def before_request():
        session.permanent = True
        app.permanent_session_lifetime = timedelta(minutes=60)
        session.modified = True

    app.config['REMEMBER_COOKIE_DURATION'] = 0

    # Configuring database
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'
    db.init_app(app)

    # Defining the uploade folder for user images
    app.config['UPLOAD_FOLDER'] = 'website/static/userimages/'

    # Defining blueprints to track routes
    from .views import views
    from .auth import auth
    
    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')

    from .models import User, Note

    create_database(app)

    login_manager = LoginManager()
    # If user is not logged in the user will see login page
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))

    return app


def create_database(app):
    if not path.exists('website/'+ DB_NAME):
        with app.app_context():
            db.create_all()
        print("Created Database!")
